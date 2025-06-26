#include "network_manager.h"
#include "repository_manager.h"
#include "identity_manager.h"
#include <QNetworkInterface>
#include <QNetworkDatagram>
#include <QDataStream>
#include <QDateTime>
#include <QDebug>
#include <QUuid>
#include <QFile>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <sodium.h>
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <functional>

const qint64 PEER_TIMEOUT_MS = 15000;
const int BROADCAST_INTERVAL_MS = 5000;
const int PENDING_CONNECTION_TIMEOUT_MS = 30000;

NetworkManager::NetworkManager(const QString &myUsername,
                               IdentityManager *identityManager,
                               RepositoryManager *repoManager,
                               QObject *parent)
    : QObject(parent),
      m_myUsername(myUsername),
      m_identityManager(identityManager),
      m_repoManager_ptr(repoManager)
{
    if (!m_identityManager || !m_repoManager_ptr)
    {
        qCritical() << "NetworkManager initialized without valid IdentityManager or RepositoryManager!";
    }

    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &NetworkManager::onNewTcpConnection);

    m_udpSocket = new QUdpSocket(this);
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &NetworkManager::onUdpReadyRead);

    m_broadcastTimer = new QTimer(this);
    connect(m_broadcastTimer, &QTimer::timeout, this, &NetworkManager::onBroadcastTimerTimeout);

    m_peerCleanupTimer = new QTimer(this);
    connect(m_peerCleanupTimer, &QTimer::timeout, this, &NetworkManager::onPeerCleanupTimerTimeout);
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2);

    qRegisterMetaType<DiscoveredPeerInfo>("DiscoveredPeerInfo");
}

NetworkManager::~NetworkManager()
{
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();

    qDeleteAll(m_incomingTransfers);
    m_incomingTransfers.clear();
    qDeleteAll(m_outgoingTransfers);
    m_outgoingTransfers.clear();

    m_socketBuffers.clear();
    m_socketToPeerUsernameMap.clear();
    m_handshakeSent.clear();
    m_peerPublicKeys.clear();
    m_pendingConnections.clear();
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString() << ":" << socket->peerPort();
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

            m_allTcpSockets.append(socket);
            m_socketToPeerUsernameMap.insert(socket, "AwaitingID:" + socket->peerAddress().toString());

            QTimer *timer = new QTimer(socket);
            timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this, socket]()
                    {
                        qWarning() << "Handshake timeout for incoming connection from" << getPeerDisplayString(socket);
                        rejectPendingTcpConnection(socket); });
            m_pendingConnections.insert(socket, timer);
            timer->start(PENDING_CONNECTION_TIMEOUT_MS);

            QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
            emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
        }
    }
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
    {
        qWarning() << "onTcpSocketReadyRead called with invalid sender.";
        return;
    }
    processIncomingTcpData(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Accepting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();

        sendIdentityOverTcp(pendingSocket);

        if (m_socketBuffers.contains(pendingSocket) && !m_socketBuffers[pendingSocket].isEmpty())
        {
            qDebug() << "Processing buffered data for newly accepted connection.";
            processIncomingTcpData(pendingSocket);
        }
    }
    else
    {
        qWarning() << "Attempted to accept a connection that was not pending:" << getPeerDisplayString(pendingSocket);
        if (m_allTcpSockets.contains(pendingSocket) && pendingSocket->state() == QAbstractSocket::ConnectedState)
        {
            qDebug() << "Socket is still connected or already processed handshake, no action needed.";
        }
        else
        {
            qWarning() << "Socket is no longer valid.";
            if (pendingSocket)
                pendingSocket->deleteLater();
        }
    }
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Rejecting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();
        pendingSocket->disconnectFromHost();
    }
    else
    {
        qWarning() << "Attempted to reject a connection that was not pending:" << getPeerDisplayString(pendingSocket);
        if (m_allTcpSockets.contains(pendingSocket) && pendingSocket->state() == QAbstractSocket::ConnectedState)
        {
            qDebug() << "Socket is still connected, likely completed handshake before rejection.";
        }
        else if (pendingSocket)
        {
            qDebug() << "Socket is already disconnected or invalid.";
            pendingSocket->deleteLater();
        }
    }
}

void NetworkManager::handleEncryptedPayload(const QString &peerId, const QVariantMap &payload)
{
    QString messageType = payload.value("__messageType").toString();
    if (messageType.isEmpty())
    {
        qWarning() << "Received encrypted payload with no messageType from" << peerId;
        return;
    }

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;
    emit secureMessageReceived(peerId, messageType, payload);
}

void NetworkManager::processIncomingTcpData(QTcpSocket *socket)
{
    QByteArray &buffer = m_socketBuffers[socket];
    QDataStream in(&buffer, QIODevice::ReadOnly);
    in.setVersion(QDataStream::Qt_5_15);

    while (socket->bytesAvailable() > 0 || buffer.size() > 0)
    {
        if (socket->bytesAvailable() > 0)
        {
            buffer.append(socket->readAll());
        }

        if (m_incomingTransfers.contains(socket))
        {
            IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
            qint64 bytesToWrite = qMin((qint64)buffer.size(), transfer->totalSize - transfer->bytesReceived);

            if (bytesToWrite > 0)
            {
                qint64 bytesWritten = transfer->file->write(buffer.constData(), bytesToWrite);
                if (bytesWritten > 0)
                {
                    buffer.remove(0, static_cast<int>(bytesWritten));
                    transfer->bytesReceived += bytesWritten;
                    emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
                }
                else
                {
                    qWarning() << "Error writing to bundle file:" << transfer->file->errorString();
                    transfer->file->close();
                    emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, false, "Error writing to local file.");
                    delete m_incomingTransfers.take(socket);
                    if (socket->property("is_transfer_socket").toBool())
                    {
                        socket->disconnectFromHost();
                    }
                    return;
                }
            }

            if (transfer->bytesReceived >= transfer->totalSize)
            {
                qDebug() << "File transfer completed for" << transfer->repoName;
                transfer->file->close();
                emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, true, "Transfer successful.");
                delete m_incomingTransfers.take(socket);
                if (socket->property("is_transfer_socket").toBool())
                {
                    socket->disconnectFromHost();
                }
                continue;
            }
            else
            {
                return;
            }
        }

        if (buffer.size() < sizeof(quint32))
        {
            return;
        }

        in.startTransaction();
        QString messageType;
        in >> messageType;

        if (in.commitTransaction())
        {
            if (messageType == "IDENTITY_HANDSHAKE_V2")
            {
                in.startTransaction();
                QString peerUsername, peerKeyHex;
                in >> peerUsername >> peerKeyHex;

                if (in.commitTransaction())
                {
                    qDebug() << "Received IDENTITY_HANDSHAKE_V2 from" << peerUsername;
                    QString currentTempId = m_socketToPeerUsernameMap.value(socket, "");
                    bool isIncomingPending = m_pendingConnections.contains(socket);
                    bool isOutgoingAttempt = socket->property("is_outgoing_attempt").toBool();

                    if (isIncomingPending)
                    {
                        qDebug() << "Handshake received for connection that was pending acceptance.";
                        QTimer *timer = m_pendingConnections.take(socket);
                        if (timer)
                            timer->deleteLater();
                    }
                    else if (isOutgoingAttempt)
                    {
                        QString expectedPeer = currentTempId;
                        if (expectedPeer.startsWith("ConnectingTo:"))
                        {
                            expectedPeer.remove("ConnectingTo:");
                        }
                        else
                        {
                            expectedPeer.clear();
                        }

                        if (!expectedPeer.isEmpty() && expectedPeer != peerUsername)
                        {
                            qWarning() << "IDENTITY_HANDSHAKE_V2 mismatch: Expected" << expectedPeer << "but got" << peerUsername << ". Disconnecting.";
                            socket->disconnectFromHost();
                            return;
                        }
                        qDebug() << "Handshake received for outgoing connection.";
                    }
                    else
                    {
                        qWarning() << "Received unexpected IDENTITY_HANDSHAKE_V2 from" << peerUsername << "on socket not marked as pending or outgoing attempt.";
                        socket->disconnectFromHost();
                        return;
                    }

                    m_socketToPeerUsernameMap.insert(socket, peerUsername);
                    m_peerPublicKeys.insert(peerUsername, QByteArray::fromHex(peerKeyHex.toUtf8()));

                    if (!m_handshakeSent.contains(socket))
                    {
                        sendIdentityOverTcp(socket);
                    }

                    emit newTcpPeerConnected(socket, peerUsername, peerKeyHex);
                }
                else
                {
                    qWarning() << "Failed to commit transaction for IDENTITY_HANDSHAKE_V2 payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "REQUEST_REPO_BUNDLE")
            {
                in.startTransaction();
                QString requestingPeerUsername, repoName, clientWantsToSaveAt;
                in >> requestingPeerUsername >> repoName >> clientWantsToSaveAt;

                if (in.commitTransaction())
                {
                    qDebug() << "Received REQUEST_REPO_BUNDLE for" << repoName << "from" << requestingPeerUsername;
                    m_socketToPeerUsernameMap.insert(socket, requestingPeerUsername);
                    emit repoBundleRequestedByPeer(socket, requestingPeerUsername, repoName, clientWantsToSaveAt);
                }
                else
                {
                    qWarning() << "Failed to commit transaction for REQUEST_REPO_BUNDLE payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "SEND_REPO_BUNDLE_START")
            {
                in.startTransaction();
                QString repoName;
                qint64 totalSize;
                in >> repoName >> totalSize;

                if (in.commitTransaction())
                {
                    qDebug() << "Received SEND_REPO_BUNDLE_START for" << repoName << "size" << totalSize;
                    QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/P2PGitBundles/" + QUuid::createUuid().toString() + ".bundle";
                    QDir tempDir(QFileInfo(tempPath).path());
                    tempDir.mkpath(".");

                    QFile *file = new QFile(tempPath, this);
                    if (file->open(QIODevice::WriteOnly))
                    {
                        auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, file, totalSize, 0};
                        m_incomingTransfers.insert(socket, transfer);
                        emit repoBundleTransferStarted(repoName, tempPath);
                    }
                    else
                    {
                        qWarning() << "Could not open temp file for bundle transfer:" << tempPath << file->errorString();
                        emit repoBundleCompleted(repoName, tempPath, false, "Could not open local file for writing bundle.");
                        delete file;
                        socket->disconnectFromHost();
                        return;
                    }
                }
                else
                {
                    qWarning() << "Failed to commit transaction for SEND_REPO_BUNDLE_START payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "SEND_REPO_BUNDLE_END")
            {
                in.startTransaction();
                QString repoName;
                in >> repoName;

                if (in.commitTransaction())
                {
                    qDebug() << "Received SEND_REPO_BUNDLE_END for" << repoName;
                    if (m_incomingTransfers.contains(socket))
                    {
                        qWarning() << "SEND_REPO_BUNDLE_END received, but transfer object is still active. Forcing completion.";
                        IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                        transfer->file->close();
                        bool success = (transfer->bytesReceived == transfer->totalSize);
                        emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, success, success ? "Transfer completed (forced)." : "Size mismatch (forced).");
                        delete transfer;
                    }
                    if (socket->property("is_transfer_socket").toBool())
                    {
                        socket->disconnectFromHost();
                    }
                }
                else
                {
                    qWarning() << "Failed to commit transaction for SEND_REPO_BUNDLE_END payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "BROADCAST_MESSAGE")
            {
                in.startTransaction();
                QString message;
                in >> message;
                if (in.commitTransaction())
                {
                    QString peerUsername = m_socketToPeerUsernameMap.value(socket);
                    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID"))
                    {
                        emit broadcastMessageReceived(socket, peerUsername, message);
                    }
                    else
                    {
                        qWarning() << "Received BROADCAST_MESSAGE from unidentified peer.";
                    }
                }
                else
                {
                    qWarning() << "Failed to commit transaction for BROADCAST_MESSAGE payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "GROUP_CHAT_MESSAGE")
            {
                in.startTransaction();
                QString repoAppId, message;
                in >> repoAppId >> message;
                if (in.commitTransaction())
                {
                    QString peerUsername = m_socketToPeerUsernameMap.value(socket);
                    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID"))
                    {
                        emit groupMessageReceived(peerUsername, repoAppId, message);
                    }
                    else
                    {
                        qWarning() << "Received GROUP_CHAT_MESSAGE from unidentified peer.";
                    }
                }
                else
                {
                    qWarning() << "Failed to commit transaction for GROUP_CHAT_MESSAGE payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else if (messageType == "ENCRYPTED_PAYLOAD")
            {
                in.startTransaction();
                QByteArray nonce, ciphertext;
                in >> nonce >> ciphertext;

                if (in.commitTransaction())
                {
                    QString peerId = m_socketToPeerUsernameMap.value(socket);
                    if (peerId.isEmpty() || !m_peerPublicKeys.contains(peerId))
                    {
                        qWarning() << "Received encrypted payload from unknown peer or peer with no public key. Disconnecting.";
                        socket->disconnectFromHost();
                        return;
                    }

                    QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();
                    QByteArray peerPubKey = m_peerPublicKeys.value(peerId);

                    if (nonce.size() != crypto_box_NONCEBYTES)
                    {
                        qWarning() << "Received encrypted payload with invalid nonce size from" << peerId;
                        continue;
                    }
                    if (ciphertext.size() < crypto_box_MACBYTES)
                    {
                        qWarning() << "Received encrypted payload with invalid ciphertext size from" << peerId;
                        continue;
                    }

                    QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

                    if (crypto_box_open_easy(
                            reinterpret_cast<unsigned char *>(decryptedMessage.data()),
                            reinterpret_cast<const unsigned char *>(ciphertext.constData()),
                            ciphertext.size(),
                            reinterpret_cast<const unsigned char *>(nonce.constData()),
                            reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
                            reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
                    {
                        qWarning() << "Failed to decrypt message from" << peerId;
                        continue;
                    }

                    QJsonDocument doc = QJsonDocument::fromJson(decryptedMessage);
                    if (doc.isObject())
                    {
                        handleEncryptedPayload(peerId, doc.object().toVariantMap());
                    }
                    else
                    {
                        qWarning() << "Decrypted message from" << peerId << " is not a JSON object.";
                    }
                }
                else
                {
                    qWarning() << "Failed to commit transaction for ENCRYPTED_PAYLOAD payload.";
                    in.rollbackTransaction();
                    socket->disconnectFromHost();
                    return;
                }
            }
            else
            {
                qWarning() << "Unknown message type received:" << messageType << "from" << getPeerDisplayString(socket) << ". Disconnecting to prevent buffer issues.";
                in.rollbackTransaction();
                socket->disconnectFromHost();
                return;
            }
        }
        else
        {
            in.rollbackTransaction();
            break;
        }

        if (buffer.isEmpty() && socket->bytesAvailable() == 0)
            break;
    }
}

bool NetworkManager::isConnectionPending(QTcpSocket *socket) const
{
    return m_pendingConnections.contains(socket);
}

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    QTcpSocket *existingSocket = nullptr;
    for (QTcpSocket *sock : qAsConst(m_allTcpSockets))
    {
        if (sock->peerAddress() == host && sock->peerPort() == port && !sock->property("is_transfer_socket").toBool() && sock->state() == QAbstractSocket::ConnectedState)
        {
            existingSocket = sock;
            break;
        }
    }

    if (existingSocket)
    {
        qDebug() << "Using existing connection to" << host << ":" << port << " for bundle request.";
        sendRepoBundleRequest(existingSocket, repoName, localPath);
        return;
    }

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_transfer_socket", true);
    m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, "Transfer:Cloning_" + repoName + "_from_" + host.toString());

    connect(socket, &QTcpSocket::connected, this, [=]()
            {
                qDebug() << "Transfer socket connected to" << host << ":" << port << ". Sending bundle request.";
                QByteArray block;
                QDataStream out(&block, QIODevice::WriteOnly);
                out.setVersion(QDataStream::Qt_5_15);
                out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoName << localPath;
                socket->write(block); });

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "Attempting to connect new transfer socket to" << host << ":" << port;
    socket->connectToHost(host, port);

    QTimer *connectTimer = new QTimer(socket);
    connectTimer->setSingleShot(true);
    connect(connectTimer, &QTimer::timeout, this, [=]()
            {
                if (socket->state() == QAbstractSocket::ConnectingState)
                {
                    qWarning() << "Transfer socket connection to" << host << ":" << port << "timed out.";
                    socket->abort();
                    emit repoBundleCompleted(repoName, localPath, false, "Connection to peer timed out.");
                } });
    connectTimer->start(15000);
}

QString NetworkManager::getPeerDisplayString(QTcpSocket *socket)
{
    if (!socket)
        return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    if (!username.isEmpty())
    {
        if (username.startsWith("AwaitingID"))
        {
            return "Incoming (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
        }
        if (username.startsWith("ConnectingTo"))
        {
            return "Connecting (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
        }
        if (username.startsWith("Transfer:"))
        {
            return "Transfer (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
        }
        return username + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
    }
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

QTcpSocket *NetworkManager::getSocketForPeer(const QString &peerUsername)
{
    for (QTcpSocket *sock : qAsConst(m_allTcpSockets))
    {
        QString username = m_socketToPeerUsernameMap.value(sock);
        if (username == peerUsername &&
            !m_pendingConnections.contains(sock) &&
            !sock->property("is_transfer_socket").toBool() &&
            sock->state() == QAbstractSocket::ConnectedState)
        {
            return sock;
        }
    }
    return nullptr;
}

void NetworkManager::sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to send bundle request on disconnected socket.";
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoDisplayName << requesterLocalPath;
    targetPeerSocket->write(block);

    qDebug() << "Sent REQUEST_REPO_BUNDLE for" << repoDisplayName << "to" << getPeerDisplayString(targetPeerSocket);
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId);
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QMap<QString, QVariant> &payload)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Cannot send encrypted message: Socket is null or not connected.";
        return;
    }

    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || peerId.startsWith("AwaitingID") || peerId.startsWith("ConnectingTo") || peerId.startsWith("Transfer:"))
    {
        qWarning() << "Cannot send encrypted message to" << getPeerDisplayString(socket) << ": Peer not fully identified.";
        return;
    }

    if (!m_identityManager || !m_identityManager->areKeysInitialized())
    {
        qWarning() << "Cannot send encrypted message: IdentityManager not initialized.";
        return;
    }

    if (!m_peerPublicKeys.contains(peerId))
    {
        qWarning() << "Cannot send encrypted message to" << peerId << ": Public key not available.";
        return;
    }

    QJsonObject jsonPayload;
    jsonPayload["__messageType"] = messageType;
    for (auto it = payload.constBegin(); it != payload.constEnd(); ++it)
    {
        jsonPayload[it.key()] = QJsonValue::fromVariant(it.value());
    }

    QByteArray plaintext = QJsonDocument(jsonPayload).toJson(QJsonDocument::Compact);
    QByteArray ciphertext(plaintext.size() + crypto_box_MACBYTES, 0);
    QByteArray nonce(crypto_box_NONCEBYTES, 0);

    randombytes_buf(nonce.data(), crypto_box_NONCEBYTES);

    QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();
    QByteArray peerPubKey = m_peerPublicKeys.value(peerId);

    if (crypto_box_easy(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            reinterpret_cast<const unsigned char *>(plaintext.constData()),
            plaintext.size(),
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
            reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
    {
        qWarning() << "Failed to encrypt message for" << peerId;
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("ENCRYPTED_PAYLOAD") << nonce << ciphertext;

    if (socket->write(block) == -1)
    {
        qWarning() << "Failed to write encrypted message to" << getPeerDisplayString(socket) << ":" << socket->errorString();
    }
    else
    {
        qDebug() << "Sent encrypted message of type" << messageType << "to" << getPeerDisplayString(socket);
    }
}

bool NetworkManager::startTcpServer(quint16 port)
{
    if (!m_identityManager || !m_identityManager->areKeysInitialized() || m_myUsername.isEmpty() || !m_repoManager_ptr)
    {
        qWarning() << "Cannot start TCP server: Dependencies not initialized.";
        emit tcpServerStatusChanged(false, port, "Dependencies not initialized.");
        return false;
    }

    if (m_tcpServer->isListening())
    {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        return true;
    }

    if (m_tcpServer->listen(QHostAddress::Any, port))
    {
        quint16 boundPort = m_tcpServer->serverPort();
        qInfo() << "TCP Server listening on port" << boundPort;
        emit tcpServerStatusChanged(true, boundPort, "");
        startUdpDiscovery();
        return true;
    }
    else
    {
        QString errorString = m_tcpServer->errorString();
        qCritical() << "Failed to start TCP server:" << errorString;
        emit tcpServerStatusChanged(false, port, errorString);
        return false;
    }
}

void NetworkManager::stopTcpServer()
{
    if (m_tcpServer && m_tcpServer->isListening())
    {
        quint16 p = m_tcpServer->serverPort();
        m_tcpServer->close();
        qInfo() << "TCP Server stopped listening on port" << p;
        emit tcpServerStatusChanged(false, p);
    }
    stopUdpDiscovery();
}

quint16 NetworkManager::getTcpServerPort() const
{
    return (m_tcpServer && m_tcpServer->isListening()) ? m_tcpServer->serverPort() : 0;
}

bool NetworkManager::connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername)
{
    if (expectedPeerUsername == m_myUsername)
    {
        QList<QHostAddress> localAddresses = QNetworkInterface::allAddresses();
        bool isLocalAddress = false;
        for (const auto &addr : localAddresses)
        {
            if (addr.protocol() == QAbstractSocket::IPv6Protocol && addr.toIPv4Address() != 0)
            {
                if (QHostAddress(addr.toIPv4Address()) == hostAddress)
                {
                    isLocalAddress = true;
                    break;
                }
            }
            else if (addr == hostAddress)
            {
                isLocalAddress = true;
                break;
            }
        }

        if (isLocalAddress)
        {
            qWarning() << "Attempted to connect to myself.";
            emit tcpConnectionStatusChanged(expectedPeerUsername, "", false, "Cannot connect to self.");
            return false;
        }
    }

    if (getSocketForPeer(expectedPeerUsername))
    {
        qDebug() << "Already connected to peer" << expectedPeerUsername;
        QString peerPubKeyHex = m_peerPublicKeys.contains(expectedPeerUsername) ? m_peerPublicKeys.value(expectedPeerUsername).toHex() : "";
        emit tcpConnectionStatusChanged(expectedPeerUsername, peerPubKeyHex, true, "Already connected.");
        return true;
    }

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);
    m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + expectedPeerUsername);

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            {
                qDebug() << "Outgoing socket connected to" << getPeerDisplayString(socket) << ". Sending identity.";
                sendIdentityOverTcp(socket); });

    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    QTimer *connectTimer = new QTimer(socket);
    connectTimer->setSingleShot(true);
    connect(connectTimer, &QTimer::timeout, this, [=]()
            {
                if (socket->state() == QAbstractSocket::ConnectingState)
                {
                    qWarning() << "Outgoing connection attempt to" << hostAddress << ":" << port << "timed out.";
                    socket->abort();
                    emit tcpConnectionStatusChanged(expectedPeerUsername, "", false, "Connection timed out.");
                } });
    connectTimer->start(15000);

    qDebug() << "Attempting outgoing connection to" << hostAddress << ":" << port << " expecting peer" << expectedPeerUsername;
    socket->connectToHost(hostAddress, port);

    return true;
}

void NetworkManager::disconnectAllTcpPeers()
{
    qDebug() << "Disconnecting all TCP peers (" << m_allTcpSockets.size() << " sockets)...";
    QList<QTcpSocket *> socketsToDisconnect = m_allTcpSockets;
    for (QTcpSocket *sock : socketsToDisconnect)
    {
        if (sock && sock->state() != QAbstractSocket::UnconnectedState)
        {
            qDebug() << "Disconnecting socket:" << getPeerDisplayString(sock);
            sock->disconnectFromHost();
        }
    }
}

bool NetworkManager::hasActiveTcpConnections() const
{
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        QString username = m_socketToPeerUsernameMap.value(socket, "");
        if (!username.isEmpty() && !username.startsWith("AwaitingID:") && !username.startsWith("Transfer:") && !username.startsWith("ConnectingTo:") && socket->state() == QAbstractSocket::ConnectedState)
        {
            return true;
        }
    }
    return false;
}

bool NetworkManager::startUdpDiscovery(quint16 udpPort)
{
    m_udpDiscoveryPort = udpPort;
    if (!m_identityManager || !m_identityManager->areKeysInitialized() || m_myUsername.isEmpty() || !m_repoManager_ptr)
    {
        qWarning() << "Cannot start UDP discovery: Dependencies not initialized.";
        return false;
    }

    if (m_udpSocket->state() != QAbstractSocket::UnconnectedState)
    {
        qDebug() << "UDP socket is already open on port" << m_udpSocket->localPort();
        if (!m_broadcastTimer->isActive())
        {
            m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
            sendDiscoveryBroadcast();
        }
        return true;
    }

    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
    {
        qInfo() << "UDP Discovery socket bound to port" << m_udpSocket->localPort();
        if (!m_broadcastTimer->isActive())
            m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast();
        return true;
    }
    qWarning() << "Failed to bind UDP Discovery socket:" << m_udpSocket->errorString();
    return false;
}

void NetworkManager::stopUdpDiscovery()
{
    qDebug() << "Stopping UDP Discovery.";
    m_broadcastTimer->stop();
    if (m_udpSocket && m_udpSocket->state() != QAbstractSocket::UnconnectedState)
    {
        m_udpSocket->close();
        qDebug() << "UDP socket closed.";
    }
}

void NetworkManager::sendDiscoveryBroadcast()
{
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myUsername.isEmpty() || !m_identityManager || !m_repoManager_ptr || m_udpSocket->state() != QAbstractSocket::BoundState)
    {
        if (!m_tcpServer || !m_tcpServer->isListening())
            qWarning() << "Cannot send broadcast: TCP server not listening.";
        if (m_myUsername.isEmpty() || !m_identityManager || !m_identityManager->areKeysInitialized())
            qWarning() << "Cannot send broadcast: Identity not ready.";
        if (!m_repoManager_ptr)
            qWarning() << "Cannot send broadcast: RepoManager not available.";
        if (m_udpSocket->state() != QAbstractSocket::BoundState)
            qWarning() << "Cannot send broadcast: UDP socket not bound.";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclySharedRepositories(QString());
    QStringList publicRepoNames;
    for (const auto &repoInfo : publicRepos)
        publicRepoNames.append(repoInfo.displayName);

    out << QString("P2PGIT_DISCOVERY_V3") << m_myUsername << m_tcpServer->serverPort() << QString::fromStdString(m_identityManager->getMyPublicKeyHex()) << publicRepoNames;

    qint64 sentBytes = m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    if (sentBytes == -1)
    {
        qWarning() << "Failed to send UDP broadcast:" << m_udpSocket->errorString();
    }
    else
    {
        qDebug() << "Sent UDP discovery broadcast (" << sentBytes << " bytes).";
    }
}

void NetworkManager::onUdpReadyRead()
{
    while (m_udpSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        datagram.resize(int(m_udpSocket->pendingDatagramSize()));
        QHostAddress senderAddress;
        quint16 senderPort;
        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort);

        QString myPubKeyHex = m_identityManager ? QString::fromStdString(m_identityManager->getMyPublicKeyHex()) : QString();
        QDataStream in(datagram);
        in.setVersion(QDataStream::Qt_5_15);
        in.startTransaction();
        QString magicHeader;
        in >> magicHeader;

        if (magicHeader == "P2PGIT_DISCOVERY_V3")
        {
            QString receivedUsername, receivedPublicKeyHex;
            quint16 receivedTcpPort;
            QStringList receivedPublicRepoNames;

            in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex >> receivedPublicRepoNames;

            if (in.commitTransaction())
            {
                if (m_identityManager && receivedPublicKeyHex == myPubKeyHex)
                {
                    qDebug() << "Ignoring broadcast from self:" << receivedUsername;
                    continue;
                }

                DiscoveredPeerInfo info;
                info.id = receivedUsername;
                info.address = senderAddress;
                info.tcpPort = receivedTcpPort;
                info.publicKeyHex = receivedPublicKeyHex;
                info.publicRepoNames = receivedPublicRepoNames;
                info.lastSeen = QDateTime::currentMSecsSinceEpoch();

                bool isNewPeer = !m_discoveredPeers.contains(receivedUsername);
                bool infoChanged = false;
                if (!isNewPeer)
                {
                    const DiscoveredPeerInfo &existing = m_discoveredPeers.value(receivedUsername);
                    if (existing.address != senderAddress || existing.tcpPort != receivedTcpPort || existing.publicKeyHex != receivedPublicKeyHex || existing.publicRepoNames != receivedPublicRepoNames)
                    {
                        infoChanged = true;
                    }
                }

                m_discoveredPeers[receivedUsername] = info;

                if (isNewPeer || infoChanged)
                {
                    qDebug() << "Discovered/Updated peer:" << receivedUsername << "@" << senderAddress.toString() << ":" << receivedTcpPort;
                    emit lanPeerDiscoveredOrUpdated(info);
                }
            }
            else
            {
                qWarning() << "Failed to commit transaction after reading discovery header from" << senderAddress.toString() << ". Incomplete data?";
            }
        }
    }
}

void NetworkManager::onBroadcastTimerTimeout()
{
    sendDiscoveryBroadcast();
}

void NetworkManager::onPeerCleanupTimerTimeout()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMutableMapIterator<QString, DiscoveredPeerInfo> i(m_discoveredPeers);
    while (i.hasNext())
    {
        i.next();
        if (now - i.value().lastSeen > PEER_TIMEOUT_MS && getSocketForPeer(i.key()) == nullptr)
        {
            qDebug() << "Peer" << i.key() << "timed out from discovery.";
            emit lanPeerLost(i.key());
            i.remove();
            m_peerPublicKeys.remove(i.key());
        }
    }
}

void NetworkManager::sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args)
{
    if (!peerSocket || peerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to send message on disconnected or null socket.";
        return;
    }

    QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
    if (peerUsername.isEmpty() || peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo") || peerUsername.startsWith("Transfer:"))
    {
        qWarning() << "Attempted to send message of type" << messageType << "on a socket that is not an established peer connection:" << getPeerDisplayString(peerSocket);
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    out << messageType;
    for (const QVariant &arg : args)
    {
        out << arg;
    }

    if (peerSocket->write(block) == -1)
    {
        qWarning() << "Failed to write message of type" << messageType << "to" << getPeerDisplayString(peerSocket) << ":" << peerSocket->errorString();
    }
    else
    {
        qDebug() << "Sent message type" << messageType << "to" << getPeerDisplayString(peerSocket) << "(" << block.size() << " bytes)";
    }
}

void NetworkManager::broadcastTcpMessage(const QString &message)
{
    for (QTcpSocket *s : qAsConst(m_allTcpSockets))
    {
        QString peerUsername = m_socketToPeerUsernameMap.value(s, "");
        if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID") && !peerUsername.startsWith("ConnectingTo") && !peerUsername.startsWith("Transfer:"))
        {
            sendMessageToPeer(s, "BROADCAST_MESSAGE", {message});
        }
    }
}

void NetworkManager::sendGroupChatMessage(const QString &repoAppId, const QString &message)
{
    if (!m_repoManager_ptr)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(repoAppId);
    if (repoInfo.appId.isEmpty())
    {
        qWarning() << "Attempted to send group chat for unknown repo App ID:" << repoAppId;
        return;
    }

    QStringList members;
    members.append(repoInfo.adminPeerId);
    members.append(repoInfo.collaborators);
    members.removeDuplicates();

    for (const QString &memberId : members)
    {
        if (memberId == m_myUsername)
            continue;

        QTcpSocket *memberSocket = getSocketForPeer(memberId);
        if (memberSocket)
        {
            qDebug() << "Sending group chat message for repo" << repoAppId << "to member" << memberId;
            sendMessageToPeer(memberSocket, "GROUP_CHAT_MESSAGE", {repoAppId, message});
        }
    }
}

void NetworkManager::sendIdentityOverTcp(QTcpSocket *socket)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager || !m_identityManager->areKeysInitialized())
    {
        qWarning() << "Cannot send identity: Socket invalid or identity not ready.";
        return;
    }

    QString currentTempId = m_socketToPeerUsernameMap.value(socket, "");
    QString newId = m_myUsername;

    if (currentTempId.startsWith("AwaitingID:"))
    {
        m_socketToPeerUsernameMap.insert(socket, newId);
    }
    else if (currentTempId.startsWith("ConnectingTo:"))
    {
        // Keep the target name until their handshake arrives
    }
    else
    {
        if (m_socketToPeerUsernameMap.value(socket) == newId && m_handshakeSent.contains(socket))
        {
            qDebug() << "Identity already sent for socket" << getPeerDisplayString(socket);
            return;
        }
        qWarning() << "Sending identity over socket with unexpected current map state:" << getPeerDisplayString(socket);
        m_socketToPeerUsernameMap.insert(socket, newId);
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    out << QString("IDENTITY_HANDSHAKE_V2") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    socket->write(block);
    m_handshakeSent.insert(socket);
    qDebug() << "Sent IDENTITY_HANDSHAKE_V2 to" << getPeerDisplayString(socket);
}

QString NetworkManager::findUsernameForAddress(const QHostAddress &address)
{
    QHostAddress addrToCompare = address;
    if (address.protocol() == QAbstractSocket::IPv6Protocol && address.toIPv4Address() != 0)
    {
        addrToCompare = QHostAddress(address.toIPv4Address());
    }
    for (const auto &peerInfo : qAsConst(m_discoveredPeers))
    {
        QHostAddress peerAddrToCompare = peerInfo.address;
        if (peerAddrToCompare.protocol() == QAbstractSocket::IPv6Protocol && peerAddrToCompare.toIPv4Address() != 0)
        {
            peerAddrToCompare = QHostAddress(peerAddrToCompare.toIPv4Address());
        }

        if (peerAddrToCompare == addrToCompare)
        {
            return peerInfo.id;
        }
    }
    return QString();
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to start bundle transfer on disconnected or null socket.";
        return;
    }
    if (m_outgoingTransfers.contains(targetPeerSocket))
    {
        qWarning() << "Already an outgoing transfer active on socket" << getPeerDisplayString(targetPeerSocket);
        return;
    }

    QFile *bundleFile = new QFile(bundleFilePath);
    if (!bundleFile->open(QIODevice::ReadOnly))
    {
        qWarning() << "Failed to open bundle file for sending:" << bundleFilePath << bundleFile->errorString();
        delete bundleFile;
        return;
    }

    qint64 fileSize = bundleFile->size();
    if (fileSize == 0)
    {
        qWarning() << "Bundle file is empty:" << bundleFilePath;
        bundleFile->close();
        delete bundleFile;
        return;
    }

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << fileSize;

    qDebug() << "Sending SEND_REPO_BUNDLE_START for" << repoDisplayName << "size" << fileSize << "to" << getPeerDisplayString(targetPeerSocket);
    qint64 writtenBytes = targetPeerSocket->write(startBlock);

    if (writtenBytes == -1)
    {
        qWarning() << "Error writing SEND_REPO_BUNDLE_START to socket:" << targetPeerSocket->errorString();
        bundleFile->close();
        delete bundleFile;
        targetPeerSocket->disconnectFromHost();
        return;
    }

    auto *transfer = new OutgoingFileTransfer{bundleFile, repoDisplayName, bundleFilePath, fileSize, 0};
    m_outgoingTransfers.insert(targetPeerSocket, transfer);

    connect(targetPeerSocket, &QIODevice::bytesWritten, this, [this, targetPeerSocket, transfer](qint64 bytes)
            {
                if (!m_outgoingTransfers.contains(targetPeerSocket) || m_outgoingTransfers.value(targetPeerSocket) != transfer)
                {
                    qWarning() << "bytesWritten signal for unexpected transfer socket?";
                    return;
                }

                transfer->bytesSent += bytes;

                while (targetPeerSocket->bytesToWrite() == 0 && !transfer->file->atEnd())
                {
                    char buffer[65536];
                    qint64 bytesRead = transfer->file->read(buffer, sizeof(buffer));
                    if (bytesRead > 0)
                    {
                        qint64 chunkWritten = targetPeerSocket->write(buffer, bytesRead);
                        if (chunkWritten == -1)
                        {
                            qWarning() << "Error writing bundle chunk to socket:" << targetPeerSocket->errorString();
                            handleOutgoingTransferError(targetPeerSocket, "Error writing bundle data.");
                            return;
                        }
                    }
                    else if (bytesRead == -1)
                    {
                        qWarning() << "Error reading from bundle file:" << transfer->file->errorString();
                        handleOutgoingTransferError(targetPeerSocket, "Error reading bundle file.");
                        return;
                    }
                }

                if (transfer->file->atEnd() && targetPeerSocket->bytesToWrite() == 0)
                {
                    qDebug() << "Finished sending all file data for bundle:" << transfer->repoName;

                    QByteArray endBlock;
                    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
                    endOut.setVersion(QDataStream::Qt_5_15);
                    endOut << QString("SEND_REPO_BUNDLE_END") << transfer->repoName;

                    qint64 endWritten = targetPeerSocket->write(endBlock);
                    if (endWritten == -1)
                    {
                        qWarning() << "Error writing SEND_REPO_BUNDLE_END to socket:" << targetPeerSocket->errorString();
                    }
                    else
                    {
                        qDebug() << "Sent SEND_REPO_BUNDLE_END for" << transfer->repoName;
                    }

                    disconnect(targetPeerSocket, &QIODevice::bytesWritten, this, 0);

                    if (m_outgoingTransfers.remove(targetPeerSocket))
                    {
                        transfer->file->close();
                        delete transfer->file;
                        delete transfer;
                    }

                    emit repoBundleSent(transfer->repoName, m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer"));
                    QFile::remove(transfer->bundleFilePath);

                    if (targetPeerSocket->property("is_transfer_socket").toBool())
                    {
                        targetPeerSocket->disconnectFromHost();
                    }
                } });
}

void NetworkManager::handleOutgoingTransferError(QTcpSocket *socket, const QString &message)
{
    qWarning() << "Outgoing transfer error for socket:" << getPeerDisplayString(socket) << ":" << message;
    if (m_outgoingTransfers.contains(socket))
    {
        OutgoingFileTransfer *transfer = m_outgoingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file;
        }
        QFile::remove(transfer->bundleFilePath);
        delete transfer;
    }
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    qDebug() << "Socket disconnected:" << getPeerDisplayString(socket);

    if (m_pendingConnections.contains(socket))
    {
        QTimer *timer = m_pendingConnections.take(socket);
        if (timer)
            timer->deleteLater();
        qDebug() << "Cleaned up pending timer for disconnected socket.";
    }

    if (m_incomingTransfers.contains(socket))
    {
        qWarning() << "Incoming file transfer interrupted due to disconnection.";
        IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file;
        }
        emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, false, "Connection disconnected during bundle transfer.");
        delete transfer;
        qDebug() << "Cleaned up incoming transfer for disconnected socket.";
    }

    if (m_outgoingTransfers.contains(socket))
    {
        qWarning() << "Outgoing file transfer interrupted due to disconnection.";
        OutgoingFileTransfer *transfer = m_outgoingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file;
        }
        QFile::remove(transfer->bundleFilePath);
        delete transfer;
        qDebug() << "Cleaned up outgoing transfer for disconnected socket.";
    }

    m_socketBuffers.remove(socket);
    m_handshakeSent.remove(socket);

    QString peerUsername = m_socketToPeerUsernameMap.value(socket);
    m_allTcpSockets.removeAll(socket);
    m_socketToPeerUsernameMap.remove(socket);

    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo"))
    {
        qDebug() << "Established peer disconnected:" << peerUsername;
        emit tcpPeerDisconnected(socket, peerUsername);
    }
    else
    {
        qDebug() << "Temporary or non-established socket disconnected:" << peerUsername;
    }

    socket->deleteLater();
    qDebug() << "Socket deleted later.";
}

void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError);
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    qWarning() << "Socket Error on" << getPeerDisplayString(socket) << ":" << socket->errorString();
}

void NetworkManager::addSharedRepoToPeer(const QString &peerId, const QString &repoName)
{
    if (m_discoveredPeers.contains(peerId))
    {
        DiscoveredPeerInfo info = m_discoveredPeers.value(peerId);
        if (!info.publicRepoNames.contains(repoName))
        {
            info.publicRepoNames.append(repoName);
            m_discoveredPeers.insert(peerId, info);
            qDebug() << "Updated discovered peer" << peerId << "with new shareable repo:" << repoName;
            emit lanPeerDiscoveredOrUpdated(info);
        }
    }
    else
    {
        qWarning() << "Attempted to add shared repo" << repoName << "to unknown discovered peer" << peerId;
    }
}

QList<QString> NetworkManager::getConnectedPeerIds() const
{
    QList<QString> ids;
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        QString username = m_socketToPeerUsernameMap.value(socket, "");
        if (!username.isEmpty() && !username.startsWith("AwaitingID:") && !username.startsWith("Transfer:") && !username.startsWith("ConnectingTo:") && socket->state() == QAbstractSocket::ConnectedState)
        {
            ids.append(username);
        }
    }
    ids.removeDuplicates();
    return ids;
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}