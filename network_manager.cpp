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
    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &NetworkManager::onNewTcpConnection);
    m_udpSocket = new QUdpSocket(this);
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &NetworkManager::onUdpReadyRead);
    m_broadcastTimer = new QTimer(this);
    connect(m_broadcastTimer, &QTimer::timeout, this, &NetworkManager::onBroadcastTimerTimeout);
    m_peerCleanupTimer = new QTimer(this);
    connect(m_peerCleanupTimer, &QTimer::timeout, this, &NetworkManager::onPeerCleanupTimerTimeout);
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2);
}

NetworkManager::~NetworkManager()
{
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();
    qDeleteAll(m_incomingTransfers);
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString();
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
            if (!m_allTcpSockets.contains(socket))
                m_allTcpSockets.append(socket);

            // Keep as pending until user accepts via UI. We'll still parse data to detect
            // temporary transfer sockets and auto-allow those.
            m_pendingConnections.insert(socket, new QTimer(socket));
            m_pendingConnections[socket]->setSingleShot(true);
            connect(m_pendingConnections[socket], &QTimer::timeout, this, [this, socket]()
                    { rejectPendingTcpConnection(socket); });
            m_pendingConnections[socket]->start(PENDING_CONNECTION_TIMEOUT_MS);

            // Defer prompting the user: allow a short grace period so if this is a temporary
            // transfer (REQUEST_REPO_BUNDLE), we won't show a connection dialog.
            QTimer *intentTimer = new QTimer(socket);
            intentTimer->setSingleShot(true);
            connect(intentTimer, &QTimer::timeout, this, [this, socket]()
                    {
                if (!socket) return;
                // If it's turned into a transfer socket, do not prompt.
                if (socket->property("is_transfer_socket").toBool()) return;
                // If still pending, prompt the user now.
                if (m_pendingConnections.contains(socket)) {
                    QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
                    emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
                } });
            intentTimer->start(5000);
        }
    }
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    m_socketBuffers[socket].append(socket->readAll());
    processIncomingTcpData(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "User accepted connection from" << pendingSocket->peerAddress().toString();
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();
        // Mark as accepted control connection
        pendingSocket->setProperty("is_transfer_socket", false);
        sendIdentityOverTcp(pendingSocket);
        if (m_socketBuffers.contains(pendingSocket) && !m_socketBuffers[pendingSocket].isEmpty())
        {
            processIncomingTcpData(pendingSocket);
        }
    }
}

void NetworkManager::handleEncryptedPayload(const QString &peerId, const QVariantMap &payload)
{
    QString messageType = payload.value("__messageType").toString();
    if (messageType.isEmpty())
    {
        qWarning() << "Decrypted payload missing __messageType from" << peerId;
        return;
    }

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;

    if (messageType == "COLLABORATOR_ADDED")
    {
        QString ownerRepoAppId, repoDisplayName, ownerPeerId;
        QStringList groupMembers;
        ownerRepoAppId = payload.value("ownerRepoAppId").toString();
        repoDisplayName = payload.value("repoDisplayName").toString();
        ownerPeerId = payload.value("ownerPeerId").toString();
        groupMembers = payload.value("groupMembers").toStringList();
        if (!ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty() && !ownerPeerId.isEmpty())
        {
            emit collaboratorAddedReceived(peerId, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers);
        }
    }
    else if (messageType == "COLLABORATOR_REMOVED")
    {
        QString ownerRepoAppId = payload.value("ownerRepoAppId").toString();
        QString repoDisplayName = payload.value("repoDisplayName").toString();
        if (!ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty())
        {
            emit collaboratorRemovedReceived(peerId, ownerRepoAppId, repoDisplayName);
        }
    }
    else if (messageType == "PROPOSAL_REVIEW_ACCEPTED")
    {
        // Owner responded to proposal review prompt
        bool accepted = payload.value("acceptProposal").toBool();
        QString repoName = payload.value("repoName").toString();
        QString forBranch = payload.value("forBranch").toString();
        emit proposalReviewAcceptedReceived(peerId, repoName, forBranch, accepted);
    }
    else if (messageType == "PROPOSE_FILES_META")
    {
        QString repoName = payload.value("repoName").toString();
        QString forBranch = payload.value("forBranch").toString();
        QString commitMessage = payload.value("commitMessage").toString();
        int fileCount = payload.value("fileCount").toInt();
        emit proposeFilesMetaReceived(peerId, repoName, forBranch, commitMessage, fileCount);
    }
    else
    {
        emit secureMessageReceived(peerId, messageType, payload);
    }
}

void NetworkManager::processIncomingTcpData(QTcpSocket *socket)
{
    QByteArray &buffer = m_socketBuffers[socket];
    QDataStream in(buffer);
    in.setVersion(QDataStream::Qt_5_15);

    while (true)
    {
        if (m_incomingTransfers.contains(socket))
        {
            IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
            QString mode = transfer->properties.value("mode").toString();
            // For raw transfers (bundles, legacy archives), consume bytes directly
            if (mode.isEmpty() || mode == "raw")
            {
                qint64 bytesToWrite = qMin((qint64)buffer.size(), transfer->totalSize - transfer->bytesReceived);
                if (bytesToWrite > 0)
                {
                    transfer->file.write(buffer.constData(), bytesToWrite);
                    buffer.remove(0, static_cast<int>(bytesToWrite));
                    transfer->bytesReceived += bytesToWrite;
                    emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
                }
                if (transfer->bytesReceived < transfer->totalSize)
                    return;
            }
            // Else, for encrypted chunk mode, do not consume here; chunks are framed messages handled below
        }

        // First, ensure we have at least a complete message type string available
        in.startTransaction();
        QString messageType;
        in >> messageType;
        if (!in.commitTransaction())
        {
            // Not enough bytes yet to read the message type
            return;
        }

        if (messageType == "IDENTITY_HANDSHAKE_V2")
        {
            in.startTransaction();
            QString peerUsername, peerKeyHex;
            in >> peerUsername >> peerKeyHex;
            if (!in.commitTransaction())
                return;

            QString expectedPeerId = m_socketToPeerUsernameMap.value(socket, "");

            if (expectedPeerId.isEmpty() || expectedPeerId.startsWith("ConnectingTo:") || expectedPeerId == peerUsername)
            {
                m_socketToPeerUsernameMap.insert(socket, peerUsername);
                // Convert peer's Ed25519 verify key to Curve25519 for crypto_box
                QByteArray edPk = QByteArray::fromHex(peerKeyHex.toUtf8());
                if (edPk.size() == crypto_sign_PUBLICKEYBYTES)
                {
                    unsigned char curvePk[crypto_box_PUBLICKEYBYTES];
                    if (crypto_sign_ed25519_pk_to_curve25519(curvePk, reinterpret_cast<const unsigned char *>(edPk.constData())) == 0)
                    {
                        m_peerCurve25519PublicKeys.insert(peerUsername, QByteArray(reinterpret_cast<const char *>(curvePk), crypto_box_PUBLICKEYBYTES));
                    }
                    else
                    {
                        qWarning() << "Failed to convert peer" << peerUsername << "ed25519 pk to curve25519; encrypted messages will fail.";
                    }
                }
                else
                {
                    qWarning() << "Unexpected peer public key size for" << peerUsername << ":" << edPk.size();
                }

                if (!m_handshakeSent.contains(socket))
                {
                    sendIdentityOverTcp(socket);
                }
                // Announce only for accepted main connections (not pending and not transfer)
                bool isTransfer = socket->property("is_transfer_socket").toBool();
                bool isPending = m_pendingConnections.contains(socket);
                if (!isTransfer && !isPending)
                {
                    emit newTcpPeerConnected(socket, peerUsername, peerKeyHex);
                }

                // --- LOGIC WITH THE FIX ---
                if (socket->property("is_transfer_socket").toBool())
                {
                    // FIX: Use .value<QVariantMap>() instead of .toVariantMap()
                    QVariantMap pendingRequest = socket->property("pending_bundle_request").value<QVariantMap>();
                    if (!pendingRequest.isEmpty())
                    {
                        QString repoName = pendingRequest.value("repoName").toString();
                        QString localPath = pendingRequest.value("localPath").toString();
                        qDebug() << "Handshake complete on transfer socket. Now sending repo bundle request for" << repoName;

                        QByteArray block;
                        QDataStream out(&block, QIODevice::WriteOnly);
                        out.setVersion(QDataStream::Qt_5_15);
                        out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoName << localPath;
                        socket->write(block);

                        socket->setProperty("pending_bundle_request", QVariant());
                    }
                }
                // --- END OF FIX ---
            }
            else
            {
                qWarning() << "Identity mismatch! Expected" << expectedPeerId << "but got" << peerUsername;
                socket->disconnectFromHost();
            }
        }
        else if (messageType == "REQUEST_REPO_BUNDLE")
        {
            in.startTransaction();
            QString requestingPeer, repoName, temp;
            in >> requestingPeer >> repoName >> temp;
            if (!in.commitTransaction())
                return;
            if (!m_socketToPeerUsernameMap.contains(socket) || m_socketToPeerUsernameMap.value(socket).startsWith("ConnectingTo:"))
            {
                m_socketToPeerUsernameMap.insert(socket, requestingPeer);
            }
            handleRepoRequest(socket, requestingPeer, repoName);
        }
        else if (messageType == "SEND_REPO_BUNDLE_START")
        {
            in.startTransaction();
            QString repoName;
            qint64 totalSize;
            in >> repoName >> totalSize;
            if (!in.commitTransaction())
                return;
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
            auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, QFile(tempPath), totalSize, 0};
            if (transfer->file.open(QIODevice::WriteOnly))
            {
                m_incomingTransfers.insert(socket, transfer);
                emit repoBundleTransferStarted(repoName, totalSize);
            }
            else
            {
                qWarning() << "Could not open temp file for bundle transfer:" << tempPath;
                delete transfer;
            }
        }
        else if (messageType == "SEND_REPO_BUNDLE_END")
        {
            in.startTransaction();
            QString repoName;
            in >> repoName;
            if (!in.commitTransaction())
                return;
            if (m_incomingTransfers.contains(socket))
            {
                IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                transfer->file.close();
                bool success = (transfer->bytesReceived == transfer->totalSize);
                emit repoBundleCompleted(repoName, transfer->tempLocalPath, success, success ? "Transfer complete." : "Size mismatch.");
                delete transfer;
                // Only disconnect here if this socket is an explicitly dedicated transfer socket
                // initiated by us (outgoing). Inbound transfer served over a control connection
                // must stay connected.
                if (socket->property("is_transfer_socket").toBool())
                {
                    socket->disconnectFromHost();
                }
            }
        }
        else if (messageType == "BROADCAST_MESSAGE")
        {
            in.startTransaction();
            QString message;
            in >> message;
            if (!in.commitTransaction())
                return;
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            if (!peerUsername.isEmpty())
                emit broadcastMessageReceived(socket, peerUsername, message);
        }
        else if (messageType == "GROUP_CHAT_MESSAGE")
        {
            in.startTransaction();
            QString repoAppId, message;
            in >> repoAppId >> message;
            if (!in.commitTransaction())
                return;
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            if (!peerUsername.isEmpty())
                emit groupMessageReceived(peerUsername, repoAppId, message);
        }
        else if (messageType == "ENCRYPTED_PAYLOAD")
        {
            in.startTransaction();
            QByteArray nonce, ciphertext;
            in >> nonce >> ciphertext;
            if (!in.commitTransaction())
            {
                qWarning() << "Encrypted payload transaction not committed (partial read).";
                return;
            }

            QString peerId = m_socketToPeerUsernameMap.value(socket);
            if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
            {
                qWarning() << "Received encrypted payload from unknown peer or peer with no public key. peerId=" << peerId;
                continue;
            }

            QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();
            QByteArray peerPubKey = m_peerCurve25519PublicKeys.value(peerId);

            QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

            if (ciphertext.size() < crypto_box_MACBYTES)
            {
                qWarning() << "Ciphertext too small for crypto_box_open_easy, size=" << ciphertext.size();
                continue;
            }
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
                qWarning() << "Decrypted message was not valid JSON object, raw size=" << decryptedMessage.size();
            }
        }
        else if (messageType == "PROPOSE_FILES_META")
        {
            in.startTransaction();
            // Legacy unencrypted path will not be used; keep parser empty to consume nothing
            if (!in.commitTransaction())
            { /* fallthrough */
            }
            // Encrypted version will trigger via ENCRYPTED_PAYLOAD case
        }
        else if (messageType == "PROPOSE_ARCHIVE_START")
        {
            in.startTransaction();
            QString repoName, forBranch, format;
            qint64 totalSize;
            in >> repoName >> forBranch >> totalSize >> format;
            if (!in.commitTransaction())
                return;
            QString suffix = (format == "tar.gz") ? ".tar.gz" : ".zip";
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + suffix;
            auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, QFile(tempPath), totalSize, 0};
            transfer->properties.insert("forBranch", forBranch);
            transfer->properties.insert("format", format);
            transfer->properties.insert("mode", "raw");
            if (transfer->file.open(QIODevice::WriteOnly))
            {
                m_incomingTransfers.insert(socket, transfer);
                emit repoBundleTransferStarted(repoName, totalSize);
            }
            else
            {
                qWarning() << "Could not open temp file for proposal archive:" << tempPath;
                delete transfer;
            }
        }
        else if (messageType == "PROPOSE_ARCHIVE_START_ENC")
        {
            in.startTransaction();
            QString repoName, forBranch, format;
            qint64 totalSize;
            in >> repoName >> forBranch >> totalSize >> format;
            if (!in.commitTransaction())
                return;
            QString suffix = (format == "tar.gz") ? ".tar.gz" : ".zip";
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + suffix;
            auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, QFile(tempPath), totalSize, 0};
            transfer->properties.insert("forBranch", forBranch);
            transfer->properties.insert("format", format);
            transfer->properties.insert("mode", "enc");
            if (transfer->file.open(QIODevice::WriteOnly))
            {
                m_incomingTransfers.insert(socket, transfer);
                emit repoBundleTransferStarted(repoName, totalSize);
            }
            else
            {
                qWarning() << "Could not open temp file for encrypted proposal archive:" << tempPath;
                delete transfer;
            }
        }
        else if (messageType == "PROPOSE_ARCHIVE_CHUNK")
        {
            in.startTransaction();
            QString repoName;
            QByteArray nonce, ciphertext;
            in >> repoName >> nonce >> ciphertext;
            if (!in.commitTransaction())
                return;
            if (!m_incomingTransfers.contains(socket))
                return;
            IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
            if (transfer->repoName != repoName)
                return;
            if (transfer->properties.value("mode").toString() != "enc")
                return;

            QString peerId = m_socketToPeerUsernameMap.value(socket);
            if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
            {
                qWarning() << "Encrypted chunk from unknown peer or missing key";
                return;
            }

            QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();
            QByteArray peerPubKey = m_peerCurve25519PublicKeys.value(peerId);
            if (ciphertext.size() < crypto_box_MACBYTES)
            {
                qWarning() << "Ciphertext too small for chunk";
                return;
            }

            QByteArray plaintext(ciphertext.size() - crypto_box_MACBYTES, 0);
            if (crypto_box_open_easy(
                    reinterpret_cast<unsigned char *>(plaintext.data()),
                    reinterpret_cast<const unsigned char *>(ciphertext.constData()),
                    ciphertext.size(),
                    reinterpret_cast<const unsigned char *>(nonce.constData()),
                    reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
                    reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
            {
                qWarning() << "Failed to decrypt archive chunk";
                return;
            }

            transfer->file.write(plaintext);
            transfer->bytesReceived += plaintext.size();
            emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
        }
        else if (messageType == "PROPOSE_ARCHIVE_END")
        {
            in.startTransaction();
            QString repoName;
            in >> repoName;
            if (!in.commitTransaction())
                return;
            if (m_incomingTransfers.contains(socket))
            {
                IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                QString forBranch = transfer->properties.value("forBranch").toString();
                transfer->file.close();
                bool success = (transfer->bytesReceived == transfer->totalSize);
                if (success)
                {
                    QString fromPeer = m_socketToPeerUsernameMap.value(socket);
                    emit changeProposalArchiveReceived(fromPeer, repoName, forBranch, transfer->tempLocalPath);
                }
                else
                {
                    QFile::remove(transfer->tempLocalPath);
                }
                delete transfer;
            }
        }
        else
        {
            qWarning() << "Unknown or unexpected message type received:" << messageType << "from" << getPeerDisplayString(socket);
            return;
        }

        buffer.remove(0, buffer.size() - in.device()->bytesAvailable());
        if (in.atEnd())
            return;
    }
}
bool NetworkManager::isConnectionPending(QTcpSocket *socket) const { return m_pendingConnections.contains(socket); }

void NetworkManager::requestBundleFromPeer(const QString &peerId, const QString &repoName, const QString &localPath)
{
    // First, check if we already have a connection to this peer
    QTcpSocket *existingSocket = getSocketForPeer(peerId);

    if (existingSocket && existingSocket->state() == QAbstractSocket::ConnectedState)
    {
        // Use the existing connection
        qDebug() << "Using existing connection to peer" << peerId << "for bundle request";
        sendRepoBundleRequest(existingSocket, repoName, localPath);
        return;
    }

    // No existing connection, need to create a new one
    qDebug() << "No existing connection to peer" << peerId << ", creating new transfer connection";

    // Get peer info to connect
    DiscoveredPeerInfo peerInfo = getDiscoveredPeerInfo(peerId);
    if (peerInfo.id.isEmpty())
    {
        qDebug() << "Cannot find peer info for" << peerId;
        emit repoBundleCompleted(repoName, "", false, "Could not find peer information");
        return;
    }

    // Create new connection using the existing method
    connectAndRequestBundle(peerInfo.address, peerInfo.tcpPort, m_myUsername, repoName, localPath);
}

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    QTcpSocket *socket = new QTcpSocket(this);
    // Mark this socket so we know its purpose
    socket->setProperty("is_transfer_socket", true);

    // Store the bundle request details as a property on the socket.
    // We will send this request *after* the handshake is complete.
    QVariantMap pendingRequest;
    pendingRequest["repoName"] = repoName;
    pendingRequest["localPath"] = localPath;
    socket->setProperty("pending_bundle_request", QVariant::fromValue(pendingRequest));

    // For handshake validation, we need to know who we are connecting to.
    // Try to find the peer's ID from the discovery list.
    QString ownerId = findUsernameForAddress(host);
    if (!ownerId.isEmpty())
    {
        m_socketToPeerUsernameMap.insert(socket, ownerId);
    }
    else
    {
        // If not found (e.g., direct connection), use a temporary placeholder.
        m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + host.toString());
    }

    m_allTcpSockets.append(socket);

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            {
        qDebug() << "Transfer socket connected. Sending initial identity handshake.";
        // The first step is ALWAYS to handshake. The actual bundle request will be sent
        // later, once the owner's identity is confirmed.
        sendIdentityOverTcp(socket); });

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "Attempting to connect dedicated transfer socket to" << host.toString() << ":" << port;
    socket->connectToHost(host, port);
}

QString NetworkManager::getPeerDisplayString(QTcpSocket *socket)
{
    if (!socket)
        return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    if (!username.isEmpty() && !username.startsWith("AwaitingID") && !username.startsWith("ConnectingTo") && !username.startsWith("Transfer:"))
    {
        return username + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
    }
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

QTcpSocket *NetworkManager::getSocketForPeer(const QString &peerUsername)
{
    return m_socketToPeerUsernameMap.key(peerUsername, nullptr);
}

void NetworkManager::sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoDisplayName << requesterLocalPath;
    targetPeerSocket->write(block);
}

bool NetworkManager::startTcpServer(quint16 port)
{
    if (m_tcpServer->isListening())
    {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        return true;
    }
    if (m_tcpServer->listen(QHostAddress::Any, port))
    {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort());
        startUdpDiscovery(); // Automatically start discovery when server starts
        return true;
    }
    emit tcpServerStatusChanged(false, port, m_tcpServer->errorString());
    return false;
}

void NetworkManager::stopTcpServer()
{
    if (m_tcpServer && m_tcpServer->isListening())
    {
        quint16 p = m_tcpServer->serverPort();
        m_tcpServer->close();
        emit tcpServerStatusChanged(false, p);
    }
}

quint16 NetworkManager::getTcpServerPort() const
{
    return (m_tcpServer && m_tcpServer->isListening()) ? m_tcpServer->serverPort() : 0;
}

bool NetworkManager::connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername)
{
    if (getSocketForPeer(expectedPeerUsername))
        return true;

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);

    if (!m_allTcpSockets.contains(socket))
        m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + expectedPeerUsername);

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            { sendIdentityOverTcp(socket); });
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    socket->connectToHost(hostAddress, port);
    return true;
}

void NetworkManager::disconnectAllTcpPeers()
{
    QList<QTcpSocket *> socketsToDisconnect = m_allTcpSockets;
    for (QTcpSocket *sock : socketsToDisconnect)
    {
        if (sock)
            sock->disconnectFromHost();
    }
}

bool NetworkManager::hasActiveTcpConnections() const
{
    return !m_socketToPeerUsernameMap.values().filter(QRegExp("^(?!AwaitingID|Transfer:|ConnectingTo).*")).isEmpty();
}

bool NetworkManager::startUdpDiscovery(quint16 udpPort)
{
    m_udpDiscoveryPort = udpPort;
    if (!m_identityManager || !m_repoManager_ptr)
        return false;
    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
    {
        if (!m_broadcastTimer->isActive())
            m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast();
        return true;
    }
    return false;
}

void NetworkManager::stopUdpDiscovery()
{
    m_broadcastTimer->stop();
    if (m_udpSocket && m_udpSocket->state() != QAbstractSocket::UnconnectedState)
        m_udpSocket->close();
    m_discoveredPeers.clear();
}

void NetworkManager::sendDiscoveryBroadcast()
{
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myUsername.isEmpty() || !m_identityManager || !m_repoManager_ptr)
        return;
    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclyShareableRepos();

    QStringList publicRepoNames;
    for (const auto &repoInfo : publicRepos)
        publicRepoNames.append(repoInfo.displayName);
    out << QString("P2PGIT_DISCOVERY_V3") << m_myUsername << m_tcpServer->serverPort() << QString::fromStdString(m_identityManager->getMyPublicKeyHex()) << publicRepoNames;
    m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
}

void NetworkManager::onUdpReadyRead()
{
    while (m_udpSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        datagram.resize(int(m_udpSocket->pendingDatagramSize()));
        QHostAddress senderAddress;
        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress);
        QDataStream in(datagram);
        in.setVersion(QDataStream::Qt_5_15);
        QString magicHeader;
        in >> magicHeader;
        if (magicHeader != "P2PGIT_DISCOVERY_V3")
            continue;
        QString receivedUsername, receivedPublicKeyHex;
        quint16 receivedTcpPort;
        QList<QString> receivedPublicRepoNames;
        in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex >> receivedPublicRepoNames;
        if (in.status() == QDataStream::Ok && receivedUsername != m_myUsername)
        {
            DiscoveredPeerInfo info;
            info.id = receivedUsername;
            info.address = senderAddress;
            info.tcpPort = receivedTcpPort;
            info.publicKeyHex = receivedPublicKeyHex;
            info.publicRepoNames = receivedPublicRepoNames;
            info.lastSeen = QDateTime::currentMSecsSinceEpoch();

            m_discoveredPeers[receivedUsername] = info;
            emit lanPeerDiscoveredOrUpdated(info);
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
        if (now - i.value().lastSeen > PEER_TIMEOUT_MS)
        {
            emit lanPeerLost(i.key());
            i.remove();
        }
    }
}

void NetworkManager::sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args)
{
    if (!peerSocket || peerSocket->state() != QAbstractSocket::ConnectedState)
        return;

    QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
    // Don't send on sockets that are pending acceptance or special-purpose
    if (m_pendingConnections.contains(peerSocket) || peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo") || peerUsername.startsWith("Transfer:"))
        return;

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << messageType;
    for (const QVariant &arg : args)
    {
        out << arg;
    }
    peerSocket->write(block);
}

void NetworkManager::broadcastTcpMessage(const QString &message)
{
    for (QTcpSocket *s : qAsConst(m_allTcpSockets))
    {
        sendMessageToPeer(s, "BROADCAST_MESSAGE", {message});
    }
}

void NetworkManager::sendGroupChatMessage(const QString &repoAppId, const QString &message)
{
    if (!m_repoManager_ptr)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(repoAppId);
    if (repoInfo.appId.isEmpty())
        return;

    QStringList members = repoInfo.groupMembers;
    members.removeDuplicates();

    for (const QString &memberId : members)
    {
        if (memberId == m_myUsername)
            continue;

        QTcpSocket *memberSocket = getSocketForPeer(memberId);
        if (memberSocket)
        {
            sendMessageToPeer(memberSocket, "GROUP_CHAT_MESSAGE", {repoAppId, message});
        }
    }
}

void NetworkManager::sendIdentityOverTcp(QTcpSocket *socket)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager)
        return;
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    QString expectedPeerId = m_socketToPeerUsernameMap.value(socket, "");
    if (expectedPeerId.startsWith("ConnectingTo:"))
    {
        expectedPeerId.remove("ConnectingTo:");
        m_socketToPeerUsernameMap.insert(socket, expectedPeerId);
    }

    out << QString("IDENTITY_HANDSHAKE_V2") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    socket->write(block);
    m_handshakeSent.insert(socket);
}

QString NetworkManager::findUsernameForAddress(const QHostAddress &address)
{
    QHostAddress addrToCompare = address;
    if (address.protocol() == QAbstractSocket::IPv6Protocol && address.toIPv4Address())
    {
        addrToCompare = QHostAddress(address.toIPv4Address());
    }
    for (const auto &peerInfo : qAsConst(m_discoveredPeers))
    {
        if (peerInfo.address == addrToCompare)
        {
            return peerInfo.id;
        }
    }
    return QString();
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundleFilePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << bundleFile.size();
    targetPeerSocket->write(startBlock);

    char buffer[65536];
    while (!bundleFile.atEnd())
    {
        qint64 bytesRead = bundleFile.read(buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            targetPeerSocket->write(buffer, bytesRead);
            if (!targetPeerSocket->waitForBytesWritten(-1))
            {
                bundleFile.close();
                return;
            }
        }
    }
    bundleFile.close();

    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("SEND_REPO_BUNDLE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);

    QString recipient = m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer");
    emit repoBundleSent(repoDisplayName, recipient);
    // Notify receiver to add repo to managed list using the persistent control connection if possible
    // to avoid mixing control messages on a short-lived transfer socket.
    QVariantMap payload;
    payload["repoDisplayName"] = repoDisplayName;
    payload["senderPeerId"] = m_myUsername;
    payload["localPathHint"] = ""; // receiver can choose location
    QTcpSocket *controlSocket = getSocketForPeer(recipient);
    if (controlSocket && controlSocket != targetPeerSocket)
    {
        sendMessageToPeer(controlSocket, "ADD_MANAGED_REPO", {QVariant::fromValue(payload)});
    }
    else
    {
        // Fall back to the current socket if no separate control connection exists
        sendMessageToPeer(targetPeerSocket, "ADD_MANAGED_REPO", {QVariant::fromValue(payload)});
    }
    QFile::remove(bundleFilePath);
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Rejecting or timing out connection from" << pendingSocket->peerAddress().toString();
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();
        pendingSocket->disconnectFromHost();
    }
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    if (socket->property("is_transfer_socket").toBool())
    {
        m_socketBuffers.remove(socket);
        m_socketToPeerUsernameMap.remove(socket);
        if (m_incomingTransfers.contains(socket))
            delete m_incomingTransfers.take(socket);
        m_allTcpSockets.removeAll(socket);
        socket->deleteLater();
        return;
    }

    m_allTcpSockets.removeAll(socket);
    m_socketBuffers.remove(socket);
    m_handshakeSent.remove(socket);
    if (m_pendingConnections.contains(socket))
    {
        QTimer *timer = m_pendingConnections.take(socket);
        if (timer)
            timer->deleteLater();
    }
    if (m_incomingTransfers.contains(socket))
        delete m_incomingTransfers.take(socket);

    QString peerUsername = m_socketToPeerUsernameMap.take(socket);
    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo"))
    {
        m_peerCurve25519PublicKeys.remove(peerUsername);
        emit tcpPeerDisconnected(socket, peerUsername);
    }
    socket->deleteLater();
}

void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError);
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    qWarning() << "Socket Error on" << getPeerDisplayString(socket) << ":" << socket->errorString();
    socket->disconnectFromHost();
}

void NetworkManager::addSharedRepoToPeer(const QString &peerId, const QString &repoName)
{
    if (m_discoveredPeers.contains(peerId))
    {
        if (!m_discoveredPeers[peerId].publicRepoNames.contains(repoName))
        {
            m_discoveredPeers[peerId].publicRepoNames.append(repoName);
            emit lanPeerDiscoveredOrUpdated(m_discoveredPeers.value(peerId));
        }
    }
}

QList<QString> NetworkManager::getConnectedPeerIds() const
{
    QList<QString> ids;
    for (auto it = m_socketToPeerUsernameMap.constBegin(); it != m_socketToPeerUsernameMap.constEnd(); ++it)
    {
        QTcpSocket *socket = it.key();
        const QString &id = it.value();
        // Only count as connected once both sides have exchanged and accepted identity,
        // and this is not a temporary transfer socket and not still pending user approval.
        if (m_pendingConnections.contains(socket))
            continue; // pending accept
        if (socket->property("is_transfer_socket").toBool())
            continue; // temp
        if (id.isEmpty())
            continue;
        if (id.startsWith("AwaitingID") || id.startsWith("Transfer:") || id.startsWith("ConnectingTo"))
            continue;
        if (!m_handshakeSent.contains(socket))
            continue; // ensure we completed our side handshake
        ids.append(id);
    }
    return ids;
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload)
{
    if (!socket)
        return;
    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
    {
        qWarning() << "Cannot send encrypted message: Unknown peer or public key for socket.";
        return;
    }

    QByteArray recipientPubKey = m_peerCurve25519PublicKeys.value(peerId);
    QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();

    QVariantMap fullPayload = payload;
    fullPayload["__messageType"] = messageType;
    QByteArray plaintextMessage = QJsonDocument(QJsonObject::fromVariantMap(fullPayload)).toJson(QJsonDocument::Compact);

    QByteArray nonce(crypto_box_NONCEBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char *>(nonce.data()), crypto_box_NONCEBYTES);

    QByteArray ciphertext(crypto_box_MACBYTES + plaintextMessage.size(), 0);

    if (crypto_box_easy(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            reinterpret_cast<const unsigned char *>(plaintextMessage.constData()),
            plaintextMessage.size(),
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(recipientPubKey.constData()),
            reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
    {
        qWarning() << "Failed to encrypt message for" << peerId;
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("ENCRYPTED_PAYLOAD") << nonce << ciphertext;
    socket->write(block);
}

void NetworkManager::handleRepoRequest(QTcpSocket *socket, const QString &requestingPeer, const QString &repoName)
{
    if (!m_repoManager_ptr)
        return;
    bool canAccess = false;
    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfoByDisplayName(repoName);
    if (!repoInfo.appId.isEmpty())
    {
        if (repoInfo.isPublic || repoInfo.groupMembers.contains(requestingPeer))
        {
            canAccess = true;
        }
    }
    if (canAccess)
    {
        // This inbound connection may be a dedicated transfer connection created by the requester,
        // or it might be the peer's existing control connection. Do NOT mark control sockets as
        // transfer sockets, otherwise the app will treat them as temporary and drop them.
        // Simply cancel any pending prompt timer and proceed to serve the request on this socket.
        // If the requester created a dedicated transfer socket, they will close it from their side
        // after receiving the bundle end signal; the control connection remains unaffected.
        // Cancel pending timer if any to auto-allow transfer without prompting.
        if (m_pendingConnections.contains(socket))
        {
            QTimer *t = m_pendingConnections.take(socket);
            if (t)
                t->deleteLater();
        }
        emit repoBundleRequestedByPeer(socket, requestingPeer, repoName, "");
    }
    else
    {
        qWarning() << "Access denied for repo" << repoName << "to peer" << requestingPeer;
        socket->disconnectFromHost();
    }
}

void NetworkManager::sendChangeProposal(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundlePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("PROPOSE_CHANGES_BUNDLE_START") << repoDisplayName << fromBranch << bundleFile.size();
    targetPeerSocket->write(startBlock);

    char buffer[65536];
    while (!bundleFile.atEnd())
    {
        qint64 bytesRead = bundleFile.read(buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            targetPeerSocket->write(buffer, bytesRead);
            if (!targetPeerSocket->waitForBytesWritten(-1))
            {
                bundleFile.close();
                QFile::remove(bundlePath);
                return;
            }
        }
    }
    bundleFile.close();

    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("PROPOSE_CHANGES_BUNDLE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);

    // The temporary bundle file is removed by the caller after sending
}

void NetworkManager::sendChangeProposalArchive(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &archivePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile arcFile(archivePath);
    if (!arcFile.open(QIODevice::ReadOnly))
        return;

    // Determine archive format from file extension
    QString format = "zip";
    if (archivePath.endsWith(".tar.gz", Qt::CaseInsensitive) || archivePath.endsWith(".tgz", Qt::CaseInsensitive))
        format = "tar.gz";

    // Encrypted chunked transfer
    QString peerId = m_socketToPeerUsernameMap.value(targetPeerSocket);
    if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
    {
        // Fallback to raw if keys unavailable
        QByteArray startBlock;
        QDataStream startOut(&startBlock, QIODevice::WriteOnly);
        startOut.setVersion(QDataStream::Qt_5_15);
        startOut << QString("PROPOSE_ARCHIVE_START") << repoDisplayName << fromBranch << arcFile.size() << format;
        targetPeerSocket->write(startBlock);

        char bufferRaw[65536];
        while (!arcFile.atEnd())
        {
            qint64 bytesRead = arcFile.read(bufferRaw, sizeof(bufferRaw));
            if (bytesRead > 0)
            {
                targetPeerSocket->write(bufferRaw, bytesRead);
                if (!targetPeerSocket->waitForBytesWritten(-1))
                {
                    arcFile.close();
                    return;
                }
            }
        }
        arcFile.close();
        QByteArray endBlock;
        QDataStream endOut(&endBlock, QIODevice::WriteOnly);
        endOut.setVersion(QDataStream::Qt_5_15);
        endOut << QString("PROPOSE_ARCHIVE_END") << repoDisplayName;
        targetPeerSocket->write(endBlock);
        return;
    }

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("PROPOSE_ARCHIVE_START_ENC") << repoDisplayName << fromBranch << arcFile.size() << format;
    targetPeerSocket->write(startBlock);

    QByteArray recipientPubKey = m_peerCurve25519PublicKeys.value(peerId);
    QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();

    char buffer[65536];
    while (!arcFile.atEnd())
    {
        qint64 bytesRead = arcFile.read(buffer, sizeof(buffer));
        if (bytesRead <= 0)
            break;
        QByteArray plaintext(buffer, static_cast<int>(bytesRead));
        QByteArray nonce(crypto_box_NONCEBYTES, 0);
        randombytes_buf(reinterpret_cast<unsigned char *>(nonce.data()), crypto_box_NONCEBYTES);
        QByteArray ciphertext(crypto_box_MACBYTES + plaintext.size(), 0);
        if (crypto_box_easy(
                reinterpret_cast<unsigned char *>(ciphertext.data()),
                reinterpret_cast<const unsigned char *>(plaintext.constData()),
                plaintext.size(),
                reinterpret_cast<const unsigned char *>(nonce.constData()),
                reinterpret_cast<const unsigned char *>(recipientPubKey.constData()),
                reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
        {
            arcFile.close();
            return;
        }

        QByteArray chunkBlock;
        QDataStream chunkOut(&chunkBlock, QIODevice::WriteOnly);
        chunkOut.setVersion(QDataStream::Qt_5_15);
        chunkOut << QString("PROPOSE_ARCHIVE_CHUNK") << repoDisplayName << nonce << ciphertext;
        targetPeerSocket->write(chunkBlock);
        if (!targetPeerSocket->waitForBytesWritten(-1))
        {
            arcFile.close();
            return;
        }
    }
    arcFile.close();

    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("PROPOSE_ARCHIVE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId, DiscoveredPeerInfo());
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}