#include "network_manager.h"
#include "repository_manager.h"
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
    if (!m_identityManager || !m_identityManager->areKeysInitialized())
    {
        qCritical() << "NetworkManager: CRITICAL - IdentityManager not provided or keys not initialized!";
    }
    if (!m_repoManager_ptr)
    {
        qCritical() << "NetworkManager: CRITICAL - RepositoryManager not provided!";
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
}

NetworkManager::~NetworkManager()
{
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();
    qDeleteAll(m_incomingTransfers);
}

bool NetworkManager::isConnectionPending(QTcpSocket *socket) const { return m_pendingConnections.contains(socket); }

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    QTcpSocket *socket = new QTcpSocket(this);
    connect(socket, &QTcpSocket::connected, this, [=]()
            {
        qDebug() << "NM: Temp socket connected for public clone. Sending request.";
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << QString("REQUEST_REPO_BUNDLE") << myUsername << repoName << localPath;
        socket->write(block); });
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
    socket->connectToHost(host, port);
}

QString NetworkManager::getPeerDisplayString(QTcpSocket *socket)
{
    if (!socket)
        return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    if (!username.isEmpty() && !username.startsWith("AwaitingID") && !username.startsWith("ConnectingTo"))
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
    QTcpSocket *existingSocket = getSocketForPeer(expectedPeerUsername);
    if (existingSocket && existingSocket->state() == QAbstractSocket::ConnectedState)
    {
        emit newTcpPeerConnected(existingSocket, expectedPeerUsername, m_peerPublicKeys.value(expectedPeerUsername));
        return true;
    }

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);
    socket->setProperty("expected_peer_username", expectedPeerUsername);

    if (!m_allTcpSockets.contains(socket))
        m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, expectedPeerUsername);

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
    return !m_allTcpSockets.isEmpty();
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
    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclySharedRepositories();
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

void NetworkManager::sendMessageToPeer(QTcpSocket *peerSocket, const QString &message)
{
    if (peerSocket && peerSocket->state() == QAbstractSocket::ConnectedState)
    {
        QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
        if (peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo"))
            return;
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << QString("CHAT_MESSAGE") << message;
        peerSocket->write(block);
    }
}

void NetworkManager::broadcastTcpMessage(const QString &message)
{
    for (QTcpSocket *s : qAsConst(m_allTcpSockets))
    {
        sendMessageToPeer(s, message);
    }
}

void NetworkManager::sendIdentityOverTcp(QTcpSocket *socket)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager)
        return;
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("IDENTITY_HANDSHAKE_V2") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    socket->write(block);
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    // State 1: We are in the middle of receiving a file.
    if (m_incomingTransfers.contains(socket))
    {
        IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
        if (transfer->state == IncomingFileTransfer::Receiving)
        {
            // Append all available data to the file until we reach the expected size.
            qint64 bytesToWrite = transfer->totalSize - transfer->bytesReceived;
            QByteArray fileData = socket->read(qMin(socket->bytesAvailable(), bytesToWrite));

            transfer->file.write(fileData);
            transfer->bytesReceived += fileData.size();
            emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);

            if (transfer->bytesReceived >= transfer->totalSize)
            {
                transfer->state = IncomingFileTransfer::Completed;
                transfer->file.close();
                qDebug() << "File data reception complete for" << transfer->repoName;
            }
        }
    }

    // State 2: We are expecting command messages.
    // This will process any data left over after a file transfer, or all data if no transfer is active.
    if (socket->bytesAvailable() > 0)
    {
        processIncomingTcpData(socket, socket->readAll());
    }
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

void NetworkManager::processIncomingTcpData(QTcpSocket *socket, const QByteArray &rawData)
{
    static QMap<QTcpSocket *, QByteArray> bufferMap;
    bufferMap[socket].append(rawData);
    QByteArray &buffer = bufferMap[socket];

    while (true)
    {
        QDataStream in(buffer);
        in.setVersion(QDataStream::Qt_5_15);
        in.startTransaction();

        QString messageType;
        in >> messageType;

        if (m_pendingConnections.contains(socket))
        {
            if (messageType == "REQUEST_REPO_BUNDLE")
            {
                QString requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath;
                in >> requestingPeerUsername >> requestedRepoDisplayName >> requesterLocalPath;
                if (!in.commitTransaction())
                    break;

                bool isPublic = false;
                if (m_repoManager_ptr)
                {
                    for (const auto &repo : m_repoManager_ptr->getMyPubliclySharedRepositories())
                    {
                        if (repo.displayName == requestedRepoDisplayName)
                        {
                            isPublic = true;
                            break;
                        }
                    }
                }
                if (isPublic)
                {
                    QTimer *timer = m_pendingConnections.take(socket);
                    if (timer)
                        timer->deleteLater();
                    disconnect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
                    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
                    m_socketToPeerUsernameMap.insert(socket, requestingPeerUsername);
                    emit repoBundleRequestedByPeer(socket, requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath);
                }
            }
            else if (messageType == "IDENTITY_HANDSHAKE_V2")
            {
                QTimer *timer = m_pendingConnections.take(socket);
                if (timer)
                    timer->deleteLater();
                QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
                emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
                in.rollbackTransaction(); // Let it be processed after acceptance
                return;
            }
            else
            {
                in.rollbackTransaction();
                return;
            }
        }
        else
        {
            if (messageType == "IDENTITY_HANDSHAKE_V2")
            {
                QString receivedPeerUsername, receivedPublicKeyHex;
                in >> receivedPeerUsername >> receivedPublicKeyHex;
                if (!in.commitTransaction())
                    break;
                bool alreadyKnown = m_socketToPeerUsernameMap.value(socket) == receivedPeerUsername;
                m_socketToPeerUsernameMap.insert(socket, receivedPeerUsername);
                m_peerPublicKeys.insert(receivedPeerUsername, QByteArray::fromHex(receivedPublicKeyHex.toUtf8()));
                if (!alreadyKnown)
                {
                    emit newTcpPeerConnected(socket, receivedPeerUsername, receivedPublicKeyHex);
                }
                sendIdentityOverTcp(socket);
            }
            else if (messageType == "REQUEST_REPO_BUNDLE")
            {
                QString requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath;
                in >> requestingPeerUsername >> requestedRepoDisplayName >> requesterLocalPath;
                if (!in.commitTransaction())
                    break;
                emit repoBundleRequestedByPeer(socket, requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath);
            }
            else if (messageType == "SEND_REPO_BUNDLE_START")
            {
                QString repoName;
                qint64 totalSize;
                in >> repoName >> totalSize;
                if (!in.commitTransaction())
                    break;
                QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
                auto *transfer = new IncomingFileTransfer();
                transfer->repoName = repoName;
                transfer->tempLocalPath = tempPath;
                transfer->totalSize = totalSize;
                transfer->file.setFileName(tempPath);
                if (!transfer->file.open(QIODevice::WriteOnly))
                {
                    delete transfer;
                    break;
                }
                m_incomingTransfers.insert(socket, transfer);
                emit repoBundleTransferStarted(repoName, tempPath);
                onTcpSocketReadyRead();
            }
            else if (messageType == "SEND_REPO_BUNDLE_END")
            {
                QString repoName;
                in >> repoName;
                if (!in.commitTransaction())
                    break;
                if (m_incomingTransfers.contains(socket))
                {
                    IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
                    if (transfer->state == IncomingFileTransfer::Completed)
                    {
                        m_incomingTransfers.remove(socket);
                        bool success = (transfer->bytesReceived == transfer->totalSize);
                        emit repoBundleCompleted(repoName, transfer->tempLocalPath, success, success ? "Transfer complete." : "Size mismatch.");
                        delete transfer;
                    }
                }
            }
            else if (messageType == "CHAT_MESSAGE")
            {
                QString chatMessage;
                in >> chatMessage;
                if (!in.commitTransaction())
                    break;
                emit tcpMessageReceived(socket, m_socketToPeerUsernameMap.value(socket, "UnknownPeer"), chatMessage);
            }
            else if (messageType == "ENCRYPTED_PAYLOAD")
            {
                QByteArray nonce, ciphertext;
                in >> nonce >> ciphertext;
                if (!in.commitTransaction())
                    break;

                QString peerId = m_socketToPeerUsernameMap.value(socket);
                QByteArray senderPubKey = m_peerPublicKeys.value(peerId);
                // <<< FIX: Call the correct, newly added getter function >>>
                QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();

                QByteArray decrypted(ciphertext.size() - crypto_box_MACBYTES, 0);

                if (crypto_box_open_easy(
                        reinterpret_cast<unsigned char *>(decrypted.data()),
                        reinterpret_cast<const unsigned char *>(ciphertext.constData()),
                        ciphertext.size(),
                        reinterpret_cast<const unsigned char *>(nonce.constData()),
                        reinterpret_cast<const unsigned char *>(senderPubKey.constData()),
                        reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
                {
                    qWarning() << "Failed to decrypt message from" << peerId;
                    break; // Stop processing on decryption failure
                }

                QJsonObject payloadObj = QJsonDocument::fromJson(decrypted).object();
                QString innerMessageType = payloadObj.value("__messageType").toString();
                payloadObj.remove("__messageType");
                emit secureMessageReceived(peerId, innerMessageType, payloadObj.toVariantMap());
            }
            else
            {
                in.rollbackTransaction();
                break; // Unknown message type, wait for more data
            }
        }

        // If we successfully read a message, remove it from the buffer
        buffer = buffer.mid(in.device()->pos());
    }

    if (buffer.isEmpty())
    {
        bufferMap.remove(socket);
    }
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundleFilePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;
    qint64 fileSize = bundleFile.size();
    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << fileSize;
    targetPeerSocket->write(startBlock);
    if (!targetPeerSocket->waitForBytesWritten())
    {
        bundleFile.close();
        return;
    }
    while (!bundleFile.atEnd())
    {
        QByteArray chunk = bundleFile.read(65536);
        targetPeerSocket->write(chunk);
        if (!targetPeerSocket->waitForBytesWritten(-1))
        {
            bundleFile.close();
            return;
        }
    }
    bundleFile.close();
    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("SEND_REPO_BUNDLE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);
    targetPeerSocket->flush();
    QString recipientUsername = m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer");
    emit repoBundleSent(repoDisplayName, recipientUsername);
    QFile::remove(bundleFilePath);
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

            QTimer *timer = new QTimer(socket);
            m_pendingConnections.insert(socket, timer);
            timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this, socket]()
                    {
                if (m_pendingConnections.contains(socket)) {
                    rejectPendingTcpConnection(socket);
                } });
            timer->start(PENDING_CONNECTION_TIMEOUT_MS);
        }
    }
}

void NetworkManager::setupAcceptedSocket(QTcpSocket *socket)
{
    if (!m_allTcpSockets.contains(socket))
        m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, "AwaitingID_Incoming");
    // We don't send our identity until we receive theirs first.
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->stop();
        setupAcceptedSocket(pendingSocket);

        // Send connection acknowledgment to the initiator
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << QString("CONNECTION_ACK") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());
        qDebug() << "NM:" << m_myUsername << "sending CONNECTION_ACK to" << pendingSocket->peerAddress().toString();
        pendingSocket->write(block);
        if (!pendingSocket->waitForBytesWritten(3000))
        {
            qWarning() << "NM:" << m_myUsername << "failed to write CONNECTION_ACK to" << pendingSocket->peerAddress().toString() << pendingSocket->errorString();
        }

        // Process any existing data
        if (pendingSocket->bytesAvailable() > 0)
        {
            onTcpSocketReadyRead();
        }
    }
}
void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        m_pendingConnections.remove(pendingSocket);
        pendingSocket->disconnectFromHost();
        pendingSocket->deleteLater();
    }
}

void NetworkManager::onTcpSocketStateChanged(QAbstractSocket::SocketState socketState)
{
    Q_UNUSED(socketState);
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    m_allTcpSockets.removeAll(socket);
    if (m_pendingConnections.contains(socket))
    {
        m_pendingConnections.remove(socket);
        socket->deleteLater();
        return;
    }
    if (m_incomingTransfers.contains(socket))
    {
        delete m_incomingTransfers.take(socket);
    }
    QString peerUsername = m_socketToPeerUsernameMap.take(socket);
    if (!peerUsername.isEmpty())
    {
        m_peerPublicKeys.remove(peerUsername);
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
    if (socket->property("is_outgoing_attempt").toBool())
    {
        emit tcpConnectionStatusChanged(socket->property("expected_peer_username").toString(), "", false, socket->errorString());
    }
    socket->disconnectFromHost();
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId, DiscoveredPeerInfo());
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}

QList<QString> NetworkManager::getConnectedPeerIds() const
{
    // Return the usernames of all fully established, non-temporary connections
    QList<QString> ids;
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        QString id = m_socketToPeerUsernameMap.value(socket);
        if (!id.isEmpty() && !id.startsWith("AwaitingID"))
        {
            ids.append(id);
        }
    }
    return ids;
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload)
{
    if (!socket)
        return;
    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || !m_peerPublicKeys.contains(peerId))
    {
        qWarning() << "Cannot send encrypted message: Unknown peer or public key for socket.";
        return;
    }

    QByteArray recipientPubKey = m_peerPublicKeys.value(peerId);
    // <<< FIX: Call the correct, newly added getter function >>>
    QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();

    QVariantMap fullPayload = payload;
    fullPayload["__messageType"] = messageType;
    QByteArray plaintextMessage = QJsonDocument(QJsonObject::fromVariantMap(fullPayload)).toJson(QJsonDocument::Compact);

    QByteArray nonce(crypto_box_NONCEBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char *>(nonce.data()), crypto_box_NONCEBYTES);

    QByteArray ciphertext(crypto_box_MACBYTES + plaintextMessage.size(), 0);

    // <<< FIX: Correctly cast QByteArray's const char* to the required const unsigned char* >>>
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
