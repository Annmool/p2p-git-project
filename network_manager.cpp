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

bool NetworkManager::connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername, bool isPublicRepoClone)
{
    if (!isPublicRepoClone)
    {
        QTcpSocket *existingSocket = getSocketForPeer(expectedPeerUsername);
        if (existingSocket && existingSocket->state() == QAbstractSocket::ConnectedState)
        {
            qDebug() << "NM: Already connected to peer" << expectedPeerUsername << ". Skipping new connection.";
            emit newTcpPeerConnected(existingSocket, expectedPeerUsername, m_peerPublicKeys.value(expectedPeerUsername));
            return true;
        }
    }

    qDebug() << "NM: Initiating new TCP connection to" << hostAddress.toString() << ":" << port;

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);
    socket->setProperty("expected_peer_username", expectedPeerUsername);
    socket->setProperty("is_public_repo_clone", isPublicRepoClone);

    if (!isPublicRepoClone)
    {
        if (!m_allTcpSockets.contains(socket))
            m_allTcpSockets.append(socket);
        m_socketToPeerUsernameMap.insert(socket, expectedPeerUsername);
    }

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            { sendIdentityOverTcp(socket); });

    if (isPublicRepoClone)
    {
        connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    }
    else
    {
        connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    }

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

    if (m_incomingTransfers.contains(socket))
    {
        IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
        if (transfer->state == IncomingFileTransfer::Receiving)
        {
            qint64 bytesAvailable = socket->bytesAvailable();
            qint64 bytesToWrite = qMin(bytesAvailable, transfer->totalSize - transfer->bytesReceived);
            QByteArray fileData = socket->read(bytesToWrite);
            transfer->file.write(fileData);
            transfer->bytesReceived += fileData.size();
            emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
            if (transfer->bytesReceived >= transfer->totalSize)
            {
                transfer->state = IncomingFileTransfer::Completed;
                transfer->file.close();
            }
        }
    }

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
    QDataStream in(rawData);
    in.setVersion(QDataStream::Qt_5_15);

    while (!in.atEnd())
    {
        in.startTransaction();
        QString messageType;
        in >> messageType;

        if (messageType == "IDENTITY_HANDSHAKE_V2")
        {
            // Handle pending connection timeout
            if (m_pendingConnections.contains(socket))
            {
                QTimer *timer = m_pendingConnections.take(socket);
                if (timer)
                    timer->stop();

                QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
                emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
            }

            // Process the handshake
            QString receivedPeerUsername, receivedPublicKeyHex;
            in >> receivedPeerUsername >> receivedPublicKeyHex;
            if (!in.commitTransaction())
                return;

            // Update or set the peer's username and public key
            bool wasKnown = m_socketToPeerUsernameMap.value(socket) == receivedPeerUsername;
            m_socketToPeerUsernameMap.insert(socket, receivedPeerUsername);
            m_peerPublicKeys.insert(receivedPeerUsername, receivedPublicKeyHex);

            // Emit newTcpPeerConnected for every successful handshake
            emit newTcpPeerConnected(socket, receivedPeerUsername, receivedPublicKeyHex);

            sendIdentityOverTcp(socket); // Reply with our own identity
        }
        else if (messageType == "REQUEST_REPO_BUNDLE")
        {
            QString requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath;
            in >> requestingPeerUsername >> requestedRepoDisplayName >> requesterLocalPath;
            if (!in.commitTransaction())
                return;

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
                if (m_pendingConnections.contains(socket))
                {
                    QTimer *timer = m_pendingConnections.take(socket);
                    if (timer)
                        timer->stop();
                }
                socket->setProperty("is_public_repo_clone", true);
                emit repoBundleRequestedByPeer(socket, requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath);
            }
            else
            {
                if (!m_allTcpSockets.contains(socket))
                {
                    qWarning() << "Received request for private repo from an unestablished connection. Rejecting.";
                    socket->disconnectFromHost();
                    return;
                }
                emit repoBundleRequestedByPeer(socket, requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath);
            }
        }
        else if (messageType == "SEND_REPO_BUNDLE_START")
        {
            QString repoName;
            qint64 totalSize;
            in >> repoName >> totalSize;
            if (!in.commitTransaction())
            {
                qDebug() << "NM: Incomplete SEND_REPO_BUNDLE_START from" << getPeerDisplayString(socket);
                return;
            }
            qDebug() << "NM: Received SEND_REPO_BUNDLE_START for" << repoName << "size" << totalSize;
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
            auto *transfer = new IncomingFileTransfer();
            transfer->repoName = repoName;
            transfer->tempLocalPath = tempPath;
            transfer->totalSize = totalSize;
            transfer->file.setFileName(tempPath);
            if (!transfer->file.open(QIODevice::WriteOnly))
            {
                qWarning() << "NM: Failed to open temp file for bundle:" << tempPath;
                delete transfer;
                return;
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
            {
                qDebug() << "NM: Incomplete SEND_REPO_BUNDLE_END from" << getPeerDisplayString(socket);
                return;
            }
            qDebug() << "NM: Received SEND_REPO_BUNDLE_END for" << repoName;
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
                else
                {
                    qWarning() << "NM: Received BUNDLE_END for" << repoName << "but not all data received.";
                }
            }
        }
        else if (messageType == "CHAT_MESSAGE")
        {
            QString chatMessage;
            in >> chatMessage;
            if (!in.commitTransaction())
            {
                qDebug() << "NM: Incomplete CHAT_MESSAGE from" << getPeerDisplayString(socket);
                return;
            }
            qDebug() << "NM: Received CHAT_MESSAGE from" << m_socketToPeerUsernameMap.value(socket, "UnknownPeer") << ":" << chatMessage;
            emit tcpMessageReceived(socket, m_socketToPeerUsernameMap.value(socket, "UnknownPeer"), chatMessage);
        }
        else
        {
            in.rollbackTransaction();
            qWarning() << "NM: Unknown or partial TCP message from" << getPeerDisplayString(socket) << "Type:" << messageType;
            return;
        }
    }
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "startSendingBundle: Cannot send, target socket not connected.";
        return;
    }

    QFile bundleFile(bundleFilePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
    {
        qWarning() << "Could not open bundle file for sending:" << bundleFile.errorString();
        return;
    }

    qint64 fileSize = bundleFile.size();
    qDebug() << "Starting to send bundle for" << repoDisplayName << "size:" << fileSize << "bytes.";

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << fileSize;
    targetPeerSocket->write(startBlock);
    if (!targetPeerSocket->waitForBytesWritten())
    {
        qWarning() << "Failed to write START command to socket.";
        bundleFile.close();
        return;
    }

    while (!bundleFile.atEnd())
    {
        QByteArray chunk = bundleFile.read(65536);
        targetPeerSocket->write(chunk);
        if (!targetPeerSocket->waitForBytesWritten(-1))
        {
            qWarning() << "Failed to write chunk to socket for" << getPeerDisplayString(targetPeerSocket);
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

    qDebug() << "Finished sending bundle commands and data for" << repoDisplayName;
    QFile::remove(bundleFilePath);
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            qDebug() << "NM: New incoming TCP connection from" << socket->peerAddress().toString();
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
    sendIdentityOverTcp(socket);
}

void NetworkManager::setupPublicRepoSocket(QTcpSocket *socket)
{
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, [this, socket]()
            { socket->deleteLater(); });
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->stop();
        setupAcceptedSocket(pendingSocket);
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