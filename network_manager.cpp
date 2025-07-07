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
#include <sodium.h>
<<<<<<< Updated upstream
=======
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <functional>
>>>>>>> Stashed changes

const qint64 PEER_TIMEOUT_MS = 15000;
const int BROADCAST_INTERVAL_MS = 5000;
const int PENDING_CONNECTION_TIMEOUT_MS = 30000;
<<<<<<< Updated upstream

NetworkManager::NetworkManager(const QString &myUsername,
                               IdentityManager *identityManager,
                               RepositoryManager *repoManager,
                               QObject *parent)
    : QObject(parent),
      m_myUsername(myUsername),
      m_identityManager(identityManager),
      m_repoManager_ptr(repoManager)
{
=======
const int FILE_TRANSFER_CHUNK_SIZE = 65536;

NetworkManager::NetworkManager(const QString &myUsername, IdentityManager *identityManager, RepositoryManager *repoManager, QObject *parent)
    : QObject(parent), m_myUsername(myUsername), m_identityManager(identityManager), m_repoManager_ptr(repoManager)
{
    if (!m_identityManager || !m_repoManager_ptr) { qCritical() << "NetworkManager initialized without valid IdentityManager or RepositoryManager!"; }
    if (sodium_init() == -1) { qCritical() << "NetworkManager: CRITICAL - libsodium could not be initialized!"; }

>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
=======
    m_incomingTransfers.clear();
    qDeleteAll(m_outgoingTransfers);
    m_outgoingTransfers.clear();
    qDeleteAll(m_pendingConnections);
    m_pendingConnections.clear();
>>>>>>> Stashed changes
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections()) {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
<<<<<<< Updated upstream
        if (socket)
        {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString();
=======
        if (socket) {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString() << ":" << socket->peerPort();
>>>>>>> Stashed changes
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
            if (!m_allTcpSockets.contains(socket)) m_allTcpSockets.append(socket);

            m_pendingConnections.insert(socket, new QTimer(socket));
            m_pendingConnections[socket]->setSingleShot(true);
            connect(m_pendingConnections[socket], &QTimer::timeout, this, [this, socket](){ rejectPendingTcpConnection(socket); });
            m_pendingConnections[socket]->start(PENDING_CONNECTION_TIMEOUT_MS);

<<<<<<< Updated upstream
=======
            m_allTcpSockets.append(socket);
            m_socketToPeerUsernameMap.insert(socket, "AwaitingID:" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));

            QTimer *timer = new QTimer(socket);
            timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this, socket]() {
                qWarning() << "Handshake timeout for incoming connection from" << getPeerDisplayString(socket);
                rejectPendingTcpConnection(socket);
            });
            m_pendingConnections.insert(socket, timer);
            timer->start(PENDING_CONNECTION_TIMEOUT_MS);

            sendIdentityOverTcp(socket);
>>>>>>> Stashed changes
            QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
            emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
        }
    }
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
<<<<<<< Updated upstream
    if (!socket) return;

    m_socketBuffers[socket].append(socket->readAll());

    if (m_pendingConnections.contains(socket)) {
        qDebug() << "Data arrived on a pending connection. Buffering only.";
        return;
    }
    
=======
    if (!socket) { qWarning() << "onTcpSocketReadyRead called with invalid sender."; return; }
>>>>>>> Stashed changes
    processIncomingTcpData(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
<<<<<<< Updated upstream
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "User accepted connection from" << pendingSocket->peerAddress().toString();
        
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer) timer->deleteLater();

        sendIdentityOverTcp(pendingSocket);

=======
    if (m_pendingConnections.contains(pendingSocket)) {
        qDebug() << "Accepting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer) timer->deleteLater();
        if (!m_handshakeSent.contains(pendingSocket)) { sendIdentityOverTcp(pendingSocket); }
>>>>>>> Stashed changes
        if (m_socketBuffers.contains(pendingSocket) && !m_socketBuffers[pendingSocket].isEmpty()) {
            qDebug() << "Processing buffered data for newly accepted connection.";
            processIncomingTcpData(pendingSocket);
        }
<<<<<<< Updated upstream
    }
=======
    } else {
        qWarning() << "Attempted to accept a connection that was not pending:" << getPeerDisplayString(pendingSocket);
    }
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket)) {
        qDebug() << "Rejecting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer) timer->deleteLater();
        pendingSocket->disconnectFromHost();
    } else {
        qWarning() << "Attempted to reject a connection that was not pending:" << getPeerDisplayString(pendingSocket);
    }
}

bool NetworkManager::extractGroupInfoFromPayload(const QVariantMap &payload, QString &ownerRepoAppId, QString &repoDisplayName, QString &ownerPeerId, QStringList &groupMembers)
{
    ownerRepoAppId = payload.value("ownerRepoAppId").toString();
    repoDisplayName = payload.value("repoDisplayName").toString();
    ownerPeerId = payload.value("ownerPeerId").toString();
    groupMembers = payload.value("groupMembers").toStringList();
    return !ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty() && !ownerPeerId.isEmpty() && !groupMembers.isEmpty();
>>>>>>> Stashed changes
}

void NetworkManager::handleEncryptedPayload(const QString &peerId, const QVariantMap &payload)
{
    QString messageType = payload.value("__messageType").toString();
<<<<<<< Updated upstream
    if (messageType.isEmpty()) return;

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;

    if (messageType == "SHARE_PRIVATE_REPO") {
=======
    if (messageType.isEmpty()) {
        qWarning() << "Received encrypted payload with no messageType from" << peerId;
        return;
    }

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;

    if (messageType == "COLLABORATOR_ADDED") {
        QString ownerRepoAppId, repoDisplayName, ownerPeerId;
        QStringList groupMembers;
        if (extractGroupInfoFromPayload(payload, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers)) {
            emit collaboratorAddedReceived(peerId, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers);
        } else {
            qWarning() << "NetworkManager: Invalid COLLABORATOR_ADDED payload from" << peerId;
        }
    } else if (messageType == "COLLABORATOR_REMOVED") {
        QString ownerRepoAppId = payload.value("ownerRepoAppId").toString();
        QString repoDisplayName = payload.value("repoDisplayName").toString();
        if (!ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty()) {
            emit collaboratorRemovedReceived(peerId, ownerRepoAppId, repoDisplayName);
        } else {
            qWarning() << "NetworkManager: Invalid COLLABORATOR_REMOVED payload from" << peerId;
        }
    } else {
>>>>>>> Stashed changes
        emit secureMessageReceived(peerId, messageType, payload);
    } else if (messageType == "COLLABORATOR_ADDED") {
        QString appId = payload.value("appId").toString();
        QString repoName = payload.value("repoName").toString();
        QString ownerId = payload.value("ownerId").toString();
        
        if (!appId.isEmpty() && m_repoManager_ptr) {
            ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfoByOrigin(ownerId, repoName);

            if (!repoInfo.appId.isEmpty()) {
                m_repoManager_ptr->addCollaborator(repoInfo.appId, m_myUsername);
                qDebug() << "I (" << m_myUsername << ") have been confirmed as a collaborator on" << repoName;
            } else {
                qWarning() << "Received COLLABORATOR_ADDED message for repo" << repoName << "but I don't have a local copy.";
            }
        }
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
            qint64 bytesToWrite = qMin((qint64)buffer.size(), transfer->totalSize - transfer->bytesReceived);
            if (bytesToWrite > 0)
            {
                transfer->file.write(buffer.constData(), bytesToWrite);
                buffer.remove(0, static_cast<int>(bytesToWrite));
                transfer->bytesReceived += bytesToWrite;
                emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
            }
            if (transfer->bytesReceived < transfer->totalSize) return;
        }

        in.startTransaction();
        QString messageType;
        in >> messageType;
        
        if (messageType == "IDENTITY_HANDSHAKE_V2")
        {
            QString peerUsername, peerKeyHex;
            in >> peerUsername >> peerKeyHex;
            if (!in.commitTransaction()) return;
            
            QString expectedPeerId = m_socketToPeerUsernameMap.value(socket, "");
            if(expectedPeerId.isEmpty() || expectedPeerId == peerUsername) {
                m_socketToPeerUsernameMap.insert(socket, peerUsername);
                m_peerPublicKeys.insert(peerUsername, QByteArray::fromHex(peerKeyHex.toUtf8()));
                if (!m_handshakeSent.contains(socket)) sendIdentityOverTcp(socket);
                emit newTcpPeerConnected(socket, peerUsername, peerKeyHex);
            } else {
                 qWarning() << "Identity mismatch! Expected" << expectedPeerId << "but got" << peerUsername;
                 socket->disconnectFromHost();
            }
        }
        else if (messageType == "REQUEST_REPO_BUNDLE") {
             QString requestingPeer, repoName, temp;
             in >> requestingPeer >> repoName >> temp;
             if (!in.commitTransaction()) return;
             m_socketToPeerUsernameMap.insert(socket, "Transfer:" + repoName);
             handleRepoRequest(socket, requestingPeer, repoName);
        }
        else if (messageType == "SEND_REPO_BUNDLE_START")
        {
            QString repoName;
            qint64 totalSize;
            in >> repoName >> totalSize;
            if (!in.commitTransaction()) return;
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
            auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, QFile(tempPath), totalSize, 0};
            if (transfer->file.open(QIODevice::WriteOnly)) {
                m_incomingTransfers.insert(socket, transfer);
            } else {
                 qWarning() << "Could not open temp file for bundle transfer:" << tempPath;
                 delete transfer;
            }
        }
        else if (messageType == "SEND_REPO_BUNDLE_END")
        {
            QString repoName;
            in >> repoName;
            if (!in.commitTransaction()) return;
            if (m_incomingTransfers.contains(socket))
            {
                IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                transfer->file.close();
                bool success = (transfer->bytesReceived == transfer->totalSize);
                emit repoBundleCompleted(repoName, transfer->tempLocalPath, success, success ? "Transfer complete." : "Size mismatch.");
                delete transfer;
                if (socket->property("is_transfer_socket").toBool()) {
                    socket->disconnectFromHost();
                }
            }
        }
        else if (messageType == "BROADCAST_MESSAGE")
        {
            QString message;
            in >> message;
            if(!in.commitTransaction()) return;
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            if (!peerUsername.isEmpty()) emit broadcastMessageReceived(socket, peerUsername, message);
        }
        else if (messageType == "GROUP_CHAT_MESSAGE")
        {
            QString repoAppId, message;
            in >> repoAppId >> message;
            if(!in.commitTransaction()) return;
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            if(!peerUsername.isEmpty()) emit groupMessageReceived(peerUsername, repoAppId, message);
        }
        else if (messageType == "ENCRYPTED_PAYLOAD")
        {
            QByteArray nonce, ciphertext;
            in >> nonce >> ciphertext;
            if(!in.commitTransaction()) return;

            QString peerId = m_socketToPeerUsernameMap.value(socket);
            if (peerId.isEmpty() || !m_peerPublicKeys.contains(peerId)) {
                qWarning() << "Received encrypted payload from unknown peer or peer with no public key.";
                continue;
            }

            QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();
            QByteArray peerPubKey = m_peerPublicKeys.value(peerId);

            QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

            if (crypto_box_open_easy(
                    reinterpret_cast<unsigned char*>(decryptedMessage.data()),
                    reinterpret_cast<const unsigned char*>(ciphertext.constData()),
                    ciphertext.size(),
                    reinterpret_cast<const unsigned char*>(nonce.constData()),
                    reinterpret_cast<const unsigned char*>(peerPubKey.constData()),
                    reinterpret_cast<const unsigned char*>(mySecretKey.constData())
                ) != 0)
            {
                qWarning() << "Failed to decrypt message from" << peerId;
                continue;
            }

            QJsonDocument doc = QJsonDocument::fromJson(decryptedMessage);
            if (doc.isObject()) {
                handleEncryptedPayload(peerId, doc.object().toVariantMap());
            }
        }
        else {
            qWarning() << "Unknown or unexpected message type received:" << messageType << "from" << getPeerDisplayString(socket);
            in.rollbackTransaction();
            return;
        }

        buffer.remove(0, buffer.size() - in.device()->bytesAvailable());
        if (in.atEnd()) return;
    }
}

bool NetworkManager::isConnectionPending(QTcpSocket *socket) const { return m_pendingConnections.contains(socket); }

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_transfer_socket", true);

    connect(socket, &QTcpSocket::connected, this, [=]()
            {
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        out << QString("REQUEST_REPO_BUNDLE") << myUsername << repoName << localPath;
        socket->write(block); });

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    m_socketToPeerUsernameMap.insert(socket, "Transfer:Cloning_" + repoName);
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

    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclySharedRepositories(QString());

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
    if (!peerSocket || peerSocket->state() != QAbstractSocket::ConnectedState) return;

    QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
    if (peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo") || peerUsername.startsWith("Transfer:"))
        return;

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << messageType;
    for(const QVariant& arg : args) {
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
    if (!m_repoManager_ptr) return;

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(repoAppId);
    if (repoInfo.appId.isEmpty()) return;

    QStringList members;
    members.append(repoInfo.adminPeerId);
    members.append(repoInfo.collaborators);
    members.removeDuplicates();

    for (const QString& memberId : members) {
        if (memberId == m_myUsername) continue;

        QTcpSocket* memberSocket = getSocketForPeer(memberId);
        if (memberSocket) {
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
    if (expectedPeerId.startsWith("ConnectingTo:")) {
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
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState) return;
    QFile bundleFile(bundleFilePath);
    if (!bundleFile.open(QIODevice::ReadOnly)) return;

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

    emit repoBundleSent(repoDisplayName, m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer"));
    QFile::remove(bundleFilePath);
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Rejecting or timing out connection from" << pendingSocket->peerAddress().toString();
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer) timer->deleteLater();
        pendingSocket->disconnectFromHost();
    }
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket) return;
    
    if (socket->property("is_transfer_socket").toBool())
    {
        m_socketBuffers.remove(socket);
        m_socketToPeerUsernameMap.remove(socket);
        if (m_incomingTransfers.contains(socket)) delete m_incomingTransfers.take(socket);
        return;
    }

    m_allTcpSockets.removeAll(socket);
    m_socketBuffers.remove(socket);
    m_handshakeSent.remove(socket);
    if (m_pendingConnections.contains(socket)) {
        QTimer *timer = m_pendingConnections.take(socket);
        if (timer) timer->deleteLater();
    }
    if (m_incomingTransfers.contains(socket)) delete m_incomingTransfers.take(socket);

    QString peerUsername = m_socketToPeerUsernameMap.take(socket);
    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo"))
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
    if (!socket) return;
    qWarning() << "Socket Error on" << getPeerDisplayString(socket) << ":" << socket->errorString();
    socket->disconnectFromHost();
}

void NetworkManager::addSharedRepoToPeer(const QString &peerId, const QString &repoName)
{
    if (m_discoveredPeers.contains(peerId))
    {
<<<<<<< Updated upstream
        if (!m_discoveredPeers[peerId].publicRepoNames.contains(repoName))
        {
            m_discoveredPeers[peerId].publicRepoNames.append(repoName);
            emit lanPeerDiscoveredOrUpdated(m_discoveredPeers.value(peerId));
=======
        // Get a mutable copy
        DiscoveredPeerInfo info = m_discoveredPeers[peerId];
        
        if (!info.publicRepoNames.contains(repoName))
        {
            info.publicRepoNames.append(repoName);
            // Put the modified copy back into the map
            m_discoveredPeers[peerId] = info;
            
            qDebug() << "Updated peer" << peerId << "with new shared repo:" << repoName;
            // This signal is essential for the UI to redraw the peer list.
            emit lanPeerDiscoveredOrUpdated(info);
>>>>>>> Stashed changes
        }
    }
}

QList<QString> NetworkManager::getConnectedPeerIds() const
{
    QList<QString> ids;
    for (const QString &id : m_socketToPeerUsernameMap.values())
    {
        if (!id.startsWith("AwaitingID") && !id.startsWith("Transfer:") && !id.startsWith("ConnectingTo"))
        {
            ids.append(id);
        }
    }
    return ids;
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload)
{
    if (!socket) return;
    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || !m_peerPublicKeys.contains(peerId))
    {
        qWarning() << "Cannot send encrypted message: Unknown peer or public key for socket.";
        return;
    }

    QByteArray recipientPubKey = m_peerPublicKeys.value(peerId);
    QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();

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
    if (!m_repoManager_ptr) return;
    bool canAccess = false;
    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfoByDisplayName(repoName);
    if (!repoInfo.appId.isEmpty())
    {
        if (repoInfo.isPublic || repoInfo.collaborators.contains(requestingPeer))
        {
            canAccess = true;
        }
    }
    if (canAccess)
    {
        emit repoBundleRequestedByPeer(socket, requestingPeer, repoName, "");
    }
    else
    {
        qWarning() << "Access denied for repo" << repoName << "to peer" << requestingPeer;
        socket->disconnectFromHost();
    }
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId, DiscoveredPeerInfo());
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}