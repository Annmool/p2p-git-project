#include "network_manager.h"
#include <QNetworkInterface>
#include <QDataStream>
#include <QDateTime>
#include <QDebug>
#include <QUuid> 


const qint64 PEER_TIMEOUT_MS = 15000;
const int BROADCAST_INTERVAL_MS = 5000;
const int PENDING_CONNECTION_TIMEOUT_MS = 30000;

NetworkManager::NetworkManager(const QString& myUsername,
                               IdentityManager* identityManager,
                               RepositoryManager* repoManager, // <<< NEW PARAMETER
                               QObject *parent)
    : QObject(parent),
      m_myUsername(myUsername),
      m_identityManager(identityManager),
      m_repoManager_ptr(repoManager) // <<< STORE REPO MANAGER
{
    if (!m_identityManager || !m_identityManager->areKeysInitialized()) {
        qCritical() << "NetworkManager: CRITICAL - IdentityManager not provided or keys not initialized!";
    }
    if (!m_repoManager_ptr) {
        qCritical() << "NetworkManager: CRITICAL - RepositoryManager not provided!";
    }

    // TCP Server
    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &NetworkManager::onNewTcpConnection);

    // UDP Socket
    m_udpSocket = new QUdpSocket(this);
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &NetworkManager::onUdpReadyRead);

    // Broadcast Timer
    m_broadcastTimer = new QTimer(this);
    connect(m_broadcastTimer, &QTimer::timeout, this, &NetworkManager::onBroadcastTimerTimeout);

    // Peer Cleanup Timer
    m_peerCleanupTimer = new QTimer(this);
    connect(m_peerCleanupTimer, &QTimer::timeout, this, &NetworkManager::onPeerCleanupTimerTimeout);
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2);
}


NetworkManager::~NetworkManager() {
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();
}

QString NetworkManager::getPeerDisplayString(QTcpSocket* socket) {
    if (!socket) return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    if (!username.isEmpty() && !username.startsWith("AwaitingID") && !username.startsWith("ConnectingTo")) {
        return username + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
    }
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

QTcpSocket* NetworkManager::getSocketForPeer(const QString& peerUsername) {
    for (QTcpSocket* socket : qAsConst(m_allTcpSockets)) {
        if (m_socketToPeerUsernameMap.value(socket) == peerUsername) {
            return socket;
        }
    }
    return nullptr;
}

void NetworkManager::sendRepoBundleRequest(QTcpSocket* targetPeerSocket, const QString& repoDisplayName, const QString& requesterLocalPath) {
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState) {
        qWarning() << "NM: Cannot send RepoBundleRequest, target socket not connected.";
        // emit repoBundleTransferError(repoDisplayName, "Target peer not connected."); // Requester side error
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    QString messageType = "REQUEST_REPO_BUNDLE";

    out << messageType << m_myUsername << repoDisplayName << requesterLocalPath; // Send our username, requested repo, and where we plan to save

    targetPeerSocket->write(block);
    qDebug() << "NM: Sent REQUEST_REPO_BUNDLE for" << repoDisplayName << "to" << getPeerDisplayString(targetPeerSocket)
             << "My path:" << requesterLocalPath;
}

// --- TCP Server --- (startTcpServer, stopTcpServer, getTcpServerPort - same as previous "connection approval" version)
bool NetworkManager::startTcpServer(quint16 port) { /* ... */ 
    if (m_tcpServer->isListening()) { emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening."); return true; }
    if (m_tcpServer->listen(QHostAddress::Any, port)) { qDebug() << "NM: TCP Server started on port" << m_tcpServer->serverPort(); emit tcpServerStatusChanged(true, m_tcpServer->serverPort()); return true;
    } else { qDebug() << "NM: TCP Server failed:" << m_tcpServer->errorString(); emit tcpServerStatusChanged(false, port, m_tcpServer->errorString()); return false; }
}
void NetworkManager::stopTcpServer() { if (m_tcpServer->isListening()) { quint16 p = m_tcpServer->serverPort(); m_tcpServer->close(); qDebug() << "NM: TCP Server stopped."; emit tcpServerStatusChanged(false, p); } }
quint16 NetworkManager::getTcpServerPort() const { if(m_tcpServer && m_tcpServer->isListening()){ return m_tcpServer->serverPort(); } return 0; }


// --- TCP Client --- (connectToTcpPeer, disconnectAllTcpPeers, hasActiveTcpConnections - modified for IdentityManager)
bool NetworkManager::connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerUsername) {
    QTcpSocket* socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);
    socket->setProperty("expected_peer_username", expectedPeerUsername);

    m_socketToPeerUsernameMap.insert(socket, expectedPeerUsername.isEmpty() ? "ConnectingTo<" + hostAddress.toString() + ">" : expectedPeerUsername);
    if(!m_allTcpSockets.contains(socket)) m_allTcpSockets.append(socket); // Add early for tracking attempts

    connect(socket, &QTcpSocket::connected, this, [this, socket]() {
        qDebug() << "NM: TCP socket connected to" << getPeerDisplayString(socket);
        sendIdentityOverTcp(socket);
    });
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "NM: Attempting TCP connection to" << hostAddress.toString() << ":" << port;
    socket->connectToHost(hostAddress, port);
    return true;
}


void NetworkManager::disconnectAllTcpPeers() { /* ... same ... */ QList<QTcpSocket*> s=m_allTcpSockets; for(QTcpSocket* sock : s) if(sock) sock->disconnectFromHost(); }
bool NetworkManager::hasActiveTcpConnections() const { return !m_allTcpSockets.isEmpty(); }


// --- UDP Discovery --- (startUdpDiscovery, stopUdpDiscovery, sendDiscoveryBroadcast, onUdpReadyRead, onBroadcastTimerTimeout, onPeerCleanupTimerTimeout - modified for IdentityManager)
bool NetworkManager::startUdpDiscovery(quint16 udpPort) {
     m_udpDiscoveryPort = udpPort;
    if (!m_identityManager || m_identityManager->getMyPublicKeyHex().empty() || !m_repoManager_ptr) {
        qWarning() << "NM: Cannot start UDP discovery, identity or repo manager not ready.";
        return false;
    }
    if (m_udpSocket->state() == QAbstractSocket::BoundState) { if(!m_broadcastTimer->isActive()) m_broadcastTimer->start(BROADCAST_INTERVAL_MS); return true; }
    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        qDebug() << "NM: UDP Discovery started for" << m_myUsername << "on port" << m_udpDiscoveryPort;
        if(!m_broadcastTimer->isActive()) m_broadcastTimer->start(BROADCAST_INTERVAL_MS); sendDiscoveryBroadcast(); return true;
    } else { qDebug() << "NM: UDP Discovery failed to bind:" << m_udpSocket->errorString(); return false; }
}
void NetworkManager::stopUdpDiscovery() { /* ... same ... */ m_broadcastTimer->stop(); if(m_udpSocket->state()!=QAbstractSocket::UnconnectedState) m_udpSocket->close(); m_discoveredPeers.clear(); }

void NetworkManager::sendDiscoveryBroadcast() {
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myUsername.isEmpty() ||
        !m_identityManager || m_identityManager->getMyPublicKeyHex().empty() || !m_repoManager_ptr) {
        qDebug() << "NM: Cannot send UDP broadcast. Requirements not met (TCP server, Username, PubKey, RepoManager).";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15); // Ensure consistent Qt version for QDataStream

    QString magicHeader = "P2PGIT_DISCOVERY_V3"; // New packet version
    quint16 tcpPort = m_tcpServer->serverPort();
    QString myPublicKeyHex = QString::fromStdString(m_identityManager->getMyPublicKeyHex());

    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclySharedRepositories();
    QList<QString> publicRepoNames;
    for(const auto& repoInfo : publicRepos) {
        publicRepoNames.append(repoInfo.displayName); // Send display names
        // Or send repoInfo.appId if you prefer to use IDs for requests later
    }

    out << magicHeader << m_myUsername << tcpPort << myPublicKeyHex << publicRepoNames; // Added publicRepoNames

    m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    // qDebug() << "NM: Sent UDP V3 broadcast for" << m_myUsername << "PK:" << myPublicKeyHex.left(8) << "Repos:" << publicRepoNames;
}

void NetworkManager::onUdpReadyRead() {
    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(int(m_udpSocket->pendingDatagramSize())); // Cast to int for resize
        QHostAddress senderAddress;
        quint16 senderUdpPort; // Port the UDP packet came from, not their TCP port

        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderUdpPort);

        QDataStream in(&datagram, QIODevice::ReadOnly);
        in.setVersion(QDataStream::Qt_5_15);

        QString magicHeader, receivedUsername, receivedPublicKeyHex;
        quint16 receivedTcpPort;
        QList<QString> receivedPublicRepoNames; // For V3

        in >> magicHeader;
        if (in.status() != QDataStream::Ok) { qDebug() << "NM: UDP - Error reading magic header."; continue; }


        if (magicHeader == "P2PGIT_DISCOVERY_V3") {
            in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex >> receivedPublicRepoNames;
            if (in.status() == QDataStream::Ok && !receivedUsername.isEmpty() && 
                !receivedPublicKeyHex.isEmpty() && receivedUsername != m_myUsername) {
                // qDebug() << "NM: Received UDP V3 from" << receivedUsername << "@" << senderAddress.toString() 
                //          << "TCP:" << receivedTcpPort << "PK:" << receivedPublicKeyHex.left(8) << "Repos:" << receivedPublicRepoNames;
                
                DiscoveredPeerInfo info;
                info.id = receivedUsername;
                info.address = senderAddress;
                info.tcpPort = receivedTcpPort;
                info.publicKeyHex = receivedPublicKeyHex;
                info.publicRepoNames = receivedPublicRepoNames; // Store received repo names
                info.lastSeen = QDateTime::currentMSecsSinceEpoch();

                m_discoveredPeers[receivedUsername] = info;
                emit lanPeerDiscoveredOrUpdated(info);
            } else if (in.status() != QDataStream::Ok) {
                 qDebug() << "NM: Malformed P2PGIT_DISCOVERY_V3 payload from" << senderAddress.toString() << "User:" << receivedUsername;
            } else if (receivedUsername == m_myUsername) {
                // Ignored self-broadcast
            }

        } else if (magicHeader == "P2PGIT_DISCOVERY_V2") { // Backward compatibility for V2
            in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex;
             if (in.status() == QDataStream::Ok && !receivedUsername.isEmpty() && 
                 !receivedPublicKeyHex.isEmpty() && receivedUsername != m_myUsername) {
                // qDebug() << "NM: Received UDP V2 from" << receivedUsername << "@" << senderAddress.toString() << "TCP:" << receivedTcpPort;
                DiscoveredPeerInfo info; info.id = receivedUsername; info.address = senderAddress;
                info.tcpPort = receivedTcpPort; info.publicKeyHex = receivedPublicKeyHex; 
                info.lastSeen = QDateTime::currentMSecsSinceEpoch(); // publicRepoNames will be empty
                m_discoveredPeers[receivedUsername] = info; emit lanPeerDiscoveredOrUpdated(info);
             }
        } else {
            qDebug() << "NM: Ignoring UDP packet from" << senderAddress.toString() << "with unknown magic header:" << magicHeader;
        }
    }
}
void NetworkManager::onBroadcastTimerTimeout() { sendDiscoveryBroadcast(); }
void NetworkManager::onPeerCleanupTimerTimeout() { /* ... same, iterate m_discoveredPeers ... */ qint64 ct=QDateTime::currentMSecsSinceEpoch(); QMutableMapIterator<QString,DiscoveredPeerInfo> i(m_discoveredPeers); while(i.hasNext()){i.next(); if(ct-i.value().lastSeen > PEER_TIMEOUT_MS){emit lanPeerLost(i.key()); i.remove();}}}

// --- TCP Messaging --- (broadcastTcpMessage - same, sendMessageToPeer updated slightly)
void NetworkManager::sendMessageToPeer(QTcpSocket* peerSocket, const QString& message) {
    if (peerSocket && peerSocket->state() == QAbstractSocket::ConnectedState && m_socketToPeerUsernameMap.contains(peerSocket)) {
        QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket);
        // Ensure peerUsername is not an "AwaitingID" or "ConnectingTo" placeholder before sending chat
        if (peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo")) {
            qDebug() << "NM: Cannot send CHAT_MESSAGE to" << getPeerDisplayString(peerSocket) << " - ID handshake not complete."; return;
        }
        qDebug() << "NM: Sending TCP CHAT to" << peerUsername << ":" << message;
        QByteArray block; QDataStream out(&block, QIODevice::WriteOnly); out.setVersion(QDataStream::Qt_5_15);
        QString messageType = "CHAT_MESSAGE"; out << messageType << message; peerSocket->write(block);
    } else { qDebug() << "NM: Cannot send TCP CHAT. Socket not connected or peer username unknown for" << getPeerDisplayString(peerSocket); }
}
void NetworkManager::broadcastTcpMessage(const QString& message) { /* ... same ... */ qDebug()<<"NM: Broadcasting TCP CHAT:"<<message; int sc=0; for(QTcpSocket* s : qAsConst(m_allTcpSockets)){sendMessageToPeer(s,message); sc++;} qDebug()<<"NM: Broadcast CHAT to"<<sc<<"peers.";}


// --- Identity Exchange over TCP --- (sendIdentityOverTcp, processIncomingTcpData modified for public key)
void NetworkManager::sendIdentityOverTcp(QTcpSocket* socket) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager || m_identityManager->getMyPublicKeyHex().empty()) {
        qWarning() << "NM: Cannot send identity - missing username/pubkey, or socket not connected."; return;
    }
    QByteArray block; QDataStream out(&block, QIODevice::WriteOnly); out.setVersion(QDataStream::Qt_5_15);
    QString messageType = "IDENTITY_HANDSHAKE_V2";
    QString myPublicKeyHex = QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    out << messageType << m_myUsername << myPublicKeyHex;
    socket->write(block);
    qDebug() << "NM: Sent IDENTITY_HANDSHAKE_V2 with ID" << m_myUsername << "and PubKey(prefix):" << myPublicKeyHex.left(8) << "to" << getPeerDisplayString(socket);
}

void NetworkManager::processIncomingTcpData(QTcpSocket* socket, const QByteArray& rawData) {
    QDataStream in(rawData); in.setVersion(QDataStream::Qt_5_15);
    while(!in.atEnd()){
        qint64 startPos = in.device()->pos(); QString messageType; in >> messageType;
        if (in.status() != QDataStream::Ok && in.atEnd()) { /* partial type */ qDebug() << "NM: Partial TCP type from" << getPeerDisplayString(socket); return; }

        if (messageType == "IDENTITY_HANDSHAKE_V2") {
            QString receivedPeerUsername, receivedPublicKeyHex;
            in >> receivedPeerUsername >> receivedPublicKeyHex;
            if (in.status() == QDataStream::Ok && !receivedPeerUsername.isEmpty() && !receivedPublicKeyHex.isEmpty()) {
                //QString oldUsername = m_socketToPeerUsernameMap.value(socket, "");
                m_socketToPeerUsernameMap.insert(socket, receivedPeerUsername);
                m_peerPublicKeys.insert(receivedPeerUsername, receivedPublicKeyHex);
                qDebug() << "NM: Received IDENTITY_HANDSHAKE_V2 from" << getPeerDisplayString(socket) << "ID:" << receivedPeerUsername << "PK:" << receivedPublicKeyHex.left(8);
                
                bool wasOutgoing = socket->property("is_outgoing_attempt").toBool();
                if (wasOutgoing) {
                    emit tcpConnectionStatusChanged(receivedPeerUsername, receivedPublicKeyHex, true, "");
                    socket->setProperty("is_outgoing_attempt", false); 
                }
                emit newTcpPeerConnected(socket, receivedPeerUsername, receivedPublicKeyHex);
            } else { qDebug() << "NM: Invalid IDENTITY_HANDSHAKE_V2 payload from" << getPeerDisplayString(socket); socket->disconnectFromHost(); return; }
        } else if (messageType == "CHAT_MESSAGE") {
            QString chatMessage; in >> chatMessage;
            if (in.status() == QDataStream::Ok) {
                QString senderUsername = m_socketToPeerUsernameMap.value(socket, "UnknownPeer");
                emit tcpMessageReceived(socket, senderUsername, chatMessage);
            } 
             else if (messageType == "REQUEST_REPO_BUNDLE") {
            QString requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath;
            in >> requestingPeerUsername >> requestedRepoDisplayName >> requesterLocalPath;

            if (in.status() == QDataStream::Ok && !requestingPeerUsername.isEmpty() && !requestedRepoDisplayName.isEmpty()) {
                qDebug() << "NM: Received REQUEST_REPO_BUNDLE from" << requestingPeerUsername
                         << "for repo" << requestedRepoDisplayName << "(they want to save at " << requesterLocalPath << ")";
                
                // Emit signal for MainWindow (Provider side) to handle this request
                // (i.e., check if repo is public, then call GitBackend to create bundle)
                emit repoBundleRequestedByPeer(socket, requestingPeerUsername, requestedRepoDisplayName, requesterLocalPath);

            } else {
                qWarning() << "NM: Malformed REQUEST_REPO_BUNDLE from" << getPeerDisplayString(socket);
                // Optionally send an error back to the requester
            }
        }
            else { qDebug() << "NM: Invalid CHAT_MESSAGE payload from" << getPeerDisplayString(socket); in.device()->seek(startPos); return; }
        } else { qDebug() << "NM: Unknown TCP type:" << messageType << "from" << getPeerDisplayString(socket); return; }
    }
}

// --- TCP Connection Approval Slots & Helpers ---
void NetworkManager::onNewTcpConnection() { // MODIFIED
    while (m_tcpServer->hasPendingConnections()) {
        QTcpSocket *pendingSocket = m_tcpServer->nextPendingConnection();
        if (pendingSocket) {
            QString pendingPeerAddr = pendingSocket->peerAddress().toString();
            quint16 pendingPeerPort = pendingSocket->peerPort();
            qDebug() << "NM: Incoming TCP request from:" << pendingPeerAddr << ":" << pendingPeerPort;

            // Try to find username from discovered peers based on IP (simple match)
            QString discoveredUsername = "Unknown (" + pendingPeerAddr + ")";
            for(const auto& peerInfo : qAsConst(m_discoveredPeers)){
                if(peerInfo.address == pendingSocket->peerAddress() /*&& peerInfo.tcpPort could be different if re-listened*/ ){
                     // A better match would be if UDP discovery packet also included a temporary connection nonce
                     // that the TCP connection could then present. For now, IP is a weak link.
                     // If multiple discovered peers from same IP, this picks the first one.
                    discoveredUsername = peerInfo.id;
                    break;
                }
            }

            QTimer *timeoutTimer = new QTimer(this); timeoutTimer->setSingleShot(true);
            connect(timeoutTimer, &QTimer::timeout, this, [this, pendingSocket, timeoutTimer]() {
                if (m_pendingConnections.contains(pendingSocket)) { 
                    qDebug() << "NM: Pending connection from" << getPeerDisplayString(pendingSocket) << "timed out. Rejecting.";
                    rejectPendingTcpConnection(pendingSocket); 
                } // Timer auto-deletes if owned by `this` and `deleteLater` is called on `this` (NetworkManager)
                  // Or manually delete it here if it's not parented, or if `this` lives longer.
                  // For now, rejectPendingTcpConnection will delete it.
            });
            timeoutTimer->start(PENDING_CONNECTION_TIMEOUT_MS);
            m_pendingConnections.insert(pendingSocket, timeoutTimer);
            emit incomingTcpConnectionRequest(pendingSocket, pendingSocket->peerAddress(), pendingSocket->peerPort(), discoveredUsername);
        }
    }
}

void NetworkManager::setupAcceptedSocket(QTcpSocket* socket) { // Helper
    if (!m_allTcpSockets.contains(socket)) { m_allTcpSockets.append(socket); }
    m_socketToPeerUsernameMap.insert(socket, "AwaitingID_Incoming"); // Temp ID
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
    qDebug() << "NM: Accepted & set up TCP connection from:" << getPeerDisplayString(socket);
    sendIdentityOverTcp(socket); // Send our ID and PubKey
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket* pendingSocket) {
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) { timer->stop(); delete timer; }
        m_pendingConnections.remove(pendingSocket);
        setupAcceptedSocket(pendingSocket);
    } else { /* ... logging for unknown socket ... */ }
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket* pendingSocket) {
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) { timer->stop(); delete timer; }
        m_pendingConnections.remove(pendingSocket);
        qDebug() << "NM: Rejecting incoming connection from" << getPeerDisplayString(pendingSocket);
        pendingSocket->disconnectFromHost(); pendingSocket->deleteLater();
    } else { /* ... logging for unknown socket ... */ }
}
// onPendingConnectionTimeout can be empty as lambda handles it.

// --- Other TCP Slots (onTcpSocketStateChanged, onTcpSocketDisconnected, onTcpSocketError) ---
void NetworkManager::onTcpSocketReadyRead() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    
    // For QDataStream based protocol, we often read all available data and
    // then try to parse one or more messages from the buffer.
    // A more robust method would involve a buffer per socket if messages can be fragmented
    // across multiple readyRead signals, or a length-prefix for each message.
    // For this stage, we assume a full QDataStream block is often available or can be pieced together.

    QByteArray buffer;
    // It's possible readyRead is emitted multiple times for one logical "message"
    // or one readyRead contains multiple messages.
    // A simple approach is to read all currently available data.
    if (socket->bytesAvailable() > 0) {
        buffer = socket->readAll(); // Read all that's currently in the socket's internal buffer
    }

    if (!buffer.isEmpty()) {
        // Pass the accumulated buffer to the processing function
        processIncomingTcpData(socket, buffer);
    } else {
        // This can happen if readyRead is emitted but then the data is consumed by another read elsewhere
        // or if it's an empty signal for some reason.
        qDebug() << "NetworkManager: onTcpSocketReadyRead called for" << getPeerDisplayString(socket) << "but no new bytes available at the moment of readAll().";
    }
}
void NetworkManager::onTcpSocketStateChanged(QAbstractSocket::SocketState socketState) { /* ... same, but use getPeerDisplayString ... */ QTcpSocket* s=qobject_cast<QTcpSocket*>(sender()); if(!s)return; qDebug()<<"NM: TCP State for"<<getPeerDisplayString(s)<<"is"<<socketState;}
void NetworkManager::onTcpSocketDisconnected() { // MODIFIED
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender()); if (!socket) return;
    if (m_pendingConnections.contains(socket)) {
        qDebug() << "NM: Pending connection" << getPeerDisplayString(socket) << "disconnected prematurely.";
        QTimer* timer = m_pendingConnections.value(socket); if (timer) { timer->stop(); delete timer; }
        m_pendingConnections.remove(socket); socket->deleteLater(); return; 
    }
    QString peerUsername = m_socketToPeerUsernameMap.value(socket, getPeerDisplayString(socket));
    qDebug() << "NM: TCP Peer disconnected:" << peerUsername;
    emit tcpPeerDisconnected(socket, peerUsername); // Use username
    m_socketToPeerUsernameMap.remove(socket);
    m_peerPublicKeys.remove(peerUsername); // Remove their public key too
    m_allTcpSockets.removeAll(socket);
    socket->deleteLater();
}
void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError) { // MODIFIED
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender()); if (!socket) return;
    QString errorStr = socket->errorString();
    QString peerUsernameOrAddr = m_socketToPeerUsernameMap.value(socket, getPeerDisplayString(socket));
    bool wasOutgoing = socket->property("is_outgoing_attempt").toBool();
    if (wasOutgoing && socket->state() != QAbstractSocket::ConnectedState) {
        QString expectedId = socket->property("expected_peer_username").toString();
        if (expectedId.isEmpty()) expectedId = getPeerDisplayString(socket);
        qDebug() << "NM: TCP Socket conn error for outgoing to" << expectedId << ":" << socketError << "-" << errorStr;
        emit tcpConnectionStatusChanged(expectedId, "", false, errorStr); // No pubkey if conn failed
        m_allTcpSockets.removeAll(socket); m_socketToPeerUsernameMap.remove(socket); socket->deleteLater();
    } else {
        qDebug() << "NM: TCP Socket error on established conn with" << peerUsernameOrAddr << ":" << socketError << "-" << errorStr;
    }
}