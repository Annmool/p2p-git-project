#include "network_manager.h"
#include <QNetworkInterface>
#include <QDataStream> // For serializing/deserializing discovery packets
#include <QDateTime>   // For timestamps
#include <QDebug>

const qint64 PEER_TIMEOUT_MS = 15000; // 15 seconds before a discovered peer is considered lost
const int BROADCAST_INTERVAL_MS = 5000; // Broadcast every 5 seconds
const int PENDING_CONNECTION_TIMEOUT_MS = 30000; // 30 seconds to accept/reject

NetworkManager::NetworkManager(QObject *parent) : QObject(parent) {
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
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2); // Check for stale peers periodically
}

NetworkManager::~NetworkManager() {
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers(); 
}

QString NetworkManager::getPeerIdentifierForSocket(QTcpSocket* socket) {
    if (!socket) return "InvalidSocket";
    if (m_socketToPeerIdMap.contains(socket) && !m_socketToPeerIdMap.value(socket).startsWith("AwaitingID") && !m_socketToPeerIdMap.value(socket).startsWith("Connecting")) {
        return m_socketToPeerIdMap[socket] + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
    }
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

// --- TCP Server Methods ---
bool NetworkManager::startTcpServer(quint16 port) {
    if (m_tcpServer->isListening()) {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        return true;
    }
    if (m_tcpServer->listen(QHostAddress::Any, port)) { 
        qDebug() << "NetworkManager: TCP Server started on port" << m_tcpServer->serverPort();
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort());
        return true;
    } else {
        qDebug() << "NetworkManager: TCP Server failed to start:" << m_tcpServer->errorString();
        emit tcpServerStatusChanged(false, port, m_tcpServer->errorString());
        return false;
    }
}

void NetworkManager::stopTcpServer() {
    if (m_tcpServer->isListening()) {
        quint16 port = m_tcpServer->serverPort();
        m_tcpServer->close();
        qDebug() << "NetworkManager: TCP Server stopped.";
        emit tcpServerStatusChanged(false, port);
    }
}

quint16 NetworkManager::getTcpServerPort() const {
    if(m_tcpServer && m_tcpServer->isListening()){
        return m_tcpServer->serverPort();
    }
    return 0;
}

// --- TCP Client Methods ---
bool NetworkManager::connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerId) {
    QTcpSocket* socket = new QTcpSocket(this);
    // Don't add to m_allTcpSockets yet, only after connection and ID handshake for outgoing.
    // Or add and mark as "attempting connection"
    socket->setProperty("is_outgoing_attempt", true);
    socket->setProperty("expected_peer_id", expectedPeerId); // Store expected ID for status changes

    m_socketToPeerIdMap.insert(socket, expectedPeerId.isEmpty() ? "ConnectingTo<" + hostAddress.toString() + ">" : expectedPeerId);


    connect(socket, &QTcpSocket::connected, this, [this, socket]() {
        qDebug() << "NetworkManager: TCP socket connected to" << getPeerIdentifierForSocket(socket);
        // Now it's connected, add to the main list and send identity
        if(!m_allTcpSockets.contains(socket)) m_allTcpSockets.append(socket); 
        sendIdentityOverTcp(socket); 
        // tcpConnectionStatusChanged will be emitted after ID handshake for outgoing
    });
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "NetworkManager: Attempting TCP connection to" << hostAddress.toString() << ":" << port;
    socket->connectToHost(hostAddress, port);
    return true;
}

void NetworkManager::disconnectFromTcpPeer(QTcpSocket* peerSocket) {
    if (peerSocket) {
        qDebug() << "NetworkManager: Requesting TCP disconnect from" << getPeerIdentifierForSocket(peerSocket);
        peerSocket->disconnectFromHost();
    }
}

void NetworkManager::disconnectAllTcpPeers() {
    qDebug() << "NetworkManager: Disconnecting all TCP peers.";
    QList<QTcpSocket*> socketsToClose = m_allTcpSockets; 
    for (QTcpSocket* socket : socketsToClose) {
        if (socket) socket->disconnectFromHost();
    }
}

bool NetworkManager::hasActiveTcpConnections() const {
    return !m_allTcpSockets.isEmpty();
}

// --- UDP Discovery Methods ---
bool NetworkManager::startUdpDiscovery(quint16 udpPort, const QString& myPeerId) {
    m_myPeerIdForTcp = myPeerId; 
    m_udpDiscoveryPort = udpPort;

    if (m_udpSocket->state() == QAbstractSocket::BoundState) { 
        qDebug() << "NetworkManager: UDP Discovery already active on port" << m_udpSocket->localPort();
        if(!m_broadcastTimer->isActive()) m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        return true;
    }

    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        qDebug() << "NetworkManager: UDP Discovery started, listening on port" << m_udpDiscoveryPort;
        m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast(); 
        return true;
    } else {
        qDebug() << "NetworkManager: UDP Discovery failed to bind to port" << m_udpDiscoveryPort << ":" << m_udpSocket->errorString();
        return false;
    }
}

void NetworkManager::stopUdpDiscovery() {
    m_broadcastTimer->stop();
    if (m_udpSocket->state() != QAbstractSocket::UnconnectedState) {
        m_udpSocket->close();
        qDebug() << "NetworkManager: UDP Discovery stopped.";
    }
    m_discoveredPeers.clear(); 
}

void NetworkManager::sendDiscoveryBroadcast() {
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myPeerIdForTcp.isEmpty()) {
        qDebug() << "NetworkManager: Cannot send discovery broadcast. TCP server not listening or MyPeerID not set.";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15); 
    QString magicHeader = "P2PGIT_DISCOVERY";
    quint16 tcpPort = m_tcpServer->serverPort();
    out << magicHeader << m_myPeerIdForTcp << tcpPort;

    qint64 bytesSent = m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    if (bytesSent == -1) {
        qDebug() << "NetworkManager: Failed to send discovery broadcast:" << m_udpSocket->errorString();
    } else {
        // qDebug() << "NetworkManager: Sent discovery broadcast for ID" << m_myPeerIdForTcp << "on TCP port" << tcpPort; // Can be noisy
    }
}

// --- TCP Messaging ---
void NetworkManager::sendMessageToPeer(QTcpSocket* peerSocket, const QString& message) {
    if (peerSocket && peerSocket->state() == QAbstractSocket::ConnectedState && m_socketToPeerIdMap.contains(peerSocket)) {
        QString peerId = m_socketToPeerIdMap.value(peerSocket, "Unknown");
        qDebug() << "NetworkManager: Sending TCP message to" << peerId << ":" << message;
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        QString messageType = "CHAT_MESSAGE";
        out << messageType << message;
        peerSocket->write(block);
    } else {
        qDebug() << "NetworkManager: Cannot send TCP message. Socket not connected or peer ID unknown for" << getPeerIdentifierForSocket(peerSocket);
    }
}

void NetworkManager::broadcastTcpMessage(const QString& message) {
    qDebug() << "NetworkManager: Broadcasting TCP message:" << message;
    int sentCount = 0;
    for (QTcpSocket* socket : qAsConst(m_allTcpSockets)) {
        // Ensure the peer ID is known (handshake completed) before sending chat messages
        if (m_socketToPeerIdMap.contains(socket) && 
            !m_socketToPeerIdMap.value(socket).startsWith("AwaitingID") &&
            !m_socketToPeerIdMap.value(socket).startsWith("ConnectingTo")) {
            sendMessageToPeer(socket, message);
            sentCount++;
        }
    }
    qDebug() << "NetworkManager: Broadcast sent to" << sentCount << "peers.";
}

// --- Identity Exchange ---
void NetworkManager::sendIdentityOverTcp(QTcpSocket* socket) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myPeerIdForTcp.isEmpty()) {
        return;
    }
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    QString messageType = "IDENTITY_HANDSHAKE";
    out << messageType << m_myPeerIdForTcp;
    socket->write(block);
    qDebug() << "NetworkManager: Sent IDENTITY_HANDSHAKE with ID" << m_myPeerIdForTcp << "to" << getPeerIdentifierForSocket(socket);
}

void NetworkManager::processIncomingTcpData(QTcpSocket* socket, const QByteArray& rawData) {
    QDataStream in(rawData);
    in.setVersion(QDataStream::Qt_5_15);

    while(!in.atEnd()){ // Process multiple messages if they were buffered together
        // Store start position in case of partial read for complex types
        qint64 startPos = in.device()->pos();
        QString messageType;
        in >> messageType;

        if (in.status() != QDataStream::Ok && in.atEnd()) { // Could be partial messageType
             in.device()->seek(startPos); // Rewind
             // Here you'd buffer this partial data and wait for more. For now, we'll log.
             qDebug() << "NetworkManager: Partial TCP messageType received from" << getPeerIdentifierForSocket(socket);
             return; 
        }


        if (messageType == "IDENTITY_HANDSHAKE") {
            QString receivedPeerId;
            in >> receivedPeerId;
            if (in.status() == QDataStream::Ok && !receivedPeerId.isEmpty()) {
                QString oldId = m_socketToPeerIdMap.value(socket, "");
                m_socketToPeerIdMap.insert(socket, receivedPeerId);
                qDebug() << "NetworkManager: Received IDENTITY_HANDSHAKE from" << getPeerIdentifierForSocket(socket) << "ID:" << receivedPeerId;
                
                bool wasOutgoing = socket->property("is_outgoing_attempt").toBool();
                if (wasOutgoing) {
                    emit tcpConnectionStatusChanged(receivedPeerId, true, ""); // For the initiator
                    socket->setProperty("is_outgoing_attempt", false); 
                }
                // Always emit newTcpPeerConnected once ID is established
                emit newTcpPeerConnected(socket, receivedPeerId);

            } else { // QDataStream error or empty ID
                qDebug() << "NetworkManager: Invalid IDENTITY_HANDSHAKE (payload error or empty ID) from" << getPeerIdentifierForSocket(socket) << "Status:" << in.status();
                socket->disconnectFromHost();
                return; // Stop processing this stream
            }
        } else if (messageType == "CHAT_MESSAGE") {
            QString chatMessage;
            in >> chatMessage;
            if (in.status() == QDataStream::Ok) {
                QString senderId = m_socketToPeerIdMap.value(socket, "UnknownPeer");
                qDebug() << "NetworkManager: CHAT_MESSAGE from" << senderId << ":" << chatMessage;
                emit tcpMessageReceived(socket, senderId, chatMessage);
            } else {
                qDebug() << "NetworkManager: Invalid CHAT_MESSAGE payload from" << getPeerIdentifierForSocket(socket);
                in.device()->seek(startPos); // Rewind if payload was bad
                return; // Stop processing
            }
        } else {
            qDebug() << "NetworkManager: Unknown TCP message type received:" << messageType << "from" << getPeerIdentifierForSocket(socket);
            // To be robust, you might want to try and skip this unknown message if possible,
            // or disconnect if the protocol is strict. For now, we stop processing this stream.
            return;
        }
    }
}

// --- TCP SLOTS ---
void NetworkManager::onNewTcpConnection() { // MODIFIED FOR CONNECTION APPROVAL
    while (m_tcpServer->hasPendingConnections()) {
        QTcpSocket *pendingSocket = m_tcpServer->nextPendingConnection();
        if (pendingSocket) {
            qDebug() << "NetworkManager: Incoming TCP connection request from:"
                     << pendingSocket->peerAddress().toString() << ":" << pendingSocket->peerPort();

            QTimer *timeoutTimer = new QTimer(this);
            timeoutTimer->setSingleShot(true);
            connect(timeoutTimer, &QTimer::timeout, this, [this, pendingSocket, timeoutTimer]() {
                if (m_pendingConnections.contains(pendingSocket)) { 
                    qDebug() << "NetworkManager: Pending connection from" 
                             << getPeerIdentifierForSocket(pendingSocket) << "timed out. Rejecting.";
                    rejectPendingTcpConnection(pendingSocket); 
                }
            });
            timeoutTimer->start(PENDING_CONNECTION_TIMEOUT_MS);
            m_pendingConnections.insert(pendingSocket, timeoutTimer);

            emit incomingTcpConnectionRequest(pendingSocket, pendingSocket->peerAddress(), pendingSocket->peerPort());
        }
    }
}

void NetworkManager::setupAcceptedSocket(QTcpSocket* socket) { // NEW HELPER
    if (!m_allTcpSockets.contains(socket)) { // Ensure not added multiple times
        m_allTcpSockets.append(socket);
    }
    m_socketToPeerIdMap.insert(socket, "AwaitingID_Incoming");

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "NetworkManager: Accepted and set up TCP connection from:" << getPeerIdentifierForSocket(socket);
    sendIdentityOverTcp(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket* pendingSocket) { // NEW
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) {
            timer->stop();
            delete timer;
        }
        m_pendingConnections.remove(pendingSocket);
        setupAcceptedSocket(pendingSocket);
    } else {
        qDebug() << "NetworkManager: acceptPending called for unknown/handled socket:" << getPeerIdentifierForSocket(pendingSocket);
        if(pendingSocket && pendingSocket->state() == QAbstractSocket::ConnectedState && !m_allTcpSockets.contains(pendingSocket)){
            pendingSocket->disconnectFromHost(); pendingSocket->deleteLater();
        }
    }
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket* pendingSocket) { // NEW
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) {
            timer->stop(); delete timer;
        }
        m_pendingConnections.remove(pendingSocket);
        qDebug() << "NetworkManager: Rejecting incoming connection from" << getPeerIdentifierForSocket(pendingSocket);
        pendingSocket->disconnectFromHost(); pendingSocket->deleteLater();
    } else {
        qDebug() << "NetworkManager: rejectPending called for unknown/handled socket:" << getPeerIdentifierForSocket(pendingSocket);
        if(pendingSocket && pendingSocket->state() == QAbstractSocket::ConnectedState && !m_allTcpSockets.contains(pendingSocket)){
            pendingSocket->disconnectFromHost(); pendingSocket->deleteLater();
        }
    }
}

void NetworkManager::onPendingConnectionTimeout() { // NEW (Empty, logic in lambda)
    qDebug() << "NetworkManager: onPendingConnectionTimeout slot called (MOC satisfaction)";
}

void NetworkManager::onTcpSocketStateChanged(QAbstractSocket::SocketState socketState) {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    qDebug() << "NetworkManager: TCP Socket state for" << getPeerIdentifierForSocket(socket) << "is" << socketState;
}

void NetworkManager::onTcpSocketReadyRead() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    
    // Basic framing: Assume QDataStream writes a complete logical message.
    // A more robust approach would involve sending message sizes first.
    // Here, we just append to a buffer and try to process.
    // This part needs to be more robust for real-world partial sends.
    // For now, we assume that if readyRead is emitted, a full QDataStream block is available.
    // This is a simplification.
    QByteArray buffer;
    while(socket->bytesAvailable() > 0){ // Read everything available now
        buffer.append(socket->readAll());
    }
    if(!buffer.isEmpty()){
        processIncomingTcpData(socket, buffer);
    } else {
        qDebug() << "NetworkManager: onTcpSocketReadyRead but no bytes available for" << getPeerIdentifierForSocket(socket);
    }
}

void NetworkManager::onTcpSocketDisconnected() { // MODIFIED
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    if (m_pendingConnections.contains(socket)) {
        qDebug() << "NetworkManager: Pending connection" << getPeerIdentifierForSocket(socket) << "disconnected prematurely.";
        QTimer* timer = m_pendingConnections.value(socket);
        if (timer) { timer->stop(); delete timer; }
        m_pendingConnections.remove(socket);
        socket->deleteLater(); 
        return; 
    }

    QString peerId = m_socketToPeerIdMap.value(socket, getPeerIdentifierForSocket(socket));
    qDebug() << "NetworkManager: TCP Peer disconnected:" << peerId;

    emit tcpPeerDisconnected(socket, peerId);

    m_socketToPeerIdMap.remove(socket);
    m_allTcpSockets.removeAll(socket);

    socket->deleteLater();
}

void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError) {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QString errorString = socket->errorString();
    QString peerId = m_socketToPeerIdMap.value(socket, getPeerIdentifierForSocket(socket)); // Use known ID or address:port
    
    // If it was an outgoing connection attempt and it's not yet connected
    bool wasOutgoingAttempt = socket->property("is_outgoing_attempt").toBool();
    if (wasOutgoingAttempt && socket->state() != QAbstractSocket::ConnectedState) {
        QString expectedId = socket->property("expected_peer_id").toString();
        if (expectedId.isEmpty()) expectedId = getPeerIdentifierForSocket(socket); // Fallback to IP:Port
        qDebug() << "NetworkManager: TCP Socket connection error for outgoing attempt to" << expectedId << ":" << socketError << "-" << errorString;
        emit tcpConnectionStatusChanged(expectedId, false, errorString);
        // Socket will likely be disconnected by Qt, onTcpSocketDisconnected will clean up lists.
        // We might remove it from m_allTcpSockets here too if it was added prematurely.
        m_allTcpSockets.removeAll(socket);
        m_socketToPeerIdMap.remove(socket);
        socket->deleteLater(); // Clean up the failed outgoing socket
    } else {
        qDebug() << "NetworkManager: TCP Socket error on established connection with" << peerId << ":" << socketError << "-" << errorString;
        // For established connections, disconnection event will handle cleanup.
        // You might emit a different signal here if needed: peerCommunicationError(peerId, errorString);
    }
}

// --- UDP SLOTS --- (Same as before)
void NetworkManager::onUdpReadyRead() { /* ... same as previous full version ... */ 
    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram; datagram.resize(m_udpSocket->pendingDatagramSize()); QHostAddress senderAddress; quint16 senderPort;
        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort);
        QDataStream in(&datagram, QIODevice::ReadOnly); in.setVersion(QDataStream::Qt_5_15);
        QString magicHeader, receivedPeerId; quint16 receivedTcpPort;
        in >> magicHeader >> receivedPeerId >> receivedTcpPort;
        if (in.status() == QDataStream::Ok && magicHeader == "P2PGIT_DISCOVERY" && !receivedPeerId.isEmpty() && receivedPeerId != m_myPeerIdForTcp) {
            DiscoveredPeerInfo info; info.id = receivedPeerId; info.address = senderAddress; info.tcpPort = receivedTcpPort; info.lastSeen = QDateTime::currentMSecsSinceEpoch();
            m_discoveredPeers[receivedPeerId] = info; emit lanPeerDiscoveredOrUpdated(info);
        } else if (magicHeader != "P2PGIT_DISCOVERY" && receivedPeerId != m_myPeerIdForTcp) { /* Ignore self or bad magic */ }
        else if (in.status() != QDataStream::Ok){ qDebug() << "NetworkManager: Malformed UDP from " << senderAddress.toString(); }
    }
}
void NetworkManager::onBroadcastTimerTimeout() { sendDiscoveryBroadcast(); }
void NetworkManager::onPeerCleanupTimerTimeout() { /* ... same as previous full version ... */
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch(); QMutableMapIterator<QString, DiscoveredPeerInfo> i(m_discoveredPeers);
    while (i.hasNext()) { i.next(); if (currentTime - i.value().lastSeen > PEER_TIMEOUT_MS) { emit lanPeerLost(i.key()); i.remove();}}}
