#include "network_manager.h"
#include <QNetworkInterface>
#include <QDataStream> // For serializing/deserializing discovery packets
#include <QDateTime>   // For timestamps
#include <QDebug>

const qint64 PEER_TIMEOUT_MS = 15000; // 15 seconds before a discovered peer is considered lost
const int BROADCAST_INTERVAL_MS = 5000; // Broadcast every 5 seconds

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
    disconnectAllTcpPeers(); // Should be handled by stopTcpServer and socket disconnections
}

QString NetworkManager::getPeerIdentifierForSocket(QTcpSocket* socket) {
    if (!socket) return "InvalidSocket";
    if (m_socketToPeerIdMap.contains(socket)) {
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
    if (m_tcpServer->listen(QHostAddress::Any, port)) { // OS picks port if port is 0
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
        // Sockets connected to our server will be closed by iterating m_allTcpSockets.
        // No need to iterate m_connectedClients (which is now part of m_allTcpSockets conceptually)
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
    m_allTcpSockets.append(socket); // Add to master list immediately
    // Store expected ID temporarily, will be confirmed by handshake
    m_socketToPeerIdMap.insert(socket, expectedPeerId.isEmpty() ? "Connecting..." : expectedPeerId);


    connect(socket, &QTcpSocket::connected, this, [this, socket]() {
        qDebug() << "NetworkManager: TCP socket connected to" << getPeerIdentifierForSocket(socket);
        sendIdentityOverTcp(socket); // Send our ID upon connection
        // We don't emit newTcpPeerConnected yet; wait for ID exchange confirmation
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
    QList<QTcpSocket*> socketsToClose = m_allTcpSockets; // Iterate over a copy
    for (QTcpSocket* socket : socketsToClose) {
        if (socket) socket->disconnectFromHost();
    }
    // m_allTcpSockets will be cleared by onTcpSocketDisconnected
}

// --- UDP Discovery Methods ---
bool NetworkManager::startUdpDiscovery(quint16 udpPort, const QString& myPeerId) {
    m_myPeerIdForTcp = myPeerId; // Store our ID for TCP handshakes and UDP broadcasts
    m_udpDiscoveryPort = udpPort;

    if (m_udpSocket->state() == QAbstractSocket::BoundState) { // Already listening
        qDebug() << "NetworkManager: UDP Discovery already active on port" << m_udpSocket->localPort();
        m_broadcastTimer->start(BROADCAST_INTERVAL_MS); // Ensure timer is running
        return true;
    }

    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        qDebug() << "NetworkManager: UDP Discovery started, listening on port" << m_udpDiscoveryPort;
        m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast(); // Send initial broadcast
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
    m_discoveredPeers.clear(); // Clear discovered peers when stopping discovery
}

void NetworkManager::sendDiscoveryBroadcast() {
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myPeerIdForTcp.isEmpty()) {
        qDebug() << "NetworkManager: Cannot send discovery broadcast. TCP server not listening or MyPeerID not set.";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15); // Or your Qt version

    // Simple packet: "P2PGIT_DISCOVERY" <OurPeerID> <OurTcpPort>
    QString magicHeader = "P2PGIT_DISCOVERY";
    quint16 tcpPort = m_tcpServer->serverPort();

    out << magicHeader << m_myPeerIdForTcp << tcpPort;

    qint64 bytesSent = m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    if (bytesSent == -1) {
        qDebug() << "NetworkManager: Failed to send discovery broadcast:" << m_udpSocket->errorString();
    } else {
        qDebug() << "NetworkManager: Sent discovery broadcast (" << bytesSent << "bytes) for ID" << m_myPeerIdForTcp << "on TCP port" << tcpPort;
    }
}

// --- TCP Messaging ---
void NetworkManager::sendMessageToPeer(QTcpSocket* peerSocket, const QString& message) {
    if (peerSocket && peerSocket->state() == QAbstractSocket::ConnectedState && m_socketToPeerIdMap.contains(peerSocket)) {
        QString peerId = m_socketToPeerIdMap.value(peerSocket, "Unknown");
        qDebug() << "NetworkManager: Sending TCP message to" << peerId << ":" << message;
        // Simple protocol: Type (QString) then Payload (QString)
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        QString messageType = "CHAT_MESSAGE";
        out << messageType << message;
        peerSocket->write(block);
    } else {
        qDebug() << "NetworkManager: Cannot send TCP message. Socket not connected or peer ID unknown.";
    }
}

void NetworkManager::broadcastTcpMessage(const QString& message) {
    qDebug() << "NetworkManager: Broadcasting TCP message:" << message;
    for (QTcpSocket* socket : qAsConst(m_allTcpSockets)) {
        sendMessageToPeer(socket, message);
    }
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
    // This needs a more robust way to handle partial messages if QDataStream is used directly on socket.
    // For simplicity, assume whole QDataStream blocks are received.
    // In a real app, you'd buffer and check for complete "packets".
    // A common way is to first send the size of the upcoming block.

    QDataStream in(rawData);
    in.setVersion(QDataStream::Qt_5_15);

    if (in.atEnd()) return;
    QString messageType;
    in >> messageType;

    if (messageType == "IDENTITY_HANDSHAKE") {
        QString receivedPeerId;
        in >> receivedPeerId;
        if (in.status() == QDataStream::Ok && !receivedPeerId.isEmpty()) {
            QString oldId = m_socketToPeerIdMap.value(socket, "");
            m_socketToPeerIdMap.insert(socket, receivedPeerId); // Update/confirm peer ID
            qDebug() << "NetworkManager: Received IDENTITY_HANDSHAKE from" << getPeerIdentifierForSocket(socket) << "ID:" << receivedPeerId;
            
            // If this is the first time we're getting an ID for this socket, or it changed.
            // This is where we formally announce the peer is fully connected with an ID.
            if (oldId.isEmpty() || oldId == "Connecting..." || oldId != receivedPeerId) {
                 emit newTcpPeerConnected(socket, receivedPeerId);
            }
            // If it was an outgoing connection we initiated, confirm its status
            if(socket->property("is_outgoing_attempt").toBool()){
                emit tcpConnectionStatusChanged(receivedPeerId, true, "");
                socket->setProperty("is_outgoing_attempt", false); // Clear the flag
            }


        } else {
            qDebug() << "NetworkManager: Invalid IDENTITY_HANDSHAKE received or empty peer ID from" << getPeerIdentifierForSocket(socket);
            socket->disconnectFromHost(); // Invalid handshake
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
        }
    } else {
        qDebug() << "NetworkManager: Unknown TCP message type received:" << messageType << "from" << getPeerIdentifierForSocket(socket);
    }
}


// --- TCP SLOTS ---
void NetworkManager::onNewTcpConnection() {
    while (m_tcpServer->hasPendingConnections()) {
        QTcpSocket *clientSocket = m_tcpServer->nextPendingConnection();
        if (clientSocket) {
            m_allTcpSockets.append(clientSocket);
            m_socketToPeerIdMap.insert(clientSocket, "AwaitingID"); // Mark as needing ID handshake
            connect(clientSocket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(clientSocket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(clientSocket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
            connect(clientSocket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
            qDebug() << "NetworkManager: New incoming TCP connection from:" << getPeerIdentifierForSocket(clientSocket);
            sendIdentityOverTcp(clientSocket); // Server also sends its ID
        }
    }
}

void NetworkManager::onTcpSocketStateChanged(QAbstractSocket::SocketState socketState) {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    qDebug() << "NetworkManager: TCP Socket state changed for" << getPeerIdentifierForSocket(socket) << "to" << socketState;
    // Additional logic can be added here, e.g., if state becomes UnconnectedState
}

void NetworkManager::onTcpSocketReadyRead() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    // For QDataStream, it's tricky as it doesn't have a natural "canReadLine" for complex objects.
    // We read all available data and try to process it.
    // A more robust solution uses a 2-phase read: 1. Read size of block. 2. Read block data.
    // For simplicity here, we assume QDataStream blocks are small enough or handled by Qt's buffering.
    QByteArray buffer = socket->readAll();
    processIncomingTcpData(socket, buffer);
}

void NetworkManager::onTcpSocketDisconnected() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    QString peerId = m_socketToPeerIdMap.value(socket, getPeerIdentifierForSocket(socket)); // Use known ID if available
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
    QString peerId = m_socketToPeerIdMap.value(socket, getPeerIdentifierForSocket(socket));
    qDebug() << "NetworkManager: TCP Socket error on" << peerId << ":" << socketError << "-" << errorString;

    // If it was an outgoing connection attempt that failed
    if (socket->property("is_outgoing_attempt").toBool() && socket->state() != QAbstractSocket::ConnectedState) {
        emit tcpConnectionStatusChanged(peerId, false, errorString); // Use the temporary ID or address
    }
    // Note: A socket error often leads to disconnection, so onTcpSocketDisconnected might also be called.
    // Depending on the error, we might want to remove it from lists here too,
    // but onTcpSocketDisconnected should handle that.
}


// --- UDP SLOTS ---
void NetworkManager::onUdpReadyRead() {
    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(m_udpSocket->pendingDatagramSize());
        QHostAddress senderAddress;
        quint16 senderPort; // This is the sender's UDP port, not their TCP listening port

        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort);

        QDataStream in(&datagram, QIODevice::ReadOnly);
        in.setVersion(QDataStream::Qt_5_15);

        QString magicHeader, receivedPeerId;
        quint16 receivedTcpPort;

        in >> magicHeader >> receivedPeerId >> receivedTcpPort;

        if (in.status() == QDataStream::Ok && magicHeader == "P2PGIT_DISCOVERY" && !receivedPeerId.isEmpty() && receivedPeerId != m_myPeerIdForTcp) {
            qDebug() << "NetworkManager: Received discovery from" << receivedPeerId
                     << "@" << senderAddress.toString() << "TCP Port:" << receivedTcpPort;

            DiscoveredPeerInfo info;
            info.id = receivedPeerId;
            info.address = senderAddress; // This is the source IP of the UDP packet
            info.tcpPort = receivedTcpPort;
            info.lastSeen = QDateTime::currentMSecsSinceEpoch();

            m_discoveredPeers[receivedPeerId] = info; // Add or update
            emit lanPeerDiscoveredOrUpdated(info);
        } else if (magicHeader != "P2PGIT_DISCOVERY") {
            qDebug() << "NetworkManager: Ignoring UDP packet from" << senderAddress.toString() << "- bad magic header or self-broadcast.";
        } else if (in.status() != QDataStream::Ok){
            qDebug() << "NetworkManager: Malformed UDP discovery packet from " << senderAddress.toString();
        }
    }
}

void NetworkManager::onBroadcastTimerTimeout() {
    sendDiscoveryBroadcast();
}

void NetworkManager::onPeerCleanupTimerTimeout() {
    qint64 currentTime = QDateTime::currentMSecsSinceEpoch();
    QMutableMapIterator<QString, DiscoveredPeerInfo> i(m_discoveredPeers);
    while (i.hasNext()) {
        i.next();
        if (currentTime - i.value().lastSeen > PEER_TIMEOUT_MS) {
            qDebug() << "NetworkManager: Peer" << i.key() << "timed out. Removing from discovered list.";
            emit lanPeerLost(i.key());
            i.remove();
        }
    }
}

bool NetworkManager::hasActiveTcpConnections() const {
    return !m_allTcpSockets.isEmpty();
}