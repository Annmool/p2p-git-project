#include "network_manager.h"
#include "identity_manager.h" // <<< ENSURE THIS IS INCLUDED
#include <QNetworkInterface>
#include <QDataStream> 
#include <QDateTime>   
#include <QDebug>
#include <QBuffer>           // <<< ADDED THIS for processIncomingTcpData
// Constants for discovery and timeouts
const qint64 PEER_TIMEOUT_MS = 15000;           // 15 seconds before a discovered peer is considered lost if not seen again
const int BROADCAST_INTERVAL_MS = 5000;       // Broadcast our presence every 5 seconds
const int PENDING_CONNECTION_TIMEOUT_MS = 30000; // 30 seconds for a user to accept/reject an incoming TCP connection

NetworkManager::NetworkManager(IdentityManager* idMgr, QObject *parent) // <<< DEFINITION
    : QObject(parent), m_identityManager(idMgr), m_myDisplayName("DefaultUser") { // <<< INITIALIZE MEMBERS
    // ... rest of constructor from previous complete version ...
    if (!m_identityManager || !m_identityManager->initializeKeys()) {
        qCritical() << "NetworkManager: FATAL - IdentityManager not provided or failed to initialize keys!";
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

NetworkManager::~NetworkManager() {
    stopUdpDiscovery();
    stopTcpServer();
    disconnectAllTcpPeers(); 
}

QString NetworkManager::getPeerIdentifierForSocket(QTcpSocket* socket) {
    if (!socket) return "InvalidSocket";
    // Prefer the handshake-confirmed ID if available
    if (m_socketToPeerIdMap.contains(socket)) {
        const QString& id = m_socketToPeerIdMap.value(socket);
        // Avoid showing temporary markers as the main ID in logs if a real ID is expected
        if (!id.startsWith("AwaitingID") && !id.startsWith("ConnectingTo")) {
            return id + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
        }
    }
    // Fallback to IP:Port if no confirmed ID yet
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

// --- TCP Server Methods ---
bool NetworkManager::startTcpServer(quint16 port) {
    if (m_tcpServer->isListening()) {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        return true;
    }
    if (m_tcpServer->listen(QHostAddress::Any, port)) {
        qDebug() << "NetworkManager: TCP Server started, listening on port" << m_tcpServer->serverPort();
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort());
        return true;
    } else {
        qDebug() << "NetworkManager: TCP Server failed to start:" << m_tcpServer->errorString();
        emit tcpServerStatusChanged(false, port, m_tcpServer->errorString());
        return false;
    }
}

void NetworkManager::stopTcpServer() {
    if (m_tcpServer && m_tcpServer->isListening()) {
        quint16 port = m_tcpServer->serverPort();
        m_tcpServer->close();
        qDebug() << "NetworkManager: TCP Server stopped.";
        // Closing the server does not automatically close existing connections.
        // We will close them in disconnectAllTcpPeers or let them disconnect naturally.
        emit tcpServerStatusChanged(false, port);
    }
}

quint16 NetworkManager::getTcpServerPort() const {
    if (m_tcpServer && m_tcpServer->isListening()) {
        return m_tcpServer->serverPort();
    }
    return 0;
}

// --- TCP Client Methods ---
bool NetworkManager::connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerId) {
    if (!m_identityManager || !m_identityManager->initializeKeys()) {
         qWarning() << "NetworkManager: Cannot connect to peer, identity not initialized.";
         emit tcpConnectionStatusChanged(expectedPeerId, false, "Local identity not initialized.");
         return false;
    }

    QTcpSocket* socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true); // Mark as an outgoing connection attempt
    socket->setProperty("expected_peer_id", expectedPeerId); // Store for status reporting

    // Add to a temporary map or list for tracking outgoing attempts if needed before connected signal
    // For now, we add to m_socketToPeerIdMap with a temporary ID
    m_socketToPeerIdMap.insert(socket, "ConnectingTo<" + expectedPeerId + "@" + hostAddress.toString() + ">");

    connect(socket, &QTcpSocket::connected, this, [this, socket]() {
        qDebug() << "NetworkManager: TCP socket successfully connected to" << getPeerIdentifierForSocket(socket);
        if (!m_allTcpSockets.contains(socket)) { // Add to master list upon successful connection
            m_allTcpSockets.append(socket);
        }
        sendIdentityOverTcp(socket); // Initiate identity handshake
    });
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "NetworkManager: Attempting TCP connection to" << hostAddress.toString() << ":" << port << " (expecting " << expectedPeerId << ")";
    socket->connectToHost(hostAddress, port);
    // Connection is asynchronous. Status (success/failure) will be emitted via signals.
    return true; // Indicates the connection attempt was initiated
}

void NetworkManager::disconnectFromTcpPeer(QTcpSocket* peerSocket) {
    if (peerSocket) {
        qDebug() << "NetworkManager: Requesting TCP disconnect from" << getPeerIdentifierForSocket(peerSocket);
        peerSocket->disconnectFromHost(); // Triggers onTcpSocketDisconnected
    }
}

void NetworkManager::disconnectAllTcpPeers() {
    qDebug() << "NetworkManager: Disconnecting all TCP peers.";
    // Iterate over a copy, as onTcpSocketDisconnected modifies m_allTcpSockets
    QList<QTcpSocket*> socketsToClose = m_allTcpSockets;
    for (QTcpSocket* socket : socketsToClose) {
        if (socket) {
            socket->disconnectFromHost();
        }
    }
    // m_allTcpSockets should be empty after this due to onTcpSocketDisconnected calls
}

bool NetworkManager::hasActiveTcpConnections() const {
    // Count only fully established connections (where ID handshake is complete)
    int activeCount = 0;
    for(QTcpSocket* socket : qAsConst(m_allTcpSockets)){
        if(m_socketToPeerIdMap.contains(socket) &&
           !m_socketToPeerIdMap.value(socket).startsWith("AwaitingID") &&
           !m_socketToPeerIdMap.value(socket).startsWith("ConnectingTo")){
            activeCount++;
        }
    }
    return activeCount > 0;
}


// --- UDP Discovery Methods ---
bool NetworkManager::startUdpDiscovery(quint16 udpPort, const QString& myDisplayName) {
    if (!m_identityManager || !m_identityManager->initializeKeys()) {
        qWarning() << "NetworkManager: Cannot start UDP discovery, identity not initialized.";
        return false;
    }
    m_myDisplayName = myDisplayName; // Store the display name provided by MainWindow
    m_udpDiscoveryPort = udpPort;

    if (m_udpSocket->state() == QAbstractSocket::BoundState) {
        qDebug() << "NetworkManager: UDP Discovery already active on port" << m_udpSocket->localPort();
        if (!m_broadcastTimer->isActive()) m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        return true;
    }

    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        qDebug() << "NetworkManager: UDP Discovery started, listening on port" << m_udpDiscoveryPort;
        m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast(); // Send an initial broadcast immediately
        return true;
    } else {
        qDebug() << "NetworkManager: UDP Discovery failed to bind to port" << m_udpDiscoveryPort << ":" << m_udpSocket->errorString();
        return false;
    }
}

void NetworkManager::stopUdpDiscovery() {
    if (m_broadcastTimer) m_broadcastTimer->stop();
    if (m_udpSocket && m_udpSocket->state() != QAbstractSocket::UnconnectedState) {
        m_udpSocket->close();
        qDebug() << "NetworkManager: UDP Discovery stopped.";
    }
    m_discoveredPeers.clear();
    // Optionally emit a signal that discovery has stopped or all peers are "lost"
}

void NetworkManager::sendDiscoveryBroadcast() {
    if (!m_tcpServer || !m_tcpServer->isListening() || !m_identityManager || m_myDisplayName.isEmpty()) {
        // qDebug() << "NetworkManager: Cannot send discovery broadcast. TCP server not listening, IdentityManager not ready, or MyDisplayName not set.";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    QString magicHeader = "P2PGIT_DISCOVERY_V2"; // Use new version for new packet structure
    QString myPublicKeyHex = QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    quint16 tcpPort = m_tcpServer->serverPort();

    out << magicHeader << m_myDisplayName << myPublicKeyHex << tcpPort;

    qint64 bytesSent = m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    if (bytesSent == -1) {
        qDebug() << "NetworkManager: Failed to send discovery broadcast:" << m_udpSocket->errorString();
    } else {
        // This log can be very noisy, enable for deep debugging if needed
        // qDebug() << "NetworkManager: Sent discovery V2 for" << m_myDisplayName << "PK:" << myPublicKeyHex.left(8) << "TCP Port:" << tcpPort;
    }
}

// --- TCP Messaging ---
void NetworkManager::sendMessageToPeer(QTcpSocket* peerSocket, const QString& message) {
    if (peerSocket && peerSocket->state() == QAbstractSocket::ConnectedState && m_socketToPeerIdMap.contains(peerSocket)) {
        QString peerId = m_socketToPeerIdMap.value(peerSocket);
        if (peerId.startsWith("AwaitingID") || peerId.startsWith("ConnectingTo")) {
            qDebug() << "NetworkManager: Cannot send CHAT to" << getPeerIdentifierForSocket(peerSocket) << "- ID handshake not complete.";
            return;
        }
        qDebug() << "NetworkManager: Sending CHAT_MESSAGE to" << peerId << ":" << message;
        QByteArray block;
        QDataStream out(&block, QIODevice::WriteOnly);
        out.setVersion(QDataStream::Qt_5_15);
        QString messageType = "CHAT_MESSAGE";
        out << messageType << message;
        peerSocket->write(block);
    } else {
        qDebug() << "NetworkManager: Cannot send CHAT. Socket not connected or peer ID unknown for" << getPeerIdentifierForSocket(peerSocket);
    }
}

void NetworkManager::broadcastTcpMessage(const QString& message) {
    qDebug() << "NetworkManager: Broadcasting TCP message:" << message;
    int sentCount = 0;
    if (m_allTcpSockets.isEmpty()) {
        qDebug() << "NetworkManager: No active TCP sockets to broadcast to.";
        return;
    }
    for (QTcpSocket* socket : qAsConst(m_allTcpSockets)) {
        sendMessageToPeer(socket, message); // sendMessageToPeer will check if ID is established
        // We count an attempt to send, even if sendMessageToPeer internally decides not to send due to handshake state.
        if (socket && socket->state() == QAbstractSocket::ConnectedState) sentCount++;
    }
    qDebug() << "NetworkManager: Broadcast attempted to" << sentCount << "connected sockets.";
}


// --- Identity Exchange (TCP) ---
void NetworkManager::sendIdentityOverTcp(QTcpSocket* socket) {
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || !m_identityManager || m_myDisplayName.isEmpty()) {
        qDebug() << "NetworkManager: Cannot send identity. Socket not connected or identity info missing.";
        return;
    }
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    QString messageType = "IDENTITY_HANDSHAKE_V2";
    QString myPublicKeyHex = QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    out << messageType << m_myDisplayName << myPublicKeyHex;
    socket->write(block);
    qDebug() << "NetworkManager: Sent IDENTITY_HANDSHAKE_V2 (Name:" << m_myDisplayName
             << ", PK:" << myPublicKeyHex.left(8) << "...) to" << getPeerIdentifierForSocket(socket);
}

void NetworkManager::processIncomingTcpData(QTcpSocket* socket, const QByteArray& rawData) {
    // A more robust implementation would use a QBuffer and loop,
    // handling cases where multiple messages are in rawData or a message is partial.
    // For now, assume rawData contains one or more complete QDataStream blocks.
    QBuffer buffer(const_cast<QByteArray*>(&rawData)); // QDataStream needs a QIODevice*
    buffer.open(QIODevice::ReadOnly);
    QDataStream in(&buffer);
    in.setVersion(QDataStream::Qt_5_15);

    while(!in.atEnd()){
        qint64 startPos = buffer.pos(); // Position before reading message type
        QString messageType;
        in >> messageType;

        if (in.status() != QDataStream::Ok) {
            if (in.atEnd() && startPos != buffer.pos()) { // Partial read of messageType
                qDebug() << "NetworkManager: Partial TCP messageType received. Buffering needed (not implemented).";
                // Here you would typically store the partial 'buffer' and wait for more data.
            } else {
                 qDebug() << "NetworkManager: QDataStream error reading messageType from" << getPeerIdentifierForSocket(socket);
            }
            return; // Stop processing this data chunk
        }

        if (messageType == "IDENTITY_HANDSHAKE_V2") {
            QString receivedDisplayName, receivedPublicKeyHex;
            in >> receivedDisplayName >> receivedPublicKeyHex;

            if (in.status() == QDataStream::Ok && !receivedDisplayName.isEmpty() && !receivedPublicKeyHex.isEmpty()) {
                // TODO: Validate receivedPublicKeyHex format if necessary
                m_socketToPeerIdMap.insert(socket, receivedDisplayName); // Use DisplayName as the key for now
                // Store public key separately: QMap<QTcpSocket*, QString> m_socketToPublicKeyHex;
                // m_socketToPublicKeyHex.insert(socket, receivedPublicKeyHex);

                qDebug() << "NetworkManager: Received IDENTITY_HANDSHAKE_V2 from" << getPeerIdentifierForSocket(socket)
                         << "Name:" << receivedDisplayName << "PK:" << receivedPublicKeyHex.left(8) << "...";

                bool wasOutgoing = socket->property("is_outgoing_attempt").toBool();
                if (wasOutgoing) {
                    emit tcpConnectionStatusChanged(receivedDisplayName, true, "");
                    socket->setProperty("is_outgoing_attempt", false);
                }
                emit newTcpPeerConnected(socket, receivedDisplayName); // Signal that peer is fully identified

            } else {
                qDebug() << "NetworkManager: Invalid IDENTITY_HANDSHAKE_V2 payload from" << getPeerIdentifierForSocket(socket) << "Status:" << in.status();
                socket->disconnectFromHost();
                return;
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
                // If payload is bad, we might have consumed part of next message, so stop.
                return;
            }
        } else {
            qDebug() << "NetworkManager: Unknown TCP message type '" << messageType << "' received from" << getPeerIdentifierForSocket(socket);
            // To be robust, skip to end or disconnect
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
                // Timer is parented to `this` (NetworkManager) or deleted in accept/reject
            });
            timeoutTimer->start(PENDING_CONNECTION_TIMEOUT_MS);
            m_pendingConnections.insert(pendingSocket, timeoutTimer);

            emit incomingTcpConnectionRequest(pendingSocket, pendingSocket->peerAddress(), pendingSocket->peerPort());
        }
    }
}

void NetworkManager::setupAcceptedSocket(QTcpSocket* socket) { // HELPER
    if (!m_allTcpSockets.contains(socket)) {
        m_allTcpSockets.append(socket);
    }
    // Initial ID, will be overwritten by handshake
    m_socketToPeerIdMap.insert(socket, "AwaitingID_Incoming<" + socket->peerAddress().toString() + ">");

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::stateChanged, this, &NetworkManager::onTcpSocketStateChanged);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "NetworkManager: Accepted and set up TCP connection for:" << getPeerIdentifierForSocket(socket);
    sendIdentityOverTcp(socket); // Server initiates identity handshake
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket* pendingSocket) { // CALLED BY MAINWINDOW
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) {
            timer->stop();
            timer->deleteLater(); // Schedule timer for deletion
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

void NetworkManager::rejectPendingTcpConnection(QTcpSocket* pendingSocket) { // CALLED BY MAINWINDOW
    if (m_pendingConnections.contains(pendingSocket)) {
        QTimer* timer = m_pendingConnections.value(pendingSocket);
        if (timer) {
            timer->stop();
            timer->deleteLater();
        }
        m_pendingConnections.remove(pendingSocket);
        qDebug() << "NetworkManager: Rejecting incoming connection from" << getPeerIdentifierForSocket(pendingSocket);
        pendingSocket->disconnectFromHost();
        pendingSocket->deleteLater();
    } else {
        qDebug() << "NetworkManager: rejectPending called for unknown/handled socket:" << getPeerIdentifierForSocket(pendingSocket);
         if(pendingSocket && pendingSocket->state() == QAbstractSocket::ConnectedState && !m_allTcpSockets.contains(pendingSocket)){
            pendingSocket->disconnectFromHost(); pendingSocket->deleteLater();
        }
    }
}

void NetworkManager::onPendingConnectionTimeout() { // SLOT FOR MOC
    qDebug() << "NetworkManager: onPendingConnectionTimeout slot called (should be handled by lambda)";
    // The actual logic is in the lambda connected to the timer's timeout signal.
    // This slot exists primarily to satisfy Qt's MOC if it was ever declared as a slot
    // and a direct connection was made. With lambdas, it's less critical.
}

void NetworkManager::onTcpSocketStateChanged(QAbstractSocket::SocketState socketState) {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;
    qDebug() << "NetworkManager: TCP Socket state for" << getPeerIdentifierForSocket(socket) << "is" << socketState;
}

void NetworkManager::onTcpSocketReadyRead() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    // A simple buffer strategy for QDataStream messages
    // Each QTcpSocket could have its own QByteArray buffer as a member if more complex
    // For now, assume all data for one logical block arrives before next readyRead for another block
    // This is a simplification!
    QByteArray data = socket->readAll(); // Read all that's currently available
    if (!data.isEmpty()) {
        processIncomingTcpData(socket, data);
    }
}

void NetworkManager::onTcpSocketDisconnected() {
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(sender());
    if (!socket) return;

    // Check if it was a pending connection that disconnected before approval
    if (m_pendingConnections.contains(socket)) {
        qDebug() << "NetworkManager: Pending connection" << getPeerIdentifierForSocket(socket) << "disconnected prematurely.";
        QTimer* timer = m_pendingConnections.value(socket);
        if (timer) {
            timer->stop();
            timer->deleteLater();
        }
        m_pendingConnections.remove(socket);
        // Don't emit tcpPeerDisconnected for pending sockets that never got an ID
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
    QString peerIdForStatus = socket->property("expected_peer_id").toString(); // From connectToTcpPeer
    if (peerIdForStatus.isEmpty()) { // Could be an incoming connection or one where ID was already set
        peerIdForStatus = m_socketToPeerIdMap.value(socket, getPeerIdentifierForSocket(socket));
    }
    
    qDebug() << "NetworkManager: TCP Socket error on (" << peerIdForStatus << "):" << socketError << "-" << errorString;

    bool wasOutgoingAttempt = socket->property("is_outgoing_attempt").toBool();
    if (wasOutgoingAttempt && socket->state() != QAbstractSocket::ConnectedState) {
        emit tcpConnectionStatusChanged(peerIdForStatus, false, errorString);
        // Socket will be cleaned up by onTcpSocketDisconnected which is usually triggered after an error.
        // Or remove and deleteLater here if it's certain it won't connect.
        m_socketToPeerIdMap.remove(socket); // Remove temporary entry
        m_allTcpSockets.removeAll(socket);  // Remove from master list if it was added
        socket->deleteLater();
    } else {
        // Error on an established connection. The disconnection will be handled by onTcpSocketDisconnected.
        // We might emit a more general "communicationError" signal here if needed.
    }
}


// --- UDP SLOTS ---
void NetworkManager::onUdpReadyRead() {
    while (m_udpSocket->hasPendingDatagrams()) {
        QByteArray datagram;
        datagram.resize(m_udpSocket->pendingDatagramSize());
        QHostAddress senderAddress;
        quint16 senderUdpPort; // UDP port of sender, not their TCP port

        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderUdpPort);

        QDataStream in(&datagram, QIODevice::ReadOnly);
        in.setVersion(QDataStream::Qt_5_15);

        QString magicHeader, receivedDisplayName, receivedPublicKeyHex;
        quint16 receivedTcpPort;

        in >> magicHeader >> receivedDisplayName >> receivedPublicKeyHex >> receivedTcpPort;

        if (in.status() == QDataStream::Ok &&
            magicHeader == "P2PGIT_DISCOVERY_V2" &&
            !receivedDisplayName.isEmpty() &&
            !receivedPublicKeyHex.isEmpty() &&
            m_identityManager && // Make sure identityManager is valid
            receivedPublicKeyHex != QString::fromStdString(m_identityManager->getMyPublicKeyHex()) /* Don't "discover" self based on pubkey */ )
        {
            qDebug() << "NetworkManager: Received discovery V2 from" << receivedDisplayName
                     << "(PK:" << receivedPublicKeyHex.left(8) << "...)"
                     << "@" << senderAddress.toString() << "TCP Port:" << receivedTcpPort;

            DiscoveredPeerInfo info;
            info.id = receivedDisplayName; // This is the display name
            info.address = senderAddress;
            info.tcpPort = receivedTcpPort;
            // Here you would also store receivedPublicKeyHex in DiscoveredPeerInfo if your struct has it
            // info.publicKeyHex = receivedPublicKeyHex;
            info.lastSeen = QDateTime::currentMSecsSinceEpoch();

            m_discoveredPeers[receivedDisplayName] = info; // Key by display name for now (can have collisions)
                                                          // Better to key by public key hex if that's part of DiscoveredPeerInfo
            emit lanPeerDiscoveredOrUpdated(info);
        } else if (in.status() != QDataStream::Ok) {
             qDebug() << "NetworkManager: Malformed UDP discovery packet from " << senderAddress.toString() << "Status:" << in.status();
        } else if (magicHeader != "P2PGIT_DISCOVERY_V2") {
            // qDebug() << "NetworkManager: Ignoring UDP with bad magic header from" << senderAddress.toString();
        } else if (m_identityManager && receivedPublicKeyHex == QString::fromStdString(m_identityManager->getMyPublicKeyHex())) {
            // qDebug() << "NetworkManager: Ignoring self-broadcast.";
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