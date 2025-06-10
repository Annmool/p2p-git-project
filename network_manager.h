#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QHostAddress>
#include <QList>
#include <QTimer>
#include <QMap>
#include "identity_manager.h" // Include IdentityManager

struct DiscoveredPeerInfo {
    QString id; // This will be the username
    QHostAddress address;
    quint16 tcpPort;
    QString publicKeyHex; // Store discovered public key
    qint64 lastSeen;
};

class NetworkManager : public QObject {
    Q_OBJECT

public:
    // Username is for display/discovery, IdentityManager handles crypto keys
    explicit NetworkManager(const QString& myUsername, IdentityManager* identityManager, QObject *parent = nullptr);
    ~NetworkManager();

    // TCP Server
    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;

    // TCP Client
    bool connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerUsername);
    void disconnectAllTcpPeers(); // Disconnects all active TCP sockets
    bool hasActiveTcpConnections() const;

    // UDP Discovery
    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast(); // Broadcasts presence

    // TCP Messaging
    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message); // <<< THIS IS NOW PUBLIC
    void broadcastTcpMessage(const QString& message); // Sends to all fully connected peers

    // Connection Approval (called by UI)
    void acceptPendingTcpConnection(QTcpSocket* pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket* pendingSocket);

signals:
    // Emitted when a TCP connection is requested by a remote peer, UI should ask user
    void incomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername);
    // Emitted after TCP connection is established AND identity handshake is complete
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex);
    // Emitted when a fully connected peer disconnects
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername);
    // Emitted when a chat message is received from a peer
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message);
    // Emitted when TCP server starts/stops or errors
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    // Emitted for status of an outgoing TCP connection attempt (before ID handshake completes)
    void tcpConnectionStatusChanged(const QString& peerUsernameOrAddress, const QString& peerPublicKeyHex, bool connected, const QString& error = "");

    // Emitted when a peer is found via UDP or its info is updated
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    // Emitted when a discovered peer times out
    void lanPeerLost(const QString& peerUsername);

private slots:
    // TCP Server
    void onNewTcpConnection(); // Handles incoming connection attempts

    // TCP Sockets (for both server-accepted clients and outgoing connections)
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();    // Data received on a TCP socket
    void onTcpSocketDisconnected(); // A TCP socket disconnected
    void onTcpSocketError(QAbstractSocket::SocketError socketError); // Error on a TCP socket

    // UDP Discovery
    void onUdpReadyRead();          // UDP datagram received
    void onBroadcastTimerTimeout(); // Time to send another UDP presence broadcast
    void onPeerCleanupTimerTimeout(); // Time to check for stale discovered peers
    // Note: onPendingConnectionTimeout is handled by a lambda in onNewTcpConnection

private:
    // TCP Members
    QTcpServer* m_tcpServer = nullptr;
    QList<QTcpSocket*> m_allTcpSockets; // Unified list of all active (post-handshake) TCP sockets
    QMap<QTcpSocket*, QString> m_socketToPeerUsernameMap; // Socket -> Confirmed Username
    QMap<QTcpSocket*, QTimer*> m_pendingConnections; // Sockets awaiting user approval & their timeout timers

    // Identity & UDP Discovery Members
    QString m_myUsername;               // User-friendly name for this instance
    IdentityManager* m_identityManager; // Manages cryptographic keys (owned by MainWindow)
    QMap<QString, QString> m_peerPublicKeys; // Username -> PublicKeyHex (for connected peers)

    QUdpSocket* m_udpSocket = nullptr;
    quint16 m_udpDiscoveryPort;
    QTimer* m_broadcastTimer = nullptr;
    QTimer* m_peerCleanupTimer = nullptr;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers; // Username -> DiscoveredPeerInfo

    // Helper Methods
    QString getPeerDisplayString(QTcpSocket* socket); // For logging and pre-handshake identification
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data); // Parses TCP messages
    void sendIdentityOverTcp(QTcpSocket* socket); // Sends username and public key
    void setupAcceptedSocket(QTcpSocket* socket); // Finalizes setup for an accepted TCP socket
};

#endif // NETWORK_MANAGER_H