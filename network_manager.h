#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QHostAddress>
#include <QList>
#include <QTimer>
#include <QMap> // For storing pending connections

struct DiscoveredPeerInfo { /* ... same as before ... */
    QString id;
    QHostAddress address;
    quint16 tcpPort;
    qint64 lastSeen;
};

class NetworkManager : public QObject {
    Q_OBJECT

public:
    explicit NetworkManager(QObject *parent = nullptr);
    ~NetworkManager();

    // TCP Server
    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;

    // TCP Client
    bool connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerId = "");
    void disconnectFromTcpPeer(QTcpSocket* peerSocket);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;

    // UDP Discovery
    bool startUdpDiscovery(quint16 udpPort = 45454, const QString& myPeerId = "DefaultPeer");
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();

    // Messaging (TCP)
    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message); // Might remove if only broadcast
    void broadcastTcpMessage(const QString& message);

    // Methods for connection approval
    void acceptPendingTcpConnection(QTcpSocket* pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket* pendingSocket);


signals:
    // TCP Signals
    void incomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port); // NEW SIGNAL
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    void tcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error = "");

    // UDP Discovery Signals
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void lanPeerLost(const QString& peerId);

private slots:
    // TCP Server Slots
    void onNewTcpConnection(); // Will be modified

    // TCP Socket Slots
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);

    // UDP Discovery Slots
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();
    void onPendingConnectionTimeout(); // For auto-rejecting pending connections


private:
    QTcpServer* m_tcpServer = nullptr;
    QList<QTcpSocket*> m_allTcpSockets;
    QMap<QTcpSocket*, QString> m_socketToPeerIdMap;
    QString m_myPeerIdForTcp;

    QUdpSocket* m_udpSocket = nullptr;
    quint16 m_udpDiscoveryPort;
    QTimer* m_broadcastTimer = nullptr;
    QTimer* m_peerCleanupTimer = nullptr;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;

    QMap<QTcpSocket*, QTimer*> m_pendingConnections; // Store pending sockets and their timeout timers

    QString getPeerIdentifierForSocket(QTcpSocket* socket);
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data);
    void sendIdentityOverTcp(QTcpSocket* socket);
    void setupAcceptedSocket(QTcpSocket* socket); // Helper
};

#endif // NETWORK_MANAGER_H