#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket> 
#include <QHostAddress>
#include <QList>
#include <QTimer> 

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
    bool hasActiveTcpConnections() const; // <<< NEW METHOD

    // UDP Discovery
    bool startUdpDiscovery(quint16 udpPort = 45454, const QString& myPeerId = "DefaultPeer");
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast(); 

    // Messaging (TCP)
    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message);
    void broadcastTcpMessage(const QString& message);

// ... signals and private slots same as before ...
signals:
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    void tcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void lanPeerLost(const QString& peerId);
private slots:
    void onNewTcpConnection();
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();
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
    QString getPeerIdentifierForSocket(QTcpSocket* socket); 
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data);
    void sendIdentityOverTcp(QTcpSocket* socket);
};

#endif // NETWORK_MANAGER_H