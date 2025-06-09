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

// Forward declaration if IdentityManager is complex or to avoid include here,
// but including is fine for now as it's not a huge header.
#include "identity_manager.h" // <<< ENSURE THIS IS PRESENT

struct DiscoveredPeerInfo {
    QString id;
    QHostAddress address;
    quint16 tcpPort;
    qint64 lastSeen;
    // QString publicKeyHex; // Optional: Add if you want to pass it around with discovered info
};

class NetworkManager : public QObject {
    Q_OBJECT

public:
    // <<< CORRECTED CONSTRUCTOR DECLARATION >>>
    explicit NetworkManager(IdentityManager* idMgr, QObject *parent = nullptr);
    ~NetworkManager();

    // ... (rest of public methods: startTcpServer, stopTcpServer, etc. ... ALL THE METHODS FROM BEFORE)
    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;
    bool connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerId = "");
    void disconnectFromTcpPeer(QTcpSocket* peerSocket);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;
    bool startUdpDiscovery(quint16 udpPort = 45454, const QString& myDisplayName = "DefaultPeer");
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();
    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message);
    void broadcastTcpMessage(const QString& message);
    void acceptPendingTcpConnection(QTcpSocket* pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket* pendingSocket);


signals:
    // ... (ALL THE SIGNALS FROM BEFORE) ...
    void incomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port);
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId);
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    void tcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void lanPeerLost(const QString& peerId);

private slots:
    // ... (ALL THE PRIVATE SLOTS FROM BEFORE) ...
    void onNewTcpConnection();
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();
    void onPendingConnectionTimeout();

private:
    // ... (m_tcpServer, m_allTcpSockets, m_socketToPeerIdMap, m_udpSocket, etc. ... ALL OTHER PRIVATE MEMBERS) ...
    QTcpServer* m_tcpServer = nullptr;
    QList<QTcpSocket*> m_allTcpSockets;
    QMap<QTcpSocket*, QString> m_socketToPeerIdMap;
    QUdpSocket* m_udpSocket = nullptr;
    quint16 m_udpDiscoveryPort;
    QTimer* m_broadcastTimer = nullptr;
    QTimer* m_peerCleanupTimer = nullptr;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;
    QMap<QTcpSocket*, QTimer*> m_pendingConnections;

    // <<< THESE MEMBERS MUST BE DECLARED >>>
    IdentityManager* m_identityManager;
    QString m_myDisplayName; // To store the display name for broadcasts

    QString getPeerIdentifierForSocket(QTcpSocket* socket);
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data);
    void sendIdentityOverTcp(QTcpSocket* socket);
    void setupAcceptedSocket(QTcpSocket* socket);
};

#endif // NETWORK_MANAGER_H