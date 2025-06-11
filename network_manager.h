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
    explicit NetworkManager(const QString& myUsername, IdentityManager* identityManager, QObject *parent = nullptr);
    ~NetworkManager();

    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;

    bool connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerUsername);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;

    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();

    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message);
    void broadcastTcpMessage(const QString& message);

    void acceptPendingTcpConnection(QTcpSocket* pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket* pendingSocket);

signals:
    void incomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername);
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername);
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    void tcpConnectionStatusChanged(const QString& peerUsernameOrAddress, const QString& peerPublicKeyHex, bool connected, const QString& error = "");

    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void lanPeerLost(const QString& peerUsername);

private slots:
    void onNewTcpConnection();
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();
    // onPendingConnectionTimeout is implicitly handled by lambda in onNewTcpConnection

private:
    QTcpServer* m_tcpServer = nullptr;
    QList<QTcpSocket*> m_allTcpSockets;
    QMap<QTcpSocket*, QString> m_socketToPeerUsernameMap;
    QString m_myUsername;
    IdentityManager* m_identityManager;
    QMap<QString, QString> m_peerPublicKeys;
    QUdpSocket* m_udpSocket = nullptr;
    quint16 m_udpDiscoveryPort;
    QTimer* m_broadcastTimer = nullptr;
    QTimer* m_peerCleanupTimer = nullptr;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;
    QMap<QTcpSocket*, QTimer*> m_pendingConnections;

    QString getPeerDisplayString(QTcpSocket* socket);
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data);
    void sendIdentityOverTcp(QTcpSocket* socket);
    void setupAcceptedSocket(QTcpSocket* socket);
};

#endif // NETWORK_MANAGER_H