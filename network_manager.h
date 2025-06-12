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
#include "identity_manager.h"
#include "repository_manager.h" // <<< NEW INCLUDE
#include <QMetaType> // <<< ADD OR ENSURE THIS IS PRESENT


// Updated DiscoveredPeerInfo struct
struct DiscoveredPeerInfo {
    QString id; // This will be the username
    QHostAddress address;
    quint16 tcpPort;
    QString publicKeyHex;
    QList<QString> publicRepoNames; // <<< NEW: List of their public repo display names
    // QList<QString> publicRepoAppIds; // Alternative: Use appIds if names aren't unique enough
    qint64 lastSeen;
};
Q_DECLARE_METATYPE(DiscoveredPeerInfo) // If needed for QVariant

class NetworkManager : public QObject {
    Q_OBJECT

public:
    // Constructor now takes RepositoryManager
    explicit NetworkManager(const QString& myUsername,
                            IdentityManager* identityManager,
                            RepositoryManager* repoManager, // <<< NEW PARAMETER
                            QObject *parent = nullptr);
    ~NetworkManager();

    // ... (TCP Server methods - same)
    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;

    // ... (TCP Client methods - same)
    bool connectToTcpPeer(const QHostAddress& hostAddress, quint16 port, const QString& expectedPeerUsername);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;

    // ... (UDP Discovery methods - startUdpDiscovery might not need myUsername anymore if it uses the member)
    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast(); // This will change to include repos

    // ... (TCP Messaging methods - same)
    void sendMessageToPeer(QTcpSocket* peerSocket, const QString& message);
    void broadcastTcpMessage(const QString& message);

    // ... (Connection Approval methods - same)
    void acceptPendingTcpConnection(QTcpSocket* pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket* pendingSocket);

    void sendRepoBundleRequest(QTcpSocket* targetPeerSocket, const QString& repoDisplayName, const QString& requesterLocalPath);
    QTcpSocket* getSocketForPeer(const QString& peerUsername); // Helper

signals:
    // ... (TCP Signals - same)
    void incomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername);
    void newTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername);
    void tcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString& error = "");
    void tcpConnectionStatusChanged(const QString& peerUsername, const QString& peerPublicKeyHex, bool connected, const QString& error = "");

    // ... (UDP Discovery Signals - lanPeerDiscoveredOrUpdated will carry the new DiscoveredPeerInfo)
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void lanPeerLost(const QString& peerUsername);
    void repoBundleRequestedByPeer(QTcpSocket* requestingPeerSocket, const QString& sourcePeerUsername, const QString& repoDisplayName, const QString& clientWantsToSaveAt);
    // For requester side, to update UI on progress or completion
    void repoBundleChunkReceived(const QString& repoName, int chunkIndex, int totalChunks); // If sending chunks
    void repoBundleCompleted(const QString& repoName, const QString& localBundlePath, bool success, const QString& message);
    void repoBundleTransferError(const QString& repoName, const QString& errorMessage);


private slots:
    // ... (All private slots - same)
    void onNewTcpConnection();
    void onTcpSocketStateChanged(QAbstractSocket::SocketState socketState);
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();

private:
    // ... (TCP Members - same)
    QTcpServer* m_tcpServer;
    QList<QTcpSocket*> m_allTcpSockets;
    QMap<QTcpSocket*, QString> m_socketToPeerUsernameMap;
    QMap<QTcpSocket*, QTimer*> m_pendingConnections;

    // Identity & UDP Discovery Members
    QString m_myUsername;
    IdentityManager* m_identityManager;
    RepositoryManager* m_repoManager_ptr; // <<< NEW MEMBER (pointer to RepoManager)
    QMap<QString, QString> m_peerPublicKeys;

    QUdpSocket* m_udpSocket;
    quint16 m_udpDiscoveryPort;
    QTimer* m_broadcastTimer;
    QTimer* m_peerCleanupTimer;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers; // Keyed by username

    // Helper Methods
    QString getPeerDisplayString(QTcpSocket* socket);
    void processIncomingTcpData(QTcpSocket* socket, const QByteArray& data);
    void sendIdentityOverTcp(QTcpSocket* socket);
    void setupAcceptedSocket(QTcpSocket* socket);
};

#endif // NETWORK_MANAGER_H