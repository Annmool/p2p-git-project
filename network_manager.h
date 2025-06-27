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
#include <QMetaType>
#include <QVariantMap>
#include <QFile>
#include <QSet>
#include <QElapsedTimer>
#include "identity_manager.h" // IdentityManager class declaration

class RepositoryManager; // Forward declaration

// Struct to track discovered peer information
struct DiscoveredPeerInfo
{
    QString id;
    QHostAddress address;
    quint16 tcpPort;
    QString publicKeyHex;
    QList<QString> publicRepoNames; // Repositories this peer advertises as shareable (public or shared with me)
    qint64 lastSeen;
};
Q_DECLARE_METATYPE(DiscoveredPeerInfo)

// Struct to track an incoming file transfer (bundle reception)
struct IncomingFileTransfer
{
    enum TransferState
    {
        Receiving,
        Completed
    };
    TransferState state = Receiving;
    QString repoName;
    QString tempLocalPath;
    QFile *file = nullptr; // Pointer to the open file (heap allocated)
    qint64 totalSize = 0;
    qint64 bytesReceived = 0;

    // Destructor to ensure the file is deleted if the struct is deleted early
    ~IncomingFileTransfer()
    {
        if (file)
        {
            if (file->isOpen())
                file->close();
            delete file;
            file = nullptr;
        }
    }
};

// Struct to track an outgoing file transfer (bundle sending)
struct OutgoingFileTransfer
{
    QFile *file = nullptr; // Pointer to the file being sent (heap allocated)
    QString repoName;
    QString bundleFilePath; // Path to the source bundle file (for cleanup)
    qint64 totalSize = 0;
    qint64 bytesSent = 0; // Bytes sent *of the file data* (after initial header)

    // Destructor to ensure the file is deleted if the struct is deleted early
    ~OutgoingFileTransfer()
    {
        if (file)
        {
            if (file->isOpen())
                file->close();
            delete file;
            file = nullptr;
        }
    }
};

class NetworkManager : public QObject
{
    Q_OBJECT

public:
    explicit NetworkManager(const QString &myUsername, IdentityManager *identityManager, RepositoryManager *repoManager, QObject *parent = nullptr);
    ~NetworkManager();

    bool startTcpServer(quint16 port = 0);
    void stopTcpServer();
    quint16 getTcpServerPort() const;
    bool connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername);
    void connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath);
    void sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath);
    void sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;
    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();
    void broadcastTcpMessage(const QString &message);
    void sendGroupChatMessage(const QString &ownerRepoAppId, const QString &message);
    void acceptPendingTcpConnection(QTcpSocket *pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket *pendingSocket);
    void startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath);
    QTcpSocket *getSocketForPeer(const QString &peerUsername);
    DiscoveredPeerInfo getDiscoveredPeerInfo(const QString &peerId) const;
    QMap<QString, DiscoveredPeerInfo> getDiscoveredPeers() const;
    QList<QString> getConnectedPeerIds() const;
    bool isConnectionPending(QTcpSocket *socket) const;
    void addSharedRepoToPeer(const QString &peerId, const QString &repoName); // repoName here is DisplayName
    QString getMyUsername() const { return m_myUsername; }

signals:
    void incomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void newTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername);
    void broadcastMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message);
    void groupMessageReceived(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString &error = "");
    void tcpConnectionStatusChanged(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo);
    void lanPeerLost(const QString &peerUsername);
    void repoBundleRequestedByPeer(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void repoBundleTransferStarted(const QString &repoName, const QString &tempLocalPath);
    void repoBundleChunkReceived(const QString &repoName, qint64 bytesReceived, qint64 totalBytes);
    void repoBundleCompleted(const QString &repoDisplayName, const QString &localBundlePath, bool success, const QString &message);
    void repoBundleSent(const QString &repoName, const QString &recipientUsername);
    void secureMessageReceived(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void collaboratorAddedReceived(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers);

private slots:
    void onNewTcpConnection();
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();

private:
    QMap<QTcpSocket *, IncomingFileTransfer *> m_incomingTransfers;
    QMap<QTcpSocket *, OutgoingFileTransfer *> m_outgoingTransfers;
    QMap<QTcpSocket *, QByteArray> m_socketBuffers;
    QSet<QTcpSocket *> m_handshakeSent;
    QTcpServer *m_tcpServer;
    QList<QTcpSocket *> m_allTcpSockets;
    QMap<QTcpSocket *, QString> m_socketToPeerUsernameMap;
    QMap<QTcpSocket *, QTimer *> m_pendingConnections;
    QString m_myUsername;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager_ptr;
    QMap<QString, QByteArray> m_peerPublicKeys;
    QUdpSocket *m_udpSocket;
    quint16 m_udpDiscoveryPort = 45454;
    QTimer *m_broadcastTimer;
    QTimer *m_peerCleanupTimer;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;

    QString getPeerDisplayString(QTcpSocket *socket);
    void processIncomingTcpData(QTcpSocket *socket);
    void sendIdentityOverTcp(QTcpSocket *socket);
    QString findUsernameForAddress(const QHostAddress &address);
    void sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args);
    void handleEncryptedPayload(const QString &peerId, const QVariantMap &payload);
    void handleOutgoingTransferError(QTcpSocket *socket, const QString &message);
    bool extractGroupInfoFromPayload(const QVariantMap &payload, QString &ownerRepoAppId, QString &repoDisplayName, QString &ownerPeerId, QStringList &groupMembers);
};

#endif // NETWORK_MANAGER_H