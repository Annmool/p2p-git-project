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
#include <QFile> // Added
#include <QSet>
#include <QElapsedTimer> // Added
#include "identity_manager.h"

class RepositoryManager; // Forward declaration

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
    // Optional: QElapsedTimer timer;

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
    void sendGroupChatMessage(const QString &repoAppId, const QString &message);
    void acceptPendingTcpConnection(QTcpSocket *pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket *pendingSocket);
    void startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath);
    QTcpSocket *getSocketForPeer(const QString &peerUsername);
    DiscoveredPeerInfo getDiscoveredPeerInfo(const QString &peerId) const;
    QMap<QString, DiscoveredPeerInfo> getDiscoveredPeers() const;
    QList<QString> getConnectedPeerIds() const;
    bool isConnectionPending(QTcpSocket *socket) const;
    void addSharedRepoToPeer(const QString &peerId, const QString &repoName);
    QString getMyUsername() const { return m_myUsername; } // New getter

signals:
    void incomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void newTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername);
    void broadcastMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message);
    void groupMessageReceived(const QString &peerUsername, const QString &repoAppId, const QString &message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString &error = "");
    void tcpConnectionStatusChanged(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo);
    void lanPeerLost(const QString &peerUsername);
    void repoBundleRequestedByPeer(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void repoBundleTransferStarted(const QString &repoName, const QString &tempLocalPath);                                   // Emitted by receiving peer
    void repoBundleChunkReceived(const QString &repoName, qint64 bytesReceived, qint64 totalBytes);                          // Emitted by receiving peer
    void repoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message); // Emitted by receiving peer
    void repoBundleSent(const QString &repoName, const QString &recipientUsername);                                          // Emitted by sending peer
    void secureMessageReceived(const QString &peerId, const QString &messageType, const QVariantMap &payload);

private slots:
    void onNewTcpConnection();
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();

private:
    // Removed struct definitions from here, moved above

    QMap<QTcpSocket *, IncomingFileTransfer *> m_incomingTransfers; // Map socket to incoming transfer
    QMap<QTcpSocket *, OutgoingFileTransfer *> m_outgoingTransfers; // Map socket to outgoing transfer

    QMap<QTcpSocket *, QByteArray> m_socketBuffers; // Buffer for incoming data
    QSet<QTcpSocket *> m_handshakeSent;             // Keep track of sockets where we sent our identity

    QTcpServer *m_tcpServer;
    QList<QTcpSocket *> m_allTcpSockets;                   // List of all active sockets
    QMap<QTcpSocket *, QString> m_socketToPeerUsernameMap; // Map socket to peer ID (can be temporary/pending)
    QMap<QTcpSocket *, QTimer *> m_pendingConnections;     // Map pending incoming sockets to handshake timers

    QString m_myUsername;
    IdentityManager *m_identityManager;         // Not owned
    RepositoryManager *m_repoManager_ptr;       // Not owned
    QMap<QString, QByteArray> m_peerPublicKeys; // Map peer ID to their public key bytes (for encryption)

    QUdpSocket *m_udpSocket;
    quint16 m_udpDiscoveryPort = 45454;                  // Default UDP port
    QTimer *m_broadcastTimer;                            // Timer for sending UDP broadcasts
    QTimer *m_peerCleanupTimer;                          // Timer for cleaning up old discovered peers
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers; // Map peer ID to discovery info

    QString getPeerDisplayString(QTcpSocket *socket);                                                     // Helper for logging socket info
    void processIncomingTcpData(QTcpSocket *socket);                                                      // Processes data from the socket buffer
    void sendIdentityOverTcp(QTcpSocket *socket);                                                         // Sends our identity handshake message
    QString findUsernameForAddress(const QHostAddress &address);                                          // Tries to find a known username for an IP address
    void sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args); // Generic message sender
    void handleRepoRequest(QTcpSocket *socket, const QString &requestingPeer, const QString &repoName);   // Handles incoming bundle request message
    void handleEncryptedPayload(const QString &peerId, const QVariantMap &payload);                       // Handles decrypted secure messages

    // Helper for cleaning up failed outgoing transfers
    void handleOutgoingTransferError(QTcpSocket *socket, const QString &message);
};

#endif // NETWORK_MANAGER_H