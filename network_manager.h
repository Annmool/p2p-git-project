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
#include "identity_manager.h"

class RepositoryManager;

struct DiscoveredPeerInfo
{
    QString id;
    QHostAddress address;
    quint16 tcpPort;
    QString publicKeyHex;
    QList<QString> publicRepoNames;
    qint64 lastSeen;
};
Q_DECLARE_METATYPE(DiscoveredPeerInfo)

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
    void requestBundleFromPeer(const QString &peerId, const QString &repoName, const QString &localPath);
    void sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath);
    // Send a repository bundle file to a peer over an existing TCP socket
    void startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath);
    void sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload);
    // New: send to a peer by id, queuing and auto-connecting if needed
    void sendEncryptedToPeerId(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    // Owner-chosen save path for proposal zip prior to transfer start
    void setPendingProposalSavePath(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, const QString &absolutePath);
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;
    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();
    void broadcastTcpMessage(const QString &message);
    void sendGroupChatMessage(const QString &repoAppId, const QString &message);
    void acceptPendingTcpConnection(QTcpSocket *pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket *pendingSocket);
    void sendChangeProposal(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage = QString()); // Now uses chunked method
    void sendProposalToPeer(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage = QString());
    // New: ask owner if they want to review before sending the zip
    void sendProposalReviewRequest(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, const QString &proposalMessage = QString());
    // New: stash pending proposal bundle until owner accepts review
    void storePendingProposalBundle(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage);
    bool takePendingProposalBundle(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, QString &outBundlePath, QString &outMessage);
    QTcpSocket *getSocketForPeer(const QString &peerUsername);
    DiscoveredPeerInfo getDiscoveredPeerInfo(const QString &peerId) const;
    QMap<QString, DiscoveredPeerInfo> getDiscoveredPeers() const;
    QList<QString> getConnectedPeerIds() const;
    bool isConnectionPending(QTcpSocket *socket) const;
    void addSharedRepoToPeer(const QString &peerId, const QString &repoName);
    QString getMyUsername() const { return m_myUsername; }
    // Chunked, encrypted proposal sending (10KB chunks)
    void startSendingProposalChunked(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage = QString());

signals:
    void incomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void newTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername);
    void broadcastMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message);
    void groupMessageReceived(const QString &senderPeerId, const QString &repoAppId, const QString &message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString &error = "");
    void tcpConnectionStatusChanged(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo);
    void lanPeerLost(const QString &peerUsername);
    void repoBundleRequestedByPeer(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void repoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void repoBundleSent(const QString &repoName, const QString &recipientUsername);
    void secureMessageReceived(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void collaboratorAddedReceived(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers);
    void collaboratorRemovedReceived(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName);
    void changeProposalReceived(const QString &fromPeer, const QString &repoName, const QString &forBranch, const QString &bundlePath, const QString &message = QString());
    void repoBundleTransferStarted(const QString &repoName, qint64 totalBytes);                     // <<< ADDED THIS LINE
    void repoBundleChunkReceived(const QString &repoName, qint64 bytesReceived, qint64 totalBytes); // <<< ADDED THIS LINE

private slots:
    void onNewTcpConnection();
    void onTcpSocketReadyRead();
    void onTcpSocketDisconnected();
    void onTcpSocketError(QAbstractSocket::SocketError socketError);
    void onUdpReadyRead();
    void onBroadcastTimerTimeout();
    void onPeerCleanupTimerTimeout();

private:
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
        QFile file;
        qint64 totalSize = 0;
        qint64 bytesReceived = 0;

        // Custom property to store extra info for different transfer types
        QMap<QString, QVariant> properties;
    };

    QMap<QTcpSocket *, IncomingFileTransfer *> m_incomingTransfers;
    QMap<QTcpSocket *, QByteArray> m_socketBuffers;
    QSet<QTcpSocket *> m_handshakeSent;
    QTcpServer *m_tcpServer;
    QList<QTcpSocket *> m_allTcpSockets;
    QMap<QTcpSocket *, QString> m_socketToPeerUsernameMap;
    QMap<QTcpSocket *, QTimer *> m_pendingConnections;
    QString m_myUsername;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager_ptr;
    // Curve25519 public keys for crypto_box (derived from peers' Ed25519 keys)
    QMap<QString, QByteArray> m_peerCurve25519PublicKeys;
    // Queue of encrypted-like messages for peers that are currently unreachable or
    // do not yet have a known Curve25519 public key. Keyed by peerId.
    QMap<QString, QList<QPair<QString, QVariantMap>>> m_queuedEncryptedMessages;
    void flushQueuedEncryptedMessagesForPeer(const QString &peerId);
    QUdpSocket *m_udpSocket;
    quint16 m_udpDiscoveryPort;
    QTimer *m_broadcastTimer;
    QTimer *m_peerCleanupTimer;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;

    // For encrypted, message-based proposal transfers keyed by a transferId (UUID)
    QMap<QString, IncomingFileTransfer *> m_encryptedIncomingProposalTransfers;

    // Collaborator-side: pending bundles waiting for owner to accept review
    QMap<QString, QPair<QString, QString>> m_pendingProposalBundles; // key -> {bundlePath, message}
    QString makeProposalKey(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch) const
    {
        return peerId + "::" + repoDisplayName + "::" + fromBranch;
    }
    // Preferred save paths chosen by owner before incoming transfer begins
    QMap<QString, QString> m_pendingProposalSavePaths; // key -> absolute save path

    QString getPeerDisplayString(QTcpSocket *socket);
    void processIncomingTcpData(QTcpSocket *socket);
    void sendIdentityOverTcp(QTcpSocket *socket);
    QString findUsernameForAddress(const QHostAddress &address);
    void sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args);
    void handleRepoRequest(QTcpSocket *socket, const QString &requestingPeer, const QString &repoName);
    void handleEncryptedPayload(const QString &peerId, const QVariantMap &payload);
};

#endif // NETWORK_MANAGER_H