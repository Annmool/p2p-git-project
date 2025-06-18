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
#include <QFile>
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
    void disconnectAllTcpPeers();
    bool hasActiveTcpConnections() const;
    bool startUdpDiscovery(quint16 udpPort = 45454);
    void stopUdpDiscovery();
    void sendDiscoveryBroadcast();
    void sendMessageToPeer(QTcpSocket *peerSocket, const QString &message);
    void broadcastTcpMessage(const QString &message);
    void acceptPendingTcpConnection(QTcpSocket *pendingSocket);
    void rejectPendingTcpConnection(QTcpSocket *pendingSocket);
    void sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath);
    void startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath);
    QTcpSocket *getSocketForPeer(const QString &peerUsername);
    DiscoveredPeerInfo getDiscoveredPeerInfo(const QString &peerId) const;

signals:
    void incomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void newTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex);
    void tcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername);
    void tcpMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message);
    void tcpServerStatusChanged(bool listening, quint16 port, const QString &error = "");
    void tcpConnectionStatusChanged(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error = "");
    void lanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo);
    void lanPeerLost(const QString &peerUsername);
    void repoBundleRequestedByPeer(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void repoBundleTransferStarted(const QString &repoName, const QString &tempLocalPath);
    void repoBundleChunkReceived(const QString &repoName, qint64 bytesReceived, qint64 totalBytes);
    void repoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);

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
    // <<< FIX: The complete struct with the state enum is defined here.
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
    };
    QMap<QTcpSocket *, IncomingFileTransfer *> m_incomingTransfers;

    QTcpServer *m_tcpServer;
    QList<QTcpSocket *> m_allTcpSockets;
    QMap<QTcpSocket *, QString> m_socketToPeerUsernameMap;
    QMap<QTcpSocket *, QTimer *> m_pendingConnections;
    QString m_myUsername;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager_ptr;
    QMap<QString, QString> m_peerPublicKeys;
    QUdpSocket *m_udpSocket;
    quint16 m_udpDiscoveryPort;
    QTimer *m_broadcastTimer;
    QTimer *m_peerCleanupTimer;
    QMap<QString, DiscoveredPeerInfo> m_discoveredPeers;

    QString getPeerDisplayString(QTcpSocket *socket);
    void processIncomingTcpData(QTcpSocket *socket, const QByteArray &data);
    void sendIdentityOverTcp(QTcpSocket *socket);
    void setupAcceptedSocket(QTcpSocket *socket);
};

#endif // NETWORK_MANAGER_H