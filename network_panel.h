#ifndef NETWORK_PANEL_H
#define NETWORK_PANEL_H

#include <QWidget>
#include <QIcon>
#include "network_manager.h" // For DiscoveredPeerInfo struct

QT_BEGIN_NAMESPACE
class QTreeWidget;
class QListWidget;
class QPushButton;
class QLineEdit;
class QTextEdit;
class QLabel;
class QTreeWidgetItem;
QT_END_NAMESPACE

class NetworkPanel : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPanel(QWidget *parent = nullptr);

    // This function is the key to connecting the panel to the backend
    void setNetworkManager(NetworkManager *manager);

    void setMyPeerInfo(const QString &username, const QString &publicKeyHex);
    void updatePeerList(const QMap<QString, DiscoveredPeerInfo> &discoveredPeers, const QList<QString> &connectedPeerIds);
    void updateConnectedPeersList(const QList<QString> &connectedPeerIds);
    void logMessage(const QString &message, const QColor &color);
    void logChatMessage(const QString &peerId, const QString &message);
    void updateServerStatus(bool listening, quint16 port, const QString &error);

signals:
    void connectToPeerRequested(const QString &peerId);
    void cloneRepoRequested(const QString &peerId, const QString &repoName);
    void sendMessageRequested(const QString &message);
    void toggleDiscoveryRequested();
    void addCollaboratorRequested(const QString &peerId);

private slots:
    void onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current);
    void onConnectClicked();
    void onCloneClicked();
    void onSendMessageClicked();
    void showContextMenu(const QPoint &pos);

private:
    void setupUi();

    NetworkManager *m_networkManager = nullptr;
    QString m_myUsername;

    QLabel *myPeerInfoLabel;
    QPushButton *toggleDiscoveryButton;
    QLabel *tcpServerStatusLabel;
    QTreeWidget *discoveredPeersTreeWidget;
    QPushButton *connectToPeerButton;
    QPushButton *cloneRepoButton;
    QListWidget *connectedTcpPeersList;
    QLineEdit *messageInput;
    QPushButton *sendMessageButton;
    QTextEdit *networkLogDisplay;

    QIcon m_peerDisconnectedIcon;
    QIcon m_peerConnectedIcon;
};

#endif // NETWORK_PANEL_H