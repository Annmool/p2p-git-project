#ifndef NETWORK_PANEL_H
#define NETWORK_PANEL_H

#include <QWidget>
#include <QIcon>
#include "network_manager.h" // For DiscoveredPeerInfo struct
// #include "repository_manager.h" // Not strictly needed here, ManagedRepositoryInfo used elsewhere

QT_BEGIN_NAMESPACE
class QTreeWidget;
class QPushButton;
class QLineEdit;
class QTextEdit;
class QLabel;
class QTreeWidgetItem;
// QComboBox, QListWidget removed as group chat moved
QT_END_NAMESPACE

class NetworkManager; // Forward declaration

class NetworkPanel : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPanel(QWidget *parent = nullptr);
    // ~NetworkPanel() is implicitly generated or can be added if needed

    void setNetworkManager(NetworkManager *manager);

    void setMyPeerInfo(const QString &username, const QString &publicKeyHex);
    void updatePeerList(const QMap<QString, DiscoveredPeerInfo> &discoveredPeers, const QList<QString> &connectedPeerIds);
    // Removed updateGroupList and updateGroupMembersList as group chat is in ProjectWindow
    void logMessage(const QString &message, const QColor &color);
    void logBroadcastMessage(const QString &peerId, const QString &message);
    void logGroupChatMessage(const QString &repoName, const QString &peerId, const QString &message); // Still useful for logging received group chats in main log
    void updateServerStatus(bool listening, quint16 port, const QString &error);

signals:
    void connectToPeerRequested(const QString &peerId);
    void cloneRepoRequested(const QString &peerId, const QString &repoName);
    void sendBroadcastMessageRequested(const QString &message);
    // Removed sendGroupMessageRequested and groupSelectionChanged
    void toggleDiscoveryRequested();
    void addCollaboratorRequested(const QString &peerId); // Signal from context menu

private slots:
    void onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current);
    void onConnectClicked();
    void onCloneClicked();
    void onSendMessageClicked();
    void showContextMenu(const QPoint &pos); // Slot for custom context menu

private:
    void setupUi();

    NetworkManager *m_networkManager = nullptr; // Pointer to the shared network manager
    QString m_myUsername;                       // Store local peer's username

    // UI elements
    QLabel *myPeerInfoLabel;
    QPushButton *toggleDiscoveryButton;
    QLabel *tcpServerStatusLabel;
    QTreeWidget *discoveredPeersTreeWidget;
    QPushButton *connectToPeerButton;
    QPushButton *cloneRepoButton;
    // Removed m_groupMembersList and m_groupChatSelector
    QLineEdit *messageInput;
    QPushButton *sendMessageButton;
    QTextEdit *networkLogDisplay;

    // Icons for peer status
    QIcon m_peerDisconnectedIcon;
    QIcon m_peerConnectedIcon;
};

#endif // NETWORK_PANEL_H