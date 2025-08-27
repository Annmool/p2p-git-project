#ifndef NETWORK_PANEL_H
#define NETWORK_PANEL_H

#include <QWidget>
#include <QIcon>
#include "network_manager.h"    // For DiscoveredPeerInfo struct
#include "repository_manager.h" // For ManagedRepositoryInfo

QT_BEGIN_NAMESPACE
class QTreeWidget;
class QListWidget;
class QPushButton;
class QLineEdit;
class QTextEdit;
class QLabel;
class QTreeWidgetItem;
class QComboBox;
QT_END_NAMESPACE

class NetworkPanel : public QWidget
{
    Q_OBJECT
public:
    explicit NetworkPanel(QWidget *parent = nullptr);

    void setNetworkManager(NetworkManager *manager);

    void setMyPeerInfo(const QString &username, const QString &publicKeyHex);
    void updatePeerList(const QMap<QString, DiscoveredPeerInfo> &discoveredPeers, const QList<QString> &connectedPeerIds);
    void updateGroupList(const QList<ManagedRepositoryInfo> &myGroupRepos);
    void updateGroupMembersList(const ManagedRepositoryInfo &repoInfo, const QList<QString> &connectedPeerIds);
    void logMessage(const QString &message, const QColor &color);
    void logBroadcastMessage(const QString &peerId, const QString &message);
    void logGroupChatMessage(const QString &repoName, const QString &peerId, const QString &message);
    void updateServerStatus(bool listening, quint16 port, const QString &error);

signals:
    void connectToPeerRequested(const QString &peerId);
    void disconnectFromPeerRequested(const QString &peerId);
    void cloneRepoRequested(const QString &peerId, const QString &repoName);
    void sendBroadcastMessageRequested(const QString &message);
    void sendGroupMessageRequested(const QString &repoAppId, const QString &message);
    void addCollaboratorRequested(const QString &peerId);
    void groupSelectionChanged(const QString &repoAppId);

private slots:
    void onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current);
    void onConnectClicked();
    void onCloneClicked();
    void onSendMessageClicked();
    void showContextMenu(const QPoint &pos);

private:
    void setupUi();
    void updateAddCollaboratorButtonState();

    NetworkManager *m_networkManager = nullptr;
    QString m_myUsername;
    QTreeWidget *discoveredPeersTreeWidget;
    QPushButton *connectToPeerButton;
    QPushButton *cloneRepoButton;
    QPushButton *disconnectFromPeerButton;
    QPushButton *addCollaboratorButton;
    QListWidget *m_groupMembersList;
    QComboBox *m_groupChatSelector;
    QLineEdit *messageInput;
    QPushButton *sendMessageButton;
    QTextEdit *networkLogDisplay;

    QIcon m_peerDisconnectedIcon;
    QIcon m_peerConnectedIcon;
    QList<QString> m_lastConnectedPeerIds;
};

#endif // NETWORK_PANEL_H