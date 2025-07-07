#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCloseEvent>
#include <QList>
#include <QMap>
#include "network_manager.h" 
#include "dashboard_panel.h" // Include the correct panel header

QT_BEGIN_NAMESPACE
class QListWidgetItem;
class QStackedWidget;
class QToolButton;
QT_END_NAMESPACE

class NetworkPanel;
class IdentityManager;
class RepositoryManager;
class ProjectWindow;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void handleAddManagedRepo(const QString &preselectedPath = "");
    void handleModifyRepoAccess(const QString &appId);
    void handleDeleteRepo(const QString &appId);
    void handleOpenRepoInProjectWindow(const QString &appId);
    void handleToggleDiscovery();
    void handleConnectToPeer(const QString &peerId);
    void handleCloneRepo(const QString &peerId, const QString &repoName);
    void handleAddCollaboratorFromPanel(const QString &peerId);
    void handleSendBroadcastMessage(const QString &message);
    void handleProjectWindowGroupMessage(const QString& ownerRepoAppId, const QString& message);
    void handleAddCollaboratorFromProjectWindow(const QString& localAppId);
    void handleRemoveCollaboratorFromProjectWindow(const QString &localAppId, const QString &peerIdToRemove);
    void handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username);
    void handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg);
    void handleGroupMessage(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message);
    void handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers);
    void handleCollaboratorRemoved(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName);
    void updateUiFromBackend();
    void onNavigationClicked(bool checked);

private:
    void setupUi();
    void connectSignals();
    void addCollaboratorToRepo(const QString& localAppId, const QString& peerIdToAdd);

    struct PendingCloneRequest
    {
        QString ownerPeerId;
        QString repoDisplayName;
        QString localClonePath;
        bool isValid() const { return !ownerPeerId.isEmpty() && !repoDisplayName.isEmpty(); }
        void clear() { ownerPeerId.clear(); repoDisplayName.clear(); localClonePath.clear(); }
    };
    PendingCloneRequest m_pendingCloneRequest;

    QString m_myUsername;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;
    QMap<QString, ProjectWindow *> m_projectWindows;

    // FIX: Use the correct class type
    DashboardPanel *m_dashboardPanel;
    NetworkPanel *m_networkPanel;
    QStackedWidget *m_mainContentWidget;
    QWidget *m_navigationPanel;
    QToolButton *m_dashboardButton;
    QToolButton *m_networkButton;
};

#endif // MAINWINDOW_H