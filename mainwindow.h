#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCloseEvent>
#include <QList>
#include <QMap>
#include "network_manager.h" 

QT_BEGIN_NAMESPACE
class QListWidgetItem;
class QSplitter;
QT_END_NAMESPACE

class NetworkPanel;
class RepoManagementPanel;
class GitBackend;
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
    void handleAddCollaborator(const QString &peerId);
    void handleSendBroadcastMessage(const QString &message);
    
    void handleProjectWindowGroupMessage(const QString& appId, const QString& message);

    void handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username);
    void handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg);
    void handleGroupMessage(const QString &peerId, const QString &repoAppId, const QString &message);

    void updateUiFromBackend();

private:
    void setupUi();
    void connectSignals();

    // Re-added the struct definition
    struct PendingCloneRequest
    {
        QString peerId;
        QString repoName;
        QString localClonePath;
        bool isValid() const { return !peerId.isEmpty() && !repoName.isEmpty(); }
        void clear()
        {
            peerId.clear();
            repoName.clear();
            localClonePath.clear();
        }
    };
    PendingCloneRequest m_pendingCloneRequest;

    QString m_myUsername;

    GitBackend *m_gitBackend;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;
    
    QMap<QString, ProjectWindow *> m_projectWindows;

    NetworkPanel *m_networkPanel;
    RepoManagementPanel *m_repoManagementPanel;
};

#endif // MAINWINDOW_H