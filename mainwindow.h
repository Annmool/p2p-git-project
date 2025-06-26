#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCloseEvent>
#include <QList>
#include <QMap>
#include <QTcpSocket>   // Include for QTcpSocket
#include <QHostAddress> // Include for QHostAddress
#include "network_manager.h"
#include "repository_manager.h" // Include for ManagedRepositoryInfo

QT_BEGIN_NAMESPACE class QListWidgetItem;
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
    // Repo Management Panel related slots
    void handleAddManagedRepo(const QString &preselectedPath = "");
    void handleModifyRepoAccess(const QString &appId);
    void handleDeleteRepo(const QString &appId);
    void handleOpenRepoInProjectWindow(const QString &appId);

    // Network Panel related slots
    void handleToggleDiscovery();
    void handleConnectToPeer(const QString &peerId);
    void handleCloneRepo(const QString &peerId, const QString &repoName);
    void handleAddCollaboratorFromNetworkPanel(const QString &peerId);
    void handleSendBroadcastMessage(const QString &message); // Added declaration

    // Project Window related slots (collaborator management & chat)
    void handleProjectWindowGroupMessage(const QString &appId, const QString &message);
    void handleAddCollaboratorFromProjectWindow(const QString &appId);
    void handleRemoveCollaboratorFromProjectWindow(const QString &appId, const QString &peerIdToRemove);

    // Network Manager signals handlers
    void handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username);
    void handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg);
    void handleGroupMessage(const QString &peerId, const QString &repoAppId, const QString &message);
    void handlePeerConnectionStatusChange();

    void updateUiFromBackend();

private:
    void setupUi();
    void connectSignals();

    // Store info about an ongoing clone request
    struct PendingCloneRequest
    {
        QString peerId;
        QString repoName;
        QString localClonePath;
        bool isValid() const { return !peerId.isEmpty() && !repoName.isEmpty() && !localClonePath.isEmpty(); }
        void clear()
        {
            peerId.clear();
            repoName.clear();
            localClonePath.clear();
        }
    };
    PendingCloneRequest m_pendingCloneRequest;

    QString m_myUsername;

    // Backend managers
    GitBackend *m_gitBackend;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;

    // UI Panels
    NetworkPanel *m_networkPanel;
    RepoManagementPanel *m_repoManagementPanel;

    // Keep track of open ProjectWindows by repository appId
    QMap<QString, ProjectWindow *> m_projectWindows;
};

#endif // MAINWINDOW_H