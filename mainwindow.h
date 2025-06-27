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
#include <QRegularExpression>   // Include for QRegularExpression

QT_BEGIN_NAMESPACE class QListWidgetItem;
class QSplitter;
QT_END_NAMESPACE

class NetworkPanel;
class RepoManagementPanel;
// GitBackend is now per ProjectWindow, no pointer here
// class GitBackend;
class IdentityManager;
class RepositoryManager;
class NetworkManager; // Already forward declared above
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
    void handleCloneRepo(const QString &peerId, const QString &repoDisplayName); // Renamed repoName to repoDisplayName for clarity
    void handleAddCollaboratorFromNetworkPanel(const QString &peerId);
    void handleSendBroadcastMessage(const QString &message); // Added declaration

    // Project Window related slots (collaborator management & chat)
    // Updated signal signature handler
    void handleProjectWindowGroupMessage(const QString &ownerRepoAppId, const QString &message);
    void handleAddCollaboratorFromProjectWindow(const QString &localAppId);                                   // Parameter is local App ID
    void handleRemoveCollaboratorFromProjectWindow(const QString &localAppId, const QString &peerIdToRemove); // Parameter is local App ID

    // Network Manager signals handlers
    void handleIncomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    // Updated signal signature for bundle request handler
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    // Updated signal signature for bundle completed handler
    void handleRepoBundleCompleted(const QString &repoDisplayName, const QString &localBundlePath, bool success, const QString &message);
    void handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg);
    // Updated signal signature handler: sender, ownerRepoAppId, message
    void handleGroupMessage(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message);
    void handlePeerConnectionStatusChange();                                                                                                 // Updates ProjectWindows' member lists and Network Panel
    void handleTcpConnectionStatus(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error = ""); // Log TCP connection status
    void handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers);
    void updateUiFromBackend();

private:
    void setupUi();
    void connectSignals();

    // Store info about an ongoing clone request
    struct PendingCloneRequest
    {
        QString ownerPeerId;     // The peer who owns the repo being cloned
        QString repoDisplayName; // The display name of the repo being cloned
        QString localClonePath;  // The desired local path for the clone
        // We don't need ownerRepoAppId here during clone initiation, it arrives in COLLABORATOR_ADDED

        bool isValid() const { return !ownerPeerId.isEmpty() && !repoDisplayName.isEmpty() && !localClonePath.isEmpty(); }
        void clear()
        {
            ownerPeerId.clear();
            repoDisplayName.clear();
            localClonePath.clear();
        }
    };
    PendingCloneRequest m_pendingCloneRequest;

    QString m_myUsername;

    // Backend managers (owned by MainWindow)
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;

    // UI Panels
    NetworkPanel *m_networkPanel;
    RepoManagementPanel *m_repoManagementPanel;

    // Keep track of open ProjectWindows by repository appId (local appId)
    QMap<QString, ProjectWindow *> m_projectWindows;
};

#endif // MAINWINDOW_H