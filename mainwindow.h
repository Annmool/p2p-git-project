#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QCloseEvent>
#include <QList>
#include <QMap>
#include <QTcpSocket>
#include <QHostAddress>
#include <QDateTime>
#include "network_manager.h"
#include "dashboard_panel.h"

// Full includes for classes used in the nested UserProfileWidget
#include <QHBoxLayout>
#include <QLabel>

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
    void notify(const QString &title, const QString &message);

public slots:
    void handleFetchBundleRequest(const QString &ownerPeerId, const QString &repoDisplayName);
    void handleProposeChangesRequest(const QString &ownerPeerId, const QString &repoDisplayName, const QString &fromBranch);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    // --- Private Nested Class for User Profile Widget ---
    class UserProfileWidget : public QWidget
    {
    public:
        UserProfileWidget(const QString &username, QWidget *parent = nullptr) : QWidget(parent)
        {
            setObjectName("userProfileWidget");
            QHBoxLayout *layout = new QHBoxLayout(this);
            layout->setContentsMargins(8, 5, 8, 5);
            layout->setSpacing(10);

            QLabel *avatar = new QLabel(username.left(1).toUpper(), this);
            avatar->setObjectName("userAvatarLabel");
            avatar->setAlignment(Qt::AlignCenter);

            QLabel *name = new QLabel(username, this);
            name->setObjectName("usernameLabel");

            layout->addWidget(avatar);
            layout->addWidget(name, 1);
        }
    };

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
    void handleProjectWindowGroupMessage(const QString &ownerRepoAppId, const QString &message);
    void handleAddCollaboratorFromProjectWindow(const QString &localAppId);
    void handleRemoveCollaboratorFromProjectWindow(const QString &localAppId, const QString &peerIdToRemove);
    void handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username);
    void handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload);
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void handleRepoBundleSent(const QString &repoName, const QString &recipientUsername);
    void handleRepoBundleTransferStarted(const QString &repoName, qint64 totalBytes);
    void handleRepoBundleProgress(const QString &repoName, qint64 bytesReceived, qint64 totalBytes);
    void handleIncomingChangeProposal(const QString &fromPeer, const QString &repoName, const QString &forBranch, const QString &bundlePath);
    void handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg);
    void handleGroupMessage(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message);
    void handleDisconnectFromPeer(const QString &peerId);
    void handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers);
    void handleCollaboratorRemoved(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName);
    void updateUiFromBackend();
    void onNavigationClicked(bool checked);

private:
    void setupUi();
    void connectSignals();
    void addCollaboratorToRepo(const QString &localAppId, const QString &peerIdToAdd);

    // This struct definition is now correct and complete
    struct PendingCloneRequest
    {
        QString ownerPeerId;
        QString repoDisplayName;
        QString localClonePath;
        bool isValid() const { return !ownerPeerId.isEmpty() && !repoDisplayName.isEmpty(); }
        void clear()
        {
            ownerPeerId.clear();
            repoDisplayName.clear();
            localClonePath.clear();
        }
    };
    PendingCloneRequest m_pendingCloneRequest;

    QString m_myUsername;
    IdentityManager *m_identityManager;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;
    QMap<QString, ProjectWindow *> m_projectWindows;
    DashboardPanel *m_dashboardPanel;
    NetworkPanel *m_networkPanel;
    QStackedWidget *m_mainContentWidget;
    QWidget *m_sidebarPanel;
    QToolButton *m_dashboardButton;
    QToolButton *m_networkButton;

    // Track last reported progress percentage per repo to avoid spammy logs
    QHash<QString, int> m_cloneProgressPct;

    // Progress dialog for repository transfers
    class CustomProgressDialog *m_transferProgressDialog;
    QDateTime m_transferStartTime;
};

#endif // MAINWINDOW_H