#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
// All required Qt includes
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSplitter>
#include <QListWidget>
#include <QListWidgetItem>
#include <QFrame>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>
#include <QTcpSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QProcess>
#include <QCloseEvent> // <<< FIX: Added the full include for QCloseEvent

// Project-Specific Includes
#include "git_backend.h"
#include "network_manager.h"

// Forward-declare classes to avoid MOC redefinition errors
class IdentityManager;
class RepositoryManager;

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();
    void onAddManagedRepoClicked();
    void onManagedRepoDoubleClicked(QListWidgetItem *item);
    void onToggleDiscoveryAndTcpServerClicked();
    void onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onCloneSelectedRepoClicked();
    void onSendMessageClicked();
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString &error);
    void handleIncomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername);
    void handleNewTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex);
    void handleTcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername);
    void handleTcpMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message);
    void handleTcpConnectionStatusChanged(const QString &peerUsername, const QString &peerPublicKeyHex, bool connected, const QString &error);
    void handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo);
    void handleLanPeerLost(const QString &peerUsername);
    void handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt);
    void handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);
    void handleRepositoryListChanged();

private:
    void setupUi();
    void setupRepoManagementUi(QSplitter *parentSplitter);
    void setupNetworkUi(QSplitter *parentSplitter);
    void updateRepositoryStatus();
    void loadCommitLog();
    void loadBranchList();
    void loadCommitLogForBranch(const std::string &branchName);
    void updateNetworkUiState();

    // <<< FIX: The complete and correct struct definition
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

    std::string m_currentlyDisplayedLogBranch;
    QString m_myUsername;

    // UI Elements
    QLineEdit *repoPathInput, *messageInput;
    QPushButton *initRepoButton, *openRepoButton, *refreshLogButton, *refreshBranchesButton, *checkoutBranchButton;
    QPushButton *addManagedRepoButton, *toggleDiscoveryButton, *cloneSelectedRepoButton, *sendMessageButton;
    QLabel *currentRepoLabel, *currentBranchLabel, *myPeerInfoLabel, *tcpServerStatusLabel;
    QTextEdit *commitLogDisplay, *messageLog, *networkLogDisplay;
    QComboBox *branchComboBox;
    QListWidget *managedReposListWidget, *connectedTcpPeersList;
    QTreeWidget *discoveredPeersTreeWidget;
    QFrame *repoManagementFrame, *networkFrame;

    // Backend/Manager Instances
    GitBackend gitBackend;
    IdentityManager *m_identityManager_ptr;
    NetworkManager *m_networkManager_ptr;
    RepositoryManager *m_repoManager_ptr;
};

#endif // MAINWINDOW_H