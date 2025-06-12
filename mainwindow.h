#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
// Individual includes for ALL Qt classes used as members or in function signatures:
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSplitter>
#include <QListWidget>
#include <QListWidgetItem> // For slot parameter
#include <QFrame>
#include <QInputDialog>
#include <QStandardPaths>
#include <QDir>
#include <QTcpSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QTreeWidget>      // For discoveredPeersTreeWidget
#include <QTreeWidgetItem>  // For slot parameter

// Project-Specific Includes
#include "git_backend.h"
#include "network_manager.h"    // Includes DiscoveredPeerInfo
#include "identity_manager.h"
#include "repository_manager.h" // Includes ManagedRepositoryInfo

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots: // <<< ONLY ONE 'private slots:' needed here
    // Git Operations
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();

    // Repository Management
    void onAddManagedRepoClicked();
    void onManagedRepoDoubleClicked(QListWidgetItem* item);

    // Network Control & Actions
    void onToggleDiscoveryAndTcpServerClicked();
    void onDiscoveredPeerOrRepoSelected(QTreeWidgetItem* current, QTreeWidgetItem* previous); // For QTreeWidget
    void onCloneSelectedRepoClicked();
    void onSendMessageClicked();

    // NetworkManager Signal Handlers
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error);
    void handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername);
    void handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex);
    void handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername);
    void handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message);
    void handleTcpConnectionStatusChanged(const QString& peerUsername, const QString& peerPublicKeyHex, bool connected, const QString& error);
    void handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void handleLanPeerLost(const QString& peerUsername);
    void handleRepoBundleRequest(QTcpSocket* requestingPeerSocket, const QString& sourcePeerUsername, const QString& repoDisplayName, const QString& clientWantsToSaveAt);

    // RepositoryManager Signal Handlers
    void handleRepositoryListChanged();

private:
    void setupUi();
    void setupRepoManagementUi(QSplitter* parentSplitter);
    void setupNetworkUi(QSplitter* parentSplitter);

    void updateRepositoryStatus();
    void loadCommitLog();
    void loadBranchList();
    void loadCommitLogForBranch(const std::string& branchName);
    std::string m_currentlyDisplayedLogBranch;
    QString m_myUsername;

    // UI Elements - Git
    QLineEdit *repoPathInput;
    QPushButton *initRepoButton;
    QPushButton *openRepoButton;
    QLabel *currentRepoLabel;
    QLabel *currentBranchLabel;
    QTextEdit *commitLogDisplay;
    QPushButton *refreshLogButton;
    QComboBox *branchComboBox;
    QPushButton *refreshBranchesButton;
    QPushButton *checkoutBranchButton;
    QTextEdit *messageLog; // General Git operation status

    // UI Elements - Repository Management
    QFrame* repoManagementFrame;
    QListWidget* managedReposListWidget; // For listing managed repos
    QPushButton* addManagedRepoButton;

    // UI Elements - Network
    QFrame* networkFrame;
    QLabel* myPeerInfoLabel;
    QPushButton* toggleDiscoveryButton;
    QLabel* tcpServerStatusLabel;
    QTreeWidget* discoveredPeersTreeWidget; // Changed from QListWidget
    QPushButton* cloneSelectedRepoButton;   // Button to clone repo selected in tree
    QListWidget* connectedTcpPeersList;   // For established TCP connections
    QLineEdit* messageInput;
    QPushButton* sendMessageButton;
    QTextEdit* networkLogDisplay;         // For network/chat messages

    // Backend/Manager Instances
    GitBackend gitBackend;
    IdentityManager* m_identityManager_ptr;
    NetworkManager*  m_networkManager_ptr;
    RepositoryManager* m_repoManager_ptr;
};

#endif // MAINWINDOW_H