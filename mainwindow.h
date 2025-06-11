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

// Project-Specific Includes
#include "git_backend.h"
#include "network_manager.h"
#include "identity_manager.h"
#include "repository_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
     // Git Operations
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();

    // Repository Management
    void onAddManagedRepoClicked(); 

    // Network Control & Actions
    void onToggleDiscoveryAndTcpServerClicked();
    void onDiscoveredPeerDoubleClicked(QListWidgetItem* item);
    void onSendMessageClicked();

    // NetworkManager Signal Handlers
    // ... (all your handle... slots are correctly declared here) ...
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error);
    void handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername);
    void handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex);
    void handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername);
    void handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message);
    void handleTcpConnectionStatusChanged(const QString& peerUsername, const QString& peerPublicKeyHex, bool connected, const QString& error);
    void handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void handleLanPeerLost(const QString& peerUsername);

    // RepositoryManager Signal Handlers
    void handleRepositoryListChanged();
    void onManagedRepoDoubleClicked(QListWidgetItem* item);

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
    QTextEdit *messageLog;

    // UI Elements - Repository Management
    QFrame* repoManagementFrame;
    QListWidget* managedReposListWidget;
    QPushButton* addManagedRepoButton;

    // UI Elements - Network
    QFrame* networkFrame;
    QLabel* myPeerInfoLabel;
    QPushButton* toggleDiscoveryButton;
    QLabel* tcpServerStatusLabel;
    QListWidget* discoveredPeersList;
    QListWidget* connectedTcpPeersList;
    QLineEdit* messageInput;
    QPushButton* sendMessageButton;
    QTextEdit* networkLogDisplay;

    // Backend/Manager Instances
    GitBackend gitBackend;
    IdentityManager* m_identityManager_ptr;
    NetworkManager*  m_networkManager_ptr;
    RepositoryManager* m_repoManager_ptr;
};

#endif // MAINWINDOW_H