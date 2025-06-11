#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
// Individual includes for Qt classes:
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
#include <QTcpSocket>
#include <QHostAddress>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QRandomGenerator>

#include "git_backend.h"     // Includes CommitInfo struct
#include "network_manager.h" // Includes DiscoveredPeerInfo
#include "identity_manager.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    // Git
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();

    // Network - Control
    void onToggleDiscoveryAndTcpServerClicked();

    // Network - Actions
    void onDiscoveredPeerDoubleClicked(QListWidgetItem* item);
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

private:
    void setupUi();
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
    GitBackend gitBackend;                 // Can remain a value member if simple to init
    IdentityManager* m_identityManager_ptr; // <<< NOW A POINTER
    NetworkManager*  m_networkManager_ptr;  // <<< NOW A POINTER
};

#endif // MAINWINDOW_H