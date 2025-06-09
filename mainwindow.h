#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSplitter>
#include <QListWidget>     // For connected peers list
#include <QFrame>          // For grouping network controls
#include <QInputDialog>
#include <QTcpSocket>      // For slot parameters

#include "git_backend.h"
#include "network_manager.h" // Includes DiscoveredPeerInfo
#include "identity_manager.h"// For IdentityManager member

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();
    void onToggleDiscoveryAndTcpServerClicked();
    void onDiscoveredPeerDoubleClicked(QListWidgetItem* item);
    void onSendMessageClicked();
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error);
    void handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port);
    void handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId);
    void handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId);
    void handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message);
    void handleTcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error);
    void handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void handleLanPeerLost(const QString& peerId);

private:
    void setupUi();
    void updateRepositoryStatus();
    void loadCommitLog();
    void loadBranchList();
    void loadCommitLogForBranch(const std::string& branchName);
    std::string m_currentlyDisplayedLogBranch;
    QString m_myPeerName;

    QLineEdit *repoPathInput; QPushButton *initRepoButton; QPushButton *openRepoButton;
    QLabel *currentRepoLabel; QLabel *currentBranchLabel; QTextEdit *commitLogDisplay;
    QPushButton *refreshLogButton; QComboBox *branchComboBox; QPushButton *refreshBranchesButton;
    QPushButton *checkoutBranchButton; QTextEdit *messageLog;

    QFrame* networkFrame; QLineEdit* myPeerNameInput; QPushButton* toggleDiscoveryButton;
    QLabel* tcpServerStatusLabel; QListWidget* discoveredPeersList;
    QListWidget* connectedTcpPeersList; QLineEdit* messageInput;
    QPushButton* sendMessageButton; QTextEdit* networkLogDisplay;

    GitBackend gitBackend;
    IdentityManager identityManager; // Declare IdentityManager
    NetworkManager networkManager;   // Declare NetworkManager ONCE
};

#endif // MAINWINDOW_H