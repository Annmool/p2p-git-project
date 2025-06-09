#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// ... (all your existing includes: QMainWindow, QPushButton, etc. + QListWidget, QFrame, QInputDialog, network_manager.h, git_backend.h) ...
#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QSplitter>
#include <QListWidget>
#include <QFrame>
#include <QInputDialog>
#include <QTcpSocket> // For slot parameters

#include "git_backend.h"
#include "network_manager.h" // Includes DiscoveredPeerInfo

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
    // ... (other Git slots) ...
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();


    // Network - Control
    void onToggleDiscoveryAndTcpServerClicked();

    // Network - Actions triggered by UI
    void onDiscoveredPeerDoubleClicked(QListWidgetItem* item);
    void onSendMessageClicked();

    // Slots to handle signals from NetworkManager
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error);
    void handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port); // NEW SLOT
    void handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId);
    void handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId);
    void handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message);
    void handleTcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error);

    void handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo);
    void handleLanPeerLost(const QString& peerId);


private:
    // ... (setupUi, Git helper methods, m_currentlyDisplayedLogBranch, m_myPeerName same as before) ...
    void setupUi(); 
    void updateRepositoryStatus(); 
    void loadCommitLog();        
    void loadBranchList();       
    void loadCommitLogForBranch(const std::string& branchName); 
    std::string m_currentlyDisplayedLogBranch; 
    QString m_myPeerName; 

    // UI Elements - Git (same as before)
    QLineEdit *repoPathInput; QPushButton *initRepoButton; QPushButton *openRepoButton;
    QLabel *currentRepoLabel; QLabel *currentBranchLabel; QTextEdit *commitLogDisplay;
    QPushButton *refreshLogButton; QComboBox *branchComboBox; QPushButton *refreshBranchesButton;
    QPushButton *checkoutBranchButton; QTextEdit *messageLog;

    // UI Elements - Network (same as before)
    QFrame* networkFrame; QLineEdit* myPeerNameInput; QPushButton* toggleDiscoveryButton;
    QLabel* tcpServerStatusLabel; QListWidget* discoveredPeersList;
    QListWidget* connectedTcpPeersList; QLineEdit* messageInput;
    QPushButton* sendMessageButton; QTextEdit* networkLogDisplay;


    GitBackend gitBackend;
    NetworkManager networkManager;
};

#endif // MAINWINDOW_H