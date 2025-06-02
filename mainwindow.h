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
#include <QListWidget>
#include <QFrame>
#include <QInputDialog> // For getting username

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
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();

<<<<<<< HEAD
private:
    void setupUi(); // Helper to organize UI creation
    void updateRepositoryStatus(); // Updates UI based on open repo, loads log & branches
    void loadCommitLog();        // Fetches and displays commit log
    void loadBranchList();      // Fetches and displays branch list, updates current branch
    void loadCommitLogForBranch(const std::string& branchName); // New helper
    std::string m_currentlyDisplayedLogBranch; 
=======
    // Network - TCP Server & Discovery Control
    void onToggleDiscoveryAndTcpServerClicked(); // Replaces start/stop listen
>>>>>>> a4462e1 (implemented udp broadcast for peer discovery and tcp socket setup for connection setup)

    // Network - TCP Client Actions (triggered by UI)
    // void onConnectToDiscoveredPeer(); // If connecting via a button next to discovered list
    void onDiscoveredPeerDoubleClicked(QListWidgetItem* item);


    // Network - Messaging
    void onSendMessageClicked();

    // Slots to handle signals from NetworkManager
    void handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error);
    void handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId); // ID is now string
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
    QString m_myPeerName; // Store the user's chosen name

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
    QLineEdit* myPeerNameInput; // For user to set their peer name
    QPushButton* toggleDiscoveryButton; // Starts/stops TCP server and UDP discovery
    QLabel* tcpServerStatusLabel;   // To show TCP server port
    QListWidget* discoveredPeersList;
    QListWidget* connectedTcpPeersList; // Separate list for established TCP connections
    QLineEdit* messageInput;
    QPushButton* sendMessageButton;
    QTextEdit* networkLogDisplay;

    GitBackend gitBackend;
    NetworkManager networkManager;
};

#endif // MAINWINDOW_H