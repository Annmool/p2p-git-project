#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFont>
#include <QSplitter>
#include <QTcpSocket>
#include <QInputDialog>
#include <QHostAddress>
#include <QHostInfo>    
#include <QStandardPaths>


#include "mainwindow.h" // Ensure all other necessary includes are at the top of the file
#include <QMessageBox>
#include <QInputDialog>
#include <QHostInfo>
#include <QStandardPaths> // Keep for QStandardPaths::AppLocalDataLocation in error string IF you want to be very specific
                         // But a simpler error message might be better.

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_currentlyDisplayedLogBranch(""), // Initialize member
      // Initialize IdentityManager first. It will determine its own data path.
      // The string argument is a subdirectory name suggestion for its data path.
      identityManager("P2PGitClientIdentityData"),
      // Pass the address of our identityManager member to NetworkManager's constructor.
      // Also set 'this' (MainWindow) as the parent for NetworkManager for QObject cleanup.
      networkManager(&identityManager, this)
{
    // Critical step: Initialize cryptographic keys.
    // This attempts to load existing keys or generate new ones.
    if (!identityManager.initializeKeys()) {
        // If key initialization fails, show a critical error.
        // The exact path where IdentityManager tried to save/load keys is internal to IdentityManager,
        // but it uses QStandardPaths::AppLocalDataLocation as a base.
        QString errorPathHint = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/P2PGitClientIdentityData";
        QMessageBox::critical(this, "Fatal Identity Error",
                              "Could not initialize or load cryptographic keys.\n"
                              "The application cannot proceed securely with network operations.\n\n"
                              "Please ensure you have write permissions for application data directories "
                              "(e.g., within: " + errorPathHint + ") and try restarting.\n\n"
                              "See application logs for more details from IdentityManager.");
        // Consider disabling network UI or even closing the application here,
        // as P2P functionality without identity is problematic.
        // For now, we'll let it continue but network features might be broken.
    }

    // Get User's Display Name for P2P Interactions (used in UDP broadcasts)
    bool nameOk;
    QString defaultName = QHostInfo::localHostName();
    if (defaultName.isEmpty()) {
        defaultName = "P2PUser"; // Fallback if hostname is empty
    }

    QString inputName = QInputDialog::getText(this, "Peer Display Name",
                                             "Enter your name for P2P discovery:",
                                             QLineEdit::Normal, defaultName, &nameOk);
    if (nameOk && !inputName.isEmpty()) {
        m_myPeerName = inputName;
    } else {
        m_myPeerName = defaultName; // Use default/hostname if dialog cancelled or empty
    }

    setupUi(); // Now that critical initializations are done, setup the UI

    // --- Connect Git related signals ---
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);

    // --- Connect Network related signals ---
    connect(toggleDiscoveryButton, &QPushButton::clicked, this, &MainWindow::onToggleDiscoveryAndTcpServerClicked);
    connect(sendMessageButton, &QPushButton::clicked, this, &MainWindow::onSendMessageClicked);
    connect(discoveredPeersList, &QListWidget::itemDoubleClicked, this, &MainWindow::onDiscoveredPeerDoubleClicked);

    // Connect signals from NetworkManager to MainWindow slots
    connect(&networkManager, &NetworkManager::tcpServerStatusChanged, this, &MainWindow::handleTcpServerStatusChanged);
    connect(&networkManager, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
    connect(&networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handleNewTcpPeerConnected);
    connect(&networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handleTcpPeerDisconnected);
    connect(&networkManager, &NetworkManager::tcpMessageReceived, this, &MainWindow::handleTcpMessageReceived);
    connect(&networkManager, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatusChanged);
    connect(&networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handleLanPeerDiscoveredOrUpdated);
    connect(&networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::handleLanPeerLost);

    updateRepositoryStatus(); // Set initial UI state for Git parts (which disables network buttons if no repo)
    setWindowTitle("P2P Git Client - " + m_myPeerName); // Set window title with chosen peer name
}

MainWindow::~MainWindow() {
    // Ensure network cleanup when window closes
    networkManager.stopUdpDiscovery();
    networkManager.stopTcpServer();
    // QObject parentship handles deletion of UI elements.
    // identityManager and networkManager are stack members, their destructors are called.
}

void MainWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget);

    // --- Top Bar: Path Input and Actions (Git) ---
    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path for Git repository or click Open/Initialize");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/p2p_git_test_repo")); // Default test path
    pathActionLayout->addWidget(repoPathInput, 1);
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing", this);
    pathActionLayout->addWidget(openRepoButton);
    mainVLayout->addLayout(pathActionLayout);

    // --- Status Bar: Current Repo and Branch (Git) ---
    QHBoxLayout *statusLayout = new QHBoxLayout();
    currentRepoLabel = new QLabel("No repository open.", this);
    QFont boldFont = currentRepoLabel->font(); boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont); statusLayout->addWidget(currentRepoLabel, 1);
    currentBranchLabel = new QLabel("Branch: -", this);
    currentBranchLabel->setFont(boldFont); statusLayout->addWidget(currentBranchLabel);
    mainVLayout->addLayout(statusLayout);

    // --- Main Content Area with Splitter (Git info on left, Network info on right) ---
    QSplitter *overallSplitter = new QSplitter(Qt::Horizontal, this);

    // --- Left Pane: Git Information ---
    QWidget *gitPaneWidget = new QWidget(overallSplitter);
    QVBoxLayout *gitPaneLayout = new QVBoxLayout(gitPaneWidget);
    QSplitter *gitInfoSplitter = new QSplitter(Qt::Vertical, gitPaneWidget); // For Log and Git Messages

    QWidget *topGitPaneWidget = new QWidget(gitInfoSplitter); // Contains Commit Log and Branch controls
    QVBoxLayout *topGitPaneLayout = new QVBoxLayout(topGitPaneWidget);
    QLabel *commitLogTitleLabel = new QLabel("Commit History:", topGitPaneWidget);
    topGitPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(topGitPaneWidget);
    commitLogDisplay->setReadOnly(true); commitLogDisplay->setFontFamily("monospace"); commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap);
    topGitPaneLayout->addWidget(commitLogDisplay, 1); // Give commit log display more vertical space
    refreshLogButton = new QPushButton("Refresh Log", topGitPaneWidget);
    topGitPaneLayout->addWidget(refreshLogButton);

    QHBoxLayout *branchControlLayout = new QHBoxLayout();
    QLabel *branchSelectionLabel = new QLabel("Branches:", topGitPaneWidget);
    branchControlLayout->addWidget(branchSelectionLabel);
    branchComboBox = new QComboBox(topGitPaneWidget);
    branchComboBox->setMinimumWidth(200); branchControlLayout->addWidget(branchComboBox, 1);
    refreshBranchesButton = new QPushButton("Refresh Branches", topGitPaneWidget);
    branchControlLayout->addWidget(refreshBranchesButton);
    checkoutBranchButton = new QPushButton("Checkout/View Selected", topGitPaneWidget);
    branchControlLayout->addWidget(checkoutBranchButton);
    topGitPaneLayout->addLayout(branchControlLayout);
    gitInfoSplitter->addWidget(topGitPaneWidget);

    messageLog = new QTextEdit(gitInfoSplitter); // General Git operation status messages
    messageLog->setReadOnly(true); messageLog->setPlaceholderText("Git operation status messages will appear here...");
    messageLog->setMaximumHeight(120); // Limit height for general messages
    gitInfoSplitter->addWidget(messageLog);
    QList<int> gitSplitterSizes; gitSplitterSizes << 350 << 100; gitInfoSplitter->setSizes(gitSplitterSizes); // Adjust as needed

    gitPaneLayout->addWidget(gitInfoSplitter);
    overallSplitter->addWidget(gitPaneWidget);

    // --- Right Pane: Network Control Panel ---
    networkFrame = new QFrame(overallSplitter);
    networkFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* networkVLayout = new QVBoxLayout(networkFrame);

    networkVLayout->addWidget(new QLabel("<b>P2P Network (UDP Discovery):</b>", networkFrame));

    // Display My Peer Name (set at startup)
    QHBoxLayout* myNameLayout = new QHBoxLayout();
    myNameLayout->addWidget(new QLabel("My Peer Name:", networkFrame));
    myPeerNameInput = new QLineEdit(m_myPeerName, networkFrame); // Display the name
    myPeerNameInput->setReadOnly(true); // Not editable here after startup
    myNameLayout->addWidget(myPeerNameInput, 1); // Allow it to stretch
    networkVLayout->addLayout(myNameLayout);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame);
    networkVLayout->addWidget(tcpServerStatusLabel);

    networkVLayout->addWidget(new QLabel("Discovered Peers on LAN (double-click to connect):", networkFrame));
    discoveredPeersList = new QListWidget(networkFrame);
    discoveredPeersList->setToolTip("Double click a peer to initiate a TCP connection with them.");
    networkVLayout->addWidget(discoveredPeersList, 1); // Give some stretch

    networkVLayout->addWidget(new QLabel("Established TCP Connections:", networkFrame));
    connectedTcpPeersList = new QListWidget(networkFrame);
    connectedTcpPeersList->setMaximumHeight(100);
    networkVLayout->addWidget(connectedTcpPeersList);

    QHBoxLayout* messageSendLayout = new QHBoxLayout();
    messageInput = new QLineEdit(networkFrame);
    messageInput->setPlaceholderText("Enter message (broadcast to TCP peers)...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Send Broadcast", networkFrame);
    messageSendLayout->addWidget(sendMessageButton);
    networkVLayout->addLayout(messageSendLayout);

    networkVLayout->addWidget(new QLabel("Network Log/Chat:", networkFrame));
    networkLogDisplay = new QTextEdit(networkFrame);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    networkVLayout->addWidget(networkLogDisplay, 2); // Give more stretch than discovered peers

    overallSplitter->addWidget(networkFrame);

    // Set initial sizes for the main horizontal splitter
    QList<int> overallSplitterSizes; overallSplitterSizes << 500 << 400; overallSplitter->setSizes(overallSplitterSizes);

    mainVLayout->addWidget(overallSplitter, 1); // Add overall splitter to main layout, make it stretch

    setCentralWidget(centralWidget);
    resize(950, 700); // Adjusted default window size
}


// --- Git Related Methods (largely same as your latest working versions) ---
void MainWindow::updateRepositoryStatus() {
    bool repoIsOpen = gitBackend.isRepositoryOpen();
    refreshLogButton->setEnabled(repoIsOpen);
    refreshBranchesButton->setEnabled(repoIsOpen);
    checkoutBranchButton->setEnabled(repoIsOpen);
    branchComboBox->setEnabled(repoIsOpen);

    if (repoIsOpen) {
        QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath());
        currentRepoLabel->setText("Current Repository: " + QDir::toNativeSeparators(path));
        loadBranchList();
        loadCommitLog(); // Load log for current HEAD
    } else {
        currentRepoLabel->setText("No repository open.");
        currentBranchLabel->setText("Branch: -");
        commitLogDisplay->clear();
        branchComboBox->clear();
        messageLog->append("No repository is open. Initialize or open one.");
        m_currentlyDisplayedLogBranch = "";
    }
}

void MainWindow::loadCommitLogForBranch(const std::string& branchNameOrSha) {
    commitLogDisplay->clear();
    if (!gitBackend.isRepositoryOpen()) {
        commitLogDisplay->setHtml("<i>No repository open.</i>");
        return;
    }
    std::string error_message_log;
    std::vector<CommitInfo> log = gitBackend.getCommitLog(100, error_message_log, branchNameOrSha);

    QString titleRefName = QString::fromStdString(branchNameOrSha).toHtmlEscaped();
    if (branchNameOrSha.empty()){ // If empty, we are loading for current HEAD
        std::string currentBranchErr;
        titleRefName = QString::fromStdString(gitBackend.getCurrentBranch(currentBranchErr));
        if (titleRefName.isEmpty() || titleRefName.startsWith("[")) { // e.g. "[Detached HEAD...]"
             titleRefName = "Current HEAD " + titleRefName; // Clarify it's HEAD even if detached
        } else {
            titleRefName = "HEAD (" + titleRefName + ")";
        }
    }

    if (!error_message_log.empty() && log.empty()) {
        commitLogDisplay->setHtml("<font color=\"red\">Error loading commit log for <b>" + titleRefName + "</b>: " + QString::fromStdString(error_message_log).toHtmlEscaped() + "</font>");
    } else if (log.empty()) {
        commitLogDisplay->setHtml("<i>No commits found for <b>" + titleRefName + "</b>.</i>");
    } else {
        QString htmlLog;
        htmlLog += "<h3>Commit History for: <b>" + titleRefName + "</b></h3><hr style=\"border: none; border-top: 1px solid #ccc;\"/>";
        for (const auto& entry : log) {
            htmlLog += QString("<b>%1</b> - %2 <%3> (%4)<br/>")
                           .arg(QString::fromStdString(entry.sha.substr(0, 7))) // Abbreviated SHA
                           .arg(QString::fromStdString(entry.author_name).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.author_email).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.date));
            htmlLog += QString("    %1<br/><hr style=\"border: none; border-top: 1px dotted #eee;\"/>") // Indent summary
                           .arg(QString::fromStdString(entry.summary).toHtmlEscaped());
        }
        commitLogDisplay->setHtml(htmlLog);
    }
}

void MainWindow::loadCommitLog() {
    m_currentlyDisplayedLogBranch = ""; // Reset when loading log for current HEAD
    loadCommitLogForBranch(""); // Pass empty string to signify current HEAD
}

void MainWindow::loadBranchList() {
    branchComboBox->clear();
    if (!gitBackend.isRepositoryOpen()) return;

    std::string error_message;
    std::vector<std::string> branches = gitBackend.listBranches(GitBackend::BranchType::ALL, error_message);

    if (!error_message.empty()) {
        messageLog->append("<font color=\"red\">Error listing branches: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
    } else {
        if (branches.empty()) {
            messageLog->append("No local or remote-tracking branches found in this repository.");
        }
        for (const std::string& branch_name_str : branches) {
            QString branch_qstr = QString::fromStdString(branch_name_str);
            if (branch_qstr.endsWith("/HEAD")) { // Skip refs like "origin/HEAD"
                continue;
            }
            branchComboBox->addItem(branch_qstr);
        }
    }

    std::string currentBranchNameStr = gitBackend.getCurrentBranch(error_message); // Get current actual HEAD target
    if (!error_message.empty() && currentBranchNameStr.empty()){
         messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
         currentBranchLabel->setText("Branch: [Error]");
    } else if (!currentBranchNameStr.empty()) {
        currentBranchLabel->setText("Branch: <b>" + QString::fromStdString(currentBranchNameStr).toHtmlEscaped() + "</b>");
        int index = branchComboBox->findText(QString::fromStdString(currentBranchNameStr));
        if (index != -1) {
            branchComboBox->setCurrentIndex(index);
        } else {
            // If current actual branch (e.g. detached HEAD short SHA) is not in the "ALL" list from listBranches
            // (which lists ref names), then it won't be selected. This is okay.
        }
    } else {
        currentBranchLabel->setText("Branch: -"); // E.g. unborn branch in empty repo
    }
}

void MainWindow::onInitRepoClicked() {
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty()) { QMessageBox::warning(this, "Input Error", "Please enter a path for the new repository."); messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>"); return; }
    std::string path = qPath.toStdString(); std::string errorMessage;
    QDir dir(QDir::toNativeSeparators(qPath));
    if (!dir.exists()) { if (!dir.mkpath(".")) { messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>"); QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath); return; } }
    if (gitBackend.initializeRepository(path, errorMessage)) { messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else { messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>"); }
    updateRepositoryStatus();
}

void MainWindow::onOpenRepoClicked() {
    QString currentPathSuggestion = repoPathInput->text().trimmed();
    if (currentPathSuggestion.isEmpty() || !QDir(currentPathSuggestion).exists()){ currentPathSuggestion = QDir::homePath(); }
    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Open Git Repository"), currentPathSuggestion, QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty()) { messageLog->append("Open repository cancelled by user."); return; }
    repoPathInput->setText(QDir::toNativeSeparators(dirPath)); std::string path = dirPath.toStdString(); std::string errorMessage;
    if (gitBackend.openRepository(path, errorMessage)) { messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else { messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>"); }
    updateRepositoryStatus();
}

void MainWindow::onRefreshLogClicked() {
    if (gitBackend.isRepositoryOpen()) {
        if (!m_currentlyDisplayedLogBranch.empty()) {
            networkLogDisplay->append("Refreshing commit log for: <b>" + QString::fromStdString(m_currentlyDisplayedLogBranch).toHtmlEscaped() + "</b>");
            loadCommitLogForBranch(m_currentlyDisplayedLogBranch);
        } else {
            networkLogDisplay->append("Refreshing commit log for current HEAD.");
            loadCommitLog();
        }
    } else {
        messageLog->append("No repository open to refresh log.");
        networkLogDisplay->append("No repository open to refresh log."); // Also log to network log for consistency
    }
}

void MainWindow::onRefreshBranchesClicked() {
    if (gitBackend.isRepositoryOpen()) {
        loadBranchList();
        messageLog->append("Branch list refreshed.");
    } else {
        messageLog->append("No repository open to refresh branches.");
    }
}

void MainWindow::onCheckoutBranchClicked() {
    if (!gitBackend.isRepositoryOpen()){ messageLog->append("<font color=\"red\">No repository open.</font>"); return; }
    QString selectedBranchQStr = branchComboBox->currentText();
    if (selectedBranchQStr.isEmpty()) { messageLog->append("<font color=\"red\">No branch selected.</font>"); QMessageBox::warning(this, "Action Error", "No branch selected from the dropdown."); return; }

    std::string selectedBranchName = selectedBranchQStr.toStdString();
    std::string error_message_op;

    // Check if the selected branch is a known local branch
    std::string error_msg_local_list;
    std::vector<std::string> local_branches = gitBackend.listBranches(GitBackend::BranchType::LOCAL, error_msg_local_list);
    bool is_actually_local_branch = false;
    if (error_msg_local_list.empty()) {
        for (const auto& local_b : local_branches) {
            if (local_b == selectedBranchName) {
                is_actually_local_branch = true;
                break;
            }
        }
    } else {
        messageLog->append("<font color=\"orange\">Warning: Could not list local branches to determine type: " + QString::fromStdString(error_msg_local_list).toHtmlEscaped() + "</font>");
        // Fallback heuristic: if it doesn't contain '/', assume local. And not like "[Detached HEAD...]"
        is_actually_local_branch = (selectedBranchName.find('/') == std::string::npos && selectedBranchName.find('[') == std::string::npos);
    }

    if (is_actually_local_branch) {
        // For local branches: Perform a full checkout.
        if (gitBackend.checkoutBranch(selectedBranchName, error_message_op)) {
            messageLog->append("<font color=\"green\">" + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            m_currentlyDisplayedLogBranch = ""; // Reset, so log will show for the new HEAD
            updateRepositoryStatus(); // This reloads log for new HEAD, branches, current branch label
        } else {
            messageLog->append("<font color=\"red\">Error checking out branch '" + selectedBranchQStr.toHtmlEscaped() + "': " + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Checkout Failed", "Could not checkout branch: " + selectedBranchQStr + "\nError: " + QString::fromStdString(error_message_op));
        }
    } else {
        // For remote-tracking branches (or tags, etc.) selected from the "ALL" list: Just load its commit log. Do not change HEAD.
        networkLogDisplay->append("Displaying commit history for: <b>" + selectedBranchQStr.toHtmlEscaped() + "</b> (Current HEAD unchanged)");
        loadCommitLogForBranch(selectedBranchName);
        m_currentlyDisplayedLogBranch = selectedBranchName; // Track that we are showing log for this specific ref
    }
}


// --- Network SLOTS Implementation ---

void MainWindow::onToggleDiscoveryAndTcpServerClicked() {
    // Check if NetworkManager's TCP server is active as a proxy for discovery state
    if (networkManager.getTcpServerPort() > 0) { // <<< CORRECTED CHECK
        networkManager.stopUdpDiscovery();
        networkManager.stopTcpServer();
        networkLogDisplay->append("Discovery and TCP Server stopped by user command.");
    } else { 
        // ... rest of the method from the previous full version ...
        if (m_myPeerName.isEmpty()) { /* ... */ return; }
        if (networkManager.startTcpServer(0)) { 
            if (networkManager.startUdpDiscovery(45454, m_myPeerName)) { 
                networkLogDisplay->append("<font color=\"blue\">UDP Discovery and TCP Server initiated.</font>");
            } else { networkLogDisplay->append("<font color=\"red\">Failed to start UDP Discovery. TCP Server also stopped.</font>"); networkManager.stopTcpServer(); }
        } else {
             networkLogDisplay->append("<font color=\"red\">TCP Server failed to start. UDP Discovery not attempted.</font>");
        }
    }
}

void MainWindow::onDiscoveredPeerDoubleClicked(QListWidgetItem* item) {
    if (!item) return;

    // Retrieve stored data from the QListWidgetItem
    // We stored IP as UserRole, Port as UserRole+1, PeerID (display name) as UserRole+2
    QString peerIpStr = item->data(Qt::UserRole).toString();
    bool portOk;
    quint16 peerTcpPort = item->data(Qt::UserRole + 1).toUInt(&portOk);
    QString peerIdToConnect = item->data(Qt::UserRole + 2).toString();

    if (peerIdToConnect == m_myPeerName) {
        networkLogDisplay->append("<font color=\"orange\">Cannot connect to self.</font>");
        return;
    }

    if (portOk && !peerIpStr.isEmpty() && peerTcpPort > 0 && !peerIdToConnect.isEmpty()) {
        QHostAddress peerIp(peerIpStr);
        networkLogDisplay->append("Attempting TCP connection to discovered peer: " + peerIdToConnect.toHtmlEscaped() +
                                  " @ " + peerIp.toString() + ":" + QString::number(peerTcpPort));
        networkManager.connectToTcpPeer(peerIp, peerTcpPort, peerIdToConnect);
    } else {
        networkLogDisplay->append("<font color=\"red\">Could not parse peer info from list item: " + item->text().toHtmlEscaped() + "</font>");
        qDebug() << "Failed to parse from item. IP:" << peerIpStr << "PortOK:" << portOk << "PortVal:" << peerTcpPort << "PeerID:" << peerIdToConnect;
    }
}


void MainWindow::onSendMessageClicked() {
    QString message = messageInput->text().trimmed();
    if (message.isEmpty()) return;

    if (!networkManager.hasActiveTcpConnections()) {
        networkLogDisplay->append("<font color=\"red\">No active TCP connections to broadcast message.</font>");
        // QMessageBox::information(this, "No Connections", "No peers are currently connected via TCP to send a message to.");
        return;
    }
    networkManager.broadcastTcpMessage(message);
    networkLogDisplay->append("<font color=\"blue\"><b>Me (Broadcast):</b> " + message.toHtmlEscaped() + "</font>");
    messageInput->clear();
}

void MainWindow::handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error) {
    if (listening) {
        tcpServerStatusLabel->setText("TCP Server: Listening on port <b>" + QString::number(port) + "</b>");
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        // myPeerNameInput->setEnabled(false); // Decided to keep it always read-only in UI after initial set
    } else {
        tcpServerStatusLabel->setText("TCP Server: Inactive");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        // myPeerNameInput->setEnabled(true);
        if (!error.isEmpty()) {
            networkLogDisplay->append("<font color=\"red\">TCP Server error/stopped: " + error.toHtmlEscaped() + "</font>");
        } else {
            // Only log "stopped" if it was previously running and deliberately stopped by user/program,
            // not if it failed to start in the first place (error would be non-empty then).
            if (toggleDiscoveryButton->text() == "Start Discovery & TCP Server") { // Implies it was stopped.
                 // Check if previous state was "Stop..." to confirm it was running before
            }
        }
    }
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port) {
    QString incomingPeerDisplayId = "Unknown Peer"; // Default
    // Try to find a matching peer from the discovered list to get their display name
    for (int i = 0; i < discoveredPeersList->count(); ++i) {
        QListWidgetItem* item = discoveredPeersList->item(i);
        if (item->data(Qt::UserRole).toString() == address.toString()) {
            // Note: This IP match is a heuristic. A more robust system might involve
            // the connecting peer sending a temporary ID in the very first unencrypted packet,
            // or matching based on UDP discovery info if available.
            // For now, we'll use the ID stored with the discovered peer if IP matches.
            QString discoveredId = item->data(Qt::UserRole + 2).toString();
            if (!discoveredId.isEmpty()) {
                incomingPeerDisplayId = discoveredId;
                break;
            }
        }
    }
    // If not found in discovered list, use IP:Port
    if (incomingPeerDisplayId == "Unknown Peer") {
        incomingPeerDisplayId = address.toString() + ":" + QString::number(port);
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Incoming Connection Request",
                                  QString("Accept incoming TCP connection from <b>%1</b>?").arg(incomingPeerDisplayId.toHtmlEscaped()),
                                  QMessageBox::Yes | QMessageBox::No | QMessageBox::Ignore); // Ignore could be "decide later"

    if (reply == QMessageBox::Yes) {
        networkLogDisplay->append("<font color=\"blue\">User accepted connection from " + incomingPeerDisplayId.toHtmlEscaped() + "</font>");
        networkManager.acceptPendingTcpConnection(pendingSocket);
    } else if (reply == QMessageBox::No) {
        networkLogDisplay->append("<font color=\"orange\">User rejected connection from " + incomingPeerDisplayId.toHtmlEscaped() + "</font>");
        networkManager.rejectPendingTcpConnection(pendingSocket);
    } else { // Ignore or closed dialog
        networkLogDisplay->append("<font color=\"gray\">Connection decision for " + incomingPeerDisplayId.toHtmlEscaped() + " deferred (will time out if not handled).</font>");
        // The pending connection will eventually time out in NetworkManager if not accepted/rejected.
    }
}

void MainWindow::handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId) {
    Q_UNUSED(peerSocket); // We use peerId which is the one confirmed via handshake
    QString fullPeerDisplayId = peerId;
    if(peerSocket){ // Should always be valid, use its current address:port for display
         fullPeerDisplayId += " (" + peerSocket->peerAddress().toString() + ":" + QString::number(peerSocket->peerPort()) + ")";
    }

    // Avoid duplicates in connectedTcpPeersList
    for(int i=0; i < connectedTcpPeersList->count(); ++i){
        if(connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerId) { // Check against stored simple ID
            connectedTcpPeersList->item(i)->setText(fullPeerDisplayId); // Update text if already there
            return;
        }
    }
    QListWidgetItem* newItem = new QListWidgetItem(fullPeerDisplayId, connectedTcpPeersList);
    newItem->setData(Qt::UserRole, peerId); // Store the simple peerId (display name from handshake)
    networkLogDisplay->append("<font color=\"green\">TCP Peer fully connected: <b>" + peerId.toHtmlEscaped() + "</b></font>");
}

void MainWindow::handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId) {
    Q_UNUSED(peerSocket);
    for (int i = 0; i < connectedTcpPeersList->count(); ++i) {
        if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerId) {
            delete connectedTcpPeersList->takeItem(i);
            break;
        }
    }
    networkLogDisplay->append("<font color=\"orange\">TCP Peer disconnected: " + peerId.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message) {
    Q_UNUSED(peerSocket);
    networkLogDisplay->append("<b>" + peerId.toHtmlEscaped() + ":</b> " + message.toHtmlEscaped());
}

void MainWindow::handleTcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error) {
    if (connected) {
        // The newTcpPeerConnected signal (after ID handshake) is now responsible for adding to the list.
        // This signal primarily informs the initiator about the TCP socket status.
        networkLogDisplay->append("<font color=\"green\">TCP connection attempt to " + peerId.toHtmlEscaped() + " successful (awaiting ID handshake).</font>");
    } else {
        networkLogDisplay->append("<font color=\"red\">Failed TCP connection attempt to " + peerId.toHtmlEscaped() + ": " + error.toHtmlEscaped() + "</font>");
    }
}

void MainWindow::handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo) {
    QString itemText = peerInfo.id + " (" + peerInfo.address.toString() + ":" + QString::number(peerInfo.tcpPort) + ")";
    // Use peerInfo.id (display name from broadcast) as the unique key for the discovered list
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerInfo.id, Qt::MatchStartsWith);

    if (!items.isEmpty()) { // Update existing item
        items.first()->setText(itemText); // Update display text
        items.first()->setData(Qt::UserRole, peerInfo.address.toString()); // Store/update IP
        items.first()->setData(Qt::UserRole + 1, peerInfo.tcpPort);        // Store/update Port
        items.first()->setData(Qt::UserRole + 2, peerInfo.id);             // Store/update Peer Display ID
    } else { // Add new item
        QListWidgetItem* newItem = new QListWidgetItem(itemText, discoveredPeersList);
        newItem->setData(Qt::UserRole, peerInfo.address.toString());
        newItem->setData(Qt::UserRole + 1, peerInfo.tcpPort);
        newItem->setData(Qt::UserRole + 2, peerInfo.id); // Store the Display Name from discovery
    }
    // This log can be noisy, maybe make it optional or less frequent
    // networkLogDisplay->append("<font color=\"purple\">LAN Peer discovered/updated: " + itemText.toHtmlEscaped() + "</font>");
}

void MainWindow::handleLanPeerLost(const QString& peerId) { // peerId here is the display name from discovery
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerId, Qt::MatchStartsWith);
    if (!items.isEmpty()) {
        delete discoveredPeersList->takeItem(discoveredPeersList->row(items.first()));
    }
    networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerId.toHtmlEscaped() + "</font>");
}