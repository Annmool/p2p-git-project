#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFont>
#include <QSplitter>
#include <QTcpSocket>
#include <QInputDialog>
#include <QHostInfo>
#include <QCryptographicHash>
#include <QRandomGenerator>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_currentlyDisplayedLogBranch(""),
      m_myUsername("DefaultUser"),
      m_identityManager_ptr(nullptr), // Initialize pointer
      m_networkManager_ptr(nullptr)   // Initialize pointer
{
    bool ok_name;
    QString name_prompt_default = QHostInfo::localHostName();
    if (name_prompt_default.isEmpty()) {
        name_prompt_default = "Peer" + QString::number(QRandomGenerator::global()->bounded(10000));
    }
    QString name_from_dialog = QInputDialog::getText(this, tr("Enter Your Peer Name"),
                                         tr("Peer Name (for discovery):"), QLineEdit::Normal,
                                         name_prompt_default, &ok_name);
    if (ok_name && !name_from_dialog.isEmpty()) {
        m_myUsername = name_from_dialog;
    } else {
        m_myUsername = name_prompt_default;
    }

    m_identityManager_ptr = new IdentityManager(m_myUsername);
    if (!m_identityManager_ptr->initializeKeys()) {
        QMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! Network features may be disabled or insecure.");
        // m_identityManager_ptr is new'd, but keys aren't ready.
        // Depending on desired behavior, could `delete m_identityManager_ptr; m_identityManager_ptr = nullptr;`
    }

    if (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized()) {
        m_networkManager_ptr = new NetworkManager(m_myUsername, m_identityManager_ptr, this); // Pass `this` as parent
    } else {
        QMessageBox::critical(this, "Network Error", "Cannot initialize network manager: Identity keys not ready.");
        // m_networkManager_ptr remains nullptr
    }

    setWindowTitle("P2P Git Client - " + m_myUsername +
                  (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized() ?
                   " [PK:" + QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(8) + "...]" :
                   " [Keys Not Initialized!]"));
    
    setupUi();

    // --- Connections ---
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);

    if (m_networkManager_ptr) {
        connect(toggleDiscoveryButton, &QPushButton::clicked, this, &MainWindow::onToggleDiscoveryAndTcpServerClicked);
        connect(sendMessageButton, &QPushButton::clicked, this, &MainWindow::onSendMessageClicked);
        connect(discoveredPeersList, &QListWidget::itemDoubleClicked, this, &MainWindow::onDiscoveredPeerDoubleClicked);
        connect(m_networkManager_ptr, &NetworkManager::tcpServerStatusChanged, this, &MainWindow::handleTcpServerStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager_ptr, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handleNewTcpPeerConnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handleTcpPeerDisconnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpMessageReceived, this, &MainWindow::handleTcpMessageReceived);
        connect(m_networkManager_ptr, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handleLanPeerDiscoveredOrUpdated);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerLost, this, &MainWindow::handleLanPeerLost);
    } else {
        if(toggleDiscoveryButton) toggleDiscoveryButton->setEnabled(false);
        if(sendMessageButton) sendMessageButton->setEnabled(false);
        if(discoveredPeersList) discoveredPeersList->setEnabled(false);
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Network services disabled (init failure).</font>");
    }
    updateRepositoryStatus();
}

MainWindow::~MainWindow() {
    delete m_identityManager_ptr; // Manually delete non-QObject pointer
    m_identityManager_ptr = nullptr;
    // m_networkManager_ptr will be deleted by Qt's parent-child mechanism as it's parented to `this`
}

void MainWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget);

    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path or click Open/Initialize");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo_p2p"));
    pathActionLayout->addWidget(repoPathInput, 1);
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing", this);
    pathActionLayout->addWidget(openRepoButton);
    mainVLayout->addLayout(pathActionLayout);

    QHBoxLayout *statusLayout = new QHBoxLayout();
    currentRepoLabel = new QLabel("No repository open.", this);
    QFont boldFont = currentRepoLabel->font(); boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont); statusLayout->addWidget(currentRepoLabel, 1);
    currentBranchLabel = new QLabel("Branch: -", this);
    currentBranchLabel->setFont(boldFont); statusLayout->addWidget(currentBranchLabel);
    mainVLayout->addLayout(statusLayout);

    QSplitter *overallSplitter = new QSplitter(Qt::Horizontal, this);
    QWidget *gitPaneWidget = new QWidget(overallSplitter);
    QVBoxLayout *gitPaneLayout = new QVBoxLayout(gitPaneWidget);
    QSplitter *gitInfoSplitter = new QSplitter(Qt::Vertical, gitPaneWidget);
    QWidget *topGitPaneWidget = new QWidget(gitInfoSplitter);
    QVBoxLayout *topGitPaneLayout = new QVBoxLayout(topGitPaneWidget);
    QLabel *commitLogTitleLabel = new QLabel("Commit History:", topGitPaneWidget);
    topGitPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(topGitPaneWidget);
    commitLogDisplay->setReadOnly(true); commitLogDisplay->setFontFamily("monospace"); commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap);
    topGitPaneLayout->addWidget(commitLogDisplay, 1);
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
    messageLog = new QTextEdit(gitInfoSplitter);
    messageLog->setReadOnly(true); messageLog->setPlaceholderText("Git operation status messages..."); messageLog->setMaximumHeight(100);
    gitInfoSplitter->addWidget(messageLog);
    QList<int> gitSplitterSizes; gitSplitterSizes << 350 << 100; gitInfoSplitter->setSizes(gitSplitterSizes);
    gitPaneLayout->addWidget(gitInfoSplitter);
    overallSplitter->addWidget(gitPaneWidget);

    networkFrame = new QFrame(overallSplitter);
    networkFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* networkVLayout = new QVBoxLayout(networkFrame);
    networkVLayout->addWidget(new QLabel("<b>P2P Network (UDP Discovery):</b>", networkFrame));

    myPeerInfoLabel = new QLabel(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(m_identityManager_ptr ? QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10) : "N/A"), networkFrame);
    myPeerInfoLabel->setWordWrap(true);
    networkVLayout->addWidget(myPeerInfoLabel);
    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame);
    networkVLayout->addWidget(tcpServerStatusLabel);
    networkVLayout->addWidget(new QLabel("Discovered Peers on LAN (double-click to connect):", networkFrame));
    discoveredPeersList = new QListWidget(networkFrame);
    discoveredPeersList->setToolTip("Double click a peer to initiate a TCP connection.");
    networkVLayout->addWidget(discoveredPeersList, 1);
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
    networkVLayout->addWidget(networkLogDisplay, 2);
    overallSplitter->addWidget(networkFrame);
    QList<int> overallSplitterSizes; overallSplitterSizes << 550 << 400;
    overallSplitter->setSizes(overallSplitterSizes);
    mainVLayout->addWidget(overallSplitter, 1);
    setCentralWidget(centralWidget);
    resize(1000, 700);
}

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
        loadCommitLog();
    } else {
        currentRepoLabel->setText("No repository open.");
        currentBranchLabel->setText("Branch: -");
        commitLogDisplay->clear();
        branchComboBox->clear();
        if(messageLog && (messageLog->toPlainText().isEmpty() || !messageLog->toPlainText().endsWith("Initialize or open one."))){
             messageLog->append("No repository is open. Initialize or open one.");
        }
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
    if (branchNameOrSha.empty()){
        std::string currentBranchErr;
        titleRefName = QString::fromStdString(gitBackend.getCurrentBranch(currentBranchErr));
        if (titleRefName.isEmpty() || titleRefName.startsWith("[")) {
            titleRefName = "Current HEAD / " + titleRefName;
        } else {
            titleRefName = "HEAD (" + titleRefName + ")";
        }
    }

    if (!error_message_log.empty() && log.empty()) { // Use std::string::empty()
        commitLogDisplay->setHtml("<font color=\"red\">Error loading commit log for <b>" + titleRefName + "</b>: " + QString::fromStdString(error_message_log).toHtmlEscaped() + "</font>");
    } else if (log.empty()) {
        commitLogDisplay->setHtml("<i>No commits found for <b>" + titleRefName + "</b>.</i>");
    } else {
        QString htmlLog;
        htmlLog += "<h3>Commit History for: <b>" + titleRefName + "</b></h3><hr/>";
        for (const auto& entry : log) {
            htmlLog += QString("<b>%1</b> - %2 <%3> (%4)<br/>")
                           .arg(QString::fromStdString(entry.sha.substr(0, 7)))
                           .arg(QString::fromStdString(entry.author_name).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.author_email).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.date));
            htmlLog += QString("    %1<br/><hr/>")
                           .arg(QString::fromStdString(entry.summary).toHtmlEscaped());
        }
        commitLogDisplay->setHtml(htmlLog);
    }
}

void MainWindow::loadCommitLog() {
    m_currentlyDisplayedLogBranch = "";
    loadCommitLogForBranch("");
}

void MainWindow::loadBranchList() {
    branchComboBox->clear();
    if (!gitBackend.isRepositoryOpen()) return;

    std::string error_message;
    std::vector<std::string> branches = gitBackend.listBranches(GitBackend::BranchType::ALL, error_message);

    if (!error_message.empty()) { // Use std::string::empty()
        messageLog->append("<font color=\"red\">Error listing branches: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
    } else {
        if (branches.empty()) {
            messageLog->append("No local or remote-tracking branches found in this repository.");
        }
        for (const std::string& branch_name_str : branches) {
            QString branch_qstr = QString::fromStdString(branch_name_str);
            if (branch_qstr.endsWith("/HEAD")) {
                continue;
            }
            branchComboBox->addItem(branch_qstr);
        }
    }

    std::string currentBranchNameStr = gitBackend.getCurrentBranch(error_message);
    if (!error_message.empty() && currentBranchNameStr.empty()){ // Use std::string::empty()
         messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
         currentBranchLabel->setText("Branch: [Error]");
    } else if (!currentBranchNameStr.empty()) { // Use std::string::empty()
        currentBranchLabel->setText("Branch: <b>" + QString::fromStdString(currentBranchNameStr).toHtmlEscaped() + "</b>");
        int index = branchComboBox->findText(QString::fromStdString(currentBranchNameStr));
        if (index != -1) {
            branchComboBox->setCurrentIndex(index);
        }
    } else {
        currentBranchLabel->setText("Branch: -");
    }
}

void MainWindow::onInitRepoClicked() {
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a path for the new repository.");
        messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>");
        return;
    }
    std::string path = qPath.toStdString();
    std::string errorMessage;
    QDir dir(QDir::toNativeSeparators(qPath));
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath);
            return;
        }
    }
    if (gitBackend.initializeRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onOpenRepoClicked() {
    QString currentPathSuggestion = repoPathInput->text().trimmed();
    if (currentPathSuggestion.isEmpty() || !QDir(currentPathSuggestion).exists()){
        currentPathSuggestion = QDir::homePath();
    }
    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Open Git Repository"),
                                                        currentPathSuggestion,
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty()) {
        messageLog->append("Open repository cancelled by user.");
        return;
    }
    repoPathInput->setText(QDir::toNativeSeparators(dirPath));
    std::string path = dirPath.toStdString();
    std::string errorMessage;
    if (gitBackend.openRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onRefreshLogClicked() {
    if (!m_networkManager_ptr) return; // Guard
    if (gitBackend.isRepositoryOpen()) {
        QString currentBranchInCombo = branchComboBox->currentText();
        bool viewingSpecificRef = (!m_currentlyDisplayedLogBranch.empty() && m_currentlyDisplayedLogBranch == currentBranchInCombo.toStdString()) ||
                                  (currentBranchInCombo.contains('/') && !currentBranchInCombo.startsWith("[Detached"));

        if (viewingSpecificRef && !currentBranchInCombo.isEmpty()) {
            networkLogDisplay->append("Refreshing commit log for selected reference: <b>" + currentBranchInCombo.toHtmlEscaped() + "</b>");
            loadCommitLogForBranch(currentBranchInCombo.toStdString());
            m_currentlyDisplayedLogBranch = currentBranchInCombo.toStdString();
        } else {
            networkLogDisplay->append("Refreshing commit log for current HEAD.");
            loadCommitLog();
        }
    } else {
        if(networkLogDisplay) networkLogDisplay->append("No repository open to refresh log.");
        if(messageLog) messageLog->append("No repository open to refresh log.");
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
    if (!m_networkManager_ptr) return; // Guard
    if (!gitBackend.isRepositoryOpen()){
        messageLog->append("<font color=\"red\">No repository open.</font>");
        return;
    }
    QString selectedBranchQStr = branchComboBox->currentText();
    if (selectedBranchQStr.isEmpty()) {
        messageLog->append("<font color=\"red\">No branch selected.</font>");
        QMessageBox::warning(this, "Action Error", "No branch selected from the dropdown.");
        return;
    }

    std::string selectedBranchName = selectedBranchQStr.toStdString();
    std::string error_message_op;

    std::string error_msg_local_list;
    std::vector<std::string> local_branches = gitBackend.listBranches(GitBackend::BranchType::LOCAL, error_msg_local_list);
    bool is_actually_local_branch = false;
    if (error_msg_local_list.empty()) { // Use std::string::empty()
        for (const auto& local_b : local_branches) {
            if (local_b == selectedBranchName) {
                is_actually_local_branch = true;
                break;
            }
        }
    } else {
        messageLog->append("<font color=\"orange\">Warning: Could not list local branches to determine type: " + QString::fromStdString(error_msg_local_list).toHtmlEscaped() + "</font>");
        is_actually_local_branch = (selectedBranchName.find('/') == std::string::npos && selectedBranchName.find('[') == std::string::npos);
    }

    if (is_actually_local_branch) {
        if (gitBackend.checkoutBranch(selectedBranchName, error_message_op)) {
            messageLog->append("<font color=\"green\">" + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            m_currentlyDisplayedLogBranch = "";
            updateRepositoryStatus();
        } else {
            messageLog->append("<font color=\"red\">Error checking out branch '" + selectedBranchQStr.toHtmlEscaped() + "': " + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Checkout Failed", "Could not checkout branch: " + selectedBranchQStr + "\nError: " + QString::fromStdString(error_message_op));
        }
    } else {
        if(networkLogDisplay) networkLogDisplay->append("Displaying commit history for: <b>" + selectedBranchQStr.toHtmlEscaped() + "</b> (Current HEAD unchanged)");
        loadCommitLogForBranch(selectedBranchName);
        m_currentlyDisplayedLogBranch = selectedBranchName;
    }
}


// --- Network SLOTS Implementation ---

void MainWindow::onToggleDiscoveryAndTcpServerClicked() {
    if (!m_networkManager_ptr || !m_identityManager_ptr) { // Guard
        QMessageBox::critical(this, "Network Error", "Network or Identity services not initialized.");
        return;
    }
    // Check based on TCP server port; NetworkManager internally handles UDP timer state
    if (m_networkManager_ptr->getTcpServerPort() > 0) {
        m_networkManager_ptr->stopUdpDiscovery();
        m_networkManager_ptr->stopTcpServer();
    } else {
        if (m_myUsername.isEmpty()) {
            QMessageBox::warning(this, "Peer Name Error", "Your peer name is not set. Please restart.");
            return;
        }
        if (!m_identityManager_ptr->areKeysInitialized() || m_identityManager_ptr->getMyPublicKeyHex().empty()){
            QMessageBox::critical(this, "Identity Error", "Cryptographic keys are not initialized. Cannot start server/discovery.");
            return;
        }

        if (m_networkManager_ptr->startTcpServer(0)) {
            if (m_networkManager_ptr->startUdpDiscovery(45454)) {
                if(networkLogDisplay) networkLogDisplay->append("<font color=\"blue\">UDP Discovery and TCP Server initiated.</font>");
            } else {
                if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">Failed to start UDP Discovery. TCP Server also stopped.</font>");
                m_networkManager_ptr->stopTcpServer();
            }
        }
    }
}

void MainWindow::onDiscoveredPeerDoubleClicked(QListWidgetItem* item) {
    if (!m_networkManager_ptr) return; // Guard
    if (!item) return;

    QString peerIpStr = item->data(Qt::UserRole).toString();
    bool portOk;
    quint16 peerTcpPort = item->data(Qt::UserRole + 1).toUInt(&portOk);
    QString peerUsername = item->data(Qt::UserRole + 2).toString();

    if (peerUsername == m_myUsername) {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"orange\">Cannot connect to self.</font>");
        return;
    }

    if (portOk && !peerIpStr.isEmpty() && peerTcpPort > 0 && !peerUsername.isEmpty()) {
        if(networkLogDisplay) networkLogDisplay->append("Attempting TCP connection to discovered peer: " + peerUsername.toHtmlEscaped() +
                                  " @ " + peerIpStr + ":" + QString::number(peerTcpPort));
        m_networkManager_ptr->connectToTcpPeer(QHostAddress(peerIpStr), peerTcpPort, peerUsername);
    } else {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">Could not parse peer info from list item: " + item->text().toHtmlEscaped() + "</font>");
    }
}

void MainWindow::onSendMessageClicked() {
    if (!m_networkManager_ptr) return; // Guard
    QString message = messageInput->text().trimmed();
    if (message.isEmpty()) return;

    if (!m_networkManager_ptr->hasActiveTcpConnections() ) {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">Not connected to any peers. Cannot send message.</font>");
        return;
    }
    m_networkManager_ptr->broadcastTcpMessage(message);
    if(networkLogDisplay) networkLogDisplay->append("<font color=\"blue\"><b>Me (Broadcast):</b> " + message.toHtmlEscaped() + "</font>");
    messageInput->clear();
}

void MainWindow::handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error) {
    if (listening) {
        tcpServerStatusLabel->setText("TCP Server: Listening on port <b>" + QString::number(port) + "</b>");
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        if (m_identityManager_ptr) { // Guard
            myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...\nTCP Port: %3")
                                     .arg(m_myUsername.toHtmlEscaped())
                                     .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10))
                                     .arg(port));
        }
    } else {
        tcpServerStatusLabel->setText("TCP Server: Inactive");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        if (m_identityManager_ptr) { // Guard
             myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10)));
        }

        if (!error.isEmpty()) { // Use std::string::empty()
            if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">TCP Server error/stopped: " + error.toHtmlEscaped() + "</font>");
        } else {
            if(networkLogDisplay && tcpServerStatusLabel->text() != "TCP Server: Inactive") { // Avoid double message if already stopped
                 networkLogDisplay->append("TCP Server stopped.");
            }
        }
    }
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername) {
    if (!m_networkManager_ptr) return; // Guard
    QString peerDisplay = discoveredUsername;
    if (discoveredUsername.isEmpty() || discoveredUsername.startsWith("Unknown")) {
        peerDisplay = address.toString() + ":" + QString::number(port);
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Incoming Connection Request",
                                  QString("Accept incoming TCP connection from '%1'?").arg(peerDisplay.toHtmlEscaped()),
                                  QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"blue\">User accepted connection from " + peerDisplay.toHtmlEscaped() + "</font>");
        m_networkManager_ptr->acceptPendingTcpConnection(pendingSocket);
    } else {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"orange\">User rejected connection from " + peerDisplay.toHtmlEscaped() + "</font>");
        m_networkManager_ptr->rejectPendingTcpConnection(pendingSocket);
    }
}

void MainWindow::handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex) {
    Q_UNUSED(peerSocket);
    QString fullPeerDisplayId = peerUsername;
    if(peerSocket){
         fullPeerDisplayId += " (" + peerSocket->peerAddress().toString() + ":" + QString::number(peerSocket->peerPort()) + ")";
    }
    if(!peerPublicKeyHex.isEmpty()){
        fullPeerDisplayId += " [PKH: " + QCryptographicHash::hash(peerPublicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8) + "]";
    }
    
    for(int i=0; i < connectedTcpPeersList->count(); ++i){
        if(connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerUsername) {
            connectedTcpPeersList->item(i)->setText(fullPeerDisplayId);
            return;
        }
    }
    QListWidgetItem* newItem = new QListWidgetItem(fullPeerDisplayId, connectedTcpPeersList);
    newItem->setData(Qt::UserRole, peerUsername);
    if(networkLogDisplay) networkLogDisplay->append("<font color=\"green\">TCP Peer fully connected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername) {
    Q_UNUSED(peerSocket);
    for (int i = 0; i < connectedTcpPeersList->count(); ++i) {
        if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerUsername) {
            delete connectedTcpPeersList->takeItem(i);
            break;
        }
    }
    if(networkLogDisplay) networkLogDisplay->append("<font color=\"orange\">TCP Peer disconnected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message) {
    Q_UNUSED(peerSocket);
    if(networkLogDisplay) networkLogDisplay->append("<b>" + peerUsername.toHtmlEscaped() + ":</b> " + message.toHtmlEscaped());
}

void MainWindow::handleTcpConnectionStatusChanged(const QString& peerUsernameOrAddress, const QString& peerPublicKeyHex, bool connected, const QString& error) {
    if (connected) {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"green\">TCP connection to " + peerUsernameOrAddress.toHtmlEscaped() + " established (PK received: " + (peerPublicKeyHex.isEmpty() ? "NO" : "YES") + "). Awaiting full handshake.</font>");
    } else {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">Failed TCP connection attempt to " + peerUsernameOrAddress.toHtmlEscaped() + ": " + error.toHtmlEscaped() + "</font>");
    }
}

void MainWindow::handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo) {
    QString itemText = peerInfo.id + " (" + peerInfo.address.toString() + ":" + QString::number(peerInfo.tcpPort) + ")";
    if(!peerInfo.publicKeyHex.isEmpty()){
        itemText += " [PKH:" + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(),QCryptographicHash::Sha1).toHex().left(6) + "]";
    }

    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerInfo.id, Qt::MatchStartsWith);

    if (!items.isEmpty()) {
        items.first()->setText(itemText);
        items.first()->setData(Qt::UserRole, peerInfo.address.toString());
        items.first()->setData(Qt::UserRole + 1, peerInfo.tcpPort);
        items.first()->setData(Qt::UserRole + 2, peerInfo.id);
        items.first()->setData(Qt::UserRole + 3, peerInfo.publicKeyHex);
    } else {
        QListWidgetItem* newItem = new QListWidgetItem(itemText, discoveredPeersList);
        newItem->setData(Qt::UserRole, peerInfo.address.toString());
        newItem->setData(Qt::UserRole + 1, peerInfo.tcpPort);
        newItem->setData(Qt::UserRole + 2, peerInfo.id);
        newItem->setData(Qt::UserRole + 3, peerInfo.publicKeyHex);
    }
}

void MainWindow::handleLanPeerLost(const QString& peerUsername) {
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerUsername, Qt::MatchStartsWith);
    if (!items.isEmpty()) {
        delete discoveredPeersList->takeItem(discoveredPeersList->row(items.first()));
    }
    if(networkLogDisplay) networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerUsername.toHtmlEscaped() + "</font>");
}