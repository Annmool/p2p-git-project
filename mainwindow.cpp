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
#include <QStandardPaths> // For settings path

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), // Base class constructor
      m_currentlyDisplayedLogBranch(""),
      m_myUsername("DefaultUser"),      // Initial default, will be set by QInputDialog
      m_identityManager_ptr(nullptr), // Initialize pointer members to nullptr
      m_networkManager_ptr(nullptr),
      m_repoManager_ptr(nullptr)      // Initialize new pointer
      // The member initializer list ends here with the last comma (or no comma if it's the last item)
{ // Constructor body starts here

    // 1. Get Peer Name (username) from user
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
        m_myUsername = name_prompt_default; // Use the generated/hostname default
    }

    // 2. Initialize IdentityManager
    m_identityManager_ptr = new IdentityManager(m_myUsername); // Uses username for path
    if (!m_identityManager_ptr->initializeKeys()) {
        QMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! Network features may be disabled or insecure.");
        // Consider how to handle this - app might still run with limited functionality
    }

    // 3. Initialize RepositoryManager
    QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir configAppDir(configPath);
    QString appSpecificDirName = "P2PGitClient";
    if (!configAppDir.exists(appSpecificDirName)) {
        configAppDir.mkdir(appSpecificDirName);
    }
    configAppDir.cd(appSpecificDirName);
    if (!configAppDir.exists(m_myUsername)) {
        configAppDir.mkdir(m_myUsername);
    }
    configAppDir.cd(m_myUsername);
    QString repoManagerStorageFile = configAppDir.filePath("managed_repositories.json");
    m_repoManager_ptr = new RepositoryManager(repoManagerStorageFile, this); // Parent to MainWindow

    // 4. Initialize NetworkManager (NOW THE IF BLOCK IS CORRECTLY PLACED)
    if (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized() && m_repoManager_ptr) {
        m_networkManager_ptr = new NetworkManager(m_myUsername, m_identityManager_ptr, m_repoManager_ptr, this); // Pass repoManager and parent
    } else {
        QMessageBox::critical(this, "Core Services Error", "Cannot initialize network or repository services due to prior initialization failures.");
        // m_networkManager_ptr will remain nullptr
    }

    // Set window title now that m_myUsername and keys are potentially known
    setWindowTitle("P2P Git Client - " + m_myUsername +
                  (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized() ?
                   " [PK:" + QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(8) + "...]" :
                   " [Keys Not Initialized!]"));
    
    setupUi(); // Create all UI elements

    // --- Connections ---
    // ... (your connect statements for Git UI) ...
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);


    // Connections for Repository Management
    if (m_repoManager_ptr) { // Check if repo manager was successfully created
        if(addManagedRepoButton) { 
             connect(addManagedRepoButton, &QPushButton::clicked, this, &MainWindow::onAddManagedRepoClicked);
        }
        if(managedReposListWidget){
             connect(managedReposListWidget, &QListWidget::itemDoubleClicked, this, &MainWindow::onManagedRepoDoubleClicked);
        }
        connect(m_repoManager_ptr, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::handleRepositoryListChanged);
    }


    // Connections for Network
    if (m_networkManager_ptr) { // Only connect network signals if manager was successfully created
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
        // If network manager failed to initialize, disable relevant network UI parts
        if(toggleDiscoveryButton) toggleDiscoveryButton->setEnabled(false);
        if(sendMessageButton) sendMessageButton->setEnabled(false);
        if(discoveredPeersList) discoveredPeersList->setEnabled(false); // Or add a "Network Unavailable" message
        if(connectedTcpPeersList) connectedTcpPeersList->setEnabled(false);
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Network services completely disabled due to critical initialization failure.</font>");
        if(tcpServerStatusLabel) tcpServerStatusLabel->setText("TCP Server: OFFLINE (Init Error)");
    }

    updateRepositoryStatus(); // Initial UI state for Git panel
    if(m_repoManager_ptr) handleRepositoryListChanged(); // Initial population of managed repos list
}
MainWindow::~MainWindow() {
    // m_networkManager_ptr and m_repoManager_ptr are QObjects parented to `this` (MainWindow),
    // so Qt will delete them automatically when MainWindow is deleted.
    // m_identityManager_ptr is NOT a QObject, so we must delete it manually.
    delete m_identityManager_ptr;
    m_identityManager_ptr = nullptr;
}

void MainWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget);

    // --- Top Bar: Path Input and Actions (Git) ---
    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path for new repo or select existing");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo_p2p"));
    pathActionLayout->addWidget(repoPathInput, 1);
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing (Local Git Repo)", this);
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

    // --- Main Content Area with Splitter (Git info, Repo Management, Network info) ---
    QSplitter *overallSplitter = new QSplitter(Qt::Horizontal, this);

    // --- Left Pane: Git Operations ---
    QWidget *gitOpsPaneWidget = new QWidget(overallSplitter); // Changed name for clarity
    QVBoxLayout *gitOpsPaneLayout = new QVBoxLayout(gitOpsPaneWidget);
    // Commit Log Area
    QLabel *commitLogTitleLabel = new QLabel("Commit History (Current Branch/Ref):", gitOpsPaneWidget);
    gitOpsPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(gitOpsPaneWidget);
    commitLogDisplay->setReadOnly(true); commitLogDisplay->setFontFamily("monospace"); commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap);
    gitOpsPaneLayout->addWidget(commitLogDisplay, 1); // Stretch commit log
    refreshLogButton = new QPushButton("Refresh Log", gitOpsPaneWidget);
    gitOpsPaneLayout->addWidget(refreshLogButton);
    // Branch Management Area
    QHBoxLayout *branchControlLayout = new QHBoxLayout();
    QLabel *branchSelectionLabel = new QLabel("Branches (All Types):", gitOpsPaneWidget);
    branchControlLayout->addWidget(branchSelectionLabel);
    branchComboBox = new QComboBox(gitOpsPaneWidget);
    branchComboBox->setMinimumWidth(200); branchControlLayout->addWidget(branchComboBox, 1);
    refreshBranchesButton = new QPushButton("Refresh Branches", gitOpsPaneWidget);
    branchControlLayout->addWidget(refreshBranchesButton);
    checkoutBranchButton = new QPushButton("Checkout Local / View Remote", gitOpsPaneWidget);
    branchControlLayout->addWidget(checkoutBranchButton);
    gitOpsPaneLayout->addLayout(branchControlLayout);
    overallSplitter->addWidget(gitOpsPaneWidget);


    // --- Middle Pane: Managed Repositories & Git Operation Messages ---
    setupRepoManagementUi(overallSplitter); // Call helper to create this section

    // --- Right Pane: Network Control Panel ---
    setupNetworkUi(overallSplitter); // Call helper to create this section

    // Adjust splitter proportions
    QList<int> overallSplitterSizes;
    overallSplitterSizes << 350 << 250 << 400; // Git Ops | Repo Mgmt | Network
    overallSplitter->setSizes(overallSplitterSizes);

    mainVLayout->addWidget(overallSplitter, 1);

    setCentralWidget(centralWidget);
    // Window title is set in constructor after m_myUsername is known
    resize(1200, 750);
}

void MainWindow::setupRepoManagementUi(QSplitter* parentSplitter) {
    repoManagementFrame = new QFrame(parentSplitter);
    repoManagementFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* repoMgmtLayout = new QVBoxLayout(repoManagementFrame);

    repoMgmtLayout->addWidget(new QLabel("<b>Managed Repositories:</b>", repoManagementFrame));
    addManagedRepoButton = new QPushButton("Add Existing Folder to Manage", repoManagementFrame);
    repoMgmtLayout->addWidget(addManagedRepoButton);

    managedReposListWidget = new QListWidget(repoManagementFrame);
    managedReposListWidget->setToolTip("List of repositories. Double-click to open. Right-click for options (TODO).");
    repoMgmtLayout->addWidget(managedReposListWidget, 1); // Stretch list

    // General Git operation messages (moved here for better layout)
    repoMgmtLayout->addWidget(new QLabel("Git Operation Status:", repoManagementFrame));
    messageLog = new QTextEdit(repoManagementFrame);
    messageLog->setReadOnly(true);
    messageLog->setPlaceholderText("Git operation status messages will appear here...");
    messageLog->setMaximumHeight(150);
    repoMgmtLayout->addWidget(messageLog);

    parentSplitter->addWidget(repoManagementFrame);
}

void MainWindow::setupNetworkUi(QSplitter* parentSplitter) {
    networkFrame = new QFrame(parentSplitter);
    networkFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* networkVLayout = new QVBoxLayout(networkFrame);

    networkVLayout->addWidget(new QLabel("<b>P2P Network (UDP Discovery):</b>", networkFrame));

    myPeerInfoLabel = new QLabel(this); // Will be updated with peer info
    myPeerInfoLabel->setWordWrap(true);
    // Set initial text, will be updated in constructor or handleTcpServerStatusChanged
    myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(m_identityManager_ptr ? QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10) : "N/A"));
    networkVLayout->addWidget(myPeerInfoLabel);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame);
    networkVLayout->addWidget(tcpServerStatusLabel);

    networkVLayout->addWidget(new QLabel("Discovered Peers on LAN (double-click to connect):", networkFrame));
    discoveredPeersList = new QListWidget(networkFrame);
    discoveredPeersList->setToolTip("Double click a peer to initiate a TCP connection.");
    networkVLayout->addWidget(discoveredPeersList, 1); // Stretch

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
    networkVLayout->addWidget(networkLogDisplay, 2); // More stretch

    parentSplitter->addWidget(networkFrame);
}


// --- Git related method implementations ---
void MainWindow::updateRepositoryStatus() {
    bool repoIsOpen = gitBackend.isRepositoryOpen();
    if(refreshLogButton) refreshLogButton->setEnabled(repoIsOpen); // Add null checks
    if(refreshBranchesButton) refreshBranchesButton->setEnabled(repoIsOpen);
    if(checkoutBranchButton) checkoutBranchButton->setEnabled(repoIsOpen);
    if(branchComboBox) branchComboBox->setEnabled(repoIsOpen);

    if (repoIsOpen) {
        QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath());
        if(currentRepoLabel) currentRepoLabel->setText("Current Repository: " + QDir::toNativeSeparators(path));
        loadBranchList();
        loadCommitLog();
    } else {
        if(currentRepoLabel) currentRepoLabel->setText("No repository open.");
        if(currentBranchLabel) currentBranchLabel->setText("Branch: -");
        if(commitLogDisplay) commitLogDisplay->clear();
        if(branchComboBox) branchComboBox->clear();
        if(messageLog && (messageLog->toPlainText().isEmpty() || !messageLog->toPlainText().endsWith("Initialize or open one."))){
             messageLog->append("No repository is open. Initialize or open one.");
        }
        m_currentlyDisplayedLogBranch = "";
    }
}

void MainWindow::loadCommitLogForBranch(const std::string& branchNameOrSha) {
    if (!commitLogDisplay) return;
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

    if (!error_message_log.empty() && log.empty()) {
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
    if (!branchComboBox || !messageLog || !currentBranchLabel) return;
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
            if (branch_qstr.endsWith("/HEAD")) { continue; }
            branchComboBox->addItem(branch_qstr);
        }
    }

    std::string currentBranchNameStr = gitBackend.getCurrentBranch(error_message);
    if (!error_message.empty() && currentBranchNameStr.empty()){
         messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
         currentBranchLabel->setText("Branch: [Error]");
    } else if (!currentBranchNameStr.empty()) {
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
        if(messageLog) messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>");
        return;
    }
    std::string path = qPath.toStdString();
    std::string errorMessage;
    QDir dir(QDir::toNativeSeparators(qPath));
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            if(messageLog) messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath);
            return;
        }
    }
    if (gitBackend.initializeRepository(path, errorMessage)) {
        if(messageLog) messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        if (m_repoManager_ptr) { // Add to managed list
            QString repoName = QFileInfo(qPath).fileName();
            if (repoName.isEmpty() && !qPath.isEmpty()) repoName = QDir(qPath).dirName();
            if (repoName.isEmpty()) repoName = "Unnamed Initialized Repo";

            bool ok_name_prompt;
            QString displayName = QInputDialog::getText(this, "Manage Repository", "Enter a display name for this new repository:", QLineEdit::Normal, repoName, &ok_name_prompt);
            if (ok_name_prompt) {
                m_repoManager_ptr->addManagedRepository(qPath, displayName.isEmpty() ? repoName : displayName, false, m_myUsername);
            }
        }
    } else {
        if(messageLog) messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
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
        if(messageLog) messageLog->append("Open repository cancelled by user.");
        return;
    }
    repoPathInput->setText(QDir::toNativeSeparators(dirPath));
    std::string path = dirPath.toStdString();
    std::string errorMessage;
    if (gitBackend.openRepository(path, errorMessage)) {
        if(messageLog) messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        if (m_repoManager_ptr) { // Check if already managed, if not, prompt to add
            ManagedRepositoryInfo existingManaged = m_repoManager_ptr->getRepositoryInfoByPath(dirPath);
            if(existingManaged.appId.isEmpty()){ // Not managed yet
                QString repoName = QFileInfo(dirPath).fileName();
                if (repoName.isEmpty()) repoName = QDir(dirPath).dirName();
                if (repoName.isEmpty()) repoName = "Unnamed Opened Repo";
                
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Manage Repository",
                                          QString("Add '%1' to managed repositories?").arg(repoName),
                                          QMessageBox::Yes|QMessageBox::No);
                if (reply == QMessageBox::Yes) {
                    bool ok_name_prompt;
                    QString displayName = QInputDialog::getText(this, "Set Display Name", "Repository display name:", QLineEdit::Normal, repoName, &ok_name_prompt);
                     if (ok_name_prompt) {
                        m_repoManager_ptr->addManagedRepository(dirPath, displayName.isEmpty() ? repoName : displayName, false, m_myUsername);
                    }
                }
            }
        }
    } else {
        if(messageLog) messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onRefreshLogClicked() {
    if (!gitBackend.isRepositoryOpen()) {
        if(networkLogDisplay) networkLogDisplay->append("No repository open to refresh log.");
        if(messageLog) messageLog->append("No repository open to refresh log.");
        return;
    }
    if (!m_networkManager_ptr && networkLogDisplay) { /* Can't use networkLogDisplay if no network manager */ }

    QString currentBranchInCombo = branchComboBox->currentText();
    bool viewingSpecificRef = (!m_currentlyDisplayedLogBranch.empty() && m_currentlyDisplayedLogBranch == currentBranchInCombo.toStdString()) ||
                              (currentBranchInCombo.contains('/') && !currentBranchInCombo.startsWith("[Detached"));

    if (viewingSpecificRef && !currentBranchInCombo.isEmpty()) {
        if(networkLogDisplay) networkLogDisplay->append("Refreshing commit log for selected reference: <b>" + currentBranchInCombo.toHtmlEscaped() + "</b>");
        loadCommitLogForBranch(currentBranchInCombo.toStdString());
        m_currentlyDisplayedLogBranch = currentBranchInCombo.toStdString();
    } else {
        if(networkLogDisplay) networkLogDisplay->append("Refreshing commit log for current HEAD.");
        loadCommitLog();
    }
}

void MainWindow::onRefreshBranchesClicked() {
    if (gitBackend.isRepositoryOpen()) {
        loadBranchList();
        if(messageLog) messageLog->append("Branch list refreshed.");
    } else {
        if(messageLog) messageLog->append("No repository open to refresh branches.");
    }
}

void MainWindow::onManagedRepoDoubleClicked(QListWidgetItem* item) {
    if (!item || !m_repoManager_ptr) { // Guard against null pointers
        qWarning() << "MainWindow::onManagedRepoDoubleClicked: Null item or repo manager.";
        return;
    }

    QString appId = item->data(Qt::UserRole).toString(); // We stored appId in UserRole
    if (appId.isEmpty()) {
        qWarning() << "MainWindow: Managed repo item double-clicked, but no AppID found in item data.";
        if(messageLog) messageLog->append("<font color='red'>Error: Could not identify selected managed repository.</font>");
        return;
    }

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty() || repoInfo.localPath.isEmpty()) { // Check if a valid repo was found
        qWarning() << "MainWindow: Could not retrieve info for managed repo with AppID:" << appId;
        if(messageLog) messageLog->append("<font color='red'>Error: Could not retrieve details for selected managed repository.</font>");
        return;
    }

    qDebug() << "MainWindow: Double-clicked managed repo:" << repoInfo.displayName << "Path:" << repoInfo.localPath;

    // Now, try to open this repository using GitBackend
    std::string errorMessage;
    if (gitBackend.openRepository(repoInfo.localPath.toStdString(), errorMessage)) {
        if(messageLog) messageLog->append("<font color=\"green\">Opened managed repository: " + repoInfo.displayName.toHtmlEscaped() + 
                                          " (" + QDir::toNativeSeparators(repoInfo.localPath).toHtmlEscaped() + ")</font>");
        if(repoPathInput) repoPathInput->setText(QDir::toNativeSeparators(repoInfo.localPath)); // Update the path input field
        updateRepositoryStatus(); // This will load its log, branches, etc.
    } else {
        if(messageLog) messageLog->append("<font color=\"red\">Failed to open managed repository '" + repoInfo.displayName.toHtmlEscaped() + 
                                          "': " + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        QMessageBox::critical(this, "Open Repository Failed",
                              "Could not open the selected managed repository: " + repoInfo.displayName +
                              "\nPath: " + repoInfo.localPath +
                              "\nError: " + QString::fromStdString(errorMessage));
        updateRepositoryStatus(); // Still call to clear any old repo state if open failed
    }
}

void MainWindow::onCheckoutBranchClicked() {
    if (!gitBackend.isRepositoryOpen()){
        if(messageLog) messageLog->append("<font color=\"red\">No repository open.</font>");
        return;
    }
    QString selectedBranchQStr = branchComboBox->currentText();
    if (selectedBranchQStr.isEmpty()) {
        if(messageLog) messageLog->append("<font color=\"red\">No branch selected.</font>");
        QMessageBox::warning(this, "Action Error", "No branch selected from the dropdown.");
        return;
    }

    std::string selectedBranchName = selectedBranchQStr.toStdString();
    std::string error_message_op;
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
        if(messageLog) messageLog->append("<font color=\"orange\">Warning: Could not list local branches to determine type: " + QString::fromStdString(error_msg_local_list).toHtmlEscaped() + "</font>");
 
        is_actually_local_branch = (selectedBranchName.find('/') == std::string::npos && 
                                   (!selectedBranchName.empty() && selectedBranchName[0] != '[') ); // <<< CORRECTED LINE
    }

    if (is_actually_local_branch) {
        if (gitBackend.checkoutBranch(selectedBranchName, error_message_op)) {
            if(messageLog) messageLog->append("<font color=\"green\">" + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            m_currentlyDisplayedLogBranch = "";
            updateRepositoryStatus();
        } else {
            if(messageLog) messageLog->append("<font color=\"red\">Error checking out branch '" + selectedBranchQStr.toHtmlEscaped() + "': " + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Checkout Failed", "Could not checkout branch: " + selectedBranchQStr + "\nError: " + QString::fromStdString(error_message_op));
        }
    } else {
        if(networkLogDisplay) networkLogDisplay->append("Displaying commit history for: <b>" + selectedBranchQStr.toHtmlEscaped() + "</b> (Current HEAD unchanged)");
        loadCommitLogForBranch(selectedBranchName);
        m_currentlyDisplayedLogBranch = selectedBranchName;
    }
}

// --- RepositoryManager Slot Implementation ---
void MainWindow::handleRepositoryListChanged() {
    if (!m_repoManager_ptr || !managedReposListWidget) return;
    managedReposListWidget->clear();
    QList<ManagedRepositoryInfo> repos = m_repoManager_ptr->getAllManagedRepositories();
    if (repos.isEmpty()){
         managedReposListWidget->addItem("<i>No repositories managed yet. Click 'Add...'</i>");
    } else {
        for (const auto& repoInfo : repos) {
            QString itemText = QString("%1 (%2)\n  Path: %3")
                               .arg(repoInfo.displayName.toHtmlEscaped())
                               .arg(repoInfo.isPublic ? "Public" : "Private")
                               .arg(QDir::toNativeSeparators(repoInfo.localPath).toHtmlEscaped());
            QListWidgetItem* item = new QListWidgetItem(itemText, managedReposListWidget);
            item->setData(Qt::UserRole, repoInfo.appId);
            item->setToolTip(QString("ID: %1\nAdmin: %2").arg(repoInfo.appId).arg(repoInfo.adminPeerId.toHtmlEscaped()));
        }
    }
}

void MainWindow::onAddManagedRepoClicked() {
    if (!m_repoManager_ptr) {
        QMessageBox::critical(this, "Error", "Repository Manager not initialized.");
        return;
    }

    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Select Git Repository Folder to Manage"),
                                                        QDir::homePath(),
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty()) {
        if(messageLog) messageLog->append("Add managed repository cancelled by user.");
        return;
    }

    // Validate if it's a Git repository before adding
    std::string tempError;
    GitBackend tempGitBackend; // Use a temporary GitBackend to check
    if (!tempGitBackend.openRepository(dirPath.toStdString(), tempError)) {
        QMessageBox::warning(this, "Not a Git Repository", 
            "The selected directory does not appear to be a valid Git repository or could not be opened.\nError: " + QString::fromStdString(tempError));
        return;
    }
    // tempGitBackend goes out of scope, repo closed.

    ManagedRepositoryInfo existingInfo = m_repoManager_ptr->getRepositoryInfoByPath(dirPath);
    if(!existingInfo.appId.isEmpty()){
        QMessageBox::information(this, "Already Managed", "This repository path is already managed:\n" + existingInfo.displayName);
        return;
    }

    QString repoName = QFileInfo(dirPath).fileName();
    if (repoName.isEmpty()) repoName = QDir(dirPath).dirName();
    if (repoName.isEmpty()) repoName = "Unnamed Repo";

    bool ok_name_prompt;
    QString displayName = QInputDialog::getText(this, "Manage Repository",
                                            "Enter a display name for this repository:",
                                            QLineEdit::Normal, repoName, &ok_name_prompt);
    if (!ok_name_prompt) { // User cancelled name input
        if(messageLog) messageLog->append("Add managed repository cancelled (name input).");
        return;
    }
    QString finalDisplayName = displayName.isEmpty() ? repoName : displayName;

    bool isPublic = (QMessageBox::question(this, "Set Visibility", 
                                           "Make this repository public on the P2P network (discoverable by others)?", 
                                           QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes);

    if (m_repoManager_ptr->addManagedRepository(dirPath, finalDisplayName, isPublic, m_myUsername)) {
        if(messageLog) messageLog->append("<font color=\"green\">Repository '" + finalDisplayName.toHtmlEscaped() + "' added to management.</font>");
    } else {
        if(messageLog) messageLog->append("<font color=\"red\">Failed to add '" + finalDisplayName.toHtmlEscaped() + "' to management. It might already be managed by path or an error occurred.</font>");
        QMessageBox::warning(this, "Add Repository Failed", "Could not add the repository to management. Check logs for details (it might already be listed).");
    }
    // The list will be updated by handleRepositoryListChanged via the signal
}


// --- Network SLOTS Implementation ---
void MainWindow::onToggleDiscoveryAndTcpServerClicked() {
    if (!m_networkManager_ptr || !m_identityManager_ptr) {
        QMessageBox::critical(this, "Service Error", "Network or Identity manager not ready.");
        return;
    }
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
    if (!m_networkManager_ptr) return;
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
        if(networkLogDisplay) networkLogDisplay->append("Attempting TCP to discovered: " + peerUsername.toHtmlEscaped() + " @ " + peerIpStr + ":" + QString::number(peerTcpPort));
        m_networkManager_ptr->connectToTcpPeer(QHostAddress(peerIpStr), peerTcpPort, peerUsername);
    } else {
        if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">Could not parse peer info: " + item->text().toHtmlEscaped() + "</font>");
    }
}

void MainWindow::onSendMessageClicked() {
    if (!m_networkManager_ptr) return;
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
    if (!tcpServerStatusLabel || !toggleDiscoveryButton || !myPeerInfoLabel || !m_identityManager_ptr) return;

    if (listening) {
        tcpServerStatusLabel->setText("TCP Server: Listening on port <b>" + QString::number(port) + "</b>");
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...\nTCP Port: %3")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10))
                                 .arg(port));
    } else {
        tcpServerStatusLabel->setText("TCP Server: Inactive");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10)));

        if (!error.isEmpty()) {
            if(networkLogDisplay) networkLogDisplay->append("<font color=\"red\">TCP Server error/stopped: " + error.toHtmlEscaped() + "</font>");
        } else {
            // Only log "stopped" if the button text indicates it *was* running
            if(networkLogDisplay && toggleDiscoveryButton->text() == "Start Discovery & TCP Server") { // It means it was just stopped
                 // Check if it was an intentional stop or a failure to start initially
                 if (tcpServerStatusLabel->text().contains("Listening")) { // If it was actually listening before stopping
                    // This condition is tricky here, as the label is already "Inactive"
                    // A better state check in NetworkManager might be needed if this log is crucial.
                 }
            } else if (networkLogDisplay) {
                // If button still says "Stop...", it means it failed to start. Error handled by NetworkManager.
                // Or, it was stopped by user.
                if(port !=0) { // If port is not 0, it means it was trying to listen or was listening
                     networkLogDisplay->append("TCP Server stopped.");
                }
            }
        }
    }
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port, const QString& discoveredUsername) {
    if (!m_networkManager_ptr || !networkLogDisplay) return;
    QString peerDisplay = discoveredUsername;
    if (discoveredUsername.isEmpty() || discoveredUsername.startsWith("Unknown")) {
        peerDisplay = address.toString() + ":" + QString::number(port);
    }

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Incoming Connection Request",
                                  QString("Accept incoming TCP connection from '%1'?").arg(peerDisplay.toHtmlEscaped()),
                                  QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        networkLogDisplay->append("<font color=\"blue\">User accepted connection from " + peerDisplay.toHtmlEscaped() + "</font>");
        m_networkManager_ptr->acceptPendingTcpConnection(pendingSocket);
    } else {
        networkLogDisplay->append("<font color=\"orange\">User rejected connection from " + peerDisplay.toHtmlEscaped() + "</font>");
        m_networkManager_ptr->rejectPendingTcpConnection(pendingSocket);
    }
}

void MainWindow::handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerUsername, const QString& peerPublicKeyHex) {
    if(!connectedTcpPeersList || !networkLogDisplay) return;
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
    networkLogDisplay->append("<font color=\"green\">TCP Peer fully connected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerUsername) {
    if(!connectedTcpPeersList || !networkLogDisplay) return;
    Q_UNUSED(peerSocket);
    for (int i = 0; i < connectedTcpPeersList->count(); ++i) {
        if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerUsername) {
            delete connectedTcpPeersList->takeItem(i);
            break;
        }
    }
    networkLogDisplay->append("<font color=\"orange\">TCP Peer disconnected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerUsername, const QString& message) {
    if(!networkLogDisplay) return;
    Q_UNUSED(peerSocket);
    networkLogDisplay->append("<b>" + peerUsername.toHtmlEscaped() + ":</b> " + message.toHtmlEscaped());
}

void MainWindow::handleTcpConnectionStatusChanged(const QString& peerUsernameOrAddress, const QString& peerPublicKeyHex, bool connected, const QString& error) {
    if(!networkLogDisplay) return;
    if (connected) {
        networkLogDisplay->append("<font color=\"green\">TCP to " + peerUsernameOrAddress.toHtmlEscaped() + " established (PK: " + (peerPublicKeyHex.isEmpty() ? "NO" : "YES") + "). Awaiting handshake.</font>");
    } else {
        networkLogDisplay->append("<font color=\"red\">Failed TCP connection to " + peerUsernameOrAddress.toHtmlEscaped() + ": " + error.toHtmlEscaped() + "</font>");
    }
}

void MainWindow::handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo) {
    if(!discoveredPeersList || !networkLogDisplay) return;
    QString itemText = peerInfo.id + " (" + peerInfo.address.toString() + ":" + QString::number(peerInfo.tcpPort) + ")";
    if(!peerInfo.publicKeyHex.isEmpty()){
        itemText += " [PKH:" + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(),QCryptographicHash::Sha1).toHex().left(6) + "]";
    }

    if (!peerInfo.publicRepoNames.isEmpty()) { 
        itemText += "\n  Offers: " + peerInfo.publicRepoNames.join(", ");
    }

    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerInfo.id, Qt::MatchStartsWith); // Match by username/ID

    if (!items.isEmpty()) {
        items.first()->setText(itemText); // Update text
        // Update data too
        items.first()->setData(Qt::UserRole, peerInfo.address.toString());
        items.first()->setData(Qt::UserRole + 1, peerInfo.tcpPort);
        items.first()->setData(Qt::UserRole + 2, peerInfo.id);
        items.first()->setData(Qt::UserRole + 3, peerInfo.publicKeyHex);
        // If you want to store the repo list in item data (more complex for QListWidget display)
        // QVariantList repoListVariant;
        // for(const QString& repoName : peerInfo.publicRepoNames) repoListVariant.append(repoName);
        // items.first()->setData(Qt::UserRole + 4, repoListVariant);
    } else {
        QListWidgetItem* newItem = new QListWidgetItem(itemText, discoveredPeersList);
        newItem->setData(Qt::UserRole, peerInfo.address.toString());
        newItem->setData(Qt::UserRole + 1, peerInfo.tcpPort);
        newItem->setData(Qt::UserRole + 2, peerInfo.id);
        newItem->setData(Qt::UserRole + 3, peerInfo.publicKeyHex);
        // newItem->setData(Qt::UserRole + 4, QVariant::fromValue(peerInfo.publicRepoNames));
    }
}

void MainWindow::handleLanPeerLost(const QString& peerUsername) {
    if(!discoveredPeersList || !networkLogDisplay) return;
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerUsername, Qt::MatchStartsWith); // Match by username/ID
    if (!items.isEmpty()) {
        delete discoveredPeersList->takeItem(discoveredPeersList->row(items.first()));
    }
    networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerUsername.toHtmlEscaped() + "</font>");
}