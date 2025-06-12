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
#include <QStandardPaths>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_currentlyDisplayedLogBranch(""),
      m_myUsername("DefaultUser"),
      m_identityManager_ptr(nullptr),
      m_networkManager_ptr(nullptr),
      m_repoManager_ptr(nullptr)
{
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
        m_myUsername = name_prompt_default;
    }

    // 2. Initialize IdentityManager
    m_identityManager_ptr = new IdentityManager(m_myUsername);
    if (!m_identityManager_ptr || !m_identityManager_ptr->initializeKeys()) {
        QMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! Network features may be disabled or insecure.");
    }

    // 3. Initialize RepositoryManager
    QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir configAppDir(configPath);
    QString appSpecificDirName = "P2PGitClient";
    if (!configAppDir.exists(appSpecificDirName)) {
        if(!configAppDir.mkdir(appSpecificDirName)) {
            qWarning() << "MainWindow: Could not create base app config directory:" << configAppDir.filePath(appSpecificDirName);
        }
    }
    configAppDir.cd(appSpecificDirName);
    if (!configAppDir.exists(m_myUsername)) {
        if(!configAppDir.mkdir(m_myUsername)) {
            qWarning() << "MainWindow: Could not create user-specific config directory:" << configAppDir.filePath(m_myUsername);
        }
    }
    configAppDir.cd(m_myUsername);
    QString repoManagerStorageFile = configAppDir.filePath("managed_repositories.json");
    m_repoManager_ptr = new RepositoryManager(repoManagerStorageFile, this);


    // 4. Initialize NetworkManager
    if (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized() && m_repoManager_ptr) {
        m_networkManager_ptr = new NetworkManager(m_myUsername, m_identityManager_ptr, m_repoManager_ptr, this);
    } else {
        QMessageBox::critical(this, "Core Services Error", "Cannot initialize network or repository services due to prior initialization failures.");
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

    if (m_repoManager_ptr) {
        if(addManagedRepoButton) {
             connect(addManagedRepoButton, &QPushButton::clicked, this, &MainWindow::onAddManagedRepoClicked);
        }
        if(managedReposListWidget){
             connect(managedReposListWidget, &QListWidget::itemDoubleClicked, this, &MainWindow::onManagedRepoDoubleClicked);
        }
        connect(m_repoManager_ptr, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::handleRepositoryListChanged);
    }

    if (m_networkManager_ptr) {
        connect(toggleDiscoveryButton, &QPushButton::clicked, this, &MainWindow::onToggleDiscoveryAndTcpServerClicked);
        connect(sendMessageButton, &QPushButton::clicked, this, &MainWindow::onSendMessageClicked);
        if(discoveredPeersTreeWidget) { // Use TreeWidget here
            connect(discoveredPeersTreeWidget, &QTreeWidget::currentItemChanged, this, &MainWindow::onDiscoveredPeerOrRepoSelected);
            // connect(discoveredPeersTreeWidget, &QTreeWidget::itemDoubleClicked, this, &MainWindow::onDiscoveredTreeItemDoubleClicked); // If you want double click on peer to connect
        }
        if(cloneSelectedRepoButton){
            connect(cloneSelectedRepoButton, &QPushButton::clicked, this, &MainWindow::onCloneSelectedRepoClicked);
        }
        connect(m_networkManager_ptr, &NetworkManager::tcpServerStatusChanged, this, &MainWindow::handleTcpServerStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager_ptr, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handleNewTcpPeerConnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handleTcpPeerDisconnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpMessageReceived, this, &MainWindow::handleTcpMessageReceived);
        connect(m_networkManager_ptr, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handleLanPeerDiscoveredOrUpdated);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerLost, this, &MainWindow::handleLanPeerLost);
        connect(m_networkManager_ptr, &NetworkManager::repoBundleRequestedByPeer, this, &MainWindow::handleRepoBundleRequest);

    } else {
        if(toggleDiscoveryButton) toggleDiscoveryButton->setEnabled(false);
        if(sendMessageButton) sendMessageButton->setEnabled(false);
        if(discoveredPeersTreeWidget) discoveredPeersTreeWidget->setEnabled(false);
        if(cloneSelectedRepoButton) cloneSelectedRepoButton->setEnabled(false);
        if(connectedTcpPeersList) connectedTcpPeersList->setEnabled(false);
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Network services disabled (init failure).</font>");
        if(tcpServerStatusLabel) tcpServerStatusLabel->setText("TCP Server: OFFLINE (Init Error)");
    }
    updateRepositoryStatus();
    if(m_repoManager_ptr) handleRepositoryListChanged();
}

MainWindow::~MainWindow() {
    delete m_identityManager_ptr;
    m_identityManager_ptr = nullptr;
    // m_repoManager_ptr and m_networkManager_ptr are QObjects parented to `this`, Qt deletes them.
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
    openRepoButton = new QPushButton("Open Existing (Local Git Repo)", this);
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

    QWidget *gitOpsPaneWidget = new QWidget(overallSplitter);
    QVBoxLayout *gitOpsPaneLayout = new QVBoxLayout(gitOpsPaneWidget);
    QLabel *commitLogTitleLabel = new QLabel("Commit History (Current Branch/Ref):", gitOpsPaneWidget);
    gitOpsPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(gitOpsPaneWidget);
    commitLogDisplay->setReadOnly(true); commitLogDisplay->setFontFamily("monospace"); commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap);
    gitOpsPaneLayout->addWidget(commitLogDisplay, 1);
    refreshLogButton = new QPushButton("Refresh Log", gitOpsPaneWidget);
    gitOpsPaneLayout->addWidget(refreshLogButton);
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

    setupRepoManagementUi(overallSplitter);
    setupNetworkUi(overallSplitter);

    QList<int> overallSplitterSizes; overallSplitterSizes << 400 << 300 << 350; 
    overallSplitter->setSizes(overallSplitterSizes);
    mainVLayout->addWidget(overallSplitter, 1);
    setCentralWidget(centralWidget);
    resize(1250, 750);
}

void MainWindow::setupRepoManagementUi(QSplitter* parentSplitter) {
    repoManagementFrame = new QFrame(parentSplitter);
    repoManagementFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* repoMgmtLayout = new QVBoxLayout(repoManagementFrame);
    repoMgmtLayout->addWidget(new QLabel("<b>Managed Repositories:</b>", repoManagementFrame));
    addManagedRepoButton = new QPushButton("Add Local Folder to Manage", repoManagementFrame);
    repoMgmtLayout->addWidget(addManagedRepoButton);
    managedReposListWidget = new QListWidget(repoManagementFrame);
    managedReposListWidget->setToolTip("List of repositories. Double-click to open.");
    repoMgmtLayout->addWidget(managedReposListWidget, 1);
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
    myPeerInfoLabel = new QLabel(this);
    myPeerInfoLabel->setWordWrap(true);
    myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                             .arg(m_myUsername.toHtmlEscaped())
                             .arg(m_identityManager_ptr ? QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10) : "N/A"));
    networkVLayout->addWidget(myPeerInfoLabel);
    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame);
    networkVLayout->addWidget(tcpServerStatusLabel);
    networkVLayout->addWidget(new QLabel("Discovered Peers & Repos on LAN:", networkFrame)); // Updated Label
    discoveredPeersTreeWidget = new QTreeWidget(networkFrame); // Changed to QTreeWidget
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->setColumnWidth(0, 220);
    discoveredPeersTreeWidget->setToolTip("Select a repository under a peer to enable Clone button.");
    networkVLayout->addWidget(discoveredPeersTreeWidget, 1); // Stretch
    cloneSelectedRepoButton = new QPushButton("Clone Selected Repository", networkFrame);
    cloneSelectedRepoButton->setEnabled(false);
    networkVLayout->addWidget(cloneSelectedRepoButton);
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
    parentSplitter->addWidget(networkFrame);
}

// --- Git related method implementations ---
void MainWindow::updateRepositoryStatus() {
    bool repoIsOpen = gitBackend.isRepositoryOpen();
    if(refreshLogButton) refreshLogButton->setEnabled(repoIsOpen);
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
        if (m_repoManager_ptr) {
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
        if (m_repoManager_ptr) {
            ManagedRepositoryInfo existingManaged = m_repoManager_ptr->getRepositoryInfoByPath(dirPath);
            if(existingManaged.appId.isEmpty()){
                QString repoName = QFileInfo(dirPath).fileName();
                if (repoName.isEmpty()) repoName = QDir(dirPath).dirName();
                if (repoName.isEmpty()) repoName = "Unnamed Opened Repo";
                
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Manage Repository",
                                          QString("Add '%1' to managed repositories?").arg(repoName.toHtmlEscaped()),
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

    QString currentBranchInCombo = branchComboBox->currentText();
    bool viewingSpecificRef = (!m_currentlyDisplayedLogBranch.empty() && m_currentlyDisplayedLogBranch == currentBranchInCombo.toStdString()) ||
                              (currentBranchInCombo.contains('/') && !currentBranchInCombo.startsWith("[D")); // Match "[Detached..."

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
    if (!item || !m_repoManager_ptr) {
        qWarning() << "MainWindow::onManagedRepoDoubleClicked: Null item or repo manager.";
        return;
    }

    QString appId = item->data(Qt::UserRole).toString();
    if (appId.isEmpty()) {
        qWarning() << "MainWindow: Managed repo item double-clicked, but no AppID found in item data.";
        if(messageLog) messageLog->append("<font color='red'>Error: Could not identify selected managed repository.</font>");
        return;
    }

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty() || repoInfo.localPath.isEmpty()) {
        qWarning() << "MainWindow: Could not retrieve info for managed repo with AppID:" << appId;
        if(messageLog) messageLog->append("<font color='red'>Error: Could not retrieve details for selected managed repository.</font>");
        return;
    }

    qDebug() << "MainWindow: Double-clicked managed repo:" << repoInfo.displayName << "Path:" << repoInfo.localPath;

    std::string errorMessage;
    if (gitBackend.openRepository(repoInfo.localPath.toStdString(), errorMessage)) {
        if(messageLog) messageLog->append("<font color=\"green\">Opened managed repository: " + repoInfo.displayName.toHtmlEscaped() +
                                          " (" + QDir::toNativeSeparators(repoInfo.localPath).toHtmlEscaped() + ")</font>");
        if(repoPathInput) repoPathInput->setText(QDir::toNativeSeparators(repoInfo.localPath));
        updateRepositoryStatus();
    } else {
        if(messageLog) messageLog->append("<font color=\"red\">Failed to open managed repository '" + repoInfo.displayName.toHtmlEscaped() +
                                          "': " + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        QMessageBox::critical(this, "Open Repository Failed",
                              "Could not open the selected managed repository: " + repoInfo.displayName +
                              "\nPath: " + repoInfo.localPath +
                              "\nError: " + QString::fromStdString(errorMessage));
        updateRepositoryStatus();
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
                                   (!selectedBranchName.empty() && selectedBranchName[0] != '[') );
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

    std::string tempError;
    GitBackend tempGitBackend;
    if (!tempGitBackend.openRepository(dirPath.toStdString(), tempError)) {
        QMessageBox::warning(this, "Not a Git Repository",
            "The selected directory does not appear to be a valid Git repository or could not be opened.\nError: " + QString::fromStdString(tempError));
        return;
    }

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
    if (!ok_name_prompt) {
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
        QMessageBox::warning(this, "Add Repository Failed", "Could not add the repository to management. Check logs.");
    }
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

void MainWindow::onDiscoveredPeerOrRepoSelected(QTreeWidgetItem* current, QTreeWidgetItem* previous) {
    Q_UNUSED(previous);
    if (!cloneSelectedRepoButton) return;

    cloneSelectedRepoButton->setEnabled(false); 
    if (current) {
        if (current->parent()) { // If it has a parent, it's a repo item
            cloneSelectedRepoButton->setEnabled(true);
        }
    }
}

void MainWindow::onCloneSelectedRepoClicked() {
    if (!m_networkManager_ptr || !m_repoManager_ptr || !discoveredPeersTreeWidget) {
        QMessageBox::critical(this, "Error", "Core services not ready for cloning.");
        return;
    }

    QTreeWidgetItem* currentItem = discoveredPeersTreeWidget->currentItem();
    if (!currentItem || !currentItem->parent()) {
        QMessageBox::warning(this, "Select Repository", "Please select a specific repository from a peer to clone.");
        return;
    }

    QString repoNameToClone = currentItem->data(0, Qt::UserRole).toString();
    QString parentPeerUsername = currentItem->data(0, Qt::UserRole + 1).toString();

    QTcpSocket* providerSocket = m_networkManager_ptr->getSocketForPeer(parentPeerUsername);

    if (!providerSocket) {
        // Attempt to connect first if not already connected
        QTreeWidgetItem* peerItem = currentItem->parent();
        if(peerItem){
            DiscoveredPeerInfo providerPeerInfo = peerItem->data(0, Qt::UserRole).value<DiscoveredPeerInfo>();
            if(!providerPeerInfo.id.isEmpty()){
                if(networkLogDisplay) networkLogDisplay->append("Initiating TCP connection to " + providerPeerInfo.id + " for cloning...");
                bool connected = m_networkManager_ptr->connectToTcpPeer(providerPeerInfo.address, providerPeerInfo.tcpPort, providerPeerInfo.id);
                // This is async. We'd need to queue the clone request until connection & handshake complete.
                // For now, tell user to connect first.
                if(!connected){ // if connectToHost itself indicated an immediate issue (rare)
                     QMessageBox::warning(this, "Connection Error", "Could not initiate connection to peer: " + parentPeerUsername + "\nPlease ensure a TCP connection manually first for now.");
                     return;
                }
                 QMessageBox::information(this, "Connection Initiated", "Attempting to connect to " + parentPeerUsername + ". Please wait for connection and try cloning again if it succeeds.");
                return;
            }
        }
        QMessageBox::warning(this, "Connection Error", "Not currently connected via TCP to peer: " + parentPeerUsername + "\nPlease establish a TCP connection first (e.g., by double-clicking the peer item if that feature is added, or wait for auto-connect feature).");
        return;
    }

    QString localClonePathBase = QFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Repository Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty()) {
        if (networkLogDisplay) networkLogDisplay->append("Clone cancelled by user (no directory selected).");
        return;
    }

    QString suggestedRepoDirName = QFileInfo(repoNameToClone).fileName();
    if (suggestedRepoDirName.isEmpty() || suggestedRepoDirName == "." || suggestedRepoDirName == "..") {
        suggestedRepoDirName = "cloned_" + repoNameToClone.remove(QRegExp(QStringLiteral("[^a-zA-Z0-9_.-]"))).left(30);
        if (suggestedRepoDirName == "cloned_") suggestedRepoDirName = "cloned_repository";
    }
    
    QString fullLocalClonePath = QDir(localClonePathBase).filePath(suggestedRepoDirName);

    if (QDir(fullLocalClonePath).exists()) {
        QMessageBox::warning(this, "Clone Error", "Target directory already exists:\n" + fullLocalClonePath + "\nPlease choose a different location or clear the existing directory.");
        return;
    }

    if(networkLogDisplay) networkLogDisplay->append(QString("Requesting to clone '%1' from peer '%2' into '%3'")
                                  .arg(repoNameToClone.toHtmlEscaped())
                                  .arg(parentPeerUsername.toHtmlEscaped())
                                  .arg(fullLocalClonePath.toHtmlEscaped()));

    m_networkManager_ptr->sendRepoBundleRequest(providerSocket, repoNameToClone, fullLocalClonePath);

    if(cloneSelectedRepoButton) cloneSelectedRepoButton->setEnabled(false); 
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
             if(networkLogDisplay && toggleDiscoveryButton->text() == "Start Discovery & TCP Server" && port !=0) { 
                 networkLogDisplay->append("TCP Server stopped.");
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
    if(!discoveredPeersTreeWidget) return; // Use TreeWidget

    QList<QTreeWidgetItem*> foundItems = discoveredPeersTreeWidget->findItems(peerInfo.id, Qt::MatchExactly | Qt::MatchRecursive, 0);
    QTreeWidgetItem* peerItem = nullptr;

    QString pkHashStr = QString(QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(6)); // Convert to QString
    QString peerDetails = QString("(%1:%2) [PKH:%3]")
                            .arg(peerInfo.address.toString())
                            .arg(peerInfo.tcpPort)
                            .arg(pkHashStr); // <<< USE THE QSTRING VARIABLE

    if (foundItems.isEmpty()) {
        peerItem = new QTreeWidgetItem(discoveredPeersTreeWidget);
        peerItem->setText(0, peerInfo.id);
        discoveredPeersTreeWidget->addTopLevelItem(peerItem);
    } else {
        peerItem = foundItems.first();
    }
    peerItem->setText(1, peerDetails);
    peerItem->setData(0, Qt::UserRole, QVariant::fromValue(peerInfo)); // Store full DiscoveredPeerInfo on peer item

    // Clear existing repo children before re-adding to prevent duplicates
    qDeleteAll(peerItem->takeChildren());

    if (!peerInfo.publicRepoNames.isEmpty()) {
        for (const QString& repoName : peerInfo.publicRepoNames) {
            QTreeWidgetItem* repoItem = new QTreeWidgetItem(peerItem);
            repoItem->setText(0, "  └── " + repoName);
            repoItem->setData(0, Qt::UserRole, repoName); // Store repo name
            repoItem->setData(0, Qt::UserRole + 1, peerInfo.id); // Store parent peer ID
            repoItem->setText(1, "Public");
        }
        peerItem->setExpanded(true);
    }
}

void MainWindow::handleLanPeerLost(const QString& peerUsername) {
    if(!discoveredPeersTreeWidget || !networkLogDisplay) return;
    QList<QTreeWidgetItem*> items = discoveredPeersTreeWidget->findItems(peerUsername, Qt::MatchExactly | Qt::MatchRecursive, 0);
    if (!items.isEmpty()) {
        delete items.first(); // This will remove the item and its children from the tree
    }
    networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerUsername.toHtmlEscaped() + "</font>");
}

// Slot for handling bundle request (Provider side)
void MainWindow::handleRepoBundleRequest(QTcpSocket* requestingPeerSocket, const QString& sourcePeerUsername, const QString& repoDisplayName, const QString& clientWantsToSaveAt) {
    if (!m_repoManager_ptr || !m_networkManager_ptr || !gitBackend.isRepositoryOpen()) { // Check if a repo is open to bundle
         if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Received bundle request, but no local repo is active to bundle, or services not ready.</font>");
        // TODO: Send error back
        return;
    }
    qDebug() << "MainWindow: Received request for bundle of" << repoDisplayName << "from" << sourcePeerUsername;
    if (networkLogDisplay) networkLogDisplay->append(QString("Received request from %1 to clone repo '%2'. They plan to save at '%3'")
                                                    .arg(sourcePeerUsername.toHtmlEscaped())
                                                    .arg(repoDisplayName.toHtmlEscaped())
                                                    .arg(clientWantsToSaveAt.toHtmlEscaped()));

    ManagedRepositoryInfo repoToBundle;
    bool found = false;
    // We should bundle the currently *active* gitBackend repository if its display name matches,
    // or iterate m_repoManager_ptr to find the repo by display name if that's how it's requested.
    // For now, let's assume the request is for the *currently open repository* if the name matches.
    // This needs to be more robust: the request should ideally use a unique repo ID.

    // Get current open repo path from gitBackend
    std::string currentOpenRepoPathStd = gitBackend.getCurrentRepositoryPath();
    if(currentOpenRepoPathStd.empty()){
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>No repository currently open in GitBackend to fulfill bundle request for '" + repoDisplayName.toHtmlEscaped() + "'.</font>");
        return;
    }
    QString currentOpenRepoPathQ = QString::fromStdString(currentOpenRepoPathStd);
    
    // Find this path in the managed repositories to get its display name and visibility
    ManagedRepositoryInfo currentManagedInfo = m_repoManager_ptr->getRepositoryInfoByPath(currentOpenRepoPathQ);

    if (currentManagedInfo.appId.isEmpty() || currentManagedInfo.displayName != repoDisplayName) {
         if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Requested repo '" + repoDisplayName.toHtmlEscaped() + "' does not match currently open and managed repo OR not found.</font>");
        // TODO: Send REPO_BUNDLE_ERROR
        return;
    }
    
    repoToBundle = currentManagedInfo;
    found = true;


    if (!found) { // This check is now somewhat redundant if we only bundle the active repo
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Requested repo '" + repoDisplayName.toHtmlEscaped() + "' not found in managed list.</font>");
        return;
    }

    if (!repoToBundle.isPublic) {
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Requested repo '" + repoDisplayName.toHtmlEscaped() + "' is private. Access denied for bundle.</font>");
        return;
    }

    std::string bundleFilePathStd;
    std::string errorMsgBundle;
    QString tempBundleDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/P2PGitBundles/" + QUuid::createUuid().toString();
    QDir().mkpath(tempBundleDir); 

    QString bundleBaseName = QFileInfo(repoToBundle.localPath).fileName();
    if (bundleBaseName.isEmpty()) bundleBaseName = "repo_bundle_" + repoToBundle.appId;
    
    if (gitBackend.createBundle(tempBundleDir.toStdString(), bundleBaseName.toStdString(), bundleFilePathStd, errorMsgBundle)) {
        if(networkLogDisplay) networkLogDisplay->append("<font color='green'>Bundle created: " + QString::fromStdString(bundleFilePathStd) + "</font>");
        
        // TODO: Implement actual file transfer via NetworkManager
        // m_networkManager_ptr->startSendingBundle(requestingPeerSocket, repoToBundle.displayName, QString::fromStdString(bundleFilePathStd));
        QMessageBox::information(this, "Bundle Request Processed", "Bundle created for " + repoDisplayName + " at " + QString::fromStdString(bundleFilePathStd) + "\n(File transfer sequence to peer not yet implemented)");
        
        // For now, we won't delete the bundle immediately to allow inspection.
        // In a real scenario, delete after successful transfer or if transfer fails to start.
        // QFile::remove(QString::fromStdString(bundleFilePathStd));
    } else {
        if(networkLogDisplay) networkLogDisplay->append("<font color='red'>Failed to create bundle for '" + repoToBundle.displayName.toHtmlEscaped() + "': " + QString::fromStdString(errorMsgBundle).toHtmlEscaped() + "</font>");
    }
}