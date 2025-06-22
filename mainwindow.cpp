#include "mainwindow.h"
#include "identity_manager.h"
#include "repository_manager.h"
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
#include <QProcess>
#include <QUuid>
#include <QStyle>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_currentlyDisplayedLogBranch(""),
      m_myUsername("DefaultUser"),
      m_identityManager_ptr(nullptr),
      m_networkManager_ptr(nullptr),
      m_repoManager_ptr(nullptr)
{
    setupUi();

    bool ok_name;
    QString name_prompt_default = QHostInfo::localHostName();
    if (name_prompt_default.isEmpty())
    {
        name_prompt_default = "Peer" + QString::number(QRandomGenerator::global()->bounded(10000));
    }
    QString name_from_dialog = QInputDialog::getText(this, tr("Enter Your Peer Name"),
                                                     tr("Peer Name (for discovery):"), QLineEdit::Normal,
                                                     name_prompt_default, &ok_name);
    if (ok_name && !name_from_dialog.isEmpty())
    {
        m_myUsername = name_from_dialog;
    }
    else
    {
        m_myUsername = name_from_dialog;
    }

    m_identityManager_ptr = new IdentityManager(m_myUsername);
    if (!m_identityManager_ptr || !m_identityManager_ptr->initializeKeys())
    {
        QMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! Network features will be disabled.");
    }

    QString baseConfigPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir configDir(baseConfigPath);
    configDir.mkpath("P2PGitClient/" + m_myUsername);
    QString repoManagerStorageFile = configDir.filePath("P2PGitClient/" + m_myUsername + "/managed_repositories.json");
    qDebug() << "RepositoryManager storage file path:" << repoManagerStorageFile;
    m_repoManager_ptr = new RepositoryManager(repoManagerStorageFile, this);

    if (m_identityManager_ptr && m_identityManager_ptr->areKeysInitialized() && m_repoManager_ptr)
    {
        m_networkManager_ptr = new NetworkManager(m_myUsername, m_identityManager_ptr, m_repoManager_ptr, this);
    }
    else
    {
        QMessageBox::warning(this, "Network Services Disabled", "Cannot initialize network services due to prior initialization failures.");
    }

    setWindowTitle("P2P Git Client - " + m_myUsername);

    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);
    connect(addManagedRepoButton, &QPushButton::clicked, this, &MainWindow::onAddManagedRepoClicked);
    connect(managedReposListWidget, &QListWidget::itemDoubleClicked, this, &MainWindow::onManagedRepoDoubleClicked);
    connect(m_repoManager_ptr, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::handleRepositoryListChanged);
    m_peerDisconnectedIcon = this->style()->standardIcon(QStyle::SP_ComputerIcon);
    m_peerConnectedIcon = this->style()->standardIcon(QStyle::SP_DialogYesButton);

    if (m_networkManager_ptr)
    {
        connect(connectToPeerButton, &QPushButton::clicked, this, &MainWindow::onConnectToPeerClicked);
        connect(toggleDiscoveryButton, &QPushButton::clicked, this, &MainWindow::onToggleDiscoveryAndTcpServerClicked);
        connect(sendMessageButton, &QPushButton::clicked, this, &MainWindow::onSendMessageClicked);
        connect(discoveredPeersTreeWidget, &QTreeWidget::currentItemChanged, this, &MainWindow::onDiscoveredPeerOrRepoSelected);
        connect(cloneSelectedRepoButton, &QPushButton::clicked, this, &MainWindow::onCloneSelectedRepoClicked);
        connect(m_networkManager_ptr, &NetworkManager::tcpServerStatusChanged, this, &MainWindow::handleTcpServerStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager_ptr, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handleNewTcpPeerConnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handleTcpPeerDisconnected);
        connect(m_networkManager_ptr, &NetworkManager::tcpMessageReceived, this, &MainWindow::handleTcpMessageReceived);
        connect(m_networkManager_ptr, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatusChanged);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handleLanPeerDiscoveredOrUpdated);
        connect(m_networkManager_ptr, &NetworkManager::lanPeerLost, this, &MainWindow::handleLanPeerLost);
        connect(m_networkManager_ptr, &NetworkManager::repoBundleRequestedByPeer, this, &MainWindow::handleRepoBundleRequest);
        connect(m_networkManager_ptr, &NetworkManager::repoBundleCompleted, this, &MainWindow::handleRepoBundleCompleted);
        connect(m_networkManager_ptr, &NetworkManager::repoBundleSent, this, &MainWindow::handleRepoBundleSent);
    }

    updateRepositoryStatus();
    handleRepositoryListChanged();
    updateNetworkUiState();
}

MainWindow::~MainWindow()
{
    qDebug() << "MainWindow destructor called.";
    delete m_identityManager_ptr;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    qDebug() << "Handling close event. Shutting down network services...";
    if (m_networkManager_ptr)
    {
        m_networkManager_ptr->stopUdpDiscovery();
        m_networkManager_ptr->stopTcpServer();
        m_networkManager_ptr->disconnectAllTcpPeers();
    }
    event->accept();
}

void MainWindow::updateNetworkUiState()
{
    bool networkReady = m_networkManager_ptr != nullptr;

    toggleDiscoveryButton->setEnabled(networkReady);
    sendMessageButton->setEnabled(networkReady);
    discoveredPeersTreeWidget->setEnabled(networkReady);
    connectedTcpPeersList->setEnabled(networkReady);

    // Buttons that depend on selection are handled in their own slot
    connectToPeerButton->setEnabled(false);
    cloneSelectedRepoButton->setEnabled(false);

    if (networkReady)
    {
        myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                     .arg(m_myUsername.toHtmlEscaped())
                                     .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10)));
    }
    else
    {
        myPeerInfoLabel->setText(QString("My Peer ID: %1\n<font color='red'>Keys not initialized!</font>").arg(m_myUsername.toHtmlEscaped()));
        networkLogDisplay->append("<font color='red'>Network services disabled (init failure).</font>");
        tcpServerStatusLabel->setText("TCP Server: OFFLINE (Init Error)");
    }
}

void MainWindow::setupUi()
{
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget);
    resize(1250, 750);

    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path or click Open/Initialize");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo_p2p"));
    initRepoButton = new QPushButton("Initialize Here", this);
    openRepoButton = new QPushButton("Open Existing (Local Git Repo)", this);
    pathActionLayout->addWidget(repoPathInput, 1);
    pathActionLayout->addWidget(initRepoButton);
    pathActionLayout->addWidget(openRepoButton);
    mainVLayout->addLayout(pathActionLayout);

    QHBoxLayout *statusLayout = new QHBoxLayout();
    currentRepoLabel = new QLabel("No repository open.", this);
    QFont boldFont = currentRepoLabel->font();
    boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont);
    currentBranchLabel = new QLabel("Branch: -", this);
    currentBranchLabel->setFont(boldFont);
    statusLayout->addWidget(currentRepoLabel, 1);
    statusLayout->addWidget(currentBranchLabel);
    mainVLayout->addLayout(statusLayout);

    QSplitter *overallSplitter = new QSplitter(Qt::Horizontal, this);
    mainVLayout->addWidget(overallSplitter, 1);

    setupRepoManagementUi(overallSplitter);
    setupNetworkUi(overallSplitter);

    overallSplitter->setSizes({550, 400});
}

void MainWindow::setupRepoManagementUi(QSplitter *parentSplitter)
{
    repoManagementFrame = new QFrame(parentSplitter);
    repoManagementFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout *mainLayout = new QVBoxLayout(repoManagementFrame);

    mainLayout->addWidget(new QLabel("<b>Commit History (Current Branch/Ref):</b>", repoManagementFrame));
    commitLogDisplay = new QTextEdit(repoManagementFrame);
    commitLogDisplay->setReadOnly(true);
    commitLogDisplay->setFontFamily("monospace");
    mainLayout->addWidget(commitLogDisplay, 1);
    refreshLogButton = new QPushButton("Refresh Log", repoManagementFrame);
    mainLayout->addWidget(refreshLogButton);

    QHBoxLayout *branchControlLayout = new QHBoxLayout();
    branchControlLayout->addWidget(new QLabel("Branches:", repoManagementFrame));
    branchComboBox = new QComboBox(repoManagementFrame);
    branchControlLayout->addWidget(branchComboBox, 1);
    refreshBranchesButton = new QPushButton("Refresh", repoManagementFrame);
    branchControlLayout->addWidget(refreshBranchesButton);
    checkoutBranchButton = new QPushButton("Checkout / View", repoManagementFrame);
    branchControlLayout->addWidget(checkoutBranchButton);
    mainLayout->addLayout(branchControlLayout);

    mainLayout->addWidget(new QLabel("<b>Managed Repositories:</b>", repoManagementFrame));
    managedReposListWidget = new QListWidget(repoManagementFrame);
    mainLayout->addWidget(managedReposListWidget, 1);
    addManagedRepoButton = new QPushButton("Add Local Folder to Manage", repoManagementFrame);
    mainLayout->addWidget(addManagedRepoButton);

    mainLayout->addWidget(new QLabel("<b>Operation Status:</b>", repoManagementFrame));
    messageLog = new QTextEdit(repoManagementFrame);
    messageLog->setReadOnly(true);
    messageLog->setMaximumHeight(100);
    mainLayout->addWidget(messageLog);

    parentSplitter->addWidget(repoManagementFrame);
}

void MainWindow::setupNetworkUi(QSplitter *parentSplitter)
{
    networkFrame = new QFrame(parentSplitter);
    networkFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout *networkVLayout = new QVBoxLayout(networkFrame);
    networkVLayout->addWidget(new QLabel("<b>P2P Network:</b>", networkFrame));
    myPeerInfoLabel = new QLabel(this);
    myPeerInfoLabel->setWordWrap(true);
    networkVLayout->addWidget(myPeerInfoLabel);
    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame);
    networkVLayout->addWidget(tcpServerStatusLabel);
    networkVLayout->addWidget(new QLabel("Discovered Peers & Repos on LAN:", networkFrame));
    discoveredPeersTreeWidget = new QTreeWidget(networkFrame);
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->setColumnWidth(0, 200);
    networkVLayout->addWidget(discoveredPeersTreeWidget, 1);
    QHBoxLayout *actionButtonLayout = new QHBoxLayout();
    connectToPeerButton = new QPushButton("Connect to Peer", networkFrame);
    cloneSelectedRepoButton = new QPushButton("Clone Repository", networkFrame);
    actionButtonLayout->addWidget(connectToPeerButton);
    actionButtonLayout->addWidget(cloneSelectedRepoButton);
    networkVLayout->addLayout(actionButtonLayout);

    // <<< FIX: Restore the "Established TCP Connections" list to the UI >>>
    networkVLayout->addWidget(new QLabel("Established TCP Connections:", networkFrame));
    connectedTcpPeersList = new QListWidget(networkFrame);
    connectedTcpPeersList->setMaximumHeight(80);
    networkVLayout->addWidget(connectedTcpPeersList);

    QHBoxLayout *messageSendLayout = new QHBoxLayout();
    messageInput = new QLineEdit(networkFrame);
    messageInput->setPlaceholderText("Enter message to broadcast...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Send", networkFrame);
    messageSendLayout->addWidget(sendMessageButton);
    networkVLayout->addLayout(messageSendLayout);
    networkVLayout->addWidget(new QLabel("Network Log:", networkFrame));
    networkLogDisplay = new QTextEdit(networkFrame);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    networkVLayout->addWidget(networkLogDisplay, 1);
    parentSplitter->addWidget(networkFrame);
}

void MainWindow::updateRepositoryStatus()
{
    bool repoIsOpen = gitBackend.isRepositoryOpen();
    refreshLogButton->setEnabled(repoIsOpen);
    refreshBranchesButton->setEnabled(repoIsOpen);
    checkoutBranchButton->setEnabled(repoIsOpen);
    branchComboBox->setEnabled(repoIsOpen);

    if (repoIsOpen)
    {
        QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath());
        currentRepoLabel->setText("Current Repository: " + QDir::toNativeSeparators(path));
        loadBranchList();
        loadCommitLog();
    }
    else
    {
        currentRepoLabel->setText("No repository open.");
        currentBranchLabel->setText("Branch: -");
        commitLogDisplay->clear();
        branchComboBox->clear();
        if (messageLog && (messageLog->toPlainText().isEmpty() || !messageLog->toPlainText().endsWith("Initialize or open one.")))
        {
            messageLog->append("No repository is open. Initialize or open one.");
        }
        m_currentlyDisplayedLogBranch = "";
    }
}

void MainWindow::loadCommitLogForBranch(const std::string &branchNameOrSha)
{
    if (!commitLogDisplay)
        return;
    commitLogDisplay->clear();
    if (!gitBackend.isRepositoryOpen())
    {
        commitLogDisplay->setHtml("<i>No repository open.</i>");
        return;
    }
    std::string error_message_log;
    std::vector<CommitInfo> log = gitBackend.getCommitLog(100, error_message_log, branchNameOrSha);

    QString titleRefName = QString::fromStdString(branchNameOrSha).toHtmlEscaped();
    if (branchNameOrSha.empty())
    {
        std::string currentBranchErr;
        titleRefName = QString::fromStdString(gitBackend.getCurrentBranch(currentBranchErr));
        if (titleRefName.isEmpty() || titleRefName.startsWith("["))
        {
            titleRefName = "Current HEAD / " + titleRefName;
        }
        else
        {
            titleRefName = "HEAD (" + titleRefName + ")";
        }
    }

    if (!error_message_log.empty() && log.empty())
    {
        commitLogDisplay->setHtml("<font color=\"red\">Error loading commit log for <b>" + titleRefName + "</b>: " + QString::fromStdString(error_message_log).toHtmlEscaped() + "</font>");
    }
    else if (log.empty())
    {
        commitLogDisplay->setHtml("<i>No commits found for <b>" + titleRefName + "</b>.</i>");
    }
    else
    {
        QString htmlLog;
        htmlLog += "<h3>Commit History for: <b>" + titleRefName + "</b></h3><hr/>";
        for (const auto &entry : log)
        {
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

void MainWindow::loadCommitLog()
{
    m_currentlyDisplayedLogBranch = "";
    loadCommitLogForBranch("");
}

void MainWindow::loadBranchList()
{
    if (!branchComboBox || !messageLog || !currentBranchLabel)
        return;
    branchComboBox->clear();
    if (!gitBackend.isRepositoryOpen())
        return;

    std::string error_message;
    std::vector<std::string> branches = gitBackend.listBranches(GitBackend::BranchType::ALL, error_message);

    if (!error_message.empty())
    {
        messageLog->append("<font color=\"red\">Error listing branches: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
    }
    else
    {
        if (branches.empty())
        {
            messageLog->append("No local or remote-tracking branches found in this repository.");
        }
        for (const std::string &branch_name_str : branches)
        {
            QString branch_qstr = QString::fromStdString(branch_name_str);
            if (branch_qstr.endsWith("/HEAD"))
            {
                continue;
            }
            branchComboBox->addItem(branch_qstr);
        }
    }

    std::string currentBranchNameStr = gitBackend.getCurrentBranch(error_message);
    if (!error_message.empty() && currentBranchNameStr.empty())
    {
        messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
        currentBranchLabel->setText("Branch: [Error]");
    }
    else if (!currentBranchNameStr.empty())
    {
        currentBranchLabel->setText("Branch: <b>" + QString::fromStdString(currentBranchNameStr).toHtmlEscaped() + "</b>");
        int index = branchComboBox->findText(QString::fromStdString(currentBranchNameStr));
        if (index != -1)
        {
            branchComboBox->setCurrentIndex(index);
        }
    }
    else
    {
        currentBranchLabel->setText("Branch: -");
    }
}

void MainWindow::onInitRepoClicked()
{
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty())
    {
        QMessageBox::warning(this, "Input Error", "Please enter a path for the new repository.");
        if (messageLog)
            messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>");
        return;
    }
    std::string path = qPath.toStdString();
    std::string errorMessage;
    QDir dir(QDir::toNativeSeparators(qPath));
    if (!dir.exists())
    {
        if (!dir.mkpath("."))
        {
            if (messageLog)
                messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath);
            return;
        }
    }
    if (gitBackend.initializeRepository(path, errorMessage))
    {
        if (messageLog)
            messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        if (m_repoManager_ptr)
        {
            QString repoName = QFileInfo(qPath).fileName();
            if (repoName.isEmpty() && !qPath.isEmpty())
                repoName = QDir(qPath).dirName();
            if (repoName.isEmpty())
                repoName = "Unnamed Initialized Repo";

            bool ok_name_prompt;
            QString displayName = QInputDialog::getText(this, "Manage Repository", "Enter a display name for this new repository:", QLineEdit::Normal, repoName, &ok_name_prompt);
            if (ok_name_prompt)
            {
                m_repoManager_ptr->addManagedRepository(qPath, displayName.isEmpty() ? repoName : displayName, false, m_myUsername);
            }
        }
    }
    else
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onOpenRepoClicked()
{
    QString currentPathSuggestion = repoPathInput->text().trimmed();
    if (currentPathSuggestion.isEmpty() || !QDir(currentPathSuggestion).exists())
    {
        currentPathSuggestion = QDir::homePath();
    }
    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Open Git Repository"),
                                                        currentPathSuggestion,
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty())
    {
        if (messageLog)
            messageLog->append("Open repository cancelled by user.");
        return;
    }
    repoPathInput->setText(QDir::toNativeSeparators(dirPath));
    std::string path = dirPath.toStdString();
    std::string errorMessage;
    if (gitBackend.openRepository(path, errorMessage))
    {
        if (messageLog)
            messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        if (m_repoManager_ptr)
        {
            ManagedRepositoryInfo existingManaged = m_repoManager_ptr->getRepositoryInfoByPath(dirPath);
            if (existingManaged.appId.isEmpty())
            {
                QString repoName = QFileInfo(dirPath).fileName();
                if (repoName.isEmpty())
                    repoName = QDir(dirPath).dirName();
                if (repoName.isEmpty())
                    repoName = "Unnamed Opened Repo";

                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Manage Repository",
                                              QString("Add '%1' to managed repositories?").arg(repoName.toHtmlEscaped()),
                                              QMessageBox::Yes | QMessageBox::No);
                if (reply == QMessageBox::Yes)
                {
                    bool ok_name_prompt;
                    QString displayName = QInputDialog::getText(this, "Set Display Name", "Repository display name:", QLineEdit::Normal, repoName, &ok_name_prompt);
                    if (ok_name_prompt)
                    {
                        m_repoManager_ptr->addManagedRepository(dirPath, displayName.isEmpty() ? repoName : displayName, false, m_myUsername);
                    }
                }
            }
        }
    }
    else
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onRefreshLogClicked()
{
    if (!gitBackend.isRepositoryOpen())
    {
        if (networkLogDisplay)
            networkLogDisplay->append("No repository open to refresh log.");
        if (messageLog)
            messageLog->append("No repository open to refresh log.");
        return;
    }

    QString currentBranchInCombo = branchComboBox->currentText();
    bool viewingSpecificRef = (!m_currentlyDisplayedLogBranch.empty() && m_currentlyDisplayedLogBranch == currentBranchInCombo.toStdString()) ||
                              (currentBranchInCombo.contains('/') && !currentBranchInCombo.startsWith("[D")); // Match "[Detached..."

    if (viewingSpecificRef && !currentBranchInCombo.isEmpty())
    {
        if (networkLogDisplay)
            networkLogDisplay->append("Refreshing commit log for selected reference: <b>" + currentBranchInCombo.toHtmlEscaped() + "</b>");
        loadCommitLogForBranch(currentBranchInCombo.toStdString());
        m_currentlyDisplayedLogBranch = currentBranchInCombo.toStdString();
    }
    else
    {
        if (networkLogDisplay)
            networkLogDisplay->append("Refreshing commit log for current HEAD.");
        loadCommitLog();
    }
}

void MainWindow::onRefreshBranchesClicked()
{
    if (gitBackend.isRepositoryOpen())
    {
        loadBranchList();
        if (messageLog)
            messageLog->append("Branch list refreshed.");
    }
    else
    {
        if (messageLog)
            messageLog->append("No repository open to refresh branches.");
    }
}

void MainWindow::onManagedRepoDoubleClicked(QListWidgetItem *item)
{
    if (!item || !m_repoManager_ptr)
    {
        qWarning() << "MainWindow::onManagedRepoDoubleClicked: Null item or repo manager.";
        return;
    }

    QString appId = item->data(Qt::UserRole).toString();
    if (appId.isEmpty())
    {
        qWarning() << "MainWindow: Managed repo item double-clicked, but no AppID found in item data.";
        if (messageLog)
            messageLog->append("<font color='red'>Error: Could not identify selected managed repository.</font>");
        return;
    }

    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty() || repoInfo.localPath.isEmpty())
    {
        qWarning() << "MainWindow: Could not retrieve info for managed repo with AppID:" << appId;
        if (messageLog)
            messageLog->append("<font color='red'>Error: Could not retrieve details for selected managed repository.</font>");
        return;
    }

    qDebug() << "MainWindow: Double-clicked managed repo:" << repoInfo.displayName << "Path:" << repoInfo.localPath;

    std::string errorMessage;
    if (gitBackend.openRepository(repoInfo.localPath.toStdString(), errorMessage))
    {
        if (messageLog)
            messageLog->append("<font color=\"green\">Opened managed repository: " + repoInfo.displayName.toHtmlEscaped() +
                               " (" + QDir::toNativeSeparators(repoInfo.localPath).toHtmlEscaped() + ")</font>");
        if (repoPathInput)
            repoPathInput->setText(QDir::toNativeSeparators(repoInfo.localPath));
        updateRepositoryStatus();
    }
    else
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">Failed to open managed repository '" + repoInfo.displayName.toHtmlEscaped() +
                               "': " + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
        QMessageBox::critical(this, "Open Repository Failed",
                              "Could not open the selected managed repository: " + repoInfo.displayName +
                                  "\nPath: " + repoInfo.localPath +
                                  "\nError: " + QString::fromStdString(errorMessage));
        updateRepositoryStatus();
    }
}

void MainWindow::onCheckoutBranchClicked()
{
    if (!gitBackend.isRepositoryOpen())
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">No repository open.</font>");
        return;
    }
    QString selectedBranchQStr = branchComboBox->currentText();
    if (selectedBranchQStr.isEmpty())
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">No branch selected.</font>");
        QMessageBox::warning(this, "Action Error", "No branch selected from the dropdown.");
        return;
    }

    std::string selectedBranchName = selectedBranchQStr.toStdString();
    std::string error_message_op;
    std::string error_msg_local_list;
    std::vector<std::string> local_branches = gitBackend.listBranches(GitBackend::BranchType::LOCAL, error_msg_local_list);
    bool is_actually_local_branch = false;

    if (error_msg_local_list.empty())
    {
        for (const auto &local_b : local_branches)
        {
            if (local_b == selectedBranchName)
            {
                is_actually_local_branch = true;
                break;
            }
        }
    }
    else
    {
        if (messageLog)
            messageLog->append("<font color=\"orange\">Warning: Could not list local branches to determine type: " + QString::fromStdString(error_msg_local_list).toHtmlEscaped() + "</font>");
        is_actually_local_branch = (selectedBranchName.find('/') == std::string::npos &&
                                    (!selectedBranchName.empty() && selectedBranchName[0] != '['));
    }

    if (is_actually_local_branch)
    {
        if (gitBackend.checkoutBranch(selectedBranchName, error_message_op))
        {
            if (messageLog)
                messageLog->append("<font color=\"green\">" + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            m_currentlyDisplayedLogBranch = "";
            updateRepositoryStatus();
        }
        else
        {
            if (messageLog)
                messageLog->append("<font color=\"red\">Error checking out branch '" + selectedBranchQStr.toHtmlEscaped() + "': " + QString::fromStdString(error_message_op).toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Checkout Failed", "Could not checkout branch: " + selectedBranchQStr + "\nError: " + QString::fromStdString(error_message_op));
        }
    }
    else
    {
        if (networkLogDisplay)
            networkLogDisplay->append("Displaying commit history for: <b>" + selectedBranchQStr.toHtmlEscaped() + "</b> (Current HEAD unchanged)");
        loadCommitLogForBranch(selectedBranchName);
        m_currentlyDisplayedLogBranch = selectedBranchName;
    }
}

// --- RepositoryManager Slot Implementation ---
void MainWindow::handleRepositoryListChanged()
{
    if (!m_repoManager_ptr || !managedReposListWidget)
        return;
    managedReposListWidget->clear();
    QList<ManagedRepositoryInfo> repos = m_repoManager_ptr->getAllManagedRepositories();
    if (repos.isEmpty())
    {
        managedReposListWidget->addItem("<i>No repositories managed yet. Click 'Add...'</i>");
    }
    else
    {
        for (const auto &repoInfo : repos)
        {
            QString itemText = QString("%1 (%2)\n  Path: %3")
                                   .arg(repoInfo.displayName.toHtmlEscaped())
                                   .arg(repoInfo.isPublic ? "Public" : "Private")
                                   .arg(QDir::toNativeSeparators(repoInfo.localPath).toHtmlEscaped());
            QListWidgetItem *item = new QListWidgetItem(itemText, managedReposListWidget);
            item->setData(Qt::UserRole, repoInfo.appId);
            item->setToolTip(QString("ID: %1\nAdmin: %2").arg(repoInfo.appId).arg(repoInfo.adminPeerId.toHtmlEscaped()));
        }
    }
}

void MainWindow::onAddManagedRepoClicked()
{
    if (!m_repoManager_ptr)
    {
        QMessageBox::critical(this, "Error", "Repository Manager not initialized.");
        return;
    }

    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Select Git Repository Folder to Manage"),
                                                        QDir::homePath(),
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty())
    {
        if (messageLog)
            messageLog->append("Add managed repository cancelled by user.");
        return;
    }

    std::string tempError;
    GitBackend tempGitBackend;
    if (!tempGitBackend.openRepository(dirPath.toStdString(), tempError))
    {
        QMessageBox::warning(this, "Not a Git Repository",
                             "The selected directory does not appear to be a valid Git repository or could not be opened.\nError: " + QString::fromStdString(tempError));
        return;
    }

    ManagedRepositoryInfo existingInfo = m_repoManager_ptr->getRepositoryInfoByPath(dirPath);
    if (!existingInfo.appId.isEmpty())
    {
        QMessageBox::information(this, "Already Managed", "This repository path is already managed:\n" + existingInfo.displayName);
        return;
    }

    QString repoName = QFileInfo(dirPath).fileName();
    if (repoName.isEmpty())
        repoName = QDir(dirPath).dirName();
    if (repoName.isEmpty())
        repoName = "Unnamed Repo";

    bool ok_name_prompt;
    QString displayName = QInputDialog::getText(this, "Manage Repository",
                                                "Enter a display name for this repository:",
                                                QLineEdit::Normal, repoName, &ok_name_prompt);
    if (!ok_name_prompt)
    {
        if (messageLog)
            messageLog->append("Add managed repository cancelled (name input).");
        return;
    }
    QString finalDisplayName = displayName.isEmpty() ? repoName : displayName;

    bool isPublic = (QMessageBox::question(this, "Set Visibility",
                                           "Make this repository public on the P2P network (discoverable by others)?",
                                           QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes);

    if (m_repoManager_ptr->addManagedRepository(dirPath, finalDisplayName, isPublic, m_myUsername))
    {
        if (messageLog)
            messageLog->append("<font color=\"green\">Repository '" + finalDisplayName.toHtmlEscaped() + "' added to management.</font>");
    }
    else
    {
        if (messageLog)
            messageLog->append("<font color=\"red\">Failed to add '" + finalDisplayName.toHtmlEscaped() + "' to management. It might already be managed by path or an error occurred.</font>");
        QMessageBox::warning(this, "Add Repository Failed", "Could not add the repository to management. Check logs.");
    }
}

// --- Network SLOTS Implementation ---
void MainWindow::onToggleDiscoveryAndTcpServerClicked()
{
    if (!m_networkManager_ptr || !m_identityManager_ptr)
    {
        QMessageBox::critical(this, "Service Error", "Network or Identity manager not ready.");
        return;
    }
    if (m_networkManager_ptr->getTcpServerPort() > 0)
    {
        m_networkManager_ptr->stopUdpDiscovery();
        m_networkManager_ptr->stopTcpServer();
    }
    else
    {
        if (m_myUsername.isEmpty())
        {
            QMessageBox::warning(this, "Peer Name Error", "Your peer name is not set. Please restart.");
            return;
        }
        if (!m_identityManager_ptr->areKeysInitialized() || m_identityManager_ptr->getMyPublicKeyHex().empty())
        {
            QMessageBox::critical(this, "Identity Error", "Cryptographic keys are not initialized. Cannot start server/discovery.");
            return;
        }
        if (m_networkManager_ptr->startTcpServer(0))
        {
            if (m_networkManager_ptr->startUdpDiscovery(45454))
            {
                if (networkLogDisplay)
                    networkLogDisplay->append("<font color=\"blue\">UDP Discovery and TCP Server initiated.</font>");
            }
            else
            {
                if (networkLogDisplay)
                    networkLogDisplay->append("<font color=\"red\">Failed to start UDP Discovery. TCP Server also stopped.</font>");
                m_networkManager_ptr->stopTcpServer();
            }
        }
    }
}

void MainWindow::onCloneSelectedRepoClicked()
{
    if (!m_networkManager_ptr || !m_repoManager_ptr || !discoveredPeersTreeWidget)
    {
        QMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
        return;
    }
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (!currentItem || !currentItem->parent())
    {
        QMessageBox::warning(this, "Selection Error", "Please select a specific repository to clone.");
        return;
    }
    QString repoNameToClone = currentItem->data(0, Qt::UserRole).toString();
    QString parentPeerUsername = currentItem->data(0, Qt::UserRole + 1).toString();

    // Check for re-cloning
    for (const auto &managedRepo : m_repoManager_ptr->getAllManagedRepositories())
    {
        if (managedRepo.clonedFromPeerId == parentPeerUsername && managedRepo.clonedFromRepoName == repoNameToClone)
        {
            if (QMessageBox::question(this, "Repository Already Cloned", "You appear to have already cloned this repository.\n\nDo you want to clone it again?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
            {
                return;
            }
            break;
        }
    }

    // Get destination path
    QString localClonePathBase = QFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty())
        return;

    QString fullLocalClonePath = QDir(localClonePathBase).filePath(repoNameToClone);
    if (QDir(fullLocalClonePath).exists())
    {
        QMessageBox::warning(this, "Directory Exists", "The target directory already exists.");
        return;
    }

    // Set pending request state

    m_pendingCloneRequest.peerId = parentPeerUsername;
    m_pendingCloneRequest.repoName = repoNameToClone;
    m_pendingCloneRequest.localClonePath = fullLocalClonePath;

    // Cloning a public repo ALWAYS uses a new, temporary connection.
    DiscoveredPeerInfo providerPeerInfo = m_networkManager_ptr->getDiscoveredPeerInfo(parentPeerUsername);
    if (providerPeerInfo.id.isEmpty())
    {
        QMessageBox::critical(this, "Connection Error", "Could not find peer info. They may have gone offline.");
        m_pendingCloneRequest.clear();
        return;
    }

    networkLogDisplay->append(QString("<font color='blue'>Initiating clone for '%1' from peer '%2'...</font>").arg(repoNameToClone, parentPeerUsername));

    // The key change: The initiator now sends a REQUEST_REPO_BUNDLE as its FIRST message on a new socket.
    m_networkManager_ptr->connectAndRequestBundle(providerPeerInfo.address, providerPeerInfo.tcpPort, m_myUsername, repoNameToClone, fullLocalClonePath);

    cloneSelectedRepoButton->setEnabled(false);
}

void MainWindow::onSendMessageClicked()
{
    if (!m_networkManager_ptr)
        return;
    QString message = messageInput->text().trimmed();
    if (message.isEmpty())
        return;
    if (!m_networkManager_ptr->hasActiveTcpConnections())
    {
        if (networkLogDisplay)
            networkLogDisplay->append("<font color=\"red\">Not connected to any peers. Cannot send message.</font>");
        return;
    }
    m_networkManager_ptr->broadcastTcpMessage(message);
    if (networkLogDisplay)
        networkLogDisplay->append("<font color=\"blue\"><b>Me (Broadcast):</b> " + message.toHtmlEscaped() + "</font>");
    messageInput->clear();
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket *pendingSocket, const QHostAddress &address, quint16 port, const QString &discoveredUsername)
{
    if (!m_networkManager_ptr)
        return;

    QString pkh;
    DiscoveredPeerInfo peerInfo = m_networkManager_ptr->getDiscoveredPeerInfo(discoveredUsername);
    if (!peerInfo.publicKeyHex.isEmpty())
    {
        pkh = " (PKH: " + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8) + "...)";
    }
    QString peerDisplay = !discoveredUsername.isEmpty() ? discoveredUsername + pkh : address.toString();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Peer Connection Request");
    msgBox.setText(QString("Peer '%1' wants to establish a connection with you. Accept?").arg(peerDisplay.toHtmlEscaped()));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);

    // This timer ensures that if the user does nothing, it's a "No"
    QTimer::singleShot(30000, &msgBox, &QMessageBox::reject);

    int result = msgBox.exec();

    // After the user clicks (or it times out), check if the connection is still pending.
    // It might have been disconnected in the background.
    if (m_networkManager_ptr->isConnectionPending(pendingSocket))
    {
        if (result == QMessageBox::Yes)
        {
            m_networkManager_ptr->acceptPendingTcpConnection(pendingSocket);
        }
        else
        {
            m_networkManager_ptr->rejectPendingTcpConnection(pendingSocket);
        }
    }
}

void MainWindow::handleTcpServerStatusChanged(bool listening, quint16 port, const QString &error)
{
    if (!tcpServerStatusLabel || !toggleDiscoveryButton || !myPeerInfoLabel || !m_identityManager_ptr)
        return;

    if (listening)
    {
        tcpServerStatusLabel->setText("TCP Server: Listening on port <b>" + QString::number(port) + "</b>");
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...\nTCP Port: %3")
                                     .arg(m_myUsername.toHtmlEscaped())
                                     .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10))
                                     .arg(port));
    }
    else
    {
        tcpServerStatusLabel->setText("TCP Server: Inactive");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        myPeerInfoLabel->setText(QString("My Peer ID: %1\nMy PubKey (prefix): %2...")
                                     .arg(m_myUsername.toHtmlEscaped())
                                     .arg(QString::fromStdString(m_identityManager_ptr->getMyPublicKeyHex()).left(10)));

        if (!error.isEmpty())
        {
            if (networkLogDisplay)
                networkLogDisplay->append("<font color=\"red\">TCP Server error/stopped: " + error.toHtmlEscaped() + "</font>");
        }
        else
        {
            if (networkLogDisplay && toggleDiscoveryButton->text() == "Start Discovery & TCP Server" && port != 0)
            {
                networkLogDisplay->append("TCP Server stopped.");
            }
        }
    }
}

void MainWindow::onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current, QTreeWidgetItem *previous)
{
    Q_UNUSED(previous);
    if (!current)
    {
        connectToPeerButton->setEnabled(false);
        cloneSelectedRepoButton->setEnabled(false);
        return;
    }
    if (current->parent())
    { // It's a repository
        connectToPeerButton->setEnabled(false);
        cloneSelectedRepoButton->setEnabled(true);
    }
    else
    { // It's a peer
        cloneSelectedRepoButton->setEnabled(false);
        // Only enable "Connect" if the peer is NOT already connected.
        QString peerUsername = current->text(0);
        bool isConnected = (m_networkManager_ptr && m_networkManager_ptr->getSocketForPeer(peerUsername));
        connectToPeerButton->setEnabled(!isConnected);
    }
}

void MainWindow::onConnectToPeerClicked()
{
    if (!m_networkManager_ptr || !discoveredPeersTreeWidget)
        return;
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (!currentItem || currentItem->parent())
        return;

    QString peerUsername = currentItem->text(0);
    if (m_networkManager_ptr->getSocketForPeer(peerUsername))
    {
        QMessageBox::information(this, "Already Connected", "You are already connected to " + peerUsername);
        return;
    }
    DiscoveredPeerInfo peerInfo = m_networkManager_ptr->getDiscoveredPeerInfo(peerUsername);
    if (peerInfo.id.isEmpty())
    {
        QMessageBox::critical(this, "Connection Error", "Could not find peer info. They may have gone offline.");
        return;
    }
    networkLogDisplay->append(QString("<font color='blue'>Initiating connection to peer '%1'...</font>").arg(peerUsername));
    m_networkManager_ptr->connectToTcpPeer(peerInfo.address, peerInfo.tcpPort, peerInfo.id);
}

void MainWindow::handleNewTcpPeerConnected(QTcpSocket *peerSocket, const QString &peerUsername, const QString &peerPublicKeyHex)
{
    if (!connectedTcpPeersList || !networkLogDisplay)
        return;

    qDebug() << "MW:" << m_myUsername << "handleNewTcpPeerConnected for" << peerUsername;

    // Add or update the peer in the "Established TCP Connections" list
    bool alreadyInList = false;
    for (int i = 0; i < connectedTcpPeersList->count(); ++i)
    {
        if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerUsername)
        {
            alreadyInList = true;
            break;
        }
    }
    if (!alreadyInList)
    {
        QString pkh = QCryptographicHash::hash(peerPublicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
        QString displayString = QString("%1 (%2) [PKH:%3]").arg(peerUsername, peerSocket->peerAddress().toString(), pkh);
        QListWidgetItem *newItem = new QListWidgetItem(m_peerConnectedIcon, displayString);
        newItem->setData(Qt::UserRole, peerUsername);
        connectedTcpPeersList->addItem(newItem);
        qDebug() << "MW:" << m_myUsername << "added" << peerUsername << "to connectedTcpPeersList";
    }

    // Update the discovery tree visual state
    QList<QTreeWidgetItem *> foundItems = discoveredPeersTreeWidget->findItems(peerUsername, Qt::MatchExactly, 0);
    if (!foundItems.isEmpty())
    {
        foundItems.first()->setIcon(0, m_peerConnectedIcon);
        foundItems.first()->setForeground(0, QBrush(QColor("lime")));
    }
    else
    {
        QTreeWidgetItem *peerItem = new QTreeWidgetItem(discoveredPeersTreeWidget);
        peerItem->setText(0, peerUsername);
        peerItem->setIcon(0, m_peerConnectedIcon);
        peerItem->setForeground(0, QBrush(QColor("lime")));
    }

    // Update button states if this peer is currently selected
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem && !currentItem->parent() && currentItem->text(0) == peerUsername)
    {
        onDiscoveredPeerOrRepoSelected(currentItem, nullptr);
    }

    networkLogDisplay->append("<font color=\"green\">TCP Peer fully connected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpPeerDisconnected(QTcpSocket *peerSocket, const QString &peerUsername)
{
    if (!networkLogDisplay)
        return;
    Q_UNUSED(peerSocket);

    // 1. Remove from the dedicated "Established TCP Connections" list
    if (connectedTcpPeersList)
    {
        for (int i = 0; i < connectedTcpPeersList->count(); ++i)
        {
            if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerUsername)
            {
                delete connectedTcpPeersList->takeItem(i);
                break;
            }
        }
    }

    // 2. Revert visual state in the main discovery tree
    QList<QTreeWidgetItem *> foundItems = discoveredPeersTreeWidget->findItems(peerUsername, Qt::MatchExactly, 0);
    if (!foundItems.isEmpty())
    {
        QTreeWidgetItem *peerItem = foundItems.first();
        peerItem->setIcon(0, m_peerDisconnectedIcon);
        peerItem->setForeground(0, this->palette().color(QPalette::WindowText));
    }

    // 3. Update button state if they were selected
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem && !currentItem->parent() && currentItem->text(0) == peerUsername)
    {
        onDiscoveredPeerOrRepoSelected(currentItem, nullptr);
    }

    networkLogDisplay->append("<font color=\"orange\">TCP Peer disconnected: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpMessageReceived(QTcpSocket *peerSocket, const QString &peerUsername, const QString &message)
{
    if (!networkLogDisplay)
        return;
    Q_UNUSED(peerSocket);
    networkLogDisplay->append("<b>" + peerUsername.toHtmlEscaped() + ":</b> " + message.toHtmlEscaped());
}

void MainWindow::handleTcpConnectionStatusChanged(const QString &peerUsernameOrAddress, const QString &peerPublicKeyHex, bool connected, const QString &error)
{
    if (!networkLogDisplay)
        return;
    if (connected)
    {
        networkLogDisplay->append("<font color=\"green\">TCP to " + peerUsernameOrAddress.toHtmlEscaped() + " established (PK: " + (peerPublicKeyHex.isEmpty() ? "NO" : "YES") + "). Awaiting handshake.</font>");
    }
    else
    {
        networkLogDisplay->append("<font color=\"red\">Failed TCP connection to " + peerUsernameOrAddress.toHtmlEscaped() + ": " + error.toHtmlEscaped() + "</font>");
    }
}

void MainWindow::handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo &peerInfo)
{
    if (!discoveredPeersTreeWidget)
    {
        qWarning() << "MW: handleLanPeerDiscoveredOrUpdated: discoveredPeersTreeWidget not initialized.";
        return;
    }

    qDebug() << "MW: Updating discovered peer" << peerInfo.id << "address" << peerInfo.address.toString() << "tcpPort" << peerInfo.tcpPort;

    QList<QTreeWidgetItem *> foundItems = discoveredPeersTreeWidget->findItems(peerInfo.id, Qt::MatchExactly, 0);
    QTreeWidgetItem *peerItem = nullptr;
    QString pkHashStr = QString(QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(6));
    QString peerDetails = QString("(%1) [PKH:%2]").arg(peerInfo.address.toString(), pkHashStr);

    if (foundItems.isEmpty())
    {
        peerItem = new QTreeWidgetItem(discoveredPeersTreeWidget);
        peerItem->setText(0, peerInfo.id);
        qDebug() << "MW: Created new tree item for peer" << peerInfo.id;
    }
    else
    {
        peerItem = foundItems.first();
        qDebug() << "MW: Found existing tree item for peer" << peerInfo.id;
    }

    bool isConnected = (m_networkManager_ptr && m_networkManager_ptr->getSocketForPeer(peerInfo.id) && m_networkManager_ptr->getSocketForPeer(peerInfo.id)->state() == QAbstractSocket::ConnectedState);
    peerItem->setIcon(0, isConnected ? m_peerConnectedIcon : m_peerDisconnectedIcon);
    peerItem->setForeground(0, isConnected ? QBrush(QColor("lime")) : QBrush(this->palette().color(QPalette::WindowText)));
    peerItem->setText(1, peerDetails);

    qDebug() << "MW: Set peer" << peerInfo.id << "icon to" << (isConnected ? "connected" : "disconnected") << "and color to" << (isConnected ? "lime" : "default");

    qDeleteAll(peerItem->takeChildren());
    for (const QString &repoName : peerInfo.publicRepoNames)
    {
        QTreeWidgetItem *repoItem = new QTreeWidgetItem(peerItem);
        repoItem->setText(0, "  " + repoName);
        repoItem->setData(0, Qt::UserRole, repoName);
        repoItem->setData(0, Qt::UserRole + 1, peerInfo.id);
        repoItem->setText(1, "Public");
        qDebug() << "MW: Added repo" << repoName << "to peer" << peerInfo.id;
    }
    peerItem->setExpanded(true);

    discoveredPeersTreeWidget->update();
    qDebug() << "MW: Forced UI refresh for discoveredPeersTreeWidget.";
}

void MainWindow::handleLanPeerLost(const QString &peerUsername)
{
    if (!discoveredPeersTreeWidget || !networkLogDisplay)
        return;
    QList<QTreeWidgetItem *> items = discoveredPeersTreeWidget->findItems(peerUsername, Qt::MatchExactly | Qt::MatchRecursive, 0);
    if (!items.isEmpty())
    {
        delete items.first(); // This will remove the item and its children from the tree
    }
    networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerUsername.toHtmlEscaped() + "</font>");
}

void MainWindow::handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt)
{
    qDebug() << "MainWindow: Received bundle request for" << repoDisplayName << "from" << sourcePeerUsername;

    if (!m_repoManager_ptr || !m_networkManager_ptr)
    {
        if (networkLogDisplay)
            networkLogDisplay->append("<font color='red'>Cannot process bundle request: core services not ready.</font>");
        // TODO: Send an error message back to the requester
        return;
    }

    // 1. Find the requested repository in the list of managed repos.
    ManagedRepositoryInfo repoToBundle;
    bool found = false;
    for (const auto &managedRepo : m_repoManager_ptr->getAllManagedRepositories())
    {
        if (managedRepo.displayName == repoDisplayName)
        {
            repoToBundle = managedRepo;
            found = true;
            break;
        }
    }

    if (!found)
    {
        if (networkLogDisplay)
            networkLogDisplay->append(QString("<font color='red'>Received bundle request for '%1', but it is not in the managed list.</font>").arg(repoDisplayName.toHtmlEscaped()));
        // TODO: Send REPO_NOT_FOUND error back
        return;
    }

    // 2. Check if the found repository is public.
    if (!repoToBundle.isPublic)
    {
        if (networkLogDisplay)
            networkLogDisplay->append(QString("<font color='red'>Denied bundle request for private repository '%1'.</font>").arg(repoDisplayName.toHtmlEscaped()));
        // TODO: Send ACCESS_DENIED error back
        return;
    }

    // 3. Use a TEMPORARY GitBackend instance to create the bundle.
    //    This does NOT affect the main UI's open repository.
    GitBackend tempGitBackend;
    std::string errorMessage;

    if (!tempGitBackend.openRepository(repoToBundle.localPath.toStdString(), errorMessage))
    {
        if (networkLogDisplay)
            networkLogDisplay->append(QString("<font color='red'>Failed to open managed repository '%1' for bundling: %2</font>").arg(repoDisplayName.toHtmlEscaped(), QString::fromStdString(errorMessage)));
        // TODO: Send an error back
        return;
    }

    // 4. Create the bundle file in a temporary location.
    std::string bundleFilePathStd;
    std::string errorMsgBundle;
    QString tempBundleDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/P2PGitBundles/" + QUuid::createUuid().toString();
    QDir().mkpath(tempBundleDir);

    QString bundleBaseName = QFileInfo(repoToBundle.localPath).fileName();
    if (bundleBaseName.isEmpty())
        bundleBaseName = "repo_bundle_" + repoToBundle.appId;

    if (tempGitBackend.createBundle(tempBundleDir.toStdString(), bundleBaseName.toStdString(), bundleFilePathStd, errorMsgBundle))
    {
        if (networkLogDisplay)
            networkLogDisplay->append(QString("<font color='green'>Bundle created for '%1'. Starting transfer to %2...</font>").arg(repoDisplayName.toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()));

        // 5. Start the network transfer.
        m_networkManager_ptr->startSendingBundle(requestingPeerSocket, repoToBundle.displayName, QString::fromStdString(bundleFilePathStd));
    }
    else
    {
        if (networkLogDisplay)
            networkLogDisplay->append(QString("<font color='red'>Failed to create bundle for '%1': %2</font>").arg(repoToBundle.displayName.toHtmlEscaped(), QString::fromStdString(errorMsgBundle).toHtmlEscaped()));
        // TODO: Send BUNDLE_CREATION_FAILED error back
    }
    // The tempGitBackend is automatically destroyed here, closing the repo.
}

void MainWindow::handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    if (cloneSelectedRepoButton)
        cloneSelectedRepoButton->setEnabled(true);

    if (!success)
    {
        QMessageBox::critical(this, "Clone Failed", QString("Failed to receive the repository bundle for '%1':\n%2").arg(repoName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoName != repoName)
    {
        QMessageBox::warning(this, "Clone Warning", QString("Received a repository bundle for '%1', but was not expecting it.").arg(repoName));
        QFile::remove(localBundlePath);
        return;
    }

    networkLogDisplay->append(QString("<font color='green'>Bundle for '%1' received. Cloning...</font>").arg(repoName));
    QString finalClonePath = m_pendingCloneRequest.localClonePath;

    QProcess gitProcess;
    gitProcess.start("git", QStringList() << "clone" << QDir::toNativeSeparators(localBundlePath) << QDir::toNativeSeparators(finalClonePath));

    if (!gitProcess.waitForFinished(-1))
    {
        QMessageBox::critical(this, "Clone Failed", "Git clone process timed out.");
    }
    else if (gitProcess.exitCode() == 0)
    {
        QMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(repoName, finalClonePath));
        m_repoManager_ptr->addManagedRepository(finalClonePath, repoName, false, m_myUsername, m_pendingCloneRequest.peerId, repoName);
        std::string err;
        gitBackend.openRepository(finalClonePath.toStdString(), err);
        updateRepositoryStatus();
    }
    else
    {
        QMessageBox::critical(this, "Clone Failed", QString("The git clone command failed:\n%1").arg(QString(gitProcess.readAllStandardError())));
    }

    QFile::remove(localBundlePath);
    m_pendingCloneRequest.clear();
}
void MainWindow::handleRepoBundleSent(const QString &repoName, const QString &recipientUsername)
{
    if (networkLogDisplay)
    {
        networkLogDisplay->append(QString("<font color='purple'>Sent bundle for '%1' to peer '%2'.</font>")
                                      .arg(repoName.toHtmlEscaped(), recipientUsername.toHtmlEscaped()));
    }
}