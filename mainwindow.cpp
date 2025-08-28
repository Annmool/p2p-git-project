#include "mainwindow.h"
#include "dashboard_panel.h"
#include "network_panel.h"
#include "project_window.h"
#include "identity_manager.h"
#include "repository_manager.h"
#include "network_manager.h"
#include "git_backend.h"
#include "custom_dialogs.h"
#include "welcome_window.h"

#include <QVBoxLayout>
#include <QStackedWidget>
#include <QToolButton>
#include <QFileDialog>
#include <QHostInfo>
#include <QRandomGenerator>
#include <QProcess>
#include <QTimer>
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QIcon>
#include <QFile>
#include <QSvgRenderer>
#include <QPainter>
#include <QTemporaryFile>
#include <QDir>
#include <QFileInfo>
#include <QDebug>

// Helper function to tint SVG icons
QIcon createTintedIcon(const QString &resourcePath, const QColor &color)
{
    QSvgRenderer renderer(resourcePath);
    if (!renderer.isValid())
    {
        qWarning() << "Could not load SVG icon:" << resourcePath;
        return QIcon();
    }

    QPixmap pixmap(renderer.defaultSize());
    pixmap.fill(Qt::transparent);

    // First paint the SVG
    QPainter painter(&pixmap);
    renderer.render(&painter);
    painter.end(); // End the first painter before starting the mask painter

    // Then apply the color mask
    QPainter maskPainter(&pixmap);
    maskPainter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    maskPainter.fillRect(pixmap.rect(), color);
    maskPainter.end();

    return QIcon(pixmap);
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_identityManager(nullptr),
      m_repoManager(nullptr),
      m_networkManager(nullptr)
{
    // Generate default name
    QString name_prompt_default = QHostInfo::localHostName();
    if (name_prompt_default.isEmpty())
    {
        name_prompt_default = "Peer" + QString::number(QRandomGenerator::global()->bounded(10000));
    }

    // Show welcome window
    WelcomeWindow welcomeWindow(name_prompt_default);
    if (welcomeWindow.exec() == QDialog::Accepted)
    {
        m_myUsername = welcomeWindow.getPeerName();
        qDebug() << "Username chosen:" << m_myUsername;
    }
    else
    {
        // User cancelled - exit application
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    if (m_myUsername.isEmpty())
    {
        m_myUsername = name_prompt_default;
    }

    m_identityManager = new IdentityManager(m_myUsername);
    if (!m_identityManager->initializeKeys())
    {
        CustomMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! The application will now close.");
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    QString configPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir configDir(configPath);
    configDir.mkpath("P2PGitClient/" + m_myUsername);
    QString repoManagerStorageFile = configDir.filePath("P2PGitClient/" + m_myUsername + "/managed_repositories.json");
    m_repoManager = new RepositoryManager(repoManagerStorageFile, m_myUsername, this);

    m_networkManager = new NetworkManager(m_myUsername, m_identityManager, m_repoManager, this);

    setupUi();
    connectSignals();

    m_networkPanel->setNetworkManager(m_networkManager);
    m_networkPanel->setMyPeerInfo(m_myUsername, QString::fromStdString(m_identityManager->getMyPublicKeyHex()));
    if (m_userProfileWidget)
    {
        QString pkHex = QString::fromStdString(m_identityManager->getMyPublicKeyHex());
        QString pkh = QCryptographicHash::hash(pkHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
        m_userProfileWidget->setPublicKeyHashDisplay(pkh);
    }
    m_networkPanel->logMessage(QString("App started as '%1'").arg(m_myUsername), QColor("#0F4C4A"));
    updateUiFromBackend();

    m_networkManager->startTcpServer();
}

MainWindow::~MainWindow() {}

void MainWindow::notify(const QString &title, const QString &message)
{
    if (m_networkPanel)
        m_networkPanel->logMessage(QString("%1: %2").arg(title, message), QColor("#0F4C4A"));
    CustomMessageBox::information(this, title, message);
}

void MainWindow::setupUi()
{
    setWindowTitle("SyncIt - " + m_myUsername);
    resize(1400, 800);
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);
    mainLayout->setSpacing(0);
    mainLayout->setContentsMargins(0, 0, 0, 0);

    m_sidebarPanel = new QWidget(this);
    m_sidebarPanel->setObjectName("sidebarPanel");
    m_sidebarPanel->setFixedWidth(240);
    QVBoxLayout *sidebarLayout = new QVBoxLayout(m_sidebarPanel);
    sidebarLayout->setContentsMargins(8, 8, 8, 8);
    sidebarLayout->setSpacing(4);

    QLabel *logoLabel = new QLabel("SyncIt", this);
    logoLabel->setObjectName("logoLabel");
    sidebarLayout->addWidget(logoLabel);
    sidebarLayout->addSpacing(10);

    m_dashboardButton = new QToolButton(this);
    m_dashboardButton->setText("Dashboard");
    m_dashboardButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_dashboardButton->setCheckable(true);
    m_dashboardButton->setChecked(true);

    m_networkButton = new QToolButton(this);
    m_networkButton->setText("Network");
    m_networkButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_networkButton->setCheckable(true);

    sidebarLayout->addWidget(m_dashboardButton);
    sidebarLayout->addWidget(m_networkButton);
    sidebarLayout->addStretch();

    m_userProfileWidget = new UserProfileWidget(m_myUsername, this);
    sidebarLayout->addWidget(m_userProfileWidget);

    m_mainContentWidget = new QStackedWidget(this);

    m_dashboardPanel = new DashboardPanel(this);
    m_dashboardPanel->setWelcomeMessage(m_myUsername);

    m_networkPanel = new NetworkPanel(this);
    // Make the Network tab background white without affecting child buttons
    if (m_networkPanel)
    {
        QPalette pal = m_networkPanel->palette();
        pal.setColor(QPalette::Window, Qt::white);
        m_networkPanel->setAutoFillBackground(true);
        m_networkPanel->setPalette(pal);
    }

    m_mainContentWidget->addWidget(m_dashboardPanel);
    m_mainContentWidget->addWidget(m_networkPanel);

    mainLayout->addWidget(m_sidebarPanel);
    mainLayout->addWidget(m_mainContentWidget, 1);

    // Initialize transfer progress dialog
    m_transferProgressDialog = nullptr;

    onNavigationClicked(true);
}

void MainWindow::connectSignals()
{
    connect(m_repoManager, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::updateUiFromBackend);

    connect(m_dashboardButton, &QToolButton::clicked, this, &MainWindow::onNavigationClicked);
    connect(m_networkButton, &QToolButton::clicked, this, &MainWindow::onNavigationClicked);

    if (m_networkManager)
    {
        connect(m_networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager, &NetworkManager::broadcastMessageReceived, this, &MainWindow::handleBroadcastMessage);
        connect(m_networkManager, &NetworkManager::groupMessageReceived, this, &MainWindow::handleGroupMessage);
        connect(m_networkManager, &NetworkManager::repoBundleRequestedByPeer, this, &MainWindow::handleRepoBundleRequest);
        connect(m_networkManager, &NetworkManager::repoBundleCompleted, this, &MainWindow::handleRepoBundleCompleted);
        connect(m_networkManager, &NetworkManager::repoBundleSent, this, &MainWindow::handleRepoBundleSent);
        connect(m_networkManager, &NetworkManager::repoBundleTransferStarted, this, &MainWindow::handleRepoBundleTransferStarted);
        connect(m_networkManager, &NetworkManager::repoBundleChunkReceived, this, &MainWindow::handleRepoBundleProgress);
        connect(m_networkManager, &NetworkManager::tcpServerStatusChanged, m_networkPanel, &NetworkPanel::updateServerStatus);
        connect(m_networkManager, &NetworkManager::secureMessageReceived, this, &MainWindow::handleSecureMessage);
        connect(m_networkManager, &NetworkManager::collaboratorAddedReceived, this, &MainWindow::handleCollaboratorAdded);
        connect(m_networkManager, &NetworkManager::collaboratorRemovedReceived, this, &MainWindow::handleCollaboratorRemoved);
        connect(m_networkManager, &NetworkManager::changeProposalReceived, this, &MainWindow::handleIncomingChangeProposal);
    }

    connect(m_dashboardPanel, &DashboardPanel::openRepoInGitPanel, this, &MainWindow::handleOpenRepoInProjectWindow);
    connect(m_dashboardPanel, &DashboardPanel::addRepoClicked, this, [this]()
            { handleAddManagedRepo(); });
    connect(m_dashboardPanel, &DashboardPanel::modifyAccessClicked, this, &MainWindow::handleModifyRepoAccess);
    connect(m_dashboardPanel, &DashboardPanel::deleteRepoClicked, this, &MainWindow::handleDeleteRepo);

    connect(m_networkPanel, &NetworkPanel::sendBroadcastMessageRequested, this, &MainWindow::handleSendBroadcastMessage);
    // Discovery toggle removed from NetworkPanel UI
    connect(m_networkPanel, &NetworkPanel::connectToPeerRequested, this, &MainWindow::handleConnectToPeer);
    connect(m_networkPanel, &NetworkPanel::cloneRepoRequested, this, &MainWindow::handleCloneRepo);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromPanel);

    // No notifications button in this build

    // Network signals for proposal meta/archive handling
    // Proposal files meta/archive not supported in this build
}

// Legacy proposal/notifications handlers removed in this build.

void MainWindow::onNavigationClicked(bool checked)
{
    Q_UNUSED(checked);
    QToolButton *clickedButton = qobject_cast<QToolButton *>(sender());
    if (!clickedButton)
    {
        clickedButton = m_dashboardButton;
    }

    m_dashboardButton->setChecked(clickedButton == m_dashboardButton);
    m_networkButton->setChecked(clickedButton == m_networkButton);

    m_dashboardButton->setIcon(createTintedIcon(":/icons/activity.svg", m_dashboardButton->isChecked() ? Qt::white : QColor("#E2E8F0")));
    m_networkButton->setIcon(createTintedIcon(":/icons/message-square.svg", m_networkButton->isChecked() ? Qt::white : QColor("#E2E8F0")));

    if (m_dashboardButton->isChecked())
        m_mainContentWidget->setCurrentWidget(m_dashboardPanel);
    else if (m_networkButton->isChecked())
        m_mainContentWidget->setCurrentWidget(m_networkPanel);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_networkManager)
    {
        m_networkManager->stopUdpDiscovery();
        m_networkManager->stopTcpServer();
    }
    event->accept();
}

void MainWindow::updateUiFromBackend()
{
    m_dashboardPanel->updateRepoList(m_repoManager->getRepositoriesIAmMemberOf(), m_myUsername);
    if (m_networkManager)
    {
        QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
        m_networkPanel->updatePeerList(m_networkManager->getDiscoveredPeers(), connectedPeers);

        for (ProjectWindow *pw : m_projectWindows.values())
        {
            pw->updateGroupMembers();
        }
    }
}

void MainWindow::handleOpenRepoInProjectWindow(const QString &appId)
{
    if (m_projectWindows.contains(appId))
    {
        m_projectWindows[appId]->activateWindow();
        return;
    }

    ProjectWindow *projectWindow = new ProjectWindow(appId, m_repoManager, m_networkManager, this);
    projectWindow->setAttribute(Qt::WA_DeleteOnClose);

    m_projectWindows.insert(appId, projectWindow);

    connect(projectWindow, &ProjectWindow::groupMessageSent, this, &MainWindow::handleProjectWindowGroupMessage);
    connect(projectWindow, &ProjectWindow::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromProjectWindow);
    connect(projectWindow, &ProjectWindow::removeCollaboratorRequested, this, &MainWindow::handleRemoveCollaboratorFromProjectWindow);
    connect(projectWindow, &ProjectWindow::fetchBundleRequested, this, &MainWindow::handleFetchBundleRequest);
    connect(projectWindow, &ProjectWindow::proposeChangesRequested, this, &MainWindow::handleProposeChangesRequest);

    connect(m_networkManager, &NetworkManager::repoBundleCompleted, projectWindow, &ProjectWindow::handleFetchBundleCompleted);

    connect(projectWindow, &QObject::destroyed, this, [this, appId]()
            { m_projectWindows.remove(appId); });

    projectWindow->show();
}

void MainWindow::handleFetchBundleRequest(const QString &ownerPeerId, const QString &repoDisplayName)
{
    DiscoveredPeerInfo providerPeerInfo = m_networkManager->getDiscoveredPeerInfo(ownerPeerId);
    if (providerPeerInfo.id.isEmpty())
    {
        CustomMessageBox::critical(this, "Connection Error", "Could not find the repository owner. They may be offline.");
        return;
    }
    m_networkManager->requestBundleFromPeer(ownerPeerId, repoDisplayName, "");
}

void MainWindow::handleProposeChangesRequest(const QString &ownerPeerId, const QString &repoDisplayName, const QString &fromBranch)
{
    // The actual sending logic is now in ProjectWindow to create the diff bundle first.
    // This MainWindow slot will be triggered by a signal from ProjectWindow.
    ProjectWindow *sender_pw = qobject_cast<ProjectWindow *>(sender());
    if (!sender_pw)
        return;

    // We can directly call the network manager's high-level send function
    // as the bundle path will be handled by the ProjectWindow.
    // The actual bundle creation and sending is initiated from ProjectWindow now.
    // This handler is kept for legacy connection but the main logic moved to ProjectWindow.
}

// Legacy propose-files meta/archive handlers removed in this build.

void MainWindow::handleIncomingChangeProposal(const QString &fromPeer, const QString &repoName, const QString &forBranch, const QString &tempBundlePath, const QString &message)
{
    // Defer to the next tick to avoid reentrancy with network signal handling.
    QTimer::singleShot(0, this, [=]()
                       {
    // The proposal bundle has been fully downloaded to tempBundlePath.
    // The progress dialog was already closed by handleRepoBundleCompleted.

    // 1. Identify the owner's repository entry.
    ManagedRepositoryInfo repoInfo;
    for (const auto &repo : m_repoManager->getRepositoriesIAmMemberOf())
    {
        if (repo.isOwner && repo.displayName == repoName)
        {
            repoInfo = repo;
            break;
        }
    }
    if (!repoInfo.isValid())
    {
        CustomMessageBox::critical(this, "Error", "Received a change proposal for a repository you don't own or manage.");
        QFile::remove(tempBundlePath);
        return;
    }

    // 2. If tempBundlePath already looks like a final selected path (because we set it in NetworkManager),
    //    skip re-asking and moving. Otherwise, prompt and move.
    QString finalPath = tempBundlePath;
    bool cameFromTemp = tempBundlePath.contains(QStandardPaths::writableLocation(QStandardPaths::TempLocation));
    if (cameFromTemp)
    {
        QString defaultName = QString("proposal_%1_from_%2.zip").arg(repoName, fromPeer);
        QString savePath = CustomFileDialog::getSaveFileName(this, "Save Incoming Proposal",
                                                             QDir(QStandardPaths::writableLocation(QStandardPaths::DownloadLocation)).filePath(defaultName),
                                                             "Zip Archive (*.zip)");

        if (savePath.isEmpty())
        {
            CustomMessageBox::information(this, "Proposal Discarded", "The incoming proposal diff file was not saved and has been discarded.");
            QFile::remove(tempBundlePath);
            return;
        }

        if (QFile::exists(savePath))
        {
            QFile::remove(savePath);
        }
        if (!QFile::rename(tempBundlePath, savePath))
        {
            CustomMessageBox::critical(this, "File Error", "Could not move the downloaded proposal file. It has been discarded.");
            QFile::remove(tempBundlePath);
            return;
        }
        finalPath = savePath;
    }

    // 3. Show the review dialog (only for viewing the received zip). No git apply will be done here.
    notify("Change Proposal Received", QString("%1 proposed changes to '%2'.\nZip saved at: %3").arg(fromPeer, repoName, finalPath));
    ProposalReviewDialog *dlg = new ProposalReviewDialog(fromPeer, repoName, forBranch, message, this);
    dlg->setAttribute(Qt::WA_DeleteOnClose);

    // 5. Connect accept/reject handlers. They will now use `savePath`.
    connect(dlg, &ProposalReviewDialog::acceptedProposal, this, [=]() mutable
            {
                // Notify collaborator once that the proposal was accepted
                QVariantMap dec;
                dec["repoName"] = repoName;
                dec["forBranch"] = forBranch;
                dec["accepted"] = true;
                m_networkManager->sendEncryptedToPeerId(fromPeer, "PROPOSAL_REVIEW_DECISION", dec);
            });

    connect(dlg, &ProposalReviewDialog::rejectedProposal, this, [=]() mutable
            {
                QVariantMap dec;
                dec["repoName"] = repoName;
                dec["forBranch"] = forBranch;
                dec["accepted"] = false;
                m_networkManager->sendEncryptedToPeerId(fromPeer, "PROPOSAL_REVIEW_DECISION", dec);
            });

    dlg->show(); });
}

// Handle pre-review requests and respond with accept/reject without pulling/applying anything.
// This is received as a secure message in secureMessageReceived switch below.

// ...
void MainWindow::handleProjectWindowGroupMessage(const QString &ownerRepoAppId, const QString &message)
{
    m_networkManager->sendGroupChatMessage(ownerRepoAppId, message);

    ManagedRepositoryInfo localRepoInfo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepoInfo.isValid() && m_projectWindows.contains(localRepoInfo.appId))
    {
        m_projectWindows[localRepoInfo.appId]->displayGroupMessage(m_myUsername, message);
    }
    // Persist outgoing chat
    if (m_repoManager && !ownerRepoAppId.isEmpty())
    {
        m_repoManager->appendChatMessage(ownerRepoAppId, m_myUsername, message);
    }
}

void MainWindow::handleGroupMessage(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message)
{
    ManagedRepositoryInfo localRepoInfo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);

    if (localRepoInfo.isValid())
    {
        if (m_projectWindows.contains(localRepoInfo.appId))
        {
            m_projectWindows[localRepoInfo.appId]->displayGroupMessage(senderPeerId, message);
        }
        else
        {
            m_networkPanel->logGroupChatMessage(localRepoInfo.displayName, senderPeerId, message);
        }
        // Persist incoming chat
        if (m_repoManager && !ownerRepoAppId.isEmpty())
        {
            m_repoManager->appendChatMessage(ownerRepoAppId, senderPeerId, message);
        }
    }
}

void MainWindow::handleDisconnectFromPeer(const QString &peerId)
{
    Q_UNUSED(peerId);
    // Refresh UI to reflect disconnected peer states
    updateUiFromBackend();
}

void MainWindow::handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg)
{
    Q_UNUSED(socket);
    m_networkPanel->logBroadcastMessage(peer, msg);
}

void MainWindow::handleSendBroadcastMessage(const QString &message)
{
    m_networkManager->broadcastTcpMessage(message);
    m_networkPanel->logBroadcastMessage(m_myUsername, message);
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username)
{
    QString pkh;
    DiscoveredPeerInfo peerInfo = m_networkManager->getDiscoveredPeerInfo(username);
    if (!peerInfo.publicKeyHex.isEmpty())
    {
        pkh = " (PKH: " + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8) + "...)";
    }
    QString peerDisplay = !username.isEmpty() ? username + pkh : address.toString();

    CustomMessageBox::StandardButton result = CustomMessageBox::question(this, "Peer Connection Request",
                                                                         QString("Peer '%1' at %2 wants to establish a connection with you.\n\nDo you want to accept?").arg(peerDisplay.toHtmlEscaped(), address.toString()),
                                                                         CustomMessageBox::Yes | CustomMessageBox::No);

    if (result == CustomMessageBox::Yes)
    {
        if (m_networkManager && m_networkManager->isConnectionPending(socket))
        {
            m_networkManager->acceptPendingTcpConnection(socket);
        }
    }
    else
    {
        if (m_networkManager && m_networkManager->isConnectionPending(socket))
        {
            m_networkManager->rejectPendingTcpConnection(socket);
        }
    }
}

void MainWindow::handleAddManagedRepo(const QString &preselectedPath)
{
    QString dirPath = preselectedPath;
    if (dirPath.isEmpty())
    {
        dirPath = CustomFileDialog::getExistingDirectory(this, "Select Git Repository Folder to Manage", QDir::homePath());
    }
    if (dirPath.isEmpty())
        return;

    qDebug() << "Selected repository path:" << dirPath;

    GitBackend tempBackend;
    std::string error;
    if (!tempBackend.openRepository(dirPath.toStdString(), error))
    {
        qDebug() << "Git backend error:" << QString::fromStdString(error);
        CustomMessageBox::warning(this, "Not a Git Repository",
                                  QString("The selected folder does not appear to be a valid Git repository.\n\nPath: %1\nError: %2")
                                      .arg(dirPath)
                                      .arg(QString::fromStdString(error)));
        return;
    }

    QString repoName = QFileInfo(dirPath).fileName();
    bool ok;
    QString displayName = CustomInputDialog::getText(this, "Manage Repository", "Enter a display name:", repoName, &ok);
    if (!ok || displayName.isEmpty())
        return;

    bool isPublic = (CustomMessageBox::question(this, "Set Visibility", "Make this repository public for other peers to discover and clone?", CustomMessageBox::Yes | CustomMessageBox::No) == CustomMessageBox::Yes);

    if (m_repoManager->addManagedRepository(displayName, dirPath, isPublic, m_myUsername, "", {m_myUsername}, true))
    {
        m_dashboardPanel->logStatus("Repository '" + displayName + "' added to management list.", false);
        if (m_networkManager)
            m_networkManager->sendDiscoveryBroadcast();
    }
    else
    {
        m_dashboardPanel->logStatus("Failed to add repository. It might already be managed.", true);
    }
}

void MainWindow::handleModifyRepoAccess(const QString &appId)
{
    if (appId.isEmpty())
        return;
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isOwner)
    {
        CustomMessageBox::warning(this, "Access Denied", "Only the owner can modify access.");
        return;
    }
    bool makePublic = !repoInfo.isPublic;
    if (CustomMessageBox::question(this, "Confirm Access Change", QString("Change access for '%1' to %2?").arg(repoInfo.displayName, makePublic ? "Public" : "Private")) == CustomMessageBox::Yes)
    {
        m_repoManager->setRepositoryVisibility(appId, makePublic);
        m_networkManager->sendDiscoveryBroadcast();
    }
}

void MainWindow::handleDeleteRepo(const QString &appId)
{
    if (appId.isEmpty())
        return;
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid())
    {
        m_dashboardPanel->logStatus("Error: Repository not found in managed list.", true);
        return;
    }
    if (CustomMessageBox::question(this, "Confirm Deletion", QString("Are you sure you want to remove '%1' from your managed list? This will not delete local files.").arg(repoInfo.displayName)) == CustomMessageBox::Yes)
    {
        m_repoManager->removeManagedRepository(appId);
        m_networkManager->sendDiscoveryBroadcast();
    }
}

void MainWindow::handleConnectToPeer(const QString &peerId)
{
    if (!m_networkManager)
        return;
    DiscoveredPeerInfo peerInfo = m_networkManager->getDiscoveredPeerInfo(peerId);
    if (peerInfo.id.isEmpty())
    {
        CustomMessageBox::critical(this, "Error", "Could not find peer info. They may have gone offline.");
        return;
    }
    m_networkPanel->logMessage("Initiating connection to peer '" + peerId + "'...", "blue");
    m_networkManager->connectToTcpPeer(peerInfo.address, peerInfo.tcpPort, peerInfo.id);
}

void MainWindow::handleCloneRepo(const QString &peerId, const QString &repoName)
{
    if (!m_networkManager || !m_repoManager)
    {
        CustomMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
        return;
    }

    if (m_repoManager->getCloneInfoByOwnerAndDisplayName(peerId, repoName).isValid())
    {
        CustomMessageBox::information(this, "Already Cloned", "You appear to have already cloned this repository.");
        return;
    }

    QString localClonePathBase = CustomFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty())
        return;

    QString fullLocalClonePath = QDir(localClonePathBase).filePath(repoName);
    if (QDir(fullLocalClonePath).exists())
    {
        CustomMessageBox::warning(this, "Directory Exists", "The target directory already exists.");
        return;
    }

    m_pendingCloneRequest.ownerPeerId = peerId;
    m_pendingCloneRequest.repoDisplayName = repoName;
    m_pendingCloneRequest.localClonePath = fullLocalClonePath;

    DiscoveredPeerInfo providerPeerInfo = m_networkManager->getDiscoveredPeerInfo(peerId);
    if (providerPeerInfo.id.isEmpty())
    {
        CustomMessageBox::critical(this, "Connection Error", "Could not find peer info. They may have gone offline.");
        m_pendingCloneRequest.clear();
        return;
    }

    m_networkPanel->logMessage(QString("Initiating clone for '%1' from '%2'...").arg(repoName, peerId), "blue");
    qDebug() << "Clone requested from" << peerId << "for repo" << repoName;
    m_networkManager->requestBundleFromPeer(peerId, repoName, fullLocalClonePath);
}

// Discovery control is automatic with TCP server lifecycle in this build.

void MainWindow::addCollaboratorToRepo(const QString &localAppId, const QString &peerIdToAdd)
{
    QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerIdToAdd);
    if (!peerSocket)
    {
        CustomMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost.").arg(peerIdToAdd));
        return;
    }

    if (m_repoManager->addCollaborator(localAppId, peerIdToAdd))
    {
        // Do not log "added" until recipient accepts/has repo; just trace silently here
        qDebug() << "Owner updated local group to include" << peerIdToAdd << "for" << m_repoManager->getRepositoryInfo(localAppId).displayName;

        ManagedRepositoryInfo updatedRepoInfo = m_repoManager->getRepositoryInfo(localAppId);

        QVariantMap payload;
        payload["ownerRepoAppId"] = updatedRepoInfo.ownerRepoAppId;
        payload["repoDisplayName"] = updatedRepoInfo.displayName;
        payload["ownerPeerId"] = updatedRepoInfo.ownerPeerId;
        payload["groupMembers"] = updatedRepoInfo.groupMembers;

        for (const QString &memberId : updatedRepoInfo.groupMembers)
        {
            if (memberId == m_myUsername)
                continue;
            QTcpSocket *memberSocket = m_networkManager->getSocketForPeer(memberId);
            if (memberSocket)
            {
                m_networkManager->sendEncryptedMessage(memberSocket, "COLLABORATOR_ADDED", payload);
                m_networkPanel->logMessage(QString("Sent collaborator invitation for '%1' to '%2'.").arg(updatedRepoInfo.displayName, memberId), QColor("#0F4C4A"));
            }
        }

        if (m_projectWindows.contains(localAppId))
        {
            m_projectWindows[localAppId]->updateGroupMembers();
        }
    }
    else
    {
        m_dashboardPanel->logStatus(QString("Failed to add '%1' as collaborator (already a member?).").arg(peerIdToAdd), true);
    }
}

void MainWindow::handleAddCollaboratorFromPanel(const QString &peerId)
{
    if (!m_networkManager || m_networkManager->getSocketForPeer(peerId) == nullptr)
    {
        CustomMessageBox::warning(this, "Not Connected", "You must be connected to a peer to add them as a collaborator.");
        return;
    }

    QList<ManagedRepositoryInfo> myOwnedRepos = m_repoManager->getRepositoriesIAmMemberOf();
    QStringList eligibleRepoNames;
    QMap<QString, QString> nameToAppIdMap;
    for (const auto &repo : myOwnedRepos)
    {
        if (repo.isOwner && !repo.groupMembers.contains(peerId))
        {
            eligibleRepoNames.append(repo.displayName);
            nameToAppIdMap[repo.displayName] = repo.appId;
        }
    }

    if (eligibleRepoNames.isEmpty())
    {
        CustomMessageBox::information(this, "No Eligible Repositories", QString("You do not own any repositories that '%1' is not already a collaborator on.").arg(peerId));
        return;
    }

    bool ok;
    QStringList repoNamesToAdd = CustomInputDialog::getMultiItems(this, "Add Collaborator", QString("Select repositories to add '%1' to:").arg(peerId), eligibleRepoNames, &ok);

    if (ok && !repoNamesToAdd.isEmpty())
    {
        for (const QString &repoName : repoNamesToAdd)
        {
            QString localAppId = nameToAppIdMap.value(repoName);
            qDebug() << "Adding collaborator" << peerId << "to repo" << repoName << "(" << localAppId << ")";
            addCollaboratorToRepo(localAppId, peerId);
        }
    }
}

void MainWindow::handleAddCollaboratorFromProjectWindow(const QString &localAppId)
{
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(localAppId);
    if (!repoInfo.isOwner)
        return;

    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
    QStringList eligiblePeers;
    for (const auto &peer : connectedPeers)
    {
        if (!repoInfo.groupMembers.contains(peer))
        {
            eligiblePeers.append(peer);
        }
    }

    if (eligiblePeers.isEmpty())
    {
        CustomMessageBox::information(this, "No Eligible Peers", "No new connected peers are available to add.");
        return;
    }

    bool ok;
    QStringList peersToAdd = CustomInputDialog::getMultiItems(this, "Add Collaborator", QString("Select peers to add to '%1':").arg(repoInfo.displayName), eligiblePeers, &ok);

    if (ok && !peersToAdd.isEmpty())
    {
        for (const QString &peer : peersToAdd)
        {
            qDebug() << "Adding collaborator" << peer << "to repo appId" << localAppId;
            addCollaboratorToRepo(localAppId, peer);
        }
    }
}

void MainWindow::handleRemoveCollaboratorFromProjectWindow(const QString &appId, const QString &peerIdToRemove)
{
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isOwner)
        return;

    if (CustomMessageBox::question(this, "Confirm Removal", QString("Are you sure you want to remove '%1' from '%2'?").arg(peerIdToRemove, repoInfo.displayName)) == CustomMessageBox::No)
    {
        return;
    }

    if (m_repoManager->removeCollaborator(appId, peerIdToRemove))
    {
        m_dashboardPanel->logStatus(QString("Removed '%1' from '%2'.").arg(peerIdToRemove, repoInfo.displayName), false);

        ManagedRepositoryInfo updatedRepoInfo = m_repoManager->getRepositoryInfo(appId);

        QVariantMap payload;
        payload["ownerRepoAppId"] = updatedRepoInfo.ownerRepoAppId;
        payload["repoDisplayName"] = updatedRepoInfo.displayName;
        payload["ownerPeerId"] = updatedRepoInfo.ownerPeerId;
        payload["groupMembers"] = updatedRepoInfo.groupMembers;

        QTcpSocket *removedPeerSocket = m_networkManager->getSocketForPeer(peerIdToRemove);
        if (removedPeerSocket)
        {
            m_networkManager->sendEncryptedMessage(removedPeerSocket, "COLLABORATOR_REMOVED", payload);
        }

        for (const QString &memberId : updatedRepoInfo.groupMembers)
        {
            if (memberId == m_myUsername)
                continue;
            QTcpSocket *memberSocket = m_networkManager->getSocketForPeer(memberId);
            if (memberSocket)
            {
                m_networkManager->sendEncryptedMessage(memberSocket, "COLLABORATOR_ADDED", payload);
            }
        }

        if (m_projectWindows.contains(appId))
        {
            m_projectWindows[appId]->updateGroupMembers();
        }
    }
}

void MainWindow::handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload)
{
    if (messageType == "PROPOSAL_REVIEW_REQUEST")
    {
        QString repo = payload.value("repoName").toString();
        QString branch = payload.value("forBranch").toString();
        QString msg = payload.value("message").toString();
        // Show a non-modal 5-second notification, then prompt for a download directory
        QTimer::singleShot(0, this, [=]()
                           {
            // Timed notification
            CustomMessageBox *infoDlg = new CustomMessageBox(CustomMessageBox::Information,
                                                             "Change Proposal",
                                                             QString("%1 proposed changes to '%2' on %3.\n\nMessage:\n%4")
                                                                 .arg(peerId, repo, branch, msg),
                                                             CustomMessageBox::NoButton,
                                                             this);
            infoDlg->setModal(false);
            infoDlg->show();

            QTimer::singleShot(5000, this, [=]() {
                if (infoDlg) {
                    infoDlg->close();
                    infoDlg->deleteLater();
                }

                // Let the owner choose directory AND filename to save the incoming .zip
                QString defaultBase = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
                if (defaultBase.isEmpty()) defaultBase = QDir::homePath();
                QString defaultName = QString("proposal_%1_from_%2.zip").arg(repo, peerId);
                QString defaultPath = QDir(defaultBase).filePath(defaultName);
                QString fullPath = CustomFileDialog::getSaveFileName(this,
                                                                     "Choose file to save incoming proposal diff",
                                                                     defaultPath,
                                                                     "Zip Archive (*.zip)");
                if (fullPath.isEmpty()) {
                    // Fallback to default path if user cancels
                    fullPath = defaultPath;
                }

                // Ensure the directory exists for the chosen path
                QDir targetDir = QFileInfo(fullPath).dir();
                if (!targetDir.exists()) targetDir.mkpath(".");

                // Set pending path so transfer writes directly here
                if (m_networkManager) {
                    m_networkManager->setPendingProposalSavePath(peerId, repo, branch, fullPath);
                }

                // Now signal readiness so collaborator can send the zip
                if (m_networkManager) {
                    QVariantMap acceptPayload;
                    acceptPayload["repoName"] = repo;
                    acceptPayload["forBranch"] = branch;
                    acceptPayload["message"] = msg;
                    m_networkManager->sendEncryptedToPeerId(peerId, "PROPOSAL_REVIEW_ACCEPTED", acceptPayload);
                }
            }); });
        return;
    }
    if (messageType == "PROPOSAL_REVIEW_ACCEPTED")
    {
        // Collaborator side informational only; actual sending is triggered internally.
        notify("Review Accepted", QString("%1 is ready to receive your proposal.").arg(peerId));
        return;
    }
    if (messageType == "PROPOSAL_REVIEW_REJECTED")
    {
        notify("Review Declined", QString("%1 declined to review your proposal.").arg(peerId));
        return;
    }
    if (messageType == "PROPOSAL_REVIEW_DECISION")
    {
        // Collaborator receives owner decision after reviewing downloaded zip
        QString repo = payload.value("repoName").toString();
        QString branch = payload.value("forBranch").toString();
        bool accepted = payload.value("accepted").toBool();
        if (accepted)
        {
            notify("Proposal Accepted", QString("%1 accepted your proposal for '%2' on %3. They may upload a new version soon.")
                                            .arg(peerId, repo, branch));
        }
        else
        {
            notify("Proposal Rejected", QString("%1 rejected your proposal for '%2' on %3.")
                                            .arg(peerId, repo, branch));
        }
        return;
    }
}

void MainWindow::handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers)
{
    ManagedRepositoryInfo localRepo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepo.isValid())
    {
        // Already tracking this owner's repo locally; just update members
        m_repoManager->updateGroupMembersAndOwnerAppId(localRepo.appId, ownerRepoAppId, groupMembers);
        m_dashboardPanel->logStatus(QString("Group members updated for '%1' by owner %2.").arg(repoDisplayName, ownerPeerId), false);
        updateUiFromBackend();
        return;
    }

    // New access granted. Prompt to clone now.
    QString title = "Collaboration Invitation";
    QString text = QString("You were granted access to '%1' by %2.\n\nDo you want to clone this repository now?")
                       .arg(repoDisplayName, ownerPeerId);
    m_networkPanel->logMessage(QString("Received collaborator invitation for '%1' from %2.").arg(repoDisplayName, ownerPeerId), QColor("#0F4C4A"));
    auto choice = CustomMessageBox::question(this, title, text, CustomMessageBox::Yes | CustomMessageBox::No);
    if (choice == CustomMessageBox::Yes)
    {
        // Reuse existing clone flow which asks for a directory and performs bundle-based clone
        handleCloneRepo(ownerPeerId, repoDisplayName);
    }
    else
    {
        // Optionally remember availability for later; show in network panel
        m_networkPanel->logMessage(QString("You can clone '%1' from %2 later from the Network tab.").arg(repoDisplayName, ownerPeerId), QColor("purple"));
        m_networkManager->addSharedRepoToPeer(ownerPeerId, repoDisplayName);
    }
    updateUiFromBackend();
}

void MainWindow::handleCollaboratorRemoved(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName)
{
    ManagedRepositoryInfo localRepo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepo.isValid())
    {
        QString localAppId = localRepo.appId;
        if (m_projectWindows.contains(localAppId))
        {
            m_projectWindows[localAppId]->close();
        }
        m_repoManager->removeManagedRepository(localAppId);

        QString msg = QString("You were removed from '%1' by owner %2. It has been removed from your managed list.").arg(repoDisplayName, peerId);
        CustomMessageBox::information(this, "Access Revoked", msg);
        m_dashboardPanel->logStatus(msg, true);
    }
}

void MainWindow::handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt)
{
    Q_UNUSED(clientWantsToSaveAt);
    if (!m_repoManager || !m_networkManager)
        return;

    ManagedRepositoryInfo repoToBundle;
    for (const auto &repo : m_repoManager->getRepositoriesIAmMemberOf())
    {
        if (repo.isOwner && repo.displayName == repoDisplayName)
        {
            repoToBundle = repo;
            break;
        }
    }

    if (!repoToBundle.isValid())
    {
        m_networkPanel->logMessage(QString("Denied bundle request for '%1': Not owned by me or not found.").arg(repoDisplayName), Qt::red);
        return;
    }

    bool canAccess = repoToBundle.isPublic || repoToBundle.groupMembers.contains(sourcePeerUsername);
    if (!canAccess)
    {
        m_networkPanel->logMessage(QString("Denied access for private repo '%1' to '%2'.").arg(repoDisplayName, sourcePeerUsername), Qt::red);
        return;
    }

    GitBackend tempGitBackend;
    std::string errorMessage;
    if (!tempGitBackend.openRepository(repoToBundle.localPath.toStdString(), errorMessage))
    {
        m_networkPanel->logMessage(QString("Failed to open '%1' for bundling: %2").arg(repoDisplayName, QString::fromStdString(errorMessage)), Qt::red);
        return;
    }

    std::string bundleFilePathStd;
    std::string errorMsgBundle;
    // Create a unique temporary directory to hold the bundle output
    QString tempBase = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QString uniqueOutDir = QDir(tempBase).filePath(QString("SyncIt.%1").arg(QUuid::createUuid().toString(QUuid::Id128)));
    if (!QDir().mkpath(uniqueOutDir))
    {
        m_networkPanel->logMessage(QString("Failed to prepare temp dir for bundling '%1'.").arg(repoDisplayName), Qt::red);
        return;
    }
    if (tempGitBackend.createBundle(uniqueOutDir.toStdString(), repoToBundle.displayName.toStdString(), bundleFilePathStd, errorMsgBundle))
    {
        m_networkPanel->logMessage(QString("Bundle for '%1' created. Starting transfer to %2...").arg(repoDisplayName, sourcePeerUsername), "purple");
        // This is now an internal detail of NetworkManager
        // m_networkManager->startSendingBundle(requestingPeerSocket, repoDisplayName, QString::fromStdString(bundleFilePathStd));
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to create bundle for '%1': %2").arg(repoToBundle.displayName, QString::fromStdString(errorMsgBundle)), Qt::red);
    }
}

void MainWindow::handleRepoBundleSent(const QString &repoName, const QString &recipientUsername)
{
    // Owner side confirmation
    m_networkPanel->logMessage(QString("Transfer of '%1' to %2 completed.").arg(repoName, recipientUsername), QColor("darkGreen"));
    CustomMessageBox::information(this, "Bundle Sent", QString("Repository '%1' has been sent to %2.").arg(repoName, recipientUsername));
}

void MainWindow::handleRepoBundleTransferStarted(const QString &repoName, qint64 totalBytes)
{
    // Record transfer start time for speed calculation
    m_transferStartTime = QDateTime::currentDateTime();

    // Create and show progress dialog if not already shown
    if (!m_transferProgressDialog)
    {
        m_transferProgressDialog = new CustomProgressDialog(this);
        m_transferProgressDialog->setAutoClose(false);
        m_transferProgressDialog->setAutoReset(false);

        // Connect cancel signal to handle transfer cancellation
        connect(m_transferProgressDialog, &CustomProgressDialog::canceled, this, [this, repoName]()
                {
            // Log the cancellation
            m_networkPanel->logMessage(QString("Transfer of '%1' was cancelled by user").arg(repoName), Qt::red);
            
            // Hide and cleanup dialog
            if (m_transferProgressDialog) {
                m_transferProgressDialog->hide();
                m_transferProgressDialog->deleteLater();
                m_transferProgressDialog = nullptr;
            }
            
            // Reset progress tracking
            m_cloneProgressPct.remove(repoName); });
    }

    // Configure the dialog for this transfer
    m_transferProgressDialog->setLabelText(QString("Downloading repository: %1\nSize: %2 KB\nStarting transfer...").arg(repoName).arg(totalBytes / 1024));
    m_transferProgressDialog->setCancelButtonText("Cancel Transfer");
    m_transferProgressDialog->setRange(0, 100);
    m_transferProgressDialog->setValue(0);
    m_transferProgressDialog->reset();

    // Show the dialog
    m_transferProgressDialog->show();
    m_transferProgressDialog->raise();
    m_transferProgressDialog->activateWindow();

    // Log transfer start
    m_networkPanel->logMessage(QString("Starting download of '%1' (%2 KB)").arg(repoName).arg(totalBytes / 1024), QColor("darkBlue"));
}

void MainWindow::handleRepoBundleProgress(const QString &repoName, qint64 bytesReceived, qint64 totalBytes)
{
    if (totalBytes <= 0)
        return;

    int pct = int((bytesReceived * 100) / totalBytes);

    // Update progress dialog if it exists
    if (m_transferProgressDialog && !m_transferProgressDialog->wasCanceled())
    {
        m_transferProgressDialog->setValue(pct);

        // Calculate transfer speed and ETA
        qint64 elapsedMs = m_transferStartTime.msecsTo(QDateTime::currentDateTime());
        QString speedInfo;
        QString etaInfo;

        if (elapsedMs > 1000 && bytesReceived > 0) // Only calculate after 1 second
        {
            double bytesPerSecond = (double)bytesReceived / (elapsedMs / 1000.0);
            double kbPerSecond = bytesPerSecond / 1024.0;

            // Calculate ETA
            qint64 remainingBytes = totalBytes - bytesReceived;
            if (bytesPerSecond > 0)
            {
                int etaSeconds = (int)(remainingBytes / bytesPerSecond);
                int etaMinutes = etaSeconds / 60;
                etaSeconds %= 60;

                if (etaMinutes > 0)
                    etaInfo = QString("ETA: %1m %2s").arg(etaMinutes).arg(etaSeconds);
                else
                    etaInfo = QString("ETA: %1s").arg(etaSeconds);
            }

            if (kbPerSecond >= 1024)
                speedInfo = QString("Speed: %.1f MB/s").arg(kbPerSecond / 1024.0);
            else
                speedInfo = QString("Speed: %.1f KB/s").arg(kbPerSecond);
        }
        else
        {
            speedInfo = "Speed: calculating...";
            etaInfo = "ETA: calculating...";
        }

        // Update label with detailed info
        QString progressText = QString("Downloading repository: %1\nProgress: %2% (%3 KB / %4 KB)\n%5\n%6")
                                   .arg(repoName)
                                   .arg(pct)
                                   .arg(bytesReceived / 1024.0, 0, 'f', 1)
                                   .arg(totalBytes / 1024.0, 0, 'f', 1)
                                   .arg(speedInfo)
                                   .arg(etaInfo);
        m_transferProgressDialog->setLabelText(progressText);
    }

    // Log progress periodically
    int last = m_cloneProgressPct.value(repoName, -1);
    if (pct / 10 != last / 10)
    { // log every ~10%
        m_networkPanel->logMessage(QString("Receiving '%1': %2% (%3 / %4 bytes)")
                                       .arg(repoName)
                                       .arg(pct)
                                       .arg(bytesReceived)
                                       .arg(totalBytes),
                                   QColor("#888888"));
        m_cloneProgressPct.insert(repoName, pct);
    }
}

void MainWindow::handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    // Close progress dialog when transfer succeeds, per requirement
    if (success && m_transferProgressDialog)
    {
        m_transferProgressDialog->hide();
        m_transferProgressDialog->deleteLater();
        m_transferProgressDialog = nullptr;
    }

    // Clean up progress tracking
    m_cloneProgressPct.remove(repoName);

    if (!success)
    {
        m_networkPanel->logMessage(QString("Failed to receive repo '%1': %2").arg(repoName, message), Qt::red);
        CustomMessageBox::critical(this, "Clone Failed", QString("Failed to receive '%1':\n%2").arg(repoName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    // This handler is now ONLY for clones. Proposals are handled by handleIncomingChangeProposal.
    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoDisplayName != repoName)
    {
        // This can happen if a proposal bundle download finishes. Ignore it here.
        qDebug() << "Bundle completed for non-clone operation:" << repoName;
        return;
    }

    m_networkPanel->logMessage(QString("Bundle for '%1' received. Cloning...").arg(repoName), "blue");
    QString finalClonePath = m_pendingCloneRequest.localClonePath;

    QProcess gitProcess;
    gitProcess.start("git", QStringList() << "clone" << QDir::toNativeSeparators(localBundlePath) << QDir::toNativeSeparators(finalClonePath));

    bool cloneSuccess = false;
    if (!gitProcess.waitForFinished(-1))
    {
        m_networkPanel->logMessage("Clone failed: Git process timed out.", Qt::red);
    }
    else if (gitProcess.exitCode() == 0)
    {
        cloneSuccess = true;
        m_networkPanel->logMessage(QString("Successfully cloned '%1'.").arg(repoName), Qt::darkGreen);
        CustomMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(repoName, finalClonePath));
    }
    else
    {
        QString errorMsg = QString(gitProcess.readAllStandardError());
        m_networkPanel->logMessage("Clone failed: " + errorMsg, Qt::red);
        CustomMessageBox::critical(this, "Clone Failed", QString("Git clone command failed:\n%1").arg(errorMsg));
    }

    // Always try to add to managed repositories if clone succeeded
    if (cloneSuccess)
    {
        if (m_repoManager->addManagedRepository(repoName, finalClonePath, false, m_pendingCloneRequest.ownerPeerId, "", {m_pendingCloneRequest.ownerPeerId, m_myUsername}, false))
        {
            updateUiFromBackend();
            ManagedRepositoryInfo newRepoInfo = m_repoManager->getRepositoryInfoByPath(finalClonePath);
            if (newRepoInfo.isValid())
            {
                m_networkPanel->logMessage(QString("Added '%1' to your managed repositories.").arg(repoName), QColor("#2c7a7b"));
                handleOpenRepoInProjectWindow(newRepoInfo.appId);
            }
        }
        else
        {
            m_networkPanel->logMessage(QString("Note: '%1' was cloned but could not be added to Dashboard (already managed?).").arg(repoName), QColor("orange"));
        }
    }

    QFile::remove(localBundlePath);
    m_pendingCloneRequest.clear();
}