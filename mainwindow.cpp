#include "mainwindow.h"
#include "dashboard_panel.h"
#include "network_panel.h"
#include "project_window.h"
#include "identity_manager.h"
#include "repository_manager.h"
#include "network_manager.h"
#include "git_backend.h"
#include "custom_dialogs.h"

#include <QVBoxLayout>
#include <QStackedWidget>
#include <QToolButton>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
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
    bool ok_name;
    QString name_prompt_default = QHostInfo::localHostName();
    if (name_prompt_default.isEmpty())
    {
        name_prompt_default = "Peer" + QString::number(QRandomGenerator::global()->bounded(10000));
    }
    m_myUsername = CustomInputDialog::getText(this, "Enter Peer Name", "Peer Name:", name_prompt_default, &ok_name);
    if (!ok_name || m_myUsername.isEmpty())
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
    updateUiFromBackend();

    m_networkManager->startTcpServer();
}

MainWindow::~MainWindow() {}

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

    UserProfileWidget *userProfile = new UserProfileWidget(m_myUsername, this);
    sidebarLayout->addWidget(userProfile);

    m_mainContentWidget = new QStackedWidget(this);

    m_dashboardPanel = new DashboardPanel(this);
    m_dashboardPanel->setWelcomeMessage(m_myUsername);

    m_networkPanel = new NetworkPanel(this);

    m_mainContentWidget->addWidget(m_dashboardPanel);
    m_mainContentWidget->addWidget(m_networkPanel);

    mainLayout->addWidget(m_sidebarPanel);
    mainLayout->addWidget(m_mainContentWidget, 1);

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
    connect(m_networkPanel, &NetworkPanel::toggleDiscoveryRequested, this, &MainWindow::handleToggleDiscovery);
    connect(m_networkPanel, &NetworkPanel::connectToPeerRequested, this, &MainWindow::handleConnectToPeer);
    connect(m_networkPanel, &NetworkPanel::cloneRepoRequested, this, &MainWindow::handleCloneRepo);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromPanel);
}

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
    {
        m_mainContentWidget->setCurrentWidget(m_dashboardPanel);
    }
    else if (m_networkButton->isChecked())
    {
        m_mainContentWidget->setCurrentWidget(m_networkPanel);
    }
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
    QTcpSocket *ownerSocket = m_networkManager->getSocketForPeer(ownerPeerId);
    if (!ownerSocket)
    {
        CustomMessageBox::warning(this, "Not Connected", QString("You must be connected to the owner (%1) to propose changes.").arg(ownerPeerId));
        return;
    }

    ManagedRepositoryInfo repoInfo = m_repoManager->getCloneInfoByOwnerAndDisplayName(ownerPeerId, repoDisplayName);
    if (!repoInfo.isValid())
        return;

    GitBackend backend;
    std::string error;
    if (!backend.openRepository(repoInfo.localPath.toStdString(), error))
        return;

    QTemporaryFile tempBundleFile(QDir::tempPath() + "/proposal_XXXXXX.bundle");
    tempBundleFile.setAutoRemove(false);
    if (tempBundleFile.open())
    {
        QString bundlePath = tempBundleFile.fileName();
        tempBundleFile.close();

        if (backend.createDiffBundle(bundlePath.toStdString(), fromBranch.toStdString(), "origin/main", error))
        {
            m_networkManager->sendChangeProposal(ownerSocket, repoDisplayName, fromBranch, bundlePath);
            CustomMessageBox::information(this, "Proposal Sent", "Your changes have been sent to the owner for review.");
        }
        else
        {
            CustomMessageBox::warning(this, "Failed to Propose", QString::fromStdString(error));
        }
    }
}

void MainWindow::handleIncomingChangeProposal(const QString &fromPeer, const QString &repoName, const QString &forBranch, const QString &bundlePath)
{
    CustomMessageBox::StandardButton ret = CustomMessageBox::question(this, "Change Proposal Received",
                                                                      QString("Peer '%1' has proposed changes for repository '%2' from their branch '%3'.\n\nDo you want to review and merge these changes?").arg(fromPeer, repoName, forBranch),
                                                                      CustomMessageBox::Yes | CustomMessageBox::No);

    if (ret == CustomMessageBox::No)
    {
        QFile::remove(bundlePath);
        return;
    }

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
        QFile::remove(bundlePath);
        return;
    }

    GitBackend backend;
    std::string error;
    if (!backend.openRepository(repoInfo.localPath.toStdString(), error))
    {
        CustomMessageBox::critical(this, "Error", "Could not open local repository to apply changes.");
        QFile::remove(bundlePath);
        return;
    }

    if (backend.applyBundle(bundlePath.toStdString(), error))
    {
        CustomMessageBox::information(this, "Changes Merged", "The proposed changes have been successfully merged.");
        if (m_projectWindows.contains(repoInfo.appId))
        {
            m_projectWindows[repoInfo.appId]->updateStatus();
        }
    }
    else
    {
        CustomMessageBox::critical(this, "Merge Failed", QString("Could not automatically merge changes. Please check the repository for conflicts.\n\nDetails: %1").arg(QString::fromStdString(error)));
    }

    QFile::remove(bundlePath);
}

// ... All other handler functions are the same as the last complete version you provided ...
void MainWindow::handleProjectWindowGroupMessage(const QString &ownerRepoAppId, const QString &message)
{
    m_networkManager->sendGroupChatMessage(ownerRepoAppId, message);

    ManagedRepositoryInfo localRepoInfo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepoInfo.isValid() && m_projectWindows.contains(localRepoInfo.appId))
    {
        m_projectWindows[localRepoInfo.appId]->displayGroupMessage(m_myUsername, message);
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
    }
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
        QMessageBox::warning(this, "Access Denied", "Only the owner can modify access.");
        return;
    }
    bool makePublic = !repoInfo.isPublic;
    if (QMessageBox::question(this, "Confirm Access Change", QString("Change access for '%1' to %2?").arg(repoInfo.displayName, makePublic ? "Public" : "Private"), QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
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
    if (QMessageBox::question(this, "Confirm Deletion", QString("Are you sure you want to remove '%1' from your managed list? This will not delete local files.").arg(repoInfo.displayName), QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
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
        QMessageBox::critical(this, "Error", "Could not find peer info. They may have gone offline.");
        return;
    }
    m_networkPanel->logMessage("Initiating connection to peer '" + peerId + "'...", "blue");
    m_networkManager->connectToTcpPeer(peerInfo.address, peerInfo.tcpPort, peerInfo.id);
}

void MainWindow::handleCloneRepo(const QString &peerId, const QString &repoName)
{
    if (!m_networkManager || !m_repoManager)
    {
        QMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
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
    m_networkManager->requestBundleFromPeer(peerId, repoName, fullLocalClonePath);
}

void MainWindow::handleToggleDiscovery()
{
    if (m_networkManager->getTcpServerPort() > 0)
    {
        m_networkManager->stopUdpDiscovery();
        m_networkManager->stopTcpServer();
    }
    else
    {
        m_networkManager->startTcpServer();
    }
}

void MainWindow::addCollaboratorToRepo(const QString &localAppId, const QString &peerIdToAdd)
{
    QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerIdToAdd);
    if (!peerSocket)
    {
        QMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost.").arg(peerIdToAdd));
        return;
    }

    if (m_repoManager->addCollaborator(localAppId, peerIdToAdd))
    {
        m_dashboardPanel->logStatus(QString("Added '%1' as a collaborator to '%2'.").arg(peerIdToAdd, m_repoManager->getRepositoryInfo(localAppId).displayName), false);

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
        QMessageBox::warning(this, "Not Connected", "You must be connected to a peer to add them as a collaborator.");
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
        QMessageBox::information(this, "No Eligible Repositories", QString("You do not own any repositories that '%1' is not already a collaborator on.").arg(peerId));
        return;
    }

    bool ok;
    QString repoNameToAdd = QInputDialog::getItem(this, "Add Collaborator", QString("Select repository to add '%1' to:").arg(peerId), eligibleRepoNames, 0, false, &ok);

    if (ok && !repoNameToAdd.isEmpty())
    {
        QString localAppId = nameToAppIdMap.value(repoNameToAdd);
        addCollaboratorToRepo(localAppId, peerId);
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
        QMessageBox::information(this, "No Eligible Peers", "No new connected peers are available to add.");
        return;
    }

    bool ok;
    QString peerToAdd = QInputDialog::getItem(this, "Add Collaborator", QString("Select a peer to add to '%1':").arg(repoInfo.displayName), eligiblePeers, 0, false, &ok);

    if (ok && !peerToAdd.isEmpty())
    {
        addCollaboratorToRepo(localAppId, peerToAdd);
    }
}

void MainWindow::handleRemoveCollaboratorFromProjectWindow(const QString &appId, const QString &peerIdToRemove)
{
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isOwner)
        return;

    if (QMessageBox::question(this, "Confirm Removal", QString("Are you sure you want to remove '%1' from '%2'?").arg(peerIdToRemove, repoInfo.displayName), QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
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
    if (messageType == "ADD_MANAGED_REPO")
    {
        QString repoName = payload.value("repoDisplayName").toString();
        QString senderPeerId = payload.value("senderPeerId").toString();
        QString localPathHint = payload.value("localPathHint").toString();
        // Check if already managed
        ManagedRepositoryInfo info = m_repoManager->getCloneInfoByOwnerAndDisplayName(senderPeerId, repoName);
        if (!info.isValid())
        {
            // Use a default path if not present
            QString baseDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
            QString repoPath = QDir(baseDir).filePath(repoName);
            m_repoManager->addManagedRepository(repoName, repoPath, false, senderPeerId, "", {senderPeerId, m_myUsername}, false);
            updateUiFromBackend();
            m_networkPanel->logMessage(QString("Added '%1' to your managed repositories (via sender notification).").arg(repoName), QColor("#2c7a7b"));
        }
    }
    else
    {
        qDebug() << "Received generic secure message of type" << messageType << "from" << peerId;
    }
}

void MainWindow::handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers)
{
    ManagedRepositoryInfo localRepo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepo.isValid())
    {
        m_repoManager->updateGroupMembersAndOwnerAppId(localRepo.appId, ownerRepoAppId, groupMembers);
        m_dashboardPanel->logStatus(QString("Group members updated for '%1' by owner %2.").arg(repoDisplayName, ownerPeerId), false);
    }
    else
    {
        m_networkPanel->logMessage(QString("Peer '%1' has granted you access to '%2'. You can now clone it.").arg(ownerPeerId, repoDisplayName), QColor("purple"));
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
        QMessageBox::information(this, "Access Revoked", msg);
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
        m_networkManager->startSendingBundle(requestingPeerSocket, repoDisplayName, QString::fromStdString(bundleFilePathStd));
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
    QMessageBox::information(this, "Bundle Sent", QString("Repository '%1' has been sent to %2.").arg(repoName, recipientUsername));
}

void MainWindow::handleRepoBundleProgress(const QString &repoName, qint64 bytesReceived, qint64 totalBytes)
{
    if (totalBytes <= 0)
        return;
    int pct = int((bytesReceived * 100) / totalBytes);
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
    if (!success)
    {
        m_networkPanel->logMessage(QString("Failed to receive repo '%1': %2").arg(repoName, message), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Failed to receive '%1':\n%2").arg(repoName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    // Always try to add the repo after a successful clone, even if message type is blank or unexpected
    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoDisplayName != repoName)
    {
        m_networkPanel->logMessage(QString("Received unexpected bundle for '%1'. Attempting to add to managed repositories anyway.").arg(repoName), QColor("orange"));
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
        QMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(repoName, finalClonePath));
    }
    else
    {
        QString errorMsg = QString(gitProcess.readAllStandardError());
        m_networkPanel->logMessage("Clone failed: " + errorMsg, Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Git clone command failed:\n%1").arg(errorMsg));
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