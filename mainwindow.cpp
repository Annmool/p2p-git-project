#include "mainwindow.h"
#include "network_panel.h"
#include "repo_management_panel.h"
#include "project_window.h"
#include "git_backend.h"
#include "identity_manager.h"
#include "repository_manager.h"
#include "network_manager.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QHostInfo>
#include <QRandomGenerator>
#include <QProcess>
#include <QUuid>
#include <QTimer>
#include <QLabel>
#include <QPushButton>
#include <QCryptographicHash>
#include <QStandardPaths>
#include <QInputDialog>
#include <QComboBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCloseEvent>
#include <QCoreApplication> // Needed for QCoreApplication::processEvents

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
    m_myUsername = QInputDialog::getText(this, "Enter Peer Name", "Peer Name:", QLineEdit::Normal, name_prompt_default, &ok_name);
    if (!ok_name || m_myUsername.isEmpty())
    {
        m_myUsername = name_prompt_default;
    }

    m_identityManager = new IdentityManager(m_myUsername);
    if (!m_identityManager->initializeKeys())
    {
        QMessageBox::critical(this, "Identity Error", "Failed to initialize cryptographic keys! The application will now close.");
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

MainWindow::~MainWindow()
{
    // Child QObjects are deleted by parent QObject automatically.
}

void MainWindow::setupUi()
{
    setWindowTitle("P2P Git Client - " + m_myUsername);
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget);
    resize(1400, 800);

    QSplitter *mainSplitter = new QSplitter(Qt::Horizontal, this);
    m_repoManagementPanel = new RepoManagementPanel(mainSplitter);
    m_networkPanel = new NetworkPanel(mainSplitter);
    mainSplitter->addWidget(m_repoManagementPanel);
    mainSplitter->addWidget(m_networkPanel);
    mainSplitter->setSizes({600, 800});

    mainVLayout->addWidget(mainSplitter);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    QList<ProjectWindow *> openProjectWindows = m_projectWindows.values();
    for (ProjectWindow *pw : openProjectWindows)
    {
        pw->deleteLater(); // Schedule for deletion
    }
    m_projectWindows.clear(); // Clear the map now

    if (m_networkManager)
    {
        m_networkManager->stopUdpDiscovery();
        m_networkManager->stopTcpServer();
        m_networkManager->disconnectAllTcpPeers();
    }

    QMainWindow::closeEvent(event);
}

void MainWindow::connectSignals()
{
    connect(m_repoManager, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::updateUiFromBackend);
    connect(m_repoManagementPanel, &RepoManagementPanel::openRepoInGitPanel, this, &MainWindow::handleOpenRepoInProjectWindow);
    connect(m_repoManagementPanel, &RepoManagementPanel::addRepoClicked, this, [this]()
            { handleAddManagedRepo(); });
    connect(m_repoManagementPanel, &RepoManagementPanel::modifyAccessClicked, this, &MainWindow::handleModifyRepoAccess);
    connect(m_repoManagementPanel, &RepoManagementPanel::deleteRepoClicked, this, &MainWindow::handleDeleteRepo);

    connect(m_networkPanel, &NetworkPanel::sendBroadcastMessageRequested, this, &MainWindow::handleSendBroadcastMessage);
    connect(m_networkPanel, &NetworkPanel::toggleDiscoveryRequested, this, &MainWindow::handleToggleDiscovery);
    connect(m_networkPanel, &NetworkPanel::connectToPeerRequested, this, &MainWindow::handleConnectToPeer);
    connect(m_networkPanel, &NetworkPanel::cloneRepoRequested, this, &MainWindow::handleCloneRepo);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromNetworkPanel);

    if (m_networkManager)
    {
        connect(m_networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handlePeerConnectionStatusChange);
        connect(m_networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handlePeerConnectionStatusChange);
        connect(m_networkManager, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager, &NetworkManager::broadcastMessageReceived, this, &MainWindow::handleBroadcastMessage);
        connect(m_networkManager, &NetworkManager::groupMessageReceived, this, &MainWindow::handleGroupMessage); // Correct signal signature
        connect(m_networkManager, &NetworkManager::repoBundleRequestedByPeer, this, &MainWindow::handleRepoBundleRequest);
        connect(m_networkManager, &NetworkManager::repoBundleCompleted, this, &MainWindow::handleRepoBundleCompleted);
        connect(m_networkManager, &NetworkManager::tcpServerStatusChanged, m_networkPanel, &NetworkPanel::updateServerStatus);
        connect(m_networkManager, &NetworkManager::secureMessageReceived, this, &MainWindow::handleSecureMessage);
        connect(m_networkManager, &NetworkManager::collaboratorAddedReceived, this, &MainWindow::handleCollaboratorAdded);
        connect(m_networkManager, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatus);
    }
}

void MainWindow::updateUiFromBackend()
{
    m_repoManagementPanel->updateRepoList(m_repoManager->getRepositoriesIAmMemberOf(), m_myUsername);

    if (m_networkManager)
    {
        QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
        m_networkPanel->updatePeerList(m_networkManager->getDiscoveredPeers(), connectedPeers);
    }

    for (ProjectWindow *pw : m_projectWindows.values())
    {
        pw->updateStatus();
        pw->updateGroupMembers();
    }
}

void MainWindow::handlePeerConnectionStatusChange()
{
    qDebug() << "MainWindow: Peer connection status changed, updating UI...";
    updateUiFromBackend();
}

void MainWindow::handleTcpConnectionStatus(const QString &peerUsername, const QString &peerPublicKeyHex, bool success, const QString &message)
{
    Q_UNUSED(peerPublicKeyHex);
    if (success)
    {
        m_networkPanel->logMessage(QString("Successfully connected to peer '%1'.").arg(peerUsername), Qt::darkGreen);
    }
    else
    {
        m_networkPanel->logMessage(QString("Connection attempt to peer '%1' failed: %2").arg(peerUsername, message), Qt::red);
    }
}

void MainWindow::handleOpenRepoInProjectWindow(const QString &appId)
{
    if (m_projectWindows.contains(appId))
    {
        m_projectWindows[appId]->activateWindow();
        return;
    }

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid())
    {
        QMessageBox::warning(this, "Error", "Could not find repository information for ID: " + appId);
        return;
    }

    ProjectWindow *projectWindow = new ProjectWindow(appId, m_repoManager, m_networkManager, this);
    projectWindow->setAttribute(Qt::WA_DeleteOnClose);
    m_projectWindows.insert(appId, projectWindow);

    connect(projectWindow, &ProjectWindow::groupMessageSent, this, &MainWindow::handleProjectWindowGroupMessage);
    connect(projectWindow, &ProjectWindow::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromProjectWindow);
    connect(projectWindow, &ProjectWindow::removeCollaboratorRequested, this, &MainWindow::handleRemoveCollaboratorFromProjectWindow);

    connect(projectWindow, &QObject::destroyed, this, [this, appId]()
            {
        m_projectWindows.remove(appId);
        qDebug() << "ProjectWindow for" << appId << "destroyed. Map size:" << m_projectWindows.size(); });

    projectWindow->show();
}

// Updated signal handler signature
void MainWindow::handleProjectWindowGroupMessage(const QString &ownerRepoAppId, const QString &message)
{
    if (m_networkManager)
    {
        // Pass the ownerRepoAppId and message to NetworkManager
        m_networkManager->sendGroupChatMessage(ownerRepoAppId, message);

        // Display the message locally in the chat window of the correct ProjectWindow
        // Find the local repo entry by ownerRepoAppId to get its local appId
        ManagedRepositoryInfo localRepoInfo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
        if (localRepoInfo.isValid() && m_projectWindows.contains(localRepoInfo.appId))
        {
            m_projectWindows[localRepoInfo.appId]->displayGroupMessage(m_myUsername, message);
        }
        else
        {
            // This case should ideally not happen if the message is sent from a valid ProjectWindow,
            // but log it just in case the repo was removed locally or window closed.
            QString repoName = localRepoInfo.isValid() ? localRepoInfo.displayName : ownerRepoAppId;
            m_networkPanel->logGroupChatMessage(repoName, m_myUsername, message);
            qWarning() << "MainWindow: Sent group message for repo group" << ownerRepoAppId << "but local ProjectWindow or repo entry not found for local display.";
        }
    }
}

// Updated signal handler signature
void MainWindow::handleGroupMessage(const QString &senderPeerId, const QString &ownerRepoAppId, const QString &message)
{
    qDebug() << "MainWindow: Received group message for repo group (Owner App ID:" << ownerRepoAppId << ") from" << senderPeerId;

    // Find the local managed repo entry whose ownerRepoAppId matches
    ManagedRepositoryInfo localRepoInfo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);

    if (localRepoInfo.isValid())
    {
        // Check if the sender is actually a member of this group according to our local info
        if (!localRepoInfo.groupMembers.contains(senderPeerId))
        {
            qWarning() << "MainWindow: Received group message for repo group" << ownerRepoAppId << "from non-member" << senderPeerId << ". Ignoring message.";
            m_networkPanel->logMessage(QString("Received group message for '%1' group from non-member %2. Ignoring.").arg(localRepoInfo.displayName, senderPeerId), Qt::yellow);
            return; // Ignore messages from non-group members
        }

        // Route message to the correct ProjectWindow based on local App ID
        if (m_projectWindows.contains(localRepoInfo.appId))
        {
            m_projectWindows[localRepoInfo.appId]->displayGroupMessage(senderPeerId, message);
        }
        else
        {
            // Log in the network panel if the project window isn't open
            m_networkPanel->logGroupChatMessage(localRepoInfo.displayName, senderPeerId, message);
        }
    }
    else
    {
        qWarning() << "MainWindow: Received group message for unknown group (Owner App ID:" << ownerRepoAppId << ") from" << senderPeerId;
        m_networkPanel->logMessage(QString("Received group message for unknown group (Owner App ID: %1) from %2. Ignoring.").arg(ownerRepoAppId, senderPeerId), Qt::gray);
    }
}

void MainWindow::handleBroadcastMessage(QTcpSocket *socket, const QString &peer, const QString &msg)
{
    Q_UNUSED(socket);
    m_networkPanel->logBroadcastMessage(peer, msg);
}

void MainWindow::handleSendBroadcastMessage(const QString &message)
{
    if (m_networkManager)
    {
        m_networkManager->broadcastTcpMessage(message);
        m_networkPanel->logBroadcastMessage(m_myUsername, message);
    }
}

void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket *socket, const QHostAddress &address, quint16 port, const QString &username)
{
    QString pkh;
    DiscoveredPeerInfo peerInfo = m_networkManager->getDiscoveredPeerInfo(username);
    if (peerInfo.id.isEmpty() && !username.startsWith("AwaitingID"))
    {
        for (const auto &info : m_networkManager->getDiscoveredPeers())
        {
            if (info.address == address)
            {
                peerInfo = info;
                break;
            }
        }
    }

    QString peerDisplay = username;
    if (!peerInfo.publicKeyHex.isEmpty())
    {
        peerDisplay = peerInfo.id;
        pkh = " (PKH: " + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8) + "...)";
        peerDisplay += pkh;
    }
    else
    {
        peerDisplay = QString("%1:%2").arg(address.toString()).arg(port);
    }

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Peer Connection Request");
    msgBox.setText(QString("Peer '%1' wants to establish a connection with you.").arg(peerDisplay.toHtmlEscaped()));
    msgBox.setInformativeText("Do you want to accept?");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);

    if (m_networkManager && m_networkManager->isConnectionPending(socket))
    {
        if (msgBox.exec() == QMessageBox::Yes)
        {
            m_networkManager->acceptPendingTcpConnection(socket);
            m_networkPanel->logMessage(QString("Accepted connection from '%1'.").arg(peerDisplay), Qt::darkGreen);
        }
        else
        {
            m_networkManager->rejectPendingTcpConnection(socket);
            m_networkPanel->logMessage(QString("Rejected connection from '%1'.").arg(peerDisplay), Qt::yellow);
        }
    }
    else
    {
        qWarning() << "MainWindow: Connection request was no longer pending for" << peerDisplay;
        m_networkPanel->logMessage(QString("Connection request from '%1' was no longer pending.").arg(peerDisplay), Qt::gray);
    }
}

void MainWindow::handleAddManagedRepo(const QString &preselectedPath)
{
    QString dirPath = preselectedPath;
    if (dirPath.isEmpty())
    {
        dirPath = QFileDialog::getExistingDirectory(this, "Select Git Repository Folder to Manage", QDir::homePath());
    }
    if (dirPath.isEmpty())
        return;

    if (m_repoManager->getRepositoryInfoByPath(dirPath).isValid())
    {
        QMessageBox::warning(this, "Already Managed", "This repository is already in your managed list.");
        return;
    }

    GitBackend tempBackend;
    std::string error;
    if (!tempBackend.openRepository(dirPath.toStdString(), error))
    {
        tempBackend.closeRepository();
        QMessageBox::warning(this, "Not a Git Repository", "The selected folder does not appear to be a valid Git repository:\n" + QString::fromStdString(error));
        return;
    }
    tempBackend.closeRepository();

    QString repoName = QFileInfo(dirPath).fileName();
    bool ok;
    QString displayName = QInputDialog::getText(this, "Manage Repository", "Enter a display name:", QLineEdit::Normal, repoName, &ok);
    if (!ok || displayName.isEmpty())
        return;

    bool isPublic = (QMessageBox::question(this, "Set Visibility", "Make this repository publicly discoverable and cloneable on the LAN?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes);

    // Add the repo as owned by the local peer. ownerRepoAppId will be set by RepoManager.
    // Initial group members list includes only the owner (myself).
    if (m_repoManager->addManagedRepository(displayName, dirPath, isPublic, m_myUsername, "", {m_myUsername}, true))
    {
        m_repoManagementPanel->logStatus("Repository '" + displayName + "' added to management list.");
        if (m_networkManager)
            m_networkManager->sendDiscoveryBroadcast();
    }
    else
    {
        m_repoManagementPanel->logStatus("Failed to add repository. It might be a duplicate by path or owner/name/appId.", true);
    }
}

void MainWindow::handleModifyRepoAccess(const QString &appId)
{
    if (appId.isEmpty())
        return;
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid())
    {
        QMessageBox::warning(this, "Error", "Repository not found in managed list.");
        return;
    }

    if (!repoInfo.isOwner)
    {
        QMessageBox::warning(this, "Access Denied", "Only the owner of the repository can modify access and collaborators.");
        return;
    }

    QDialog accessDialog(this);
    accessDialog.setWindowTitle(QString("Modify Access for '%1'").arg(repoInfo.displayName));
    QVBoxLayout dialogLayout(&accessDialog);

    QLabel *visibilityLabel = new QLabel("Visibility (Your Share):");
    QComboBox *visibilityCombo = new QComboBox();
    visibilityCombo->addItem("Private", false);
    visibilityCombo->addItem("Public", true);
    visibilityCombo->setCurrentIndex(visibilityCombo->findData(repoInfo.isPublic));

    QHBoxLayout *visibilityLayout = new QHBoxLayout();
    visibilityLayout->addWidget(visibilityLabel);
    visibilityLayout->addWidget(visibilityCombo);
    dialogLayout.addLayout(visibilityLayout);

    QLabel *membersLabel = new QLabel("Group Members (Owner + Collaborators):");
    QListWidget *membersList = new QListWidget();
    QStringList sortedMembers = repoInfo.groupMembers;
    sortedMembers.sort();
    if (sortedMembers.isEmpty())
    {
        membersList->addItem("None yet.");
        membersList->setEnabled(false);
    }
    else
    {
        for (const QString &member : sortedMembers)
        {
            QString memberDisplay = member;
            if (member == repoInfo.ownerPeerId)
            {
                memberDisplay += " (owner)";
            }
            membersList->addItem(memberDisplay);
        }
        membersList->setEnabled(true);
    }
    membersList->setMaximumHeight(100);
    membersList->setMinimumHeight(50);
    dialogLayout.addWidget(membersLabel);
    dialogLayout.addWidget(membersList);
    dialogLayout.addWidget(new QLabel("<i>Manage collaborators via the Project Window's Collaboration tab.</i>", &accessDialog));

    QPushButton *okButton = new QPushButton("OK");
    QPushButton *cancelButton = new QPushButton("Cancel");
    QHBoxLayout *buttonBox = new QHBoxLayout();
    buttonBox->addWidget(okButton);
    buttonBox->addWidget(cancelButton);
    dialogLayout.addLayout(buttonBox);

    connect(okButton, &QPushButton::clicked, &accessDialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &accessDialog, &QDialog::reject);

    if (accessDialog.exec() == QDialog::Accepted)
    {
        bool newIsPublic = visibilityCombo->currentData().toBool();
        if (repoInfo.isOwner && newIsPublic != repoInfo.isPublic)
        {
            if (m_repoManager->setRepositoryVisibility(appId, newIsPublic))
            {
                m_repoManagementPanel->logStatus(QString("Visibility for '%1' changed to %2.").arg(repoInfo.displayName, newIsPublic ? "Public" : "Private"), false);
                if (m_networkManager)
                    m_networkManager->sendDiscoveryBroadcast();
            }
            else
            {
                m_repoManagementPanel->logStatus(QString("Failed to change visibility for '%1'.").arg(repoInfo.displayName), true);
            }
        }
    }
}

void MainWindow::handleDeleteRepo(const QString &appId)
{
    if (appId.isEmpty())
        return;

    if (m_projectWindows.contains(appId))
    {
        m_projectWindows[appId]->deleteLater();
    }

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid())
    {
        m_repoManagementPanel->logStatus("Error: Repository not found in managed list.", true);
        return;
    }

    QString confirmationText;
    if (repoInfo.isOwner)
    {
        confirmationText = QString("You are the owner of '%1'. Removing it from your managed list WILL NOT delete the local files, but it will stop sharing it with other peers and remove it from their group member lists. Are you sure you want to remove it from the managed list?").arg(repoInfo.displayName);
    }
    else
    {
        confirmationText = QString("Are you sure you want to remove the clone of '%1' (owned by %2) from your managed list? This will NOT delete the local files.").arg(repoInfo.displayName, repoInfo.ownerPeerId);
    }

    if (QMessageBox::question(this, "Confirm Removal", confirmationText, QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
    {
        return;
    }

    if (repoInfo.isOwner && repoInfo.groupMembers.size() > 1)
    {
        qWarning() << "Owner removing repo:" << repoInfo.displayName << ". Notifying collaborators is not implemented yet.";
        m_networkPanel->logMessage(QString("Warning: Collaborators of '%1' will not be automatically notified of repository removal.").arg(repoInfo.displayName), Qt::yellow);
    }

    if (m_repoManager->removeManagedRepository(appId))
    {
        m_repoManagementPanel->logStatus("Repository '" + repoInfo.displayName + "' removed from management list.", false);
        if (repoInfo.isOwner && repoInfo.isPublic && m_networkManager)
        {
            m_networkManager->sendDiscoveryBroadcast();
        }
        updateUiFromBackend();
    }
    else
    {
        m_repoManagementPanel->logStatus("Failed to remove repository from list.", true);
    }
}

void MainWindow::handleConnectToPeer(const QString &peerId)
{
    if (!m_networkManager)
        return;

    DiscoveredPeerInfo peerInfo = m_networkManager->getDiscoveredPeerInfo(peerId);
    if (peerInfo.id.isEmpty())
    {
        QMessageBox::critical(this, "Connection Error", QString("Could not find peer info for '%1'. They may have gone offline.").arg(peerId));
        return;
    }

    if (m_networkManager->getSocketForPeer(peerId) != nullptr)
    {
        m_networkPanel->logMessage(QString("Already connected to peer '%1'.").arg(peerId), Qt::gray);
        return;
    }

    m_networkPanel->logMessage(QString("Initiating connection to peer '%1' at %2:%3...").arg(peerId, peerInfo.address.toString()).arg(peerInfo.tcpPort), "blue");

    m_networkManager->connectToTcpPeer(peerInfo.address, peerInfo.tcpPort, peerInfo.id);
}

void MainWindow::handleCloneRepo(const QString &peerId, const QString &repoDisplayName)
{
    if (!m_networkManager || !m_repoManager)
    {
        QMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
        return;
    }

    if (m_repoManager->getCloneInfoByOwnerAndDisplayName(peerId, repoDisplayName).isValid())
    {
        QMessageBox::information(this, "Repository Already Cloned", QString("You appear to have already cloned '%1' from peer '%2'.\nIf you wish to clone it again, please remove the existing managed entry first.").arg(repoDisplayName, peerId));
        return;
    }

    QString localClonePathBase = QFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty())
        return;

    QString suggestedFolderName = repoDisplayName.toLower();
    suggestedFolderName.replace(QRegularExpression(QStringLiteral("[^a-zA-Z0-9_.-]")), "_");
    suggestedFolderName.remove(QRegularExpression(QStringLiteral("^[.-]")));
    suggestedFolderName.remove(QRegularExpression(QStringLiteral("[.-]$")));
    if (suggestedFolderName.isEmpty())
        suggestedFolderName = "cloned_repo";

    QString fullLocalClonePath = QDir(localClonePathBase).filePath(suggestedFolderName);
    QDir targetDir(fullLocalClonePath);
    if (targetDir.exists() && !targetDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty())
    {
        QMessageBox::warning(this, "Directory Exists and is Not Empty", QString("The target directory '%1' already exists and contains files. Please choose an empty directory or a different location.").arg(fullLocalClonePath));
        return;
    }

    m_pendingCloneRequest.ownerPeerId = peerId;
    m_pendingCloneRequest.repoDisplayName = repoDisplayName;
    m_pendingCloneRequest.localClonePath = fullLocalClonePath;

    QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerId);
    if (!peerSocket)
    {
        m_networkPanel->logMessage(QString("Attempting to connect to '%1' to initiate clone...").arg(peerId), "blue");
        DiscoveredPeerInfo providerPeerInfo = m_networkManager->getDiscoveredPeerInfo(peerId);
        if (providerPeerInfo.id.isEmpty())
        {
            QMessageBox::critical(this, "Connection Error", "Could not find peer info. They may have gone offline.");
            m_pendingCloneRequest.clear();
            return;
        }
        m_networkManager->connectAndRequestBundle(providerPeerInfo.address, providerPeerInfo.tcpPort, m_myUsername, repoDisplayName, fullLocalClonePath);
    }
    else
    {
        m_networkPanel->logMessage(QString("Initiating clone for '%1' from '%2' via existing connection...").arg(repoDisplayName, peerId), "blue");
        m_networkManager->sendRepoBundleRequest(peerSocket, repoDisplayName, fullLocalClonePath);
    }
}

void MainWindow::handleToggleDiscovery()
{
    if (m_networkManager->getTcpServerPort() > 0)
    {
        m_networkManager->stopUdpDiscovery();
        m_networkManager->stopTcpServer();
        m_networkManager->disconnectAllTcpPeers();
    }
    else
    {
        m_networkManager->startTcpServer();
    }
}

void MainWindow::handleAddCollaboratorFromNetworkPanel(const QString &peerId)
{
    if (!m_networkManager || !m_repoManager)
        return;

    if (peerId == m_myUsername)
    {
        QMessageBox::information(this, "Cannot Add Self", "You cannot add yourself as a collaborator.");
        return;
    }

    QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerId);
    if (!peerSocket)
    {
        QMessageBox::warning(this, "Not Connected", QString("You must have an established TCP connection with '%1' to add them as a collaborator.").arg(peerId));
        return;
    }

    QList<ManagedRepositoryInfo> myOwnedRepos = m_repoManager->getRepositoriesIAmMemberOf();
    QList<ManagedRepositoryInfo> eligibleRepos;
    for (const auto &repo : myOwnedRepos)
    {
        if (repo.isOwner && !repo.groupMembers.contains(peerId))
        {
            eligibleRepos.append(repo);
        }
    }

    if (eligibleRepos.isEmpty())
    {
        QMessageBox::information(this, "No Eligible Repositories", QString("You do not own any repositories that '%1' is not already a collaborator on.").arg(peerId));
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QString("Add '%1' as Collaborator").arg(peerId));
    QVBoxLayout layout(&dialog); // Stack variable
    QListWidget listWidget(&dialog);

    for (const auto &repo : eligibleRepos)
    {
        auto *item = new QListWidgetItem(repo.displayName, &listWidget);
        item->setData(Qt::UserRole, repo.appId);
    }

    listWidget.setSelectionMode(QAbstractItemView::MultiSelection);
    layout.addWidget(new QLabel(QString("Select repositories to add '%1' as a collaborator:").arg(peerId), &dialog)); // Use .addWidget
    layout.addWidget(&listWidget);                                                                                    // Use .addWidget

    QHBoxLayout *buttonBox = new QHBoxLayout(); // Stack variable
    QPushButton *okButton = new QPushButton("Add", &dialog);
    QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
    buttonBox->addWidget(okButton);
    buttonBox->addWidget(cancelButton);
    layout.addLayout(buttonBox); // Use .addLayout

    connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    if (dialog.exec() == QDialog::Accepted)
    {
        QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerId);
        if (!peerSocket)
        {
            QMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost. Cannot add collaborator.").arg(peerId));
            return;
        }

        QList<QListWidgetItem *> selectedItems = listWidget.selectedItems();
        if (selectedItems.isEmpty())
        {
            QMessageBox::information(this, "No Selection", "No repositories selected.");
            return;
        }

        for (auto *item : selectedItems)
        {
            QString localAppId = item->data(Qt::UserRole).toString();
            ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(localAppId);

            if (!repoInfo.isValid() || !repoInfo.isOwner)
            {
                qWarning() << "Attempted to add collaborator to repo" << localAppId << "which is not owned by me or invalid.";
                m_networkPanel->logMessage(QString("Failed to add '%1' as collaborator to '%2': Internal error.").arg(peerId, repoInfo.displayName), Qt::red);
                continue;
            }

            if (m_repoManager->addCollaborator(localAppId, peerId))
            {
                m_networkPanel->logMessage(QString("Added '%1' to local group list for '%2'.").arg(peerId, repoInfo.displayName), "green");

                repoInfo = m_repoManager->getRepositoryInfo(localAppId);

                QVariantMap payload;
                payload["ownerRepoAppId"] = repoInfo.appId;
                payload["repoDisplayName"] = repoInfo.displayName;
                payload["ownerPeerId"] = repoInfo.ownerPeerId;
                payload["groupMembers"] = repoInfo.groupMembers;

                m_networkManager->sendEncryptedMessage(peerSocket, "COLLABORATOR_ADDED", payload);

                if (m_projectWindows.contains(localAppId))
                {
                    m_projectWindows[localAppId]->updateGroupMembers();
                }
            }
            else
            {
                m_networkPanel->logMessage(QString("Failed to add '%1' as collaborator to '%2' locally (already member?).").arg(peerId, repoInfo.displayName), Qt::red);
            }
        }
    }
}

void MainWindow::handleAddCollaboratorFromProjectWindow(const QString &appId)
{
    if (!m_networkManager || !m_repoManager)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid() || !repoInfo.isOwner)
    {
        QMessageBox::warning(this, "Access Denied", "You are not the owner of this repository or it was not found.");
        return;
    }

    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
    QStringList eligiblePeers;
    for (const QString &peerId : connectedPeers)
    {
        if (peerId != m_myUsername && !repoInfo.groupMembers.contains(peerId))
        {
            eligiblePeers.append(peerId);
        }
    }
    eligiblePeers.sort();

    if (eligiblePeers.isEmpty())
    {
        QMessageBox::information(this, "No Eligible Peers", "No connected peers are available to add as collaborators.");
        return;
    }

    bool ok;
    QString peerToAdd = QInputDialog::getItem(this, "Add Collaborator", QString("Select a peer to add to '%1':").arg(repoInfo.displayName), eligiblePeers, 0, false, &ok);

    if (ok && !peerToAdd.isEmpty())
    {
        QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerToAdd);
        if (!peerSocket)
        {
            QMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost. Cannot add collaborator.").arg(peerToAdd));
            return;
        }

        if (m_repoManager->addCollaborator(appId, peerToAdd))
        {
            m_networkPanel->logMessage(QString("Added '%1' to local group list for '%2'.").arg(peerToAdd, repoInfo.displayName), "green");

            repoInfo = m_repoManager->getRepositoryInfo(appId);

            QVariantMap payload;
            payload["ownerRepoAppId"] = repoInfo.appId;
            payload["repoDisplayName"] = repoInfo.displayName;
            payload["ownerPeerId"] = repoInfo.ownerPeerId;
            payload["groupMembers"] = repoInfo.groupMembers;

            m_networkManager->sendEncryptedMessage(peerSocket, "COLLABORATOR_ADDED", payload);

            if (m_projectWindows.contains(appId))
            {
                m_projectWindows[appId]->updateGroupMembers();
            }
        }
        else
        {
            m_networkPanel->logMessage(QString("Failed to add '%1' as collaborator to '%2' locally (already member?).").arg(peerToAdd, repoInfo.displayName), Qt::red);
        }
    }
}

void MainWindow::handleRemoveCollaboratorFromProjectWindow(const QString &appId, const QString &peerIdToRemove)
{
    if (!m_repoManager || !m_networkManager)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.isValid() || !repoInfo.isOwner)
    {
        QMessageBox::warning(this, "Access Denied", "You are not the owner of this repository or it was not found.");
        return;
    }

    if (peerIdToRemove == repoInfo.ownerPeerId)
    {
        QMessageBox::warning(this, "Invalid Action", "Cannot remove the repository owner (which is you).");
        return;
    }

    if (peerIdToRemove == m_myUsername)
    {
        QMessageBox::warning(this, "Invalid Action", "You cannot remove yourself from the group list.");
        return;
    }

    if (!repoInfo.groupMembers.contains(peerIdToRemove))
    {
        QMessageBox::warning(this, "Error", QString("'%1' is not listed as a collaborator for '%2'.").arg(peerIdToRemove, repoInfo.displayName));
        return;
    }

    if (QMessageBox::question(this, "Confirm Removal",
                              QString("Are you sure you want to remove '%1' as a collaborator from '%2'?\n\nThey will lose access to this private repository from you.").arg(peerIdToRemove, repoInfo.displayName),
                              QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
    {
        return;
    }

    if (m_repoManager->removeCollaborator(appId, peerIdToRemove))
    {
        m_networkPanel->logMessage(QString("Removed '%1' from local group list for '%2'.").arg(peerIdToRemove, repoInfo.displayName), "green");

        if (m_projectWindows.contains(appId))
        {
            m_projectWindows[appId]->updateGroupMembers();
        }
        // Note: Ideally, notify the removed peer and other existing members as well.
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to remove '%1' as collaborator from '%2' locally (not found?).").arg(peerIdToRemove, repoInfo.displayName), Qt::red);
    }
}

void MainWindow::handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload)
{
    qDebug() << "MainWindow: Received secure message type" << messageType << " from" << peerId;
    // Handle other secure message types here if needed...
    // COLLABORATOR_ADDED is handled via collaboratorAddedReceived signal
}

void MainWindow::handleRepoBundleCompleted(const QString &repoDisplayName, const QString &localBundlePath, bool success, const QString &message)
{
    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoDisplayName != repoDisplayName || m_pendingCloneRequest.localClonePath.isEmpty())
    {
        m_networkPanel->logMessage(QString("Received bundle for '%1' unexpectedly. Saved to temp: %2").arg(repoDisplayName, localBundlePath), QColor("orange"));
        QMessageBox::warning(this, "Unexpected Bundle", QString("Received a repository bundle for '%1', but was not expecting it. The temporary file has been saved at:\n%2").arg(repoDisplayName, localBundlePath));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    if (!success)
    {
        m_networkPanel->logMessage(QString("Failed to receive repository '%1' bundle: %2").arg(repoDisplayName, message), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Failed to receive the repository bundle for '%1':\n%2").arg(repoDisplayName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    m_networkPanel->logMessage(QString("Bundle for '%1' received successfully at %2. Initiating local git clone...").arg(repoDisplayName, localBundlePath), "blue");

    QString finalClonePath = m_pendingCloneRequest.localClonePath;

    QDir targetDir(finalClonePath);
    if (targetDir.exists() && !targetDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty())
    {
        m_networkPanel->logMessage(QString("Clone failed: Target directory '%1' already exists and is not empty.").arg(finalClonePath), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("The target directory already exists and is not empty:\n%1").arg(finalClonePath));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }
    if (!targetDir.exists() && !targetDir.mkpath("."))
    {
        m_networkPanel->logMessage(QString("Clone failed: Could not create target directory '%1'.").arg(finalClonePath), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Could not create the target directory:\n%1").arg(finalClonePath));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    QProcess *gitCloneProcess = new QProcess(this);
    QStringList arguments;
    arguments << "clone" << QDir::toNativeSeparators(localBundlePath) << QDir::toNativeSeparators(finalClonePath);

    qDebug() << "Running git" << arguments.join(" ") << "in" << targetDir.absolutePath();

    connect(gitCloneProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [=](int exitCode, QProcess::ExitStatus exitStatus)
            {
                QString processOutput = QString(gitCloneProcess->readAllStandardOutput());
                QString processError = QString(gitCloneProcess->readAllStandardError());

                QString cloneOwnerPeerId = m_pendingCloneRequest.ownerPeerId;
                QString cloneRepoDisplayName = m_pendingCloneRequest.repoDisplayName;
                QString cloneLocalPath = m_pendingCloneRequest.localClonePath;
                m_pendingCloneRequest.clear();

                QFile::remove(localBundlePath);

                if (exitStatus == QProcess::NormalExit && exitCode == 0)
                {
                    m_networkPanel->logMessage(QString("Successfully cloned '%1' to '%2'.").arg(cloneRepoDisplayName, cloneLocalPath), Qt::darkGreen);
                    m_networkPanel->logMessage("Git clone stdout: " + processOutput, Qt::gray);
                    if (!processError.isEmpty())
                        m_networkPanel->logMessage("Git clone stderr: " + processError, Qt::yellow);

                    QMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(cloneRepoDisplayName, cloneLocalPath));

                    QStringList initialGroupMembers = {cloneOwnerPeerId, m_myUsername};
                    initialGroupMembers.removeDuplicates();

                    if (m_repoManager->addManagedRepository(cloneRepoDisplayName, cloneLocalPath, false,
                                                           cloneOwnerPeerId, "", initialGroupMembers, false))
                    {
                        m_networkPanel->logMessage(QString("Cloned repository '%1' added to management list.").arg(cloneRepoDisplayName), Qt::darkGreen);
                        ManagedRepositoryInfo newRepoInfo = m_repoManager->getRepositoryInfoByPath(cloneLocalPath);
                        if (newRepoInfo.isValid())
                        {
                             handleOpenRepoInProjectWindow(newRepoInfo.appId);
                        }
                        else
                        {
                            qWarning() << "Failed to find the newly added managed repo by path after cloning.";
                            m_networkPanel->logMessage(QString("Failed to find cloned repo '%1' in managed list after adding.").arg(cloneRepoDisplayName), Qt::red);
                        }
                    }
                    else
                    {
                        m_networkPanel->logMessage(QString("Failed to add cloned repository '%1' to management list. It might already be managed?").arg(cloneRepoDisplayName), Qt::red);
                        ManagedRepositoryInfo existingRepoInfo = m_repoManager->getRepositoryInfoByPath(cloneLocalPath);
                        if (existingRepoInfo.isValid()) {
                             handleOpenRepoInProjectWindow(existingRepoInfo.appId);
                        } else {
                             qWarning() << "Failed to find existing managed repo by path after addManagedRepository failed.";
                        }
                    }
                }
                else
                {
                    QString errorMsg = (exitStatus == QProcess::NormalExit) ? processError : QString("Git process failed to start or crashed: %1").arg(gitCloneProcess->errorString());
                    m_networkPanel->logMessage("Clone failed: " + errorMsg, Qt::red);
                    m_networkPanel->logMessage("Git clone stdout: " + processOutput, Qt::gray);
                    if (!processError.isEmpty())
                        m_networkPanel->logMessage("Git clone stderr: " + processError, Qt::red);

                    QMessageBox::critical(this, "Clone Failed", QString("The git clone command failed:\n%1").arg(errorMsg));

                    GitBackend cleanupCheckBackend;
                    std::string checkError;
                    if (!cleanupCheckBackend.openRepository(cloneLocalPath.toStdString(), checkError))
                    {
                        QDir cleanupDir(cloneLocalPath);
                        if (cleanupDir.exists() && cleanupDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty())
                        {
                            if (cleanupDir.rmdir("."))
                            {
                                m_networkPanel->logMessage(QString("Cleaned up empty target directory '%1'.").arg(cloneLocalPath), Qt::gray);
                            }
                            else
                            {
                                m_networkPanel->logMessage(QString("Failed to clean up empty target directory '%1'. Manual removal may be needed.").arg(cloneLocalPath), Qt::yellow);
                            }
                        } else if (cleanupDir.exists() && !cleanupDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty()) {
                              m_networkPanel->logMessage(QString("Note: Target directory '%1' was created and is not empty. Manual cleanup may be needed.").arg(cloneLocalPath), Qt::yellow);
                        }
                    }
                    else
                    {
                        m_networkPanel->logMessage(QString("Note: Target directory '%1' contains a .git repo. Manual cleanup or git reset may be needed.").arg(cloneLocalPath), Qt::yellow);
                        cleanupCheckBackend.closeRepository();
                    }
                }

                gitCloneProcess->deleteLater(); });

    gitCloneProcess->start("git", arguments);

    if (!gitCloneProcess->waitForStarted(5000))
    {
        QString errorString = gitCloneProcess->errorString();
        m_networkPanel->logMessage("Clone failed: Could not start git process: " + errorString, Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Could not start the git process:\n%1").arg(errorString));

        m_pendingCloneRequest.clear();
        QFile::remove(localBundlePath);
        gitCloneProcess->deleteLater();
    }
}

void MainWindow::handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt)
{
    qDebug() << "MainWindow: Received bundle request for" << repoDisplayName << "from" << sourcePeerUsername;
    Q_UNUSED(clientWantsToSaveAt);

    if (!m_repoManager || !m_networkManager)
    {
        m_networkPanel->logMessage("Cannot process bundle request: core services not ready.", Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    ManagedRepositoryInfo repoToBundle;
    QList<ManagedRepositoryInfo> myOwnedRepos = m_repoManager->getRepositoriesIAmMemberOf();
    for (const auto &info : myOwnedRepos)
    {
        if (info.isOwner && info.displayName == repoDisplayName)
        {
            repoToBundle = info;
            break;
        }
    }

    if (!repoToBundle.isValid())
    {
        m_networkPanel->logMessage(QString("Received bundle request for '%1', but it is not *owned* by me or does not exist.").arg(repoDisplayName.toHtmlEscaped()), Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    bool canAccess = repoToBundle.isPublic || repoToBundle.groupMembers.contains(sourcePeerUsername);
    if (!canAccess)
    {
        m_networkPanel->logMessage(QString("Denied bundle request for private repository '%1' from '%2': Access denied.").arg(repoDisplayName.toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()), Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    GitBackend tempGitBackend;
    std::string errorMessage;
    if (!tempGitBackend.openRepository(repoToBundle.localPath.toStdString(), errorMessage))
    {
        m_networkPanel->logMessage(QString("Failed to open managed repository '%1' for bundling: %2").arg(repoDisplayName.toHtmlEscaped(), QString::fromStdString(errorMessage)), Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    std::string bundleFilePathStd;
    std::string errorMsgBundle;
    QString tempBundleDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/P2PGitBundles/" + QUuid::createUuid().toString();
    QDir().mkpath(tempBundleDir);

    QString bundleBaseName = repoToBundle.displayName;
    if (bundleBaseName.isEmpty())
        bundleBaseName = "repo_bundle_" + repoToBundle.appId;

    if (tempGitBackend.createBundle(tempBundleDir.toStdString(), bundleBaseName.toStdString(), bundleFilePathStd, errorMsgBundle))
    {
        m_networkPanel->logMessage(QString("Bundle created for '%1' at %2. Starting transfer to %3...").arg(repoDisplayName.toHtmlEscaped(), QString::fromStdString(bundleFilePathStd).toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()), QColor("purple"));
        m_networkManager->startSendingBundle(requestingPeerSocket, repoToBundle.displayName, QString::fromStdString(bundleFilePathStd));
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to create bundle for '%1': %2").arg(repoToBundle.displayName.toHtmlEscaped(), QString::fromStdString(errorMsgBundle).toHtmlEscaped()), Qt::red);
        requestingPeerSocket->disconnectFromHost();
        QDir(tempBundleDir).removeRecursively();
    }

    tempGitBackend.closeRepository();
}

void MainWindow::handleCollaboratorAdded(const QString &peerId, const QString &ownerRepoAppId, const QString &repoDisplayName, const QString &ownerPeerId, const QStringList &groupMembers)
{
    qDebug() << "MainWindow: Received COLLABORATOR_ADDED for repo" << repoDisplayName << "from" << peerId;

    if (peerId != ownerPeerId)
    {
        qWarning() << "Received COLLABORATOR_ADDED from" << peerId << "but message claims owner is" << ownerPeerId << ". Ignoring.";
        m_networkPanel->logMessage(QString("Received COLLABORATOR_ADDED for '%1' (owner: %2) from unexpected peer %3. Ignoring.").arg(repoDisplayName, ownerPeerId, peerId), Qt::red);
        return;
    }
    if (ownerPeerId == m_myUsername)
    {
        qWarning() << "Received COLLABORATOR_ADDED message from myself? Ignoring.";
        return;
    }
    if (!groupMembers.contains(m_myUsername))
    {
        qWarning() << "Received COLLABORATOR_ADDED message for repo" << repoDisplayName << "(owner:" << ownerPeerId << "), but my ID ('" << m_myUsername << "') is not in the provided groupMembers list. Ignoring.";
        m_networkPanel->logMessage(QString("Received COLLABORATOR_ADDED for '%1' (owner: %2), but your ID is not in the group list. Ignoring.").arg(repoDisplayName, ownerPeerId), Qt::red);
        return;
    }

    ManagedRepositoryInfo localRepo = m_repoManager->getRepositoryInfoByOwnerAppId(ownerRepoAppId);
    if (localRepo.isValid())
    {
        qDebug() << "MainWindow: Found local clone (" << localRepo.appId << ") matching COLLABORATOR_ADDED message (" << ownerRepoAppId << "). Updating group members and owner app id.";
        if (m_repoManager->updateGroupMembersAndOwnerAppId(localRepo.appId, ownerRepoAppId, groupMembers))
        {
            m_networkPanel->logMessage(QString("Group list and Owner App ID updated for clone of '%1' (owner: %2).").arg(repoDisplayName, ownerPeerId), QColor("purple"));
            if (m_projectWindows.contains(localRepo.appId))
            {
                m_projectWindows[localRepo.appId]->updateGroupMembers();
            }
            updateUiFromBackend();
        }
        else
        {
            m_networkPanel->logMessage(QString("Failed to update group list/Owner App ID for clone of '%1' (owner: %2) locally.").arg(repoDisplayName, ownerPeerId), Qt::red);
        }
    }
    else
    {
        qDebug() << "MainWindow: Received COLLABORATOR_ADDED for repo group (Owner App ID:" << ownerRepoAppId << ", name:" << repoDisplayName << ", owner:" << ownerPeerId << ") but no local entry found. Notifying user.";
        m_networkPanel->logMessage(QString("Peer '%1' has granted you access to their private repository: '%2'. You can now clone it from them.").arg(ownerPeerId, repoDisplayName), QColor("purple"));
        m_networkManager->addSharedRepoToPeer(ownerPeerId, repoDisplayName);
        updateUiFromBackend();
    }
}