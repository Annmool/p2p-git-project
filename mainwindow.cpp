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

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_gitBackend(new GitBackend()),
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
    m_networkManager->startUdpDiscovery();
}

MainWindow::~MainWindow()
{
    delete m_networkManager;
    delete m_repoManager;
    delete m_gitBackend;
    delete m_identityManager;
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
        pw->close();
    }
    m_projectWindows.clear();

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
    // Repo Management Panel signals
    connect(m_repoManager, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::updateUiFromBackend);
    connect(m_repoManagementPanel, &RepoManagementPanel::openRepoInGitPanel, this, &MainWindow::handleOpenRepoInProjectWindow);
    connect(m_repoManagementPanel, &RepoManagementPanel::addRepoClicked, this, [this]()
            { handleAddManagedRepo(); });
    connect(m_repoManagementPanel, &RepoManagementPanel::modifyAccessClicked, this, &MainWindow::handleModifyRepoAccess);
    connect(m_repoManagementPanel, &RepoManagementPanel::deleteRepoClicked, this, &MainWindow::handleDeleteRepo);

    // Network Panel signals
    connect(m_networkPanel, &NetworkPanel::sendBroadcastMessageRequested, this, &MainWindow::handleSendBroadcastMessage);
    connect(m_networkPanel, &NetworkPanel::toggleDiscoveryRequested, this, &MainWindow::handleToggleDiscovery);
    connect(m_networkPanel, &NetworkPanel::connectToPeerRequested, this, &MainWindow::handleConnectToPeer);
    connect(m_networkPanel, &NetworkPanel::cloneRepoRequested, this, &MainWindow::handleCloneRepo);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromNetworkPanel);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaboratorFromProjectWindow);

    // Network Manager signals
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
        connect(m_networkManager, &NetworkManager::tcpServerStatusChanged, m_networkPanel, &NetworkPanel::updateServerStatus);
        connect(m_networkManager, &NetworkManager::secureMessageReceived, this, &MainWindow::handleSecureMessage);
        connect(m_networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handlePeerConnectionStatusChange);
        connect(m_networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handlePeerConnectionStatusChange);
        connect(m_networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handlePeerConnectionStatusChange);
        connect(m_networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::handlePeerConnectionStatusChange);
        // Added to log connection status
        connect(m_networkManager, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatus);
    }
}

void MainWindow::updateUiFromBackend()
{
    m_repoManagementPanel->updateRepoList(m_repoManager->getRepositoriesIAmMemberOf(m_myUsername), m_myUsername);
    for (ProjectWindow *pw : m_projectWindows.values())
    {
        pw->updateGroupMembers();
        pw->updateStatus();
    }
    if (m_networkManager)
    {
        QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
        m_networkPanel->updatePeerList(m_networkManager->getDiscoveredPeers(), connectedPeers);
    }
}

void MainWindow::handlePeerConnectionStatusChange()
{
    qDebug() << "MainWindow: Peer connection status changed, updating ProjectWindows...";
    for (ProjectWindow *pw : m_projectWindows.values())
    {
        pw->updateGroupMembers();
    }
}

void MainWindow::handleTcpConnectionStatus(const QString &peerUsername, const QString &publicKeyHex, bool success, const QString &message)
{
    Q_UNUSED(publicKeyHex);
    if (success)
    {
        m_networkPanel->logMessage(QString("Successfully connected to peer '%1'.").arg(peerUsername), Qt::darkGreen);
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to connect to peer '%1': %2").arg(peerUsername, message), Qt::red);
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
    if (repoInfo.appId.isEmpty())
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

void MainWindow::handleProjectWindowGroupMessage(const QString &appId, const QString &message)
{
    if (m_networkManager)
    {
        m_networkManager->sendGroupChatMessage(appId, message);
        if (m_projectWindows.contains(appId))
        {
            m_projectWindows[appId]->displayGroupMessage(m_myUsername, message);
        }
    }
}

void MainWindow::handleGroupMessage(const QString &peerId, const QString &repoAppId, const QString &message)
{
    qDebug() << "MainWindow: Received group message for repo" << repoAppId << "from" << peerId;
    if (m_projectWindows.contains(repoAppId))
    {
        m_projectWindows[repoAppId]->displayGroupMessage(peerId, message);
    }
    else
    {
        ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(repoAppId);
        QString repoName = repoInfo.displayName.isEmpty() ? repoAppId : repoInfo.displayName;
        m_networkPanel->logGroupChatMessage(repoName, peerId, message);
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
    if (peerInfo.id.isEmpty())
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

    if (!peerInfo.publicKeyHex.isEmpty())
    {
        pkh = " (PKH: " + QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8) + "...)";
    }
    QString peerDisplay = !username.isEmpty() ? username + pkh : address.toString();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Peer Connection Request");
    msgBox.setText(QString("Peer '%1' at %2 wants to establish a connection with you.").arg(peerDisplay.toHtmlEscaped(), address.toString()));
    msgBox.setInformativeText("Do you want to accept?");
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);

    if (msgBox.exec() == QMessageBox::Yes)
    {
        if (m_networkManager && m_networkManager->isConnectionPending(socket))
        {
            m_networkManager->acceptPendingTcpConnection(socket);
            m_networkPanel->logMessage(QString("Accepted connection from '%1'.").arg(peerDisplay), Qt::darkGreen);
        }
        else
        {
            m_networkPanel->logMessage(QString("Connection request from '%1' was no longer pending.").arg(peerDisplay), Qt::gray);
        }
    }
    else
    {
        if (m_networkManager && m_networkManager->isConnectionPending(socket))
        {
            m_networkManager->rejectPendingTcpConnection(socket);
            m_networkPanel->logMessage(QString("Rejected connection from '%1'.").arg(peerDisplay), Qt::yellow);
        }
        else
        {
            m_networkPanel->logMessage(QString("Rejected connection request from '%1', but it was no longer pending.").arg(peerDisplay), Qt::gray);
        }
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

    if (!m_repoManager->getRepositoryInfoByPath(dirPath).appId.isEmpty())
    {
        QMessageBox::warning(this, "Already Managed", "This repository is already in your managed list.");
        return;
    }

    std::string error;
    GitBackend tempBackend;
    if (!tempBackend.openRepository(dirPath.toStdString(), error))
    {
        QMessageBox::warning(this, "Not a Git Repository", "The selected folder does not appear to be a valid Git repository:\n" + QString::fromStdString(error));
        return;
    }
    tempBackend.closeRepository();

    QString repoName = QFileInfo(dirPath).fileName();
    bool ok;
    QString displayName = QInputDialog::getText(this, "Manage Repository", "Enter a display name:", QLineEdit::Normal, repoName, &ok);
    if (!ok || displayName.isEmpty())
        return;

    if (!m_repoManager->getRepositoryInfoByDisplayName(displayName).appId.isEmpty())
    {
        QMessageBox::warning(this, "Name Conflict", "A repository with this display name already exists in your managed list. Please choose a different name.");
        return;
    }

    bool isPublic = (QMessageBox::question(this, "Set Visibility", "Make this repository public for other peers to discover and clone?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes);

    if (m_repoManager->addManagedRepository(dirPath, displayName, isPublic, m_myUsername, ""))
    {
        m_repoManagementPanel->logStatus("Repository '" + displayName + "' added to management list.");
        if (m_networkManager)
            m_networkManager->sendDiscoveryBroadcast();
    }
    else
    {
        m_repoManagementPanel->logStatus("Failed to add repository.", true);
    }
}

void MainWindow::handleModifyRepoAccess(const QString &appId)
{
    if (appId.isEmpty())
        return;
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty())
    {
        QMessageBox::warning(this, "Error", "Repository not found in managed list.");
        return;
    }

    if (repoInfo.adminPeerId != m_myUsername)
    {
        QMessageBox::warning(this, "Access Denied", "Only the owner can modify access and collaborators.");
        return;
    }

    QDialog accessDialog(this);
    accessDialog.setWindowTitle(QString("Modify Access for '%1'").arg(repoInfo.displayName));
    QVBoxLayout dialogLayout(&accessDialog);

    QLabel *visibilityLabel = new QLabel("Visibility:");
    QComboBox *visibilityCombo = new QComboBox();
    visibilityCombo->addItem("Private", false);
    visibilityCombo->addItem("Public", true);
    visibilityCombo->setCurrentIndex(visibilityCombo->findData(repoInfo.isPublic));

    QHBoxLayout *visibilityLayout = new QHBoxLayout();
    visibilityLayout->addWidget(visibilityLabel);
    visibilityLayout->addWidget(visibilityCombo);
    dialogLayout.addLayout(visibilityLayout);

    QLabel *collaboratorsLabel = new QLabel("Collaborators:");
    QListWidget *collaboratorsList = new QListWidget();
    if (repoInfo.collaborators.isEmpty())
    {
        collaboratorsList->addItem("None yet.");
        collaboratorsList->setEnabled(false);
    }
    else
    {
        QStringList sortedCollaborators = repoInfo.collaborators;
        sortedCollaborators.sort();
        for (const QString &collab : sortedCollaborators)
        {
            collaboratorsList->addItem(collab);
        }
    }
    collaboratorsList->setMaximumHeight(100);
    collaboratorsList->setMinimumHeight(50);
    dialogLayout.addWidget(collaboratorsLabel);
    dialogLayout.addWidget(collaboratorsList);

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
        if (newIsPublic != repoInfo.isPublic)
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
        m_projectWindows[appId]->close();
    }

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty())
    {
        m_repoManagementPanel->logStatus("Error: Repository not found in managed list.", true);
        return;
    }

    if (repoInfo.adminPeerId == m_myUsername && !repoInfo.collaborators.isEmpty())
    {
        if (QMessageBox::warning(this, "Confirm Deletion",
                                 QString("You are the owner of '%1'. Removing it from your managed list WILL NOT delete the local files, but it will stop sharing it with %2 collaborator(s).\n\nAre you sure you want to remove it from the managed list?").arg(repoInfo.displayName).arg(repoInfo.collaborators.size()),
                                 QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
        {
            return;
        }
    }
    else
    {
        if (QMessageBox::question(this, "Confirm Deletion", QString("Are you sure you want to remove '%1' from your managed list? This will NOT delete the local files.").arg(repoInfo.displayName), QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
        {
            return;
        }
    }

    if (m_repoManager->removeManagedRepository(appId))
    {
        m_repoManagementPanel->logStatus("Repository '" + repoInfo.displayName + "' removed from management list.");
        if (repoInfo.isPublic && m_networkManager)
        {
            m_networkManager->sendDiscoveryBroadcast();
        }
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
        QMessageBox::critical(this, "Error", "Could not find peer info. They may have gone offline.");
        return;
    }
    if (m_networkManager->getSocketForPeer(peerId) != nullptr)
    {
        m_networkPanel->logMessage(QString("Already connected to peer '%1'.").arg(peerId), Qt::gray);
        return;
    }
    m_networkPanel->logMessage(QString("Initiating connection to peer '%1' at %2:%3...").arg(peerId).arg(peerInfo.address.toString()).arg(peerInfo.tcpPort), "blue");
    m_networkManager->connectToTcpPeer(peerInfo.address, peerInfo.tcpPort, peerInfo.id);
}

void MainWindow::handleCloneRepo(const QString &peerId, const QString &repoName)
{
    if (!m_networkManager || !m_repoManager)
    {
        QMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
        return;
    }

    if (!m_repoManager->getRepositoryInfoByOrigin(peerId, repoName).appId.isEmpty())
    {
        QMessageBox::information(this, "Repository Already Cloned", "You appear to have already cloned this specific repository from this peer.\nIf you wish to clone it again, please delete the existing managed entry first.");
        return;
    }

    QString localClonePathBase = QFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty())
        return;

    QString fullLocalClonePath = QDir(localClonePathBase).filePath(repoName);
    QDir targetDir(fullLocalClonePath);
    if (targetDir.exists() && !targetDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty())
    {
        QMessageBox::warning(this, "Directory Exists and is Not Empty", "The target directory already exists and contains files. Please choose an empty directory or a different location.");
        return;
    }

    m_pendingCloneRequest.peerId = peerId;
    m_pendingCloneRequest.repoName = repoName;
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
        m_networkManager->connectAndRequestBundle(providerPeerInfo.address, providerPeerInfo.tcpPort, m_myUsername, repoName, fullLocalClonePath);
    }
    else
    {
        m_networkPanel->logMessage(QString("Initiating clone for '%1' from '%2' via existing connection...").arg(repoName, peerId), "blue");
        m_networkManager->sendRepoBundleRequest(peerSocket, repoName, fullLocalClonePath);
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
    if (!m_networkManager || m_networkManager->getSocketForPeer(peerId) == nullptr)
    {
        QMessageBox::warning(this, "Not Connected", QString("You must have an established TCP connection with '%1' to add them as a collaborator.").arg(peerId));
        return;
    }
    if (peerId == m_myUsername)
    {
        QMessageBox::information(this, "Cannot Add Self", "You cannot add yourself as a collaborator.");
        return;
    }

    QList<ManagedRepositoryInfo> myOwnedRepos = m_repoManager->getMyPrivateRepositories(m_myUsername);
    QList<ManagedRepositoryInfo> eligibleRepos;
    for (const auto &repo : myOwnedRepos)
    {
        if (!repo.collaborators.contains(peerId))
        {
            eligibleRepos.append(repo);
        }
    }

    if (eligibleRepos.isEmpty())
    {
        QMessageBox::information(this, "No Eligible Repositories", QString("You do not own any private repositories that '%1' is not already a collaborator on.").arg(peerId));
        return;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QString("Add '%1' as Collaborator").arg(peerId));
    QVBoxLayout layout(&dialog);
    QListWidget listWidget(&dialog);

    for (const auto &repo : eligibleRepos)
    {
        auto *item = new QListWidgetItem(repo.displayName, &listWidget);
        item->setData(Qt::UserRole, repo.appId);
    }

    listWidget.setSelectionMode(QAbstractItemView::MultiSelection);
    layout.addWidget(new QLabel(QString("Select repositories to add '%1' as a collaborator:").arg(peerId), &dialog));
    layout.addWidget(&listWidget);

    QHBoxLayout *buttonBox = new QHBoxLayout();
    QPushButton *okButton = new QPushButton("Add", &dialog);
    QPushButton *cancelButton = new QPushButton("Cancel", &dialog);
    buttonBox->addWidget(okButton);
    buttonBox->addWidget(cancelButton);
    layout.addLayout(buttonBox);

    connect(okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    connect(cancelButton, &QPushButton::clicked, &dialog, &QDialog::reject);

    if (dialog.exec() == QDialog::Accepted)
    {
        QTcpSocket *peerSocket = m_networkManager->getSocketForPeer(peerId);
        if (!peerSocket)
        {
            QMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost.").arg(peerId));
            return;
        }

        for (auto *item : listWidget.selectedItems())
        {
            QString appId = item->data(Qt::UserRole).toString();
            ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
            if (repoInfo.appId.isEmpty() || repoInfo.collaborators.contains(peerId))
                continue;

            if (m_repoManager->addCollaborator(appId, peerId))
            {
                m_networkPanel->logMessage(QString("Added '%1' as a collaborator to '%2'.").arg(peerId, repoInfo.displayName), "green");
                QVariantMap payload;
                payload["appId"] = repoInfo.appId;
                payload["repoName"] = repoInfo.displayName;
                payload["ownerId"] = repoInfo.adminPeerId;
                m_networkManager->sendEncryptedMessage(peerSocket, "COLLABORATOR_ADDED", payload);
                if (m_projectWindows.contains(appId))
                {
                    m_projectWindows[appId]->updateGroupMembers();
                }
            }
            else
            {
                m_networkPanel->logMessage(QString("Failed to add '%1' as collaborator to '%2' locally.").arg(peerId, repoInfo.displayName), Qt::red);
            }
        }
    }
}

void MainWindow::handleAddCollaboratorFromProjectWindow(const QString &appId)
{
    if (!m_networkManager || !m_repoManager)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty() || repoInfo.adminPeerId != m_myUsername)
    {
        QMessageBox::warning(this, "Access Denied", "You are not the owner of this repository or it was not found.");
        return;
    }

    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
    QStringList eligiblePeers;
    for (const QString &peerId : connectedPeers)
    {
        if (!repoInfo.collaborators.contains(peerId) && peerId != m_myUsername)
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
            QMessageBox::warning(this, "Connection Lost", QString("The connection to '%1' was lost.").arg(peerToAdd));
            return;
        }

        if (m_repoManager->addCollaborator(appId, peerToAdd))
        {
            m_networkPanel->logMessage(QString("Added '%1' as a collaborator to '%2'.").arg(peerToAdd, repoInfo.displayName), "green");
            QVariantMap payload;
            payload["appId"] = repoInfo.appId;
            payload["repoName"] = repoInfo.displayName;
            payload["ownerId"] = repoInfo.adminPeerId;
            m_networkManager->sendEncryptedMessage(peerSocket, "COLLABORATOR_ADDED", payload);
            if (m_projectWindows.contains(appId))
            {
                m_projectWindows[appId]->updateGroupMembers();
            }
        }
        else
        {
            m_networkPanel->logMessage(QString("Failed to add '%1' as collaborator to '%2' locally.").arg(peerToAdd, repoInfo.displayName), Qt::red);
        }
    }
}

void MainWindow::handleRemoveCollaboratorFromProjectWindow(const QString &appId, const QString &peerIdToRemove)
{
    if (!m_repoManager)
        return;

    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (repoInfo.appId.isEmpty() || repoInfo.adminPeerId != m_myUsername)
    {
        QMessageBox::warning(this, "Access Denied", "You are not the owner of this repository or it was not found.");
        return;
    }

    if (peerIdToRemove.isEmpty() || peerIdToRemove == m_myUsername)
    {
        QMessageBox::warning(this, "Invalid Action", "Cannot remove the repository owner or yourself.");
        return;
    }

    if (!repoInfo.collaborators.contains(peerIdToRemove))
    {
        QMessageBox::warning(this, "Error", QString("'%1' is not listed as a collaborator for '%2'.").arg(peerIdToRemove, repoInfo.displayName));
        return;
    }

    if (QMessageBox::question(this, "Confirm Removal",
                              QString("Are you sure you want to remove '%1' as a collaborator from '%2'?\n\nThey will lose access to this private repository from you.").arg(peerIdToRemove, repoInfo.displayName),
                              QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
    {
        if (m_repoManager->removeCollaborator(appId, peerIdToRemove))
        {
            m_networkPanel->logMessage(QString("Removed '%1' as a collaborator from '%2'.").arg(peerIdToRemove, repoInfo.displayName), "green");
            if (m_projectWindows.contains(appId))
            {
                m_projectWindows[appId]->updateGroupMembers();
            }
        }
        else
        {
            m_networkPanel->logMessage(QString("Failed to remove '%1' as collaborator from '%2' locally.").arg(peerIdToRemove, repoInfo.displayName), Qt::red);
        }
    }
}

void MainWindow::handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload)
{
    qDebug() << "MainWindow: Received secure message type" << messageType << " from" << peerId;

    if (messageType == "COLLABORATOR_ADDED")
    {
        QString appId = payload.value("appId").toString();
        QString repoName = payload.value("repoName").toString();
        QString ownerId = payload.value("ownerId").toString();

        if (ownerId.isEmpty() || repoName.isEmpty() || ownerId == m_myUsername)
        {
            qWarning() << "MainWindow: Received invalid COLLABORATOR_ADDED message (missing info or from self).";
            return;
        }

        m_networkPanel->logMessage(QString("Peer '%1' has added you as a collaborator to private repository '%2'.").arg(peerId, repoName), "purple");

        ManagedRepositoryInfo localCloneInfo = m_repoManager->getRepositoryInfoByOrigin(ownerId, repoName);
        if (!localCloneInfo.appId.isEmpty())
        {
            qDebug() << "MainWindow: Updating local clone (" << localCloneInfo.appId << ") collaborator list to include myself.";
            m_repoManager->addCollaborator(localCloneInfo.appId, m_myUsername);
            if (m_projectWindows.contains(localCloneInfo.appId))
            {
                m_projectWindows[localCloneInfo.appId]->updateGroupMembers();
            }
            QMessageBox::information(this, "Private Repository Shared", QString("Peer '%1' has granted you access to their private repository: '%2'.\nYour local managed copy has been updated.").arg(peerId, repoName));
        }
        else
        {
            QMessageBox::information(this, "Private Repository Shared", QString("Peer '%1' has granted you access to their private repository: '%2'.\nIt will now appear in their discovered list for you to clone.").arg(peerId, repoName));
            m_networkManager->addSharedRepoToPeer(peerId, repoName);
        }
        updateUiFromBackend();
    }
}

void MainWindow::handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt)
{
    qDebug() << "MainWindow: Received bundle request for" << repoDisplayName << "from" << sourcePeerUsername;

    if (!m_repoManager || !m_networkManager)
    {
        m_networkPanel->logMessage("Cannot process bundle request: core services not ready.", Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    ManagedRepositoryInfo repoToBundle = m_repoManager->getRepositoryInfoByDisplayName(repoDisplayName);
    if (repoToBundle.appId.isEmpty() || repoToBundle.adminPeerId != m_myUsername)
    {
        m_networkPanel->logMessage(QString("Received bundle request for '%1', but it is not *owned* by me.").arg(repoDisplayName.toHtmlEscaped()), Qt::red);
        requestingPeerSocket->disconnectFromHost();
        return;
    }

    bool canAccess = repoToBundle.isPublic || repoToBundle.collaborators.contains(sourcePeerUsername);
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
        m_networkPanel->logMessage(QString("Bundle created for '%1' at %2. Starting transfer to %3...").arg(repoDisplayName.toHtmlEscaped(), QString::fromStdString(bundleFilePathStd).toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()), "purple");
        m_networkManager->startSendingBundle(requestingPeerSocket, repoToBundle.displayName, QString::fromStdString(bundleFilePathStd));
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to create bundle for '%1': %2").arg(repoToBundle.displayName.toHtmlEscaped(), QString::fromStdString(errorMsgBundle).toHtmlEscaped()), Qt::red);
        requestingPeerSocket->disconnectFromHost();
    }
    tempGitBackend.closeRepository();
}

void MainWindow::handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    if (!success)
    {
        m_networkPanel->logMessage(QString("Failed to receive repository '%1' bundle: %2").arg(repoName, message), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Failed to receive the repository bundle for '%1':\n%2").arg(repoName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoName != repoName)
    {
        m_networkPanel->logMessage(QString("Received bundle for '%1' unexpectedly. Saved to temp: %2").arg(repoName, localBundlePath), QColor("orange"));
        QMessageBox::warning(this, "Unexpected Bundle", QString("Received a repository bundle for '%1', but was not expecting it. The temporary file has been saved at:\n%2").arg(repoName, localBundlePath));
        m_pendingCloneRequest.clear();
        return;
    }

    m_networkPanel->logMessage(QString("Bundle for '%1' received successfully at %2. Initiating local git clone...").arg(repoName, localBundlePath), "blue");

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
    connect(gitCloneProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, [=](int exitCode, QProcess::ExitStatus exitStatus)
            {
                QString processOutput = QString(gitCloneProcess->readAllStandardOutput());
                QString processError = QString(gitCloneProcess->readAllStandardError());

                if (exitStatus == QProcess::NormalExit && exitCode == 0)
                {
                    m_networkPanel->logMessage(QString("Successfully cloned '%1' to '%2'.").arg(repoName, finalClonePath), Qt::darkGreen);
                    m_networkPanel->logMessage("Git clone stdout: " + processOutput, Qt::gray);
                    if (!processError.isEmpty())
                        m_networkPanel->logMessage("Git clone stderr: " + processError, Qt::yellow);

                    QMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(repoName, finalClonePath));

                    if (m_repoManager->addManagedRepository(finalClonePath, repoName, false, m_myUsername, m_pendingCloneRequest.peerId))
                    {
                        m_networkPanel->logMessage(QString("Cloned repository '%1' added to management list.").arg(repoName), Qt::darkGreen);
                        ManagedRepositoryInfo newRepoInfo = m_repoManager->getRepositoryInfoByPath(finalClonePath);
                        if (!newRepoInfo.appId.isEmpty())
                        {
                            handleOpenRepoInProjectWindow(newRepoInfo.appId);
                        }
                    }
                    else
                    {
                        m_networkPanel->logMessage(QString("Failed to add cloned repository '%1' to management list. It might already be managed?").arg(repoName), Qt::red);
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
                    if (!cleanupCheckBackend.openRepository(finalClonePath.toStdString(), checkError))
                    {
                        QDir cleanupDir(finalClonePath);
                        if (cleanupDir.exists() && cleanupDir.entryList(QDir::NoDotAndDotDot | QDir::AllEntries).isEmpty())
                        {
                            if (cleanupDir.rmdir("."))
                            {
                                m_networkPanel->logMessage(QString("Cleaned up empty target directory '%1'.").arg(finalClonePath), Qt::gray);
                            }
                            else
                            {
                                m_networkPanel->logMessage(QString("Failed to clean up empty target directory '%1'.").arg(finalClonePath), Qt::yellow);
                            }
                        }
                    }
                    else
                    {
                        m_networkPanel->logMessage(QString("Note: Target directory '%1' contains a partial .git repo. Manual cleanup may be needed.").arg(finalClonePath), Qt::yellow);
                        cleanupCheckBackend.closeRepository();
                    }
                }

                QFile::remove(localBundlePath);
                m_pendingCloneRequest.clear();
                gitCloneProcess->deleteLater(); });

    gitCloneProcess->start("git", QStringList() << "clone" << QDir::toNativeSeparators(localBundlePath) << QDir::toNativeSeparators(finalClonePath));

    if (!gitCloneProcess->waitForStarted(5000))
    {
        QString errorString = gitCloneProcess->errorString();
        m_networkPanel->logMessage("Clone failed: Could not start git process: " + errorString, Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Could not start the git process:\n%1").arg(errorString));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        gitCloneProcess->deleteLater();
    }
}