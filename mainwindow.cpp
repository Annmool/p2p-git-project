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
    m_repoManager = new RepositoryManager(repoManagerStorageFile, this);

    m_networkManager = new NetworkManager(m_myUsername, m_identityManager, m_repoManager, this);

    setupUi();
    connectSignals();
    m_networkPanel->setNetworkManager(m_networkManager);

    m_networkPanel->setMyPeerInfo(m_myUsername, QString::fromStdString(m_identityManager->getMyPublicKeyHex()));
    updateUiFromBackend();
}

MainWindow::~MainWindow()
{
    delete m_gitBackend;
    delete m_identityManager;
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
    mainSplitter->setSizes({800, 600});

    mainVLayout->addWidget(mainSplitter);
}

void MainWindow::connectSignals()
{
    connect(m_repoManager, &RepositoryManager::managedRepositoryListChanged, this, &MainWindow::updateUiFromBackend);
    if (m_networkManager)
    {
        connect(m_networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::updateUiFromBackend);
        connect(m_networkManager, &NetworkManager::secureMessageReceived, this, &MainWindow::handleSecureMessage);
        connect(m_networkManager, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest);
        connect(m_networkManager, &NetworkManager::repoBundleRequestedByPeer, this, &MainWindow::handleRepoBundleRequest);
        connect(m_networkManager, &NetworkManager::repoBundleCompleted, this, &MainWindow::handleRepoBundleCompleted);
        connect(m_networkManager, &NetworkManager::tcpServerStatusChanged, m_networkPanel, &NetworkPanel::updateServerStatus);

        connect(m_networkManager, &NetworkManager::tcpMessageReceived, this, [this](QTcpSocket *socket, const QString &peer, const QString &msg)
                {
            Q_UNUSED(socket); // We don't need the socket pointer in the UI panel for this log message
            m_networkPanel->logChatMessage(peer, msg); });

        connect(m_networkManager, &NetworkManager::repoBundleSent, this, [this](const QString &repoName, const QString &recipient)
                { m_networkPanel->logMessage(QString("Sent bundle for '%1' to peer '%2'.").arg(repoName, recipient), "purple"); });
    }

    connect(m_repoManagementPanel, &RepoManagementPanel::addRepoClicked, this, [this]()
            { handleAddManagedRepo(); });
    connect(m_repoManagementPanel, &RepoManagementPanel::modifyAccessClicked, this, &MainWindow::handleModifyRepoAccess);
    connect(m_repoManagementPanel, &RepoManagementPanel::deleteRepoClicked, this, &MainWindow::handleDeleteRepo);
    connect(m_repoManagementPanel, &RepoManagementPanel::openRepoInGitPanel, this, &MainWindow::handleOpenRepoInProjectWindow);

    connect(m_networkPanel, &NetworkPanel::toggleDiscoveryRequested, this, &MainWindow::handleToggleDiscovery);
    connect(m_networkPanel, &NetworkPanel::connectToPeerRequested, this, &MainWindow::handleConnectToPeer);
    connect(m_networkPanel, &NetworkPanel::cloneRepoRequested, this, &MainWindow::handleCloneRepo);
    connect(m_networkPanel, &NetworkPanel::addCollaboratorRequested, this, &MainWindow::handleAddCollaborator);
    connect(m_networkPanel, &NetworkPanel::sendMessageRequested, this, &MainWindow::handleSendMessage);
}

void MainWindow::updateUiFromBackend()
{
    m_repoManagementPanel->updateRepoList(m_repoManager->getAllManagedRepositories());
    if (m_networkManager)
    {
        m_networkPanel->updatePeerList(m_networkManager->getDiscoveredPeers(), m_networkManager->getConnectedPeerIds());
        m_networkPanel->updateConnectedPeersList(m_networkManager->getConnectedPeerIds());
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

    std::string error;
    GitBackend tempBackend;
    if (!tempBackend.openRepository(dirPath.toStdString(), error))
    {
        QMessageBox::warning(this, "Not a Git Repository", "The selected folder does not appear to be a valid Git repository.");
        return;
    }

    QString repoName = QFileInfo(dirPath).fileName();
    bool ok;
    QString displayName = QInputDialog::getText(this, "Manage Repository", "Enter a display name:", QLineEdit::Normal, repoName, &ok);
    if (!ok || displayName.isEmpty())
        return;

    bool isPublic = (QMessageBox::question(this, "Set Visibility", "Make this repository public for other peers to discover and clone?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes);

    if (m_repoManager->addManagedRepository(dirPath, displayName, isPublic, m_myUsername))
    {
        m_repoManagementPanel->logStatus("Repository '" + displayName + "' added to management list.");
        if (m_networkManager)
            m_networkManager->sendDiscoveryBroadcast();
    }
    else
    {
        m_repoManagementPanel->logStatus("Failed to add repository. It might already be managed.", true);
    }
}

void MainWindow::handleModifyRepoAccess(const QString &appId)
{
    if (appId.isEmpty())
        return;
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (repoInfo.adminPeerId != m_myUsername)
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
    if (QMessageBox::question(this, "Confirm Deletion", QString("Are you sure you want to remove '%1' from your managed list?").arg(repoInfo.displayName), QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
    {
        m_repoManager->removeManagedRepository(appId);
        m_networkManager->sendDiscoveryBroadcast();
    }
}

// void MainWindow::handleOpenRepoInGitPanel(const QString &path)
// {
//     if (path.isEmpty())
//         return;
//     std::string error;
//     if (m_gitBackend->openRepository(path.toStdString(), error))
//     {
//         m_repoManagementPanel->logStatus("Repository opened: " + path);
//         // This is where you would update the git panel with new commit logs etc.
//     }
//     else
//     {
//         m_repoManagementPanel->logStatus("Error opening repository: " + QString::fromStdString(error), true);
//     }
// }

void MainWindow::handleOpenRepoInProjectWindow(const QString &appId)
{
    ManagedRepositoryInfo repoInfo = m_repoManager->getRepositoryInfo(appId);
    if (!repoInfo.appId.isEmpty())
    {
        for (ProjectWindow *window : m_projectWindows)
        {
            if (window->property("repoPath") == repoInfo.localPath)
            {
                window->activateWindow();
                return;
            }
        }
        ProjectWindow *projectWindow = new ProjectWindow(repoInfo.localPath);
        projectWindow->setAttribute(Qt::WA_DeleteOnClose);
        projectWindow->setProperty("repoPath", repoInfo.localPath);
        m_projectWindows.append(projectWindow);
        connect(projectWindow, &QObject::destroyed, this, [this, projectWindow]()
                { m_projectWindows.removeAll(projectWindow); });
        projectWindow->show();
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
    // This is the implementation you provided, integrated here.
    if (!m_networkManager || !m_repoManager)
    {
        QMessageBox::critical(this, "Fatal Error", "Core services are not ready.");
        return;
    }

    for (const auto &managedRepo : m_repoManager->getAllManagedRepositories())
    {
        if (managedRepo.originPeerId == peerId && managedRepo.displayName == repoName)
        {
            if (QMessageBox::question(this, "Repository Already Cloned", "You appear to have already cloned this repository.\n\nDo you want to clone it again?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::No)
            {
                return;
            }
            break;
        }
    }

    QString localClonePathBase = QFileDialog::getExistingDirectory(this, "Select Base Directory to Clone Into", QDir::homePath() + "/P2P_Clones");
    if (localClonePathBase.isEmpty())
        return;

    QString fullLocalClonePath = QDir(localClonePathBase).filePath(repoName);
    if (QDir(fullLocalClonePath).exists())
    {
        QMessageBox::warning(this, "Directory Exists", "The target directory already exists.");
        return;
    }

    DiscoveredPeerInfo providerPeerInfo = m_networkManager->getDiscoveredPeerInfo(peerId);
    if (providerPeerInfo.id.isEmpty())
    {
        QMessageBox::critical(this, "Connection Error", "Could not find peer info. They may have gone offline.");
        return;
    }

    m_networkPanel->logMessage(QString("Initiating automated clone for '%1' from '%2'...").arg(repoName, peerId), "blue");
    m_networkManager->connectAndRequestBundle(providerPeerInfo.address, providerPeerInfo.tcpPort, m_myUsername, repoName, fullLocalClonePath);
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
        m_networkManager->startUdpDiscovery();
    }
}

void MainWindow::handleSendMessage(const QString &message)
{
    m_networkManager->broadcastTcpMessage(message);
}

void MainWindow::handleAddCollaborator(const QString &peerId)
{
    QList<ManagedRepositoryInfo> privateRepos = m_repoManager->getMyPrivateRepositories(m_myUsername);
    if (privateRepos.isEmpty())
    {
        QMessageBox::information(this, "No Private Repositories", "You do not have any private repositories that you own.");
        return;
    }
    QDialog dialog(this);
    dialog.setWindowTitle("Share Private Repositories");
    QVBoxLayout layout(&dialog);
    QListWidget listWidget(&dialog);
    for (const auto &repo : privateRepos)
    {
        if (repo.adminPeerId == m_myUsername)
        {
            auto *item = new QListWidgetItem(repo.displayName, &listWidget);
            item->setData(Qt::UserRole, repo.appId);
        }
    }
    listWidget.setSelectionMode(QAbstractItemView::MultiSelection);
    layout.addWidget(new QLabel(QString("Select private repositories to share with '%1':").arg(peerId), &dialog));
    layout.addWidget(&listWidget);
    QPushButton okButton("Share", &dialog);
    connect(&okButton, &QPushButton::clicked, &dialog, &QDialog::accept);
    layout.addWidget(&okButton);
    if (dialog.exec() == QDialog::Accepted)
    {
        for (auto *item : listWidget.selectedItems())
        {
            QString appId = item->data(Qt::UserRole).toString();
            m_repoManager->addCollaborator(appId, peerId);
            QVariantMap payload;
            payload["appId"] = appId;
            payload["repoName"] = item->text();
            m_networkManager->sendEncryptedMessage(m_networkManager->getSocketForPeer(peerId), "SHARE_PRIVATE_REPO", payload);
        }
    }
}

void MainWindow::handleSecureMessage(const QString &peerId, const QString &messageType, const QVariantMap &payload)
{
    if (messageType == "SHARE_PRIVATE_REPO")
    {
        QString repoName = payload["repoName"].toString();
        m_networkPanel->logMessage(QString("Peer '%1' has shared the private repository '%2' with you.").arg(peerId, repoName), "purple");
        QMessageBox::information(this, "Private Repository Shared", QString("Peer '%1' has granted you access to their private repository: '%2'.\nIt will now appear in their discovered list for you to clone.").arg(peerId, repoName));
        m_networkManager->sendDiscoveryBroadcast();
    }
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

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Peer Connection Request");
    msgBox.setText(QString("Peer '%1' wants to establish a connection with you. Accept?").arg(peerDisplay.toHtmlEscaped()));
    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    msgBox.setDefaultButton(QMessageBox::No);
    QTimer::singleShot(30000, &msgBox, &QMessageBox::reject);

    if (msgBox.exec() == QMessageBox::Yes)
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

// void MainWindow::onInitRepoClicked()
// {
//     QString qPath = QFileDialog::getExistingDirectory(this, "Select Folder to Initialize Repository In", QDir::homePath());
//     if (qPath.isEmpty())
//     {
//         return;
//     }

//     std::string path = qPath.toStdString();
//     std::string errorMessage;

//     if (m_gitBackend->initializeRepository(path, errorMessage))
//     {
//         m_repoManagementPanel->logStatus("Repository initialized successfully.", false);
//         // Ask to manage the new repo
//         if (QMessageBox::question(this, "Manage Repository", "Do you want to add this new repository to your managed list?", QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes)
//         {
//             handleAddManagedRepo(qPath);
//         }
//     }
//     else
//     {
//         m_repoManagementPanel->logStatus("Error initializing repository: " + QString::fromStdString(errorMessage), true);
//     }
// }

// void MainWindow::onOpenRepoClicked()
// {
//     QString dirPath = QFileDialog::getExistingDirectory(this, "Open Git Repository", QDir::homePath());
//     if (!dirPath.isEmpty())
//     {
//         handleOpenRepoInGitPanel(dirPath);
//     }
// }

// This slot is executed on the SENDER's machine when they receive a clone request.
void MainWindow::handleRepoBundleRequest(QTcpSocket *requestingPeerSocket, const QString &sourcePeerUsername, const QString &repoDisplayName, const QString &clientWantsToSaveAt)
{
    qDebug() << "MainWindow: Received bundle request for" << repoDisplayName << "from" << sourcePeerUsername;

    if (!m_repoManager || !m_networkManager)
    {
        m_networkPanel->logMessage("Cannot process bundle request: core services not ready.", Qt::red);
        return;
    }

    // 1. Find the requested repository in the list of managed repos.
    ManagedRepositoryInfo repoToBundle;
    bool found = false;
    for (const auto &managedRepo : m_repoManager->getAllManagedRepositories())
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
        m_networkPanel->logMessage(QString("Received bundle request for '%1', but it is not in the managed list.").arg(repoDisplayName.toHtmlEscaped()), Qt::red);
        // TODO: Send REPO_NOT_FOUND error back to the requester
        return;
    }

    // 2. Check permissions (Is it public? Or is the requester a collaborator?)
    bool canAccess = repoToBundle.isPublic || repoToBundle.collaborators.contains(sourcePeerUsername);
    if (!canAccess)
    {
        m_networkPanel->logMessage(QString("Denied bundle request for private repository '%1' from '%2'.").arg(repoDisplayName.toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()), Qt::red);
        // TODO: Send ACCESS_DENIED error back
        return;
    }

    // 3. Use a TEMPORARY GitBackend instance to create the bundle.
    GitBackend tempGitBackend;
    std::string errorMessage;

    if (!tempGitBackend.openRepository(repoToBundle.localPath.toStdString(), errorMessage))
    {
        m_networkPanel->logMessage(QString("Failed to open managed repository '%1' for bundling: %2").arg(repoDisplayName.toHtmlEscaped(), QString::fromStdString(errorMessage)), Qt::red);
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
        m_networkPanel->logMessage(QString("Bundle created for '%1'. Starting transfer to %2...").arg(repoDisplayName.toHtmlEscaped(), sourcePeerUsername.toHtmlEscaped()), "purple");

        // 5. Start the network transfer.
        m_networkManager->startSendingBundle(requestingPeerSocket, repoToBundle.displayName, QString::fromStdString(bundleFilePathStd));
    }
    else
    {
        m_networkPanel->logMessage(QString("Failed to create bundle for '%1': %2").arg(repoToBundle.displayName.toHtmlEscaped(), QString::fromStdString(errorMsgBundle).toHtmlEscaped()), Qt::red);
    }
}

// This slot is executed on the CLONER's machine when the bundle transfer finishes.
void MainWindow::handleRepoBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    // The clone button can be re-enabled now that the process is over.
    // The onDiscoveredPeerOrRepoSelected slot will correctly handle enabling/disabling it.

    if (!success)
    {
        m_networkPanel->logMessage(QString("Failed to receive repository '%1': %2").arg(repoName, message), Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("Failed to receive the repository bundle for '%1':\n%2").arg(repoName, message));
        QFile::remove(localBundlePath);
        m_pendingCloneRequest.clear();
        return;
    }

    if (!m_pendingCloneRequest.isValid() || m_pendingCloneRequest.repoName != repoName)
    {
        m_networkPanel->logMessage(QString("Received bundle for '%1', but was not expecting it. Saved to temp.").arg(repoName), QColor("orange"));
        QMessageBox::warning(this, "Clone Warning", QString("Received a repository bundle for '%1', but was not expecting it. The temporary file has been saved at:\n%2").arg(repoName, localBundlePath));
        return;
    }

    m_networkPanel->logMessage(QString("Bundle for '%1' received. Cloning...").arg(repoName), "blue");
    QString finalClonePath = m_pendingCloneRequest.localClonePath;

    QProcess gitProcess;
    gitProcess.start("git", QStringList() << "clone" << QDir::toNativeSeparators(localBundlePath) << QDir::toNativeSeparators(finalClonePath));

    if (!gitProcess.waitForFinished(-1))
    {
        m_networkPanel->logMessage("Clone failed: Git process timed out.", Qt::red);
        QMessageBox::critical(this, "Clone Failed", "Git clone process timed out.");
    }
    else if (gitProcess.exitCode() == 0)
    {
        m_networkPanel->logMessage(QString("Successfully cloned '%1'.").arg(repoName), Qt::darkGreen);
        QMessageBox::information(this, "Clone Successful", QString("Successfully cloned '%1' to:\n%2").arg(repoName, finalClonePath));

        // Add the newly cloned repo to our managed list, preserving its origin info.
        if (m_repoManager->addManagedRepository(finalClonePath, repoName, false, m_myUsername, m_pendingCloneRequest.peerId))
        {
            // <<< FIX: Look up the new repo by path to get its appId >>>
            ManagedRepositoryInfo newRepoInfo = m_repoManager->getRepositoryInfoByPath(finalClonePath);
            if (!newRepoInfo.appId.isEmpty())
            {
                // Now call the function to open the project window with the correct ID
                handleOpenRepoInProjectWindow(newRepoInfo.appId);
            }
        }
    }
    else
    {
        QString errorMsg = QString(gitProcess.readAllStandardError());
        m_networkPanel->logMessage("Clone failed: " + errorMsg, Qt::red);
        QMessageBox::critical(this, "Clone Failed", QString("The git clone command failed:\n%1").arg(errorMsg));
    }

    QFile::remove(localBundlePath);
    m_pendingCloneRequest.clear();
}