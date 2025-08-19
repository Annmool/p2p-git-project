#include "project_window.h"
#include "mainwindow.h" // Required for qobject_cast in constructor

#include <QDesktopServices>
#include <QStandardPaths>
#include <QDir>
#include <QProcess>
#include <QMessageBox>
#include <QInputDialog>
#include <QTimer>
#include <QStyle>
#include <QFileInfo>
#include <QUrl>
#include <QSplitter>
#include <QMenu>

// --- CommitWidget Implementation ---

CommitWidget::CommitWidget(const CommitInfo& info, QWidget* parent) : QWidget(parent) {
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(4);
    mainLayout->setContentsMargins(10, 8, 10, 8);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    QLabel* shaLabel = new QLabel(QString("<b>commit</b> <font color='#64748B'>%1</font>").arg(QString::fromStdString(info.sha)), this);
    shaLabel->setFont(QFont("monospace"));
    
    QPushButton* viewFilesButton = new QPushButton("View Files", this);
    viewFilesButton->setFixedSize(100, 28);
    viewFilesButton->setProperty("commitSha", QString::fromStdString(info.sha));

    headerLayout->addWidget(shaLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(viewFilesButton);

    QLabel* authorLabel = new QLabel(QString("<b>Author:</b> %1 <%2>").arg(
        QString::fromStdString(info.author_name).toHtmlEscaped(),
        QString::fromStdString(info.author_email).toHtmlEscaped()
    ), this);

    QLabel* dateLabel = new QLabel(QString("<b>Date:</b>   %1").arg(QString::fromStdString(info.date)), this);
    
    QLabel* summaryLabel = new QLabel(QString::fromStdString(info.summary), this);
    summaryLabel->setWordWrap(true);
    summaryLabel->setStyleSheet("margin-left: 15px;");

    mainLayout->addLayout(headerLayout);
    mainLayout->addWidget(authorLabel);
    mainLayout->addWidget(dateLabel);
    mainLayout->addWidget(summaryLabel);
    
    connect(viewFilesButton, &QPushButton::clicked, this, &CommitWidget::onButtonClicked);
}

void CommitWidget::onButtonClicked() {
    QPushButton* button = qobject_cast<QPushButton*>(sender());
    if(button) {
        emit viewFilesClicked(button->property("commitSha").toString());
    }
}

// --- ProjectWindow Implementation ---

ProjectWindow::ProjectWindow(const QString &appId, RepositoryManager* repoManager, NetworkManager* networkManager, QWidget *parent)
    : QMainWindow(parent),
      m_appId(appId),
      m_repoManager(repoManager),
      m_networkManager(networkManager)
{
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid()) {
        QMessageBox::critical(this, "Error", "Could not find repository information for ID: " + appId);
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    setupUi();

    std::string error;
    if (!m_gitBackend.openRepository(m_repoInfo.localPath.toStdString(), error))
    {
        QMessageBox::critical(this, "Error", "Could not open repository:\n" + QString::fromStdString(error));
        close();
        return;
    }
    updateStatus();
    updateGroupMembers();

    connect(m_groupChatSendButton, &QPushButton::clicked, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_groupChatInput, &QLineEdit::returnPressed, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_addCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onAddCollaboratorClicked);
    connect(m_removeCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onRemoveCollaboratorClicked);
    connect(m_groupMembersList, &QListWidget::currentItemChanged, this, &ProjectWindow::onGroupMemberSelectionChanged);
    
    connect(this, &ProjectWindow::fetchBundleRequested, qobject_cast<MainWindow*>(parentWidget()), &MainWindow::handleFetchBundleRequest);
    connect(this, &ProjectWindow::proposeChangesRequested, qobject_cast<MainWindow*>(parentWidget()), &MainWindow::handleProposeChangesRequest);

    connect(m_refreshStatusButton, &QPushButton::clicked, this, &ProjectWindow::refreshStatus);
    connect(m_stageAllButton, &QPushButton::clicked, this, &ProjectWindow::onStageAllClicked);
    connect(m_unstageAllButton, &QPushButton::clicked, this, &ProjectWindow::onUnstageAllClicked);
    connect(m_commitButton, &QPushButton::clicked, this, &ProjectWindow::onCommitClicked);
    connect(m_unstagedFilesList, &QListWidget::customContextMenuRequested, this, &ProjectWindow::onFileContextMenuRequested);
    connect(m_stagedFilesList, &QListWidget::customContextMenuRequested, this, &ProjectWindow::onFileContextMenuRequested);

    refreshStatus();
}

ProjectWindow::~ProjectWindow() {}

QWidget* ProjectWindow::createChangesTab()
{
    QWidget* changesWidget = new QWidget();
    QVBoxLayout* mainLayout = new QVBoxLayout(changesWidget);
    
    QSplitter* splitter = new QSplitter(Qt::Vertical, changesWidget);
    
    QWidget* stagingArea = new QWidget(splitter);
    QVBoxLayout* stagingLayout = new QVBoxLayout(stagingArea);
    stagingLayout->setContentsMargins(0,0,0,0);
    
    QHBoxLayout* unstagedHeaderLayout = new QHBoxLayout();
    unstagedHeaderLayout->addWidget(new QLabel("<b>Unstaged Changes</b>"));
    unstagedHeaderLayout->addStretch();
    m_refreshStatusButton = new QPushButton("Refresh", stagingArea);
    unstagedHeaderLayout->addWidget(m_refreshStatusButton);
    m_stageAllButton = new QPushButton("Stage All", stagingArea);
    unstagedHeaderLayout->addWidget(m_stageAllButton);
    stagingLayout->addLayout(unstagedHeaderLayout);
    
    m_unstagedFilesList = new QListWidget(stagingArea);
    m_unstagedFilesList->setContextMenuPolicy(Qt::CustomContextMenu);
    stagingLayout->addWidget(m_unstagedFilesList);
    
    QHBoxLayout* stagedHeaderLayout = new QHBoxLayout();
    stagedHeaderLayout->addWidget(new QLabel("<b>Staged Changes (Index)</b>"));
    stagedHeaderLayout->addStretch();
    m_unstageAllButton = new QPushButton("Unstage All", stagingArea);
    stagedHeaderLayout->addWidget(m_unstageAllButton);
    stagingLayout->addLayout(stagedHeaderLayout);

    m_stagedFilesList = new QListWidget(stagingArea);
    m_stagedFilesList->setContextMenuPolicy(Qt::CustomContextMenu);
    stagingLayout->addWidget(m_stagedFilesList);
    
    splitter->addWidget(stagingArea);

    QWidget* commitArea = new QWidget(splitter);
    QVBoxLayout* commitLayout = new QVBoxLayout(commitArea);
    commitLayout->addWidget(new QLabel("<b>Commit Message</b>"));
    m_commitMessageInput = new QTextEdit(commitArea);
    m_commitMessageInput->setPlaceholderText("Enter a summary of your changes...");
    m_commitMessageInput->setMaximumHeight(100);
    commitLayout->addWidget(m_commitMessageInput);
    
    std::string branchName;
    m_commitButton = new QPushButton("Commit to " + QString::fromStdString(m_gitBackend.getCurrentBranch(branchName)), this);
    commitLayout->addWidget(m_commitButton);
    
    splitter->addWidget(commitArea);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(splitter);
    return changesWidget;
}

void ProjectWindow::setupUi()
{
    setWindowTitle("Project: " + m_repoInfo.displayName);
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    m_tabWidget = new QTabWidget(this);
    mainLayout->addWidget(m_tabWidget);

    // Create tabs
    m_changesTab = createChangesTab();
    m_historyTab = new QWidget();
    m_collabTab = new QWidget();

    // Setup History Tab
    QVBoxLayout *historyLayout = new QVBoxLayout(m_historyTab);
    m_statusLabel = new QLabel(this);
    historyLayout->addWidget(m_statusLabel);
    m_commitLogDisplay = new QListWidget(this);
    m_commitLogDisplay->setAlternatingRowColors(true);
    m_commitLogDisplay->setStyleSheet("QListWidget { border: 1px solid #dee2e6; }");
    historyLayout->addWidget(m_commitLogDisplay, 1);
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_refreshLogButton = new QPushButton("Refresh Log", this);
    m_fetchButton = new QPushButton("Fetch", this);
    m_proposeChangesButton = new QPushButton("Propose Changes", this);
    m_branchComboBox = new QComboBox(this);
    m_refreshBranchesButton = new QPushButton("Refresh Branches", this);
    m_checkoutButton = new QPushButton("Checkout Branch", this);
    controlsLayout->addWidget(m_fetchButton);
    controlsLayout->addWidget(m_proposeChangesButton);
    controlsLayout->addStretch();
    controlsLayout->addWidget(m_refreshLogButton);
    controlsLayout->addWidget(m_refreshBranchesButton);
    controlsLayout->addWidget(m_branchComboBox, 1);
    controlsLayout->addWidget(m_checkoutButton);
    historyLayout->addLayout(controlsLayout);
    connect(m_refreshLogButton, &QPushButton::clicked, this, &ProjectWindow::refreshLog);
    connect(m_refreshBranchesButton, &QPushButton::clicked, this, &ProjectWindow::refreshBranches);
    connect(m_fetchButton, &QPushButton::clicked, this, &ProjectWindow::onFetchClicked);
    connect(m_proposeChangesButton, &QPushButton::clicked, this, &ProjectWindow::onProposeChangesClicked);
    connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    connect(m_branchComboBox, &QComboBox::currentTextChanged, this, &ProjectWindow::viewRemoteBranchHistory);

    // Setup Collaboration Tab
    QVBoxLayout *collabLayout = new QVBoxLayout(m_collabTab);
    collabLayout->addWidget(new QLabel("<b>Group Members:</b>"));
    m_groupMembersList = new QListWidget(this);
    m_groupMembersList->setMaximumHeight(120);
    collabLayout->addWidget(m_groupMembersList);
    QHBoxLayout *collabButtonLayout = new QHBoxLayout();
    m_addCollaboratorButton = new QPushButton("Add Collaborator...", this);
    m_removeCollaboratorButton = new QPushButton("Remove Collaborator", this);
    collabButtonLayout->addWidget(m_addCollaboratorButton);
    collabButtonLayout->addWidget(m_removeCollaboratorButton);
    collabLayout->addLayout(collabButtonLayout);
    collabLayout->addWidget(new QLabel("<b>Group Chat:</b>"));
    m_groupChatDisplay = new QTextEdit(this);
    m_groupChatDisplay->setReadOnly(true);
    collabLayout->addWidget(m_groupChatDisplay, 1);
    QHBoxLayout* chatInputLayout = new QHBoxLayout();
    m_groupChatInput = new QLineEdit(this);
    m_groupChatInput->setPlaceholderText("Type message to group...");
    m_groupChatSendButton = new QPushButton("Send");
    chatInputLayout->addWidget(m_groupChatInput, 1);
    chatInputLayout->addWidget(m_groupChatSendButton);
    collabLayout->addLayout(chatInputLayout);

    // Add all tabs
    m_tabWidget->addTab(m_changesTab, "Changes");
    m_tabWidget->addTab(m_historyTab, "History");
    m_tabWidget->addTab(m_collabTab, "Collaboration");

    resize(800, 600);
}

void ProjectWindow::updateStatus()
{
    std::string error;
    std::string branch = m_gitBackend.getCurrentBranch(error);
    m_statusLabel->setText(QString("<b>Path:</b> %1<br><b>Current Branch:</b> %2").arg(m_repoInfo.localPath, QString::fromStdString(branch).toHtmlEscaped()));
    m_commitButton->setText("Commit to " + QString::fromStdString(branch));
    m_proposeChangesButton->setEnabled(!m_repoInfo.isOwner);
    loadBranchList();
    loadCommitLog();
}

void ProjectWindow::updateGroupMembers()
{
    if (!m_networkManager) return;
    
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid()) return;

    m_groupMembersList->clear();
    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
    
    QStringList members = m_repoInfo.groupMembers;
    members.removeDuplicates();
    members.sort();

    for (const QString& member : members) {
        QListWidgetItem* item = new QListWidgetItem(m_groupMembersList);
        bool isConnected = connectedPeers.contains(member) || (member == m_networkManager->getMyUsername());
        
        item->setText(member + (member == m_repoInfo.ownerPeerId ? " (owner)" : ""));
        item->setIcon(isConnected ? style()->standardIcon(QStyle::SP_DialogYesButton) : style()->standardIcon(QStyle::SP_DialogCancelButton));
        item->setForeground(isConnected ? palette().color(QPalette::Text) : QColor("grey"));
        item->setData(Qt::UserRole, member);
    }
    
    m_addCollaboratorButton->setVisible(m_repoInfo.isOwner);
    m_removeCollaboratorButton->setVisible(m_repoInfo.isOwner);
    onGroupMemberSelectionChanged();
}


void ProjectWindow::displayGroupMessage(const QString& peerId, const QString& message)
{
    QString myUsername = m_networkManager ? m_networkManager->getMyUsername() : "";
    QString formattedMessage = QString("<b>%1:</b> %2")
                                   .arg(peerId == myUsername ? "Me" : peerId.toHtmlEscaped())
                                   .arg(message.toHtmlEscaped());
    m_groupChatDisplay->append(formattedMessage);
}

void ProjectWindow::onSendGroupMessageClicked()
{
    QString message = m_groupChatInput->text().trimmed();
    if (message.isEmpty()) return;
    emit groupMessageSent(m_repoInfo.ownerRepoAppId, message);
    m_groupChatInput->clear();
}

void ProjectWindow::onAddCollaboratorClicked()
{
    emit addCollaboratorRequested(m_appId);
}

void ProjectWindow::onRemoveCollaboratorClicked()
{
    QListWidgetItem* selectedItem = m_groupMembersList->currentItem();
    if (!selectedItem) return;
    QString peerIdToRemove = selectedItem->data(Qt::UserRole).toString();
    emit removeCollaboratorRequested(m_appId, peerIdToRemove);
}

void ProjectWindow::onGroupMemberSelectionChanged()
{
    bool canRemove = false;
    QListWidgetItem* selectedItem = m_groupMembersList->currentItem();
    if (selectedItem && m_repoInfo.isOwner) {
        QString peerId = selectedItem->data(Qt::UserRole).toString();
        if (peerId != m_repoInfo.ownerPeerId) {
            canRemove = true;
        }
    }
    m_removeCollaboratorButton->setEnabled(canRemove);
}

void ProjectWindow::refreshLog()
{
    loadCommitLog(m_branchComboBox->currentText().toStdString());
}

void ProjectWindow::refreshBranches()
{
    loadBranchList();
}

void ProjectWindow::checkoutBranch()
{
    QString branchName = m_branchComboBox->currentText();
    if (branchName.isEmpty()) return;
    std::string error;
    if (m_gitBackend.checkoutBranch(branchName.toStdString(), error)) {
        QMessageBox::information(this, "Success", "Checked out branch: " + branchName);
        updateStatus();
    } else {
        QMessageBox::warning(this, "Checkout Failed", QString::fromStdString(error));
    }
}

void ProjectWindow::viewRemoteBranchHistory()
{
    loadCommitLog(m_branchComboBox->currentText().toStdString());
}

void ProjectWindow::loadCommitLog(const std::string &ref)
{
    m_commitLogDisplay->clear();
    std::string error;
    auto log = m_gitBackend.getCommitLog(100, error, ref);

    if (!error.empty() && log.empty()) {
        QListWidgetItem* item = new QListWidgetItem(m_commitLogDisplay);
        item->setText("Error: " + QString::fromStdString(error));
        item->setForeground(Qt::red);
        return;
    }
    if (log.empty()) {
        new QListWidgetItem("No commits found for this reference.", m_commitLogDisplay);
        return;
    }
    for (const auto &commit : log) {
        QListWidgetItem* item = new QListWidgetItem(m_commitLogDisplay);
        CommitWidget* commitWidget = new CommitWidget(commit, m_commitLogDisplay);
        item->setSizeHint(commitWidget->sizeHint());
        m_commitLogDisplay->setItemWidget(item, commitWidget);
        connect(commitWidget, &CommitWidget::viewFilesClicked, this, &ProjectWindow::onViewFilesClicked);
    }
}

void ProjectWindow::loadBranchList()
{
    m_branchComboBox->clear();
    std::string error;
    auto branches = m_gitBackend.listBranches(GitBackend::BranchType::ALL, error);
    for (const auto &branch : branches) {
        if (QString::fromStdString(branch).endsWith("/HEAD"))
            continue;
        m_branchComboBox->addItem(QString::fromStdString(branch));
    }
    std::string currentBranch = m_gitBackend.getCurrentBranch(error);
    int index = m_branchComboBox->findText(QString::fromStdString(currentBranch));
    if (index != -1) {
        m_branchComboBox->setCurrentIndex(index);
    }
}

void ProjectWindow::onViewFilesClicked(const QString& sha)
{
    if (sha.isEmpty()) {
        QMessageBox::warning(this, "Error", "Could not retrieve commit SHA.");
        return;
    }
    QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) +
                       "/SyncIt_View/" + QFileInfo(m_repoInfo.localPath).fileName() + "_" + sha.left(7);
    QDir tempDir(tempPath);
    if (tempDir.exists()) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
        return;
    }
    if (!tempDir.mkpath(".")) {
        QMessageBox::critical(this, "Error", "Could not create temporary directory to view files.");
        return;
    }

    QProcess gitProcess;
    gitProcess.setWorkingDirectory(m_repoInfo.localPath);
    QStringList args;
    args << "archive" << sha << "--format=tar";
    QProcess tarProcess;
    tarProcess.setWorkingDirectory(tempPath);
    gitProcess.setStandardOutputProcess(&tarProcess);
    gitProcess.start("git", args);
    tarProcess.start("tar", QStringList() << "-x");
    if (!gitProcess.waitForFinished(-1) || !tarProcess.waitForFinished(-1)) {
        QMessageBox::critical(this, "Checkout Failed", "Could not archive and extract the specific commit.");
        tempDir.removeRecursively();
        return;
    }
    QMessageBox::information(this, "Opening Files", 
        QString("Checked out commit %1 in a temporary folder.\n\nPath: %2\n\nThis folder can be safely deleted when you are done.")
        .arg(sha.left(7), tempPath));
    QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
}

void ProjectWindow::onFetchClicked()
{
    if (m_repoInfo.isOwner) {
        QMessageBox::information(this, "Fetch", "You are the owner of this repository. There is no remote to fetch from.");
        return;
    }
    m_fetchButton->setEnabled(false);
    m_fetchButton->setText("Fetching...");
    emit fetchBundleRequested(m_repoInfo.ownerPeerId, m_repoInfo.displayName);
}

void ProjectWindow::onProposeChangesClicked()
{
    if (m_repoInfo.isOwner) {
        QMessageBox::information(this, "Action Not Available", "You are the owner. You commit directly, you don't need to propose changes.");
        return;
    }
    std::string error;
    std::string currentBranch = m_gitBackend.getCurrentBranch(error);
    if (currentBranch.empty() || currentBranch.rfind("[Detached HEAD", 0) == 0) {
        QMessageBox::warning(this, "Cannot Propose", "You must be on a branch to propose changes.");
        return;
    }
    m_proposeChangesButton->setEnabled(false);
    m_proposeChangesButton->setText("Bundling...");
    emit proposeChangesRequested(m_repoInfo.ownerPeerId, m_repoInfo.displayName, QString::fromStdString(currentBranch));
}

void ProjectWindow::handleFetchBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    m_fetchButton->setEnabled(true);
    m_fetchButton->setText("Fetch");
    if (!success) {
        QMessageBox::warning(this, "Fetch Failed", QString("Could not retrieve updates from owner: %1").arg(message));
        QFile::remove(localBundlePath);
        return;
    }
    std::string error;
    if (m_gitBackend.fetchFromBundle(localBundlePath.toStdString(), error)) {
        QMessageBox::information(this, "Fetch Successful", "Successfully fetched updates from the owner.");
        loadBranchList();
    } else {
        QMessageBox::warning(this, "Fetch Failed", QString("Could not apply updates from bundle:\n%1").arg(QString::fromStdString(error)));
    }
    QFile::remove(localBundlePath);
}

void ProjectWindow::refreshStatus()
{
    m_unstagedFilesList->clear();
    m_stagedFilesList->clear();
    
    std::string error;
    std::vector<FileStatus> statuses = m_gitBackend.getRepositoryStatus(error);

    if (!error.empty()) {
        QMessageBox::warning(this, "Status Error", QString::fromStdString(error));
        return;
    }
    
    for (const auto& fs : statuses) {
        QString path = QString::fromStdString(fs.path);
        if (fs.git_status & (GIT_STATUS_WT_NEW | GIT_STATUS_WT_MODIFIED | GIT_STATUS_WT_DELETED | GIT_STATUS_WT_TYPECHANGE | GIT_STATUS_WT_RENAMED)) {
            new QListWidgetItem(path, m_unstagedFilesList);
        }
        if (fs.git_status & (GIT_STATUS_INDEX_NEW | GIT_STATUS_INDEX_MODIFIED | GIT_STATUS_INDEX_DELETED | GIT_STATUS_INDEX_RENAMED | GIT_STATUS_INDEX_TYPECHANGE)) {
            new QListWidgetItem(path, m_stagedFilesList);
        }
    }
}

void ProjectWindow::onFileContextMenuRequested(const QPoint& pos)
{
    QListWidget* listWidget = qobject_cast<QListWidget*>(sender());
    if (!listWidget) return;

    QListWidgetItem* item = listWidget->itemAt(pos);
    if (!item) return;

    QMenu contextMenu(this);
    if (listWidget == m_unstagedFilesList) {
        contextMenu.addAction("Stage this file");
    } else {
        contextMenu.addAction("Unstage this file");
    }

    QAction* selectedAction = contextMenu.exec(listWidget->mapToGlobal(pos));
    if (!selectedAction) return;

    std::string path = item->text().toStdString();
    std::string error;

    if (selectedAction->text() == "Stage this file") {
        if (!m_gitBackend.stagePath(path, error)) {
             QMessageBox::warning(this, "Error", QString::fromStdString(error));
        }
    } else {
        if (!m_gitBackend.unstagePath(path, error)) {
            QMessageBox::warning(this, "Error", QString::fromStdString(error));
        }
    }
    refreshStatus();
}

void ProjectWindow::onStageAllClicked()
{
    std::string error;
    if (!m_gitBackend.stageAll(error)) {
        QMessageBox::warning(this, "Error", QString::fromStdString(error));
    }
    refreshStatus();
}

void ProjectWindow::onUnstageAllClicked()
{
    std::string error;
    if(!m_gitBackend.unstageAll(error)) {
        QMessageBox::warning(this, "Error", QString::fromStdString(error));
    }
    refreshStatus();
}

void ProjectWindow::onCommitClicked()
{
    QString message = m_commitMessageInput->toPlainText().trimmed();
    if (message.isEmpty()) {
        QMessageBox::warning(this, "Commit Failed", "Please enter a commit message.");
        return;
    }

    if (m_stagedFilesList->count() == 0) {
        QMessageBox::warning(this, "Commit Failed", "There are no staged files to commit.");
        return;
    }

    std::string name = m_networkManager->getMyUsername().toStdString();
    std::string email = name + "@syncit.p2p";
    std::string error;

    if (m_gitBackend.commitChanges(message.toStdString(), name, email, error)) {
        QMessageBox::information(this, "Success", "Commit created successfully.");
        m_commitMessageInput->clear();
        refreshStatus();
        loadCommitLog();
    } else {
        QMessageBox::critical(this, "Commit Failed", QString::fromStdString(error));
    }
}