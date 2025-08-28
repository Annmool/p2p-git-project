#include "project_window.h"
#include "mainwindow.h" // Required for qobject_cast in constructor
#include "custom_dialogs.h"

#include <QDesktopServices>
#include <QStandardPaths>
#include <QDir>
#include <QProcess>
#include <QInputDialog>
#include <QTimer>
#include <QStyle>
#include <QFileInfo>
#include <QUrl>
#include <QSplitter>
#include <QMenu>
#include <QClipboard>
#include <QApplication>
#include <QDateTime>
#include <QTemporaryFile>
#include "info_dot.h"

// --- CommitWidget Implementation ---

// This is a test comment

CommitWidget::CommitWidget(const CommitInfo &info, QWidget *parent) : QWidget(parent)
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(4);
    mainLayout->setContentsMargins(10, 8, 10, 8);

    QHBoxLayout *headerLayout = new QHBoxLayout();
    QLabel *shaLabel = new QLabel(QString("<b>commit</b> <font color='#64748B'>%1</font>").arg(QString::fromStdString(info.sha)), this);
    shaLabel->setFont(QFont("monospace"));
    shaLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    QPushButton *copyShaButton = new QPushButton("Copy SHA", this);
    copyShaButton->setFixedSize(90, 28);
    copyShaButton->setProperty("commitSha", QString::fromStdString(info.sha));

    QPushButton *viewFilesButton = new QPushButton("View Files", this);
    viewFilesButton->setFixedSize(100, 28);
    viewFilesButton->setProperty("commitSha", QString::fromStdString(info.sha));

    headerLayout->addWidget(shaLabel);
    headerLayout->addStretch();
    headerLayout->addWidget(copyShaButton);
    headerLayout->addWidget(makeInfoDot("Copy the full commit ID (SHA-1) to your clipboard.", this));
    headerLayout->addWidget(viewFilesButton);

    QLabel *authorLabel = new QLabel(QString("<b>Author:</b> %1 <%2>").arg(QString::fromStdString(info.author_name).toHtmlEscaped(), QString::fromStdString(info.author_email).toHtmlEscaped()), this);
    authorLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    QLabel *dateLabel = new QLabel(QString("<b>Date:</b>   %1").arg(QString::fromStdString(info.date)), this);
    dateLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    QLabel *summaryLabel = new QLabel(QString::fromStdString(info.summary), this);
    summaryLabel->setWordWrap(true);
    summaryLabel->setStyleSheet("margin-left: 15px;");
    summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);

    mainLayout->addLayout(headerLayout);
    mainLayout->addWidget(authorLabel);
    mainLayout->addWidget(dateLabel);
    mainLayout->addWidget(summaryLabel);

    connect(viewFilesButton, &QPushButton::clicked, this, &CommitWidget::onButtonClicked);
    connect(copyShaButton, &QPushButton::clicked, this, [this, copyShaButton]()
            {
        const QString sha = copyShaButton->property("commitSha").toString();
        if (!sha.isEmpty())
        {
            QClipboard *cb = QApplication::clipboard();
            cb->setText(sha);
            CustomMessageBox::information(this, "Copied", QString("Commit ID copied:\n%1").arg(sha));
        } });
}

void CommitWidget::onButtonClicked()
{
    QPushButton *button = qobject_cast<QPushButton *>(sender());
    if (button)
    {
        emit viewFilesClicked(button->property("commitSha").toString());
    }
}

// --- ProjectWindow Implementation ---

ProjectWindow::ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent)
    : QMainWindow(parent),
      m_appId(appId),
      m_repoManager(repoManager),
      m_networkManager(networkManager)
{
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid())
    {
        CustomMessageBox::critical(this, "Error", "Could not find repository information for ID: " + appId);
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    setupUi();

    std::string error;
    if (!m_gitBackend.openRepository(m_repoInfo.localPath.toStdString(), error))
    {
        CustomMessageBox::critical(this, "Error", "Could not open repository:\n" + QString::fromStdString(error));
        close();
        return;
    }
    // After repository is open, ensure the Propose tab branch list is populated for collaborators
    if (!m_repoInfo.isOwner)
    {
        populateProposeBranches();
    }
    updateStatus();
    updateGroupMembers();

    connect(m_groupChatSendButton, &QPushButton::clicked, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_groupChatInput, &QLineEdit::returnPressed, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_addCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onAddCollaboratorClicked);
    connect(m_removeCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onRemoveCollaboratorClicked);
    connect(m_groupMembersList, &QListWidget::currentItemChanged, this, &ProjectWindow::onGroupMemberSelectionChanged);

    connect(this, &ProjectWindow::fetchBundleRequested, qobject_cast<MainWindow *>(parentWidget()), &MainWindow::handleFetchBundleRequest);
    connect(this, &ProjectWindow::proposeChangesRequested, qobject_cast<MainWindow *>(parentWidget()), &MainWindow::handleProposeChangesRequest);

    connect(m_refreshStatusButton, &QPushButton::clicked, this, &ProjectWindow::refreshStatus);
    connect(m_stageAllButton, &QPushButton::clicked, this, &ProjectWindow::onStageAllClicked);
    connect(m_unstageAllButton, &QPushButton::clicked, this, &ProjectWindow::onUnstageAllClicked);
    connect(m_commitButton, &QPushButton::clicked, this, &ProjectWindow::onCommitClicked);
    connect(m_unstagedFilesList, &QListWidget::customContextMenuRequested, this, &ProjectWindow::onFileContextMenuRequested);
    connect(m_stagedFilesList, &QListWidget::customContextMenuRequested, this, &ProjectWindow::onFileContextMenuRequested);

    // Load last 24 hours of chat history into the display
    if (m_repoManager && !m_repoInfo.ownerRepoAppId.isEmpty())
    {
        QList<ChatMessage> history = m_repoManager->getRecentChatMessages(m_repoInfo.ownerRepoAppId);
        QString my = m_networkManager ? m_networkManager->getMyUsername() : "";
        for (const ChatMessage &cm : history)
        {
            QString tsLocal = cm.timestamp.isValid() ? cm.timestamp.toLocalTime().toString("hh:mm:ss") : QDateTime::currentDateTime().toString("hh:mm:ss");
            QString formatted = QString("[%1] <b>%2:</b> %3")
                                    .arg(tsLocal)
                                    .arg(cm.sender == my ? "Me" : cm.sender.toHtmlEscaped())
                                    .arg(cm.text.toHtmlEscaped());
            m_groupChatDisplay->append(formatted);
        }
    }

    refreshStatus();
}

ProjectWindow::~ProjectWindow() {}

void ProjectWindow::showDiffForRange(const QString &commitA, const QString &commitB)
{
    m_commitAInput->setText(commitA);
    m_commitBInput->setText(commitB);
    onComputeDiffClicked();
    focusDiffsTab();
}

void ProjectWindow::focusDiffsTab()
{
    int idx = m_tabWidget->indexOf(m_diffsTab);
    if (idx >= 0)
    {
        m_tabWidget->setCurrentIndex(idx);
    }
}

QWidget *ProjectWindow::createChangesTab()
{
    QWidget *changesWidget = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(changesWidget);

    QSplitter *splitter = new QSplitter(Qt::Vertical, changesWidget);

    QWidget *stagingArea = new QWidget(splitter);
    QVBoxLayout *stagingLayout = new QVBoxLayout(stagingArea);
    stagingLayout->setContentsMargins(0, 0, 0, 0);

    QHBoxLayout *unstagedHeaderLayout = new QHBoxLayout();
    unstagedHeaderLayout->addWidget(new QLabel("<b>Unstaged Changes</b>"));
    unstagedHeaderLayout->addStretch();
    m_refreshStatusButton = new QPushButton("Refresh", stagingArea);
    m_refreshStatusButton->setObjectName("refreshStatusButton");
    unstagedHeaderLayout->addWidget(m_refreshStatusButton);
    unstagedHeaderLayout->addWidget(makeInfoDot("Update the change lists to reflect the current working directory.", stagingArea));
    m_stageAllButton = new QPushButton("Stage All", stagingArea);
    m_stageAllButton->setObjectName("stageAllButton");
    unstagedHeaderLayout->addWidget(m_stageAllButton);
    unstagedHeaderLayout->addWidget(makeInfoDot("Stage all changed files to include them in the next commit.", stagingArea));
    stagingLayout->addLayout(unstagedHeaderLayout);

    m_unstagedFilesList = new QListWidget(stagingArea);
    m_unstagedFilesList->setContextMenuPolicy(Qt::CustomContextMenu);
    stagingLayout->addWidget(m_unstagedFilesList);

    QHBoxLayout *stagedHeaderLayout = new QHBoxLayout();
    stagedHeaderLayout->addWidget(new QLabel("<b>Staged Changes (Index)</b>"));
    stagedHeaderLayout->addStretch();
    m_unstageAllButton = new QPushButton("Unstage All", stagingArea);
    m_unstageAllButton->setObjectName("unstageAllButton");
    stagedHeaderLayout->addWidget(m_unstageAllButton);
    stagedHeaderLayout->addWidget(makeInfoDot("Remove all files from the staging area; changes stay in your working tree.", stagingArea));
    stagingLayout->addLayout(stagedHeaderLayout);

    m_stagedFilesList = new QListWidget(stagingArea);
    m_stagedFilesList->setContextMenuPolicy(Qt::CustomContextMenu);
    stagingLayout->addWidget(m_stagedFilesList);

    splitter->addWidget(stagingArea);

    QWidget *commitArea = new QWidget(splitter);
    QVBoxLayout *commitLayout = new QVBoxLayout(commitArea);
    commitLayout->addWidget(new QLabel("<b>Commit Message</b>"));
    m_commitMessageInput = new QTextEdit(commitArea);
    m_commitMessageInput->setPlaceholderText("Enter a summary of your changes...");
    m_commitMessageInput->setMaximumHeight(100);
    commitLayout->addWidget(m_commitMessageInput);

    std::string branchName;
    m_commitButton = new QPushButton("Commit to " + QString::fromStdString(m_gitBackend.getCurrentBranch(branchName)), this);
    m_commitButton->setObjectName("commitButton");
    commitLayout->addWidget(m_commitButton);

    splitter->addWidget(commitArea);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);

    mainLayout->addWidget(splitter);
    return changesWidget;
}

QWidget *ProjectWindow::createProposeTab()
{
    QWidget *proposeWidget = new QWidget();
    QVBoxLayout *mainLayout = new QVBoxLayout(proposeWidget);

    // Branch selection
    QHBoxLayout *branchLayout = new QHBoxLayout();
    branchLayout->addWidget(new QLabel("<b>Propose to Branch:</b>"));
    m_targetBranchDropdown = new QComboBox(proposeWidget);
    branchLayout->addWidget(m_targetBranchDropdown, 1);
    mainLayout->addLayout(branchLayout);

    // Proposed files list and controls
    QHBoxLayout *fileButtonsLayout = new QHBoxLayout();
    m_addFilesButton = new QPushButton("Add Files...", proposeWidget);
    m_removeFilesButton = new QPushButton("Remove Selected", proposeWidget);
    fileButtonsLayout->addWidget(m_addFilesButton);
    fileButtonsLayout->addWidget(m_removeFilesButton);
    fileButtonsLayout->addStretch();
    mainLayout->addLayout(fileButtonsLayout);

    m_proposedFilesList = new QListWidget(proposeWidget);
    m_proposedFilesList->setSelectionMode(QAbstractItemView::ExtendedSelection);
    mainLayout->addWidget(m_proposedFilesList, 1);

    // Proposal message
    mainLayout->addWidget(new QLabel("<b>Proposal Message</b>"));
    m_proposalMessageInput = new QTextEdit(proposeWidget);
    m_proposalMessageInput->setPlaceholderText("Describe your proposed changes for the owner...");
    m_proposalMessageInput->setMaximumHeight(120);
    mainLayout->addWidget(m_proposalMessageInput);

    // Send button
    m_sendProposalButton = new QPushButton("Propose Changes", proposeWidget);
    mainLayout->addWidget(m_sendProposalButton);

    // Wire actions
    // m_addFilesButton handler below uses ExistingFiles dialog
    connect(m_addFilesButton, &QPushButton::clicked, this, [this]()
            {
        // Use CustomFileDialog in ExistingFiles mode for multi-select
        CustomFileDialog dlg(this, "Select Files to Propose", m_repoInfo.localPath);
        dlg.setFileMode(CustomFileDialog::ExistingFiles);
        if (dlg.exec() == QDialog::Accepted)
        {
            QStringList paths = dlg.selectedFiles();
            for (const QString &p : paths)
            {
                QString rel = QDir(m_repoInfo.localPath).relativeFilePath(p);
                if (rel.isEmpty() || rel.startsWith(".."))
                    continue;
                bool exists = false;
                for (int i = 0; i < m_proposedFilesList->count(); ++i)
                {
                    if (m_proposedFilesList->item(i)->text() == rel)
                    { exists = true; break; }
                }
                if (!exists)
                    m_proposedFilesList->addItem(rel);
            }
        } });
    connect(m_removeFilesButton, &QPushButton::clicked, this, [this]()
            {
        auto selected = m_proposedFilesList->selectedItems();
        for (QListWidgetItem *it : selected)
        {
            delete it;
        } });
    connect(m_sendProposalButton, &QPushButton::clicked, this, [this]()
            {
        if (m_repoInfo.isOwner)
        {
            CustomMessageBox::information(this, "Not Allowed", "Owners don't propose; commit directly.");
            return;
        }

        QString targetBranch = m_targetBranchDropdown->currentText().trimmed();
        if (targetBranch.isEmpty())
        {
            CustomMessageBox::warning(this, "Branch Required", "Please select a target branch.");
            return;
        }
        if (m_proposedFilesList->count() == 0)
        {
            CustomMessageBox::warning(this, "No Files", "Please add one or more files to include in your proposal.");
            return;
        }

        // Create a temporary commit with the selected files and bundle diff against owner's branch tip
        std::string err;
        // Save current HEAD for cleanup
        QString headBefore;
        {
            QProcess p; p.setWorkingDirectory(m_repoInfo.localPath);
            p.start("git", {"rev-parse", "HEAD"});
            if (p.waitForFinished(10000) && p.exitCode() == 0)
                headBefore = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
        }

        // Stage only selected files
        for (int i = 0; i < m_proposedFilesList->count(); ++i)
        {
            std::string rel = m_proposedFilesList->item(i)->text().toStdString();
            m_gitBackend.stagePath(rel, err);
        }

        // Create a throwaway commit on a temp branch
        QString proposer = m_networkManager->getMyUsername();
        QString tempBranch = QString("syncit/proposal/%1/%2").arg(proposer, QString::number(QDateTime::currentMSecsSinceEpoch()));
        QProcess g;
        g.setWorkingDirectory(m_repoInfo.localPath);
        g.start("git", {"checkout", "-b", tempBranch});
        if (!g.waitForFinished(20000) || g.exitCode() != 0)
        {
            CustomMessageBox::critical(this, "Error", "Could not create temporary branch for proposal.");
            return;
        }
        std::string name = proposer.toStdString();
        std::string email = name + "@syncit.p2p";
        std::string cmErr;
        QString message = m_proposalMessageInput->toPlainText();
        if (!m_gitBackend.commitChanges((QString("Proposal: ") + message).toStdString(), name, email, cmErr))
        {
            CustomMessageBox::critical(this, "Error", QString("Failed to create proposal commit: %1").arg(QString::fromStdString(cmErr)));
            // Try to checkout back
            if (!headBefore.isEmpty())
            {
                QProcess chk; chk.setWorkingDirectory(m_repoInfo.localPath); chk.start("git", {"checkout", headBefore}); chk.waitForFinished(10000);
            }
            return;
        }

        // Build a diff bundle tempBranch ^ targetBranch
        QTemporaryFile tempBundle(QDir::tempPath() + "/proposal_XXXXXX.zip");
        tempBundle.setAutoRemove(false);
        if (!tempBundle.open())
        {
            CustomMessageBox::critical(this, "Error", "Failed to create temporary bundle file.");
            return;
        }
        QString bundlePath = tempBundle.fileName();
        tempBundle.close();

        if (!m_gitBackend.createDiffArchive(bundlePath.toStdString(), tempBranch.toStdString(), targetBranch.toStdString(), cmErr))
        {
            QFile::remove(bundlePath);
            CustomMessageBox::warning(this, "No Changes", QString::fromStdString(cmErr).isEmpty() ? "No differences to propose." : QString::fromStdString(cmErr));
        }
        else
        {
            // Notify owner and send bundle over TCP (work when disconnected too)
            m_networkManager->sendProposalToPeer(m_repoInfo.ownerPeerId, m_repoInfo.displayName, targetBranch, bundlePath, message);
            CustomMessageBox::information(this, "Proposal Sent", "Your proposed changes have been sent to the owner.");
        }

        // Cleanup: checkout back and delete temp branch
        if (!headBefore.isEmpty())
        {
            QProcess chk; chk.setWorkingDirectory(m_repoInfo.localPath); chk.start("git", {"checkout", headBefore}); chk.waitForFinished(10000);
        }
        QProcess del; del.setWorkingDirectory(m_repoInfo.localPath); del.start("git", {"branch", "-D", tempBranch}); del.waitForFinished(10000);
        // Unstage everything after operation
        std::string unErr; m_gitBackend.unstageAll(unErr); });

    return proposeWidget;
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
    m_proposeTab = createProposeTab();
    m_historyTab = new QWidget();
    m_collabTab = new QWidget();
    m_diffsTab = createDiffsTab();

    // Setup History Tab
    QVBoxLayout *historyLayout = new QVBoxLayout(m_historyTab);
    m_statusLabel = new QLabel(this);
    m_statusLabel->setObjectName("statusLabel");
    historyLayout->addWidget(m_statusLabel);
    m_commitLogDisplay = new QListWidget(this);
    m_commitLogDisplay->setAlternatingRowColors(true);
    historyLayout->addWidget(m_commitLogDisplay, 1);
    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_refreshButton = new QPushButton("Refresh", this);
    m_refreshButton->setObjectName("refreshButton");
    m_fetchButton = new QPushButton("Fetch", this);
    m_fetchButton->setObjectName("fetchButton");
    m_proposeChangesButton = new QPushButton("Propose Changes", this);
    m_proposeChangesButton->setObjectName("proposeChangesButton");
    m_branchComboBox = new QComboBox(this);
    m_checkoutButton = new QPushButton("Checkout Branch", this);
    // Hide Fetch and Propose Changes buttons in History tab per requirement
    m_fetchButton->setVisible(false);
    m_proposeChangesButton->setVisible(false);
    controlsLayout->addWidget(m_fetchButton);
    controlsLayout->addWidget(m_proposeChangesButton);
    controlsLayout->addStretch();
    controlsLayout->addWidget(m_refreshButton);
    controlsLayout->addWidget(m_branchComboBox, 1);
    controlsLayout->addWidget(m_checkoutButton);
    historyLayout->addLayout(controlsLayout);
    connect(m_refreshButton, &QPushButton::clicked, this, &ProjectWindow::refreshAll);
    connect(m_fetchButton, &QPushButton::clicked, this, &ProjectWindow::onFetchClicked);
    connect(m_proposeChangesButton, &QPushButton::clicked, this, &ProjectWindow::onProposeChangesClicked);
    connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    connect(m_branchComboBox, &QComboBox::currentTextChanged, this, &ProjectWindow::viewRemoteBranchHistory);

    // Add tabs to tab widget
    // Only owners see the Changes tab. Collaborators see the Propose tab.
    if (m_repoInfo.isOwner)
        m_tabWidget->addTab(m_changesTab, "Changes");
    else
        m_tabWidget->addTab(m_proposeTab, "Propose");
    m_tabWidget->addTab(m_historyTab, "History");
    m_tabWidget->addTab(m_collabTab, "Collaboration");
    m_tabWidget->addTab(m_diffsTab, "Diffs");

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
    QHBoxLayout *chatInputLayout = new QHBoxLayout();
    m_groupChatInput = new QLineEdit(this);
    m_groupChatInput->setPlaceholderText("Type message to group...");
    m_groupChatSendButton = new QPushButton("Send");
    chatInputLayout->addWidget(m_groupChatInput, 1);
    chatInputLayout->addWidget(m_groupChatSendButton);
    collabLayout->addLayout(chatInputLayout);

    resize(800, 600);

    // Propose branches are populated after repo open in constructor
}

QWidget *ProjectWindow::createDiffsTab()
{
    QWidget *tab = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(tab);

    // Header inputs
    QHBoxLayout *header = new QHBoxLayout();
    QLabel *labelA = new QLabel("Commit A:", tab);
    m_commitAInput = new QLineEdit(tab);
    m_commitAInput->setPlaceholderText("e.g., abc123 or branch/tag");
    QLabel *labelB = new QLabel("Commit B:", tab);
    m_commitBInput = new QLineEdit(tab);
    m_commitBInput->setPlaceholderText("e.g., def456 or HEAD");
    m_swapCommitsButton = new QPushButton("Swap", tab);
    m_computeDiffButton = new QPushButton("Compute Diff", tab);
    header->addWidget(labelA);
    header->addWidget(m_commitAInput, 1);
    header->addSpacing(8);
    header->addWidget(labelB);
    header->addWidget(m_commitBInput, 1);
    header->addSpacing(8);
    header->addWidget(m_swapCommitsButton);
    header->addWidget(m_computeDiffButton);
    layout->addLayout(header);

    // Status label
    m_diffStatusLabel = new QLabel(tab);
    m_diffStatusLabel->setWordWrap(true);
    setDiffStatus("Enter two commit IDs or refs to compare. Shows changes from A..B (A exclusive, B inclusive).", QColor("#666"));
    layout->addWidget(m_diffStatusLabel);

    // Split: left file list, right diff viewer
    QSplitter *split = new QSplitter(Qt::Horizontal, tab);
    m_diffFilesList = new QListWidget(split);
    m_diffFilesList->setSelectionMode(QAbstractItemView::SingleSelection);
    m_diffViewer = new QTextEdit(split);
    m_diffViewer->setReadOnly(true);
    split->addWidget(m_diffFilesList);
    split->addWidget(m_diffViewer);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 3);
    layout->addWidget(split, 1);

    // Wire signals
    connect(m_swapCommitsButton, &QPushButton::clicked, this, &ProjectWindow::onSwapCommitsClicked);
    connect(m_computeDiffButton, &QPushButton::clicked, this, &ProjectWindow::onComputeDiffClicked);
    connect(m_diffFilesList, &QListWidget::itemClicked, this, &ProjectWindow::onDiffFileSelected);

    return tab;
}

void ProjectWindow::setDiffStatus(const QString &text, const QColor &color)
{
    m_diffStatusLabel->setText(text);
    QPalette pal = m_diffStatusLabel->palette();
    pal.setColor(QPalette::WindowText, color);
    m_diffStatusLabel->setPalette(pal);
}

void ProjectWindow::populateProposeBranches()
{
    if (m_repoInfo.isOwner || !m_targetBranchDropdown)
        return;
    m_targetBranchDropdown->clear();
    std::string err;
    auto branches = m_gitBackend.listBranches(GitBackend::BranchType::ALL, err);
    for (const auto &b : branches)
    {
        QString qs = QString::fromStdString(b);
        if (qs.endsWith("/HEAD"))
            continue;
        m_targetBranchDropdown->addItem(qs);
    }
    // Select current branch if present
    QString cur = QString::fromStdString(m_gitBackend.getCurrentBranch(err));
    int idx = m_targetBranchDropdown->findText(cur);
    if (idx >= 0)
        m_targetBranchDropdown->setCurrentIndex(idx);
}

QString ProjectWindow::runGit(const QStringList &args, int timeoutMs, int *exitCodeOut)
{
    QProcess p;
    p.setWorkingDirectory(m_repoInfo.localPath);
    p.start("git", args);
    if (!p.waitForFinished(timeoutMs))
        return QString();
    if (exitCodeOut)
        *exitCodeOut = p.exitCode();
    return QString::fromUtf8(p.readAllStandardOutput());
}

bool ProjectWindow::verifyCommit(const QString &shaOrRef, QString &normalizedSha, QString &errorOut)
{
    if (shaOrRef.trimmed().isEmpty())
    {
        errorOut = "Commit/Ref is empty";
        return false;
    }
    // Resolve to full SHA
    int ec = 0;
    QString out = runGit({"rev-parse", shaOrRef}, 10000, &ec).trimmed();
    if (ec != 0 || out.isEmpty())
    {
        errorOut = QString("Could not resolve '%1' to a commit").arg(shaOrRef);
        return false;
    }
    normalizedSha = out;
    return true;
}

bool ProjectWindow::checkRelatedHistories(const QString &a, const QString &b)
{
    // Check if there is any merge-base between the two commits.
    int ec = 0;
    QString base = runGit({"merge-base", a, b}, 10000, &ec).trimmed();
    return (ec == 0 && !base.isEmpty());
}

void ProjectWindow::onSwapCommitsClicked()
{
    QString a = m_commitAInput->text();
    QString b = m_commitBInput->text();
    m_commitAInput->setText(b);
    m_commitBInput->setText(a);
}

void ProjectWindow::onComputeDiffClicked()
{
    m_diffFilesList->clear();
    m_diffViewer->clear();

    QString aIn = m_commitAInput->text().trimmed();
    QString bIn = m_commitBInput->text().trimmed();
    QString a, b, err;

    if (!verifyCommit(aIn, a, err))
    {
        setDiffStatus(QString("A: %1").arg(err), Qt::red);
        return;
    }
    if (!verifyCommit(bIn, b, err))
    {
        setDiffStatus(QString("B: %1").arg(err), Qt::red);
        return;
    }

    m_diffCommitA = a;
    m_diffCommitB = b;

    // Check if histories are related
    if (!checkRelatedHistories(a, b))
    {
        setDiffStatus("These commits do not share history. Showing diff is not meaningful.", QColor("#B58900"));
        return;
    }

    // List changed files between a..b
    int ec = 0;
    QString nameStatus = runGit({"diff", "--name-status", a + ".." + b}, 60000, &ec);
    if (ec != 0)
    {
        setDiffStatus("Failed to compute diff (name-status).", Qt::red);
        return;
    }

    QStringList lines = nameStatus.split('\n', Qt::SkipEmptyParts);
    if (lines.isEmpty())
    {
        setDiffStatus("No changes between the selected commits.", QColor("#2AA198"));
        return;
    }

    setDiffStatus(QString("%1 files changed between %2..%3").arg(lines.size()).arg(a.left(7)).arg(b.left(7)), QColor("#444"));

    for (const QString &line : lines)
    {
        // Format: "M\tpath" or "R100\told\tnew" etc.
        QStringList parts = line.split('\t');
        if (parts.isEmpty())
            continue;
        QString status = parts[0];
        QString display;
        QString filePath;
        if (status.startsWith('R'))
        {
            // rename: Rxxx\told\tnew
            if (parts.size() >= 3)
            {
                display = QString("Renamed: %1 → %2").arg(parts[1], parts[2]);
                filePath = parts[2];
            }
        }
        else if (status == "A" && parts.size() >= 2)
        {
            display = QString("Added: %1").arg(parts[1]);
            filePath = parts[1];
        }
        else if (status == "D" && parts.size() >= 2)
        {
            display = QString("Deleted: %1").arg(parts[1]);
            filePath = parts[1];
        }
        else if (parts.size() >= 2)
        {
            display = QString("Modified: %1").arg(parts[1]);
            filePath = parts[1];
        }

        if (!filePath.isEmpty())
        {
            QListWidgetItem *item = new QListWidgetItem(display, m_diffFilesList);
            item->setData(Qt::UserRole, filePath);
        }
    }
}

void ProjectWindow::onDiffFileSelected(QListWidgetItem *item)
{
    if (!item)
        return;
    QString path = item->data(Qt::UserRole).toString();
    if (path.isEmpty() || m_diffCommitA.isEmpty() || m_diffCommitB.isEmpty())
        return;

    // Show unified diff for a single file
    int ec = 0;
    QString diff = runGit({"diff", m_diffCommitA + ".." + m_diffCommitB, "--", path}, 60000, &ec);
    if (ec != 0)
    {
        m_diffViewer->setPlainText("Failed to load diff for this file.");
        return;
    }
    if (diff.trimmed().isEmpty())
    {
        m_diffViewer->setPlainText("No textual changes (binary or metadata-only change).");
        return;
    }
    m_diffViewer->setPlainText(diff);
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
    if (!m_networkManager)
        return;

    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid())
        return;

    m_groupMembersList->clear();
    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();

    QStringList members = m_repoInfo.groupMembers;
    members.removeDuplicates();
    members.sort();

    for (const QString &member : members)
    {
        QListWidgetItem *item = new QListWidgetItem(m_groupMembersList);
        bool isConnected = connectedPeers.contains(member) || (member == m_networkManager->getMyUsername());

        item->setText(member + (member == m_repoInfo.ownerPeerId ? " (owner)" : ""));
        QIcon statusIcon(isConnected ? QIcon(":/icons/check-circle-green.svg") : QIcon(":/icons/x-circle-red.svg"));
        item->setIcon(statusIcon);
        item->setForeground(isConnected ? palette().color(QPalette::Text) : QColor("grey"));
        item->setData(Qt::UserRole, member);
    }

    m_addCollaboratorButton->setVisible(m_repoInfo.isOwner);
    m_removeCollaboratorButton->setVisible(m_repoInfo.isOwner);
    onGroupMemberSelectionChanged();
}

void ProjectWindow::displayGroupMessage(const QString &peerId, const QString &message)
{
    QString myUsername = m_networkManager ? m_networkManager->getMyUsername() : "";
    // Display with timestamp
    QString ts = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString formattedMessage = QString("[%1] <b>%2:</b> %3")
                                   .arg(ts)
                                   .arg(peerId == myUsername ? "Me" : peerId.toHtmlEscaped())
                                   .arg(message.toHtmlEscaped());
    m_groupChatDisplay->append(formattedMessage);
}

void ProjectWindow::onSendGroupMessageClicked()
{
    QString message = m_groupChatInput->text().trimmed();
    if (message.isEmpty())
        return;
    emit groupMessageSent(m_repoInfo.ownerRepoAppId, message);
    m_groupChatInput->clear();
}

// Load last 24h chat history on construction end

void ProjectWindow::onAddCollaboratorClicked()
{
    // Owner: show multi-select dialog for connected peers not already in group
    if (!m_repoInfo.isOwner || !m_networkManager)
        return;
    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds();
    QStringList eligiblePeers;
    for (const auto &peer : connectedPeers)
    {
        if (!m_repoInfo.groupMembers.contains(peer))
            eligiblePeers.append(peer);
    }
    if (eligiblePeers.isEmpty())
    {
        CustomMessageBox::information(this, "No Eligible Peers", "No new connected peers are available to add.");
        return;
    }
    // Let MainWindow handle the actual peer selection and processing
    emit addCollaboratorRequested(m_appId);
}

void ProjectWindow::onRemoveCollaboratorClicked()
{
    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();
    if (!selectedItem)
        return;
    QString peerIdToRemove = selectedItem->data(Qt::UserRole).toString();
    emit removeCollaboratorRequested(m_appId, peerIdToRemove);
}

void ProjectWindow::onGroupMemberSelectionChanged()
{
    bool canRemove = false;
    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();
    if (selectedItem && m_repoInfo.isOwner)
    {
        QString peerId = selectedItem->data(Qt::UserRole).toString();
        if (peerId != m_repoInfo.ownerPeerId)
        {
            canRemove = true;
        }
    }
    m_removeCollaboratorButton->setEnabled(canRemove);
}

void ProjectWindow::refreshAll()
{
    loadBranchList();
    loadCommitLog(m_branchComboBox->currentText().toStdString());
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
    if (branchName.isEmpty())
        return;
    std::string error;
    if (m_gitBackend.checkoutBranch(branchName.toStdString(), error))
    {
        CustomMessageBox::information(this, "Success", "Checked out branch: " + branchName);
        updateStatus();
    }
    else
    {
        CustomMessageBox::warning(this, "Checkout Failed", QString::fromStdString(error));
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

    if (!error.empty() && log.empty())
    {
        QListWidgetItem *item = new QListWidgetItem(m_commitLogDisplay);
        item->setText("Error: " + QString::fromStdString(error));
        item->setForeground(Qt::red);
        return;
    }
    if (log.empty())
    {
        new QListWidgetItem("No commits found for this reference.", m_commitLogDisplay);
        return;
    }
    for (const auto &commit : log)
    {
        QListWidgetItem *item = new QListWidgetItem(m_commitLogDisplay);
        CommitWidget *commitWidget = new CommitWidget(commit, m_commitLogDisplay);
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
    for (const auto &branch : branches)
    {
        if (QString::fromStdString(branch).endsWith("/HEAD"))
            continue;
        m_branchComboBox->addItem(QString::fromStdString(branch));
    }
    std::string currentBranch = m_gitBackend.getCurrentBranch(error);
    int index = m_branchComboBox->findText(QString::fromStdString(currentBranch));
    if (index != -1)
    {
        m_branchComboBox->setCurrentIndex(index);
    }
}

void ProjectWindow::onViewFilesClicked(const QString &sha)
{
    if (sha.isEmpty())
    {
        CustomMessageBox::warning(this, "Error", "Could not retrieve commit SHA.");
        return;
    }
    QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) +
                       "/SyncIt_View/" + QFileInfo(m_repoInfo.localPath).fileName() + "_" + sha.left(7);
    QDir tempDir(tempPath);
    if (tempDir.exists())
    {
        QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
        return;
    }
    if (!tempDir.mkpath("."))
    {
        CustomMessageBox::critical(this, "Error", "Could not create temporary directory to view files.");
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
    if (!gitProcess.waitForFinished(-1) || !tarProcess.waitForFinished(-1))
    {
        CustomMessageBox::critical(this, "Checkout Failed", "Could not archive and extract the specific commit.");
        tempDir.removeRecursively();
        return;
    }
    CustomMessageBox::information(this, "Opening Files",
                                  QString("Checked out commit %1 in a temporary folder.\n\nPath: %2\n\nThis folder can be safely deleted when you are done.")
                                      .arg(sha.left(7), tempPath));
    QDesktopServices::openUrl(QUrl::fromLocalFile(tempPath));
}

void ProjectWindow::onFetchClicked()
{
    if (m_repoInfo.isOwner)
    {
        CustomMessageBox::information(this, "Fetch", "You are the owner of this repository. There is no remote to fetch from.");
        return;
    }
    m_fetchButton->setEnabled(false);
    m_fetchButton->setText("Fetching...");
    emit fetchBundleRequested(m_repoInfo.ownerPeerId, m_repoInfo.displayName);
}

void ProjectWindow::onProposeChangesClicked()
{
    if (m_repoInfo.isOwner)
    {
        CustomMessageBox::information(this, "Action Not Available", "You are the owner. You commit directly, you don't need to propose changes.");
        return;
    }
    std::string error;
    std::string currentBranch = m_gitBackend.getCurrentBranch(error);
    if (currentBranch.empty() || currentBranch.rfind("[Detached HEAD", 0) == 0)
    {
        CustomMessageBox::warning(this, "Cannot Propose", "You must be on a branch to propose changes.");
        return;
    }
    m_proposeChangesButton->setEnabled(false);
    m_proposeChangesButton->setText("Bundling...");
    // The bundle creation and sending is handled within the Propose tab's button now.
    // This is a legacy button from the History tab that is now hidden.
    // To be safe, we can emit the main signal if this is ever clicked.
    emit proposeChangesRequested(m_repoInfo.ownerPeerId, m_repoInfo.displayName, QString::fromStdString(currentBranch));
}

void ProjectWindow::handleFetchBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message)
{
    m_fetchButton->setEnabled(true);
    m_fetchButton->setText("Fetch");
    if (!success)
    {
        CustomMessageBox::warning(this, "Fetch Failed", QString("Could not retrieve updates from owner: %1").arg(message));
        QFile::remove(localBundlePath);
        return;
    }
    std::string error;
    if (m_gitBackend.fetchFromBundle(localBundlePath.toStdString(), error))
    {
        CustomMessageBox::information(this, "Fetch Successful", "Successfully fetched updates from the owner.");
        loadBranchList();
    }
    else
    {
        CustomMessageBox::warning(this, "Fetch Failed", QString("Could not apply updates from bundle:\n%1").arg(QString::fromStdString(error)));
    }
    QFile::remove(localBundlePath);
}

void ProjectWindow::refreshStatus()
{
    m_unstagedFilesList->clear();
    m_stagedFilesList->clear();

    std::string error;
    std::vector<FileStatus> statuses = m_gitBackend.getRepositoryStatus(error);

    if (!error.empty())
    {
        CustomMessageBox::warning(this, "Status Error", QString::fromStdString(error));
        return;
    }

    for (const auto &fs : statuses)
    {
        QString path = QString::fromStdString(fs.path);
        if (fs.git_status & (GIT_STATUS_WT_NEW | GIT_STATUS_WT_MODIFIED | GIT_STATUS_WT_DELETED | GIT_STATUS_WT_TYPECHANGE | GIT_STATUS_WT_RENAMED))
        {
            new QListWidgetItem(path, m_unstagedFilesList);
        }
        if (fs.git_status & (GIT_STATUS_INDEX_NEW | GIT_STATUS_INDEX_MODIFIED | GIT_STATUS_INDEX_DELETED | GIT_STATUS_INDEX_RENAMED | GIT_STATUS_INDEX_TYPECHANGE))
        {
            new QListWidgetItem(path, m_stagedFilesList);
        }
    }
}

void ProjectWindow::onFileContextMenuRequested(const QPoint &pos)
{
    QListWidget *listWidget = qobject_cast<QListWidget *>(sender());
    if (!listWidget)
        return;

    QListWidgetItem *item = listWidget->itemAt(pos);
    if (!item)
        return;

    QMenu contextMenu(this);
    if (listWidget == m_unstagedFilesList)
    {
        contextMenu.addAction("Stage this file");
    }
    else
    {
        contextMenu.addAction("Unstage this file");
    }

    QAction *selectedAction = contextMenu.exec(listWidget->mapToGlobal(pos));
    if (!selectedAction)
        return;

    std::string path = item->text().toStdString();
    std::string error;

    if (selectedAction->text() == "Stage this file")
    {
        if (!m_gitBackend.stagePath(path, error))
        {
            CustomMessageBox::warning(this, "Error", QString::fromStdString(error));
        }
    }
    else
    {
        if (!m_gitBackend.unstagePath(path, error))
        {
            CustomMessageBox::warning(this, "Error", QString::fromStdString(error));
        }
    }
    refreshStatus();
}

void ProjectWindow::onStageAllClicked()
{
    std::string error;
    if (!m_gitBackend.stageAll(error))
    {
        CustomMessageBox::warning(this, "Error", QString::fromStdString(error));
    }
    refreshStatus();
}

void ProjectWindow::onUnstageAllClicked()
{
    std::string error;
    if (!m_gitBackend.unstageAll(error))
    {
        CustomMessageBox::warning(this, "Error", QString::fromStdString(error));
    }
    refreshStatus();
}

void ProjectWindow::onCommitClicked()
{
    QString message = m_commitMessageInput->toPlainText().trimmed();
    if (message.isEmpty())
    {
        CustomMessageBox::warning(this, "Commit Failed", "Please enter a commit message.");
        return;
    }

    if (m_stagedFilesList->count() == 0)
    {
        CustomMessageBox::warning(this, "Commit Failed", "There are no staged files to commit.");
        return;
    }

    std::string name = m_networkManager->getMyUsername().toStdString();
    std::string email = name + "@syncit.p2p";
    std::string error;

    if (m_gitBackend.commitChanges(message.toStdString(), name, email, error))
    {
        CustomMessageBox::information(this, "Success", "Commit created successfully.");
        m_commitMessageInput->clear();
        refreshStatus();
        loadCommitLog();
    }
    else
    {
        CustomMessageBox::critical(this, "Commit Failed", QString::fromStdString(error));
    }
}