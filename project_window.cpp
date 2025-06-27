#include "project_window.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QLabel>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>
#include <QTabWidget>
#include <QListWidget>
#include <QLineEdit>
#include <QStyle>           // Added for icons
#include <QInputDialog>     // Added for add collaborator dialog
#include <QTimer>           // Added for singleShot close
#include <QCoreApplication> // Added for processEvents (optional cleanup)

ProjectWindow::ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent)
    : QMainWindow(parent),
      m_appId(appId),                  // Store the local appId
      m_repoManager(repoManager),      // Store pointer (NOT owned)
      m_networkManager(networkManager) // Store pointer (NOT owned)
{
    // Ensure managers are valid
    if (!m_repoManager || !m_networkManager)
    {
        qCritical() << "ProjectWindow initialized without valid managers.";
        QMessageBox::critical(this, "Fatal Error", "ProjectWindow initialized without valid managers.");
        QTimer::singleShot(0, this, &QWidget::close); // Close async
        return;
    }

    // Retrieve the latest repository info using the local appId
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid()) // Use the isValid check from the struct
    {
        qCritical() << "ProjectWindow initialized for invalid repo appId:" << appId;
        QMessageBox::critical(this, "Error", "Could not find repository information for ID: " + appId);
        QTimer::singleShot(0, this, &QWidget::close); // Close async
        return;
    }

    setupUi(); // Setup the UI elements

    std::string error;
    // Open the repository using the GitBackend instance owned by this window
    if (!m_gitBackend.openRepository(m_repoInfo.localPath.toStdString(), error))
    {
        qCritical() << "Failed to open git repo for ProjectWindow:" << m_repoInfo.localPath << "Error:" << QString::fromStdString(error);
        QMessageBox::critical(this, "Error", "Could not open repository:\n" + m_repoInfo.localPath + "\nError: " + QString::fromStdString(error));
        QTimer::singleShot(0, this, &QWidget::close); // Close async
        return;
    }

    // Set window title based on display name
    setWindowTitle("Project: " + m_repoInfo.displayName);

    // Initial UI updates
    updateStatus();       // Refresh branch/commit info display, ownership, visibility
    updateGroupMembers(); // Refresh member list and status icons

    // Connect signals for History Tab controls (already in setupUi)
    // connect(m_refreshLogButton, &QPushButton::clicked, this, &ProjectWindow::refreshLog);
    // connect(m_refreshBranchesButton, &QPushButton::clicked, this, &ProjectWindow::refreshBranches);
    // connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    // connect(m_branchComboBox, QOverload<const QString &>::of(&QComboBox::currentTextChanged), this, &ProjectWindow::viewRemoteBranchHistory);

    // Connect signals for Collaboration Tab controls
    connect(m_groupChatSendButton, &QPushButton::clicked, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_groupChatInput, &QLineEdit::returnPressed, this, &ProjectWindow::onSendGroupMessageClicked); // Send on Enter key
    connect(m_addCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onAddCollaboratorClicked);
    connect(m_removeCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onRemoveCollaboratorClicked);
    connect(m_groupMembersList, &QListWidget::currentItemChanged, this, &ProjectWindow::onGroupMemberSelectionChanged);

    // Set initial state of collaborator buttons based on ownership
    bool isOwner = m_repoInfo.isOwner;               // Use the new isOwner flag from struct
    m_addCollaboratorButton->setVisible(isOwner);    // Hide if not owner
    m_removeCollaboratorButton->setVisible(isOwner); // Hide if not owner
    m_removeCollaboratorButton->setEnabled(false);   // Initially disabled
}

ProjectWindow::~ProjectWindow()
{
    // m_gitBackend instance is a member, its destructor will be called automatically.
    // Managers (m_repoManager, m_networkManager) are NOT owned by this window.
    // No need to close repo explicitly here, GitBackend destructor handles it.
    qDebug() << "ProjectWindow for" << m_appId << "destructor called.";
}

void ProjectWindow::setupUi()
{
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    m_tabWidget = new QTabWidget(this);
    mainLayout->addWidget(m_tabWidget);

    // --- History Tab ---
    m_historyTab = new QWidget();
    QVBoxLayout *historyLayout = new QVBoxLayout(m_historyTab);

    m_statusLabel = new QLabel(this);
    m_statusLabel->setWordWrap(true);
    historyLayout->addWidget(m_statusLabel);

    m_commitLogDisplay = new QTextEdit(this);
    m_commitLogDisplay->setReadOnly(true);
    m_commitLogDisplay->setFontFamily("monospace");
    m_commitLogDisplay->document()->setIndentWidth(20); // Set indent for log entries
    historyLayout->addWidget(m_commitLogDisplay, 1);

    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_refreshLogButton = new QPushButton("Refresh Log", this);
    m_branchComboBox = new QComboBox(this);
    m_refreshBranchesButton = new QPushButton("Refresh Branches", this);
    m_checkoutButton = new QPushButton("Checkout / View History", this);
    controlsLayout->addWidget(m_refreshLogButton);
    controlsLayout->addWidget(m_branchComboBox, 1);
    controlsLayout->addWidget(m_refreshBranchesButton);
    controlsLayout->addWidget(m_checkoutButton);
    historyLayout->addLayout(controlsLayout);

    // Connect signals for History Tab controls
    connect(m_refreshLogButton, &QPushButton::clicked, this, &ProjectWindow::refreshLog);
    connect(m_refreshBranchesButton, &QPushButton::clicked, this, &ProjectWindow::refreshBranches);
    connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    connect(m_branchComboBox, QOverload<const QString &>::of(&QComboBox::currentTextChanged), this, &ProjectWindow::viewRemoteBranchHistory);

    // --- Collaboration Tab ---
    m_collabTab = new QWidget();
    QVBoxLayout *collabLayout = new QVBoxLayout(m_collabTab);

    collabLayout->addWidget(new QLabel("<b>Group Members:</b>"));
    m_groupMembersList = new QListWidget();
    m_groupMembersList->setMaximumHeight(120);
    collabLayout->addWidget(m_groupMembersList);

    // Add Add/Remove Collaborator buttons
    QHBoxLayout *collabButtonLayout = new QHBoxLayout();
    m_addCollaboratorButton = new QPushButton("Add Collaborator...", this);
    m_removeCollaboratorButton = new QPushButton("Remove Collaborator", this);
    collabButtonLayout->addWidget(m_addCollaboratorButton);
    collabButtonLayout->addWidget(m_removeCollaboratorButton);
    collabLayout->addLayout(collabButtonLayout);

    collabLayout->addWidget(new QLabel("<b>Group Chat:</b>"));
    m_groupChatDisplay = new QTextEdit();
    m_groupChatDisplay->setReadOnly(true);
    m_groupChatDisplay->setFontFamily("monospace"); // Monospace font for chat log
    m_groupChatDisplay->setWordWrapMode(QTextOption::WordWrap);
    m_groupChatDisplay->setStyleSheet("QTextEdit { background-color: #f8f8f8; }"); // Light background for chat
    collabLayout->addWidget(m_groupChatDisplay, 1);                                // Give chat display stretch factor

    QHBoxLayout *chatInputLayout = new QHBoxLayout();
    m_groupChatInput = new QLineEdit();
    m_groupChatInput->setPlaceholderText("Type message to group...");
    m_groupChatSendButton = new QPushButton("Send");
    chatInputLayout->addWidget(m_groupChatInput, 1); // Give input stretch factor
    chatInputLayout->addWidget(m_groupChatSendButton);
    collabLayout->addLayout(chatInputLayout);

    // Connect signals for Collaboration Tab controls (already done in constructor)
    // connect(m_groupChatSendButton, &QPushButton::clicked, this, &ProjectWindow::onSendGroupMessageClicked);
    // connect(m_groupChatInput, &QLineEdit::returnPressed, this, &ProjectWindow::onSendGroupMessageClicked);
    // connect(m_addCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onAddCollaboratorClicked);
    // connect(m_removeCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onRemoveCollaboratorClicked);
    // connect(m_groupMembersList, &QListWidget::currentItemChanged, this, &ProjectWindow::onGroupMemberSelectionChanged);

    // --- Add tabs to widget ---
    m_tabWidget->addTab(m_historyTab, "History");
    m_tabWidget->addTab(m_collabTab, "Collaboration");

    resize(800, 600); // Default window size
}

void ProjectWindow::updateStatus()
{
    // Refresh the repository info from the manager in case visibility/collaborators changed
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid()) // Use the isValid check from the struct
    {
        m_statusLabel->setText("<font color='red'>Repository information not found!</font>");
        m_commitLogDisplay->clear();
        m_branchComboBox->clear();
        m_branchComboBox->setEnabled(false);
        m_checkoutButton->setEnabled(false);
        return;
    }

    std::string error;
    std::string branch = m_gitBackend.getCurrentBranch(error); // Get current branch via this window's backend

    // Use HTML formatting for the status label
    QString statusHtml = QString("<b>Local Path:</b> %1<br><b>Current Branch:</b> %2").arg(m_repoInfo.localPath.toHtmlEscaped(), QString::fromStdString(branch).toHtmlEscaped());

    // Add ownership info
    statusHtml += QString("<br><b>Owner:</b> %1").arg(m_repoInfo.isOwner ? "You" : m_repoInfo.ownerPeerId.toHtmlEscaped());

    // Only show "Visibility" for repos *I* own
    if (m_repoInfo.isOwner)
    {
        statusHtml += QString("<br><b>Visibility (Your Share):</b> %1").arg(m_repoInfo.isPublic ? "Public" : "Private");
    }
    else
    {
        // For clones, mention who it was cloned from (ownerPeerId)
        // Status already shows owner, maybe add something about the group?
        // "Group ID: <OwnerAppId>"
        statusHtml += QString("<br><b>Group ID:</b> %1").arg(m_repoInfo.ownerRepoAppId);
    }

    m_statusLabel->setText(statusHtml);

    // Refresh branch list and commit log for the current branch
    loadBranchList();
    // After loading branch list, the current text changed signal might trigger loadCommitLog
    // If not, explicitly call it for the current branch if the combobox is empty initially
    if (m_branchComboBox->currentText().isEmpty())
    {
        loadCommitLog(branch); // Load log for the branch name returned by getCurrentBranch
    }
    // Otherwise, viewRemoteBranchHistory will be called by setting the index in loadBranchList
}

void ProjectWindow::updateGroupMembers()
{
    if (!m_networkManager || !m_repoManager)
        return;

    // Refresh the repository info to get the latest group member list
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid())
    {
        m_groupMembersList->clear();
        m_groupMembersList->addItem("<font color='red'>Repository info not found.</font>");
        // Also hide collaborator buttons if not owner
        bool isOwner = false; // Use the new isOwner flag from struct
        m_addCollaboratorButton->setVisible(isOwner);
        m_removeCollaboratorButton->setVisible(isOwner);
        m_removeCollaboratorButton->setEnabled(false);
        return;
    }

    m_groupMembersList->clear(); // Clear existing list items

    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds(); // Get list of currently connected peers
    QString myUsername = m_networkManager->getMyUsername();

    QStringList members = m_repoInfo.groupMembers; // Use the groupMembers list from the struct
    members.removeDuplicates();
    members.sort(); // Sort members alphabetically

    for (const QString &member : members)
    {
        QListWidgetItem *item = new QListWidgetItem(m_groupMembersList);

        bool isMe = (member == myUsername);
        bool isOwner = (member == m_repoInfo.ownerPeerId);          // Use ownerPeerId from struct
        bool isConnected = isMe || connectedPeers.contains(member); // Owner is always 'connected' locally

        item->setText(member + (isOwner ? " (owner)" : ""));                                                                                   // Append (owner) text
        item->setIcon(isConnected ? style()->standardIcon(QStyle::SP_DialogYesButton) : style()->standardIcon(QStyle::SP_DialogCancelButton)); // Set icon
        item->setForeground(isConnected ? palette().color(QPalette::Text) : QBrush(Qt::gray));                                                 // Set color (gray for offline)

        item->setData(Qt::UserRole, member); // Store the actual peerId in item data
    }

    // Set visibility of collaborator buttons based on ownership
    bool isLocalOwner = m_repoInfo.isOwner; // Use the new isOwner flag from struct
    m_addCollaboratorButton->setVisible(isLocalOwner);
    m_removeCollaboratorButton->setVisible(isLocalOwner);

    // Re-evaluate remove button state based on new list/selection (if any)
    onGroupMemberSelectionChanged();
}

void ProjectWindow::displayGroupMessage(const QString &peerId, const QString &message)
{
    if (!m_networkManager)
        return;
    QString myUsername = m_networkManager->getMyUsername();
    // Format message with sender name and escape HTML
    QString formattedMessage = QString("<b>%1:</b> %2")
                                   .arg(peerId == myUsername ? "Me" : peerId.toHtmlEscaped())
                                   .arg(message.toHtmlEscaped());
    m_groupChatDisplay->append(formattedMessage);
}

void ProjectWindow::onSendGroupMessageClicked()
{
    QString message = m_groupChatInput->text().trimmed();
    if (message.isEmpty())
        return;

    // Ensure we are a member of this repository group
    if (!m_repoManager || !m_networkManager)
        return;
    ManagedRepositoryInfo currentRepoInfo = m_repoManager->getRepositoryInfo(m_appId);
    // Check if myUsername is in the groupMembers list for this repo
    if (!currentRepoInfo.isValid() || !currentRepoInfo.groupMembers.contains(m_networkManager->getMyUsername()))
    {
        QMessageBox::warning(this, "Access Denied", "You are not a member of this repository group and cannot send messages.");
        m_groupChatInput->clear();
        return;
    }

    // Emit signal to MainWindow to send the message to other group members
    // Pass ownerRepoAppId as the common group identifier
    emit groupMessageSent(currentRepoInfo.ownerRepoAppId, message); // Corrected signal parameters

    // Display the message locally in our chat log (MainWindow handles this now via signal)
    // displayGroupMessage(m_networkManager->getMyUsername(), message);

    m_groupChatInput->clear(); // Clear input field after sending
}

void ProjectWindow::onAddCollaboratorClicked()
{
    // This button is only visible if isOwner is true (handled in updateGroupMembers).
    // This slot emits a signal to MainWindow to handle the workflow.
    emit addCollaboratorRequested(m_appId); // Pass our local appId
}

void ProjectWindow::onRemoveCollaboratorClicked()
{
    // This button is only visible if isOwner is true.
    // This slot gets the selected member and emits a signal to MainWindow.
    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();
    if (!selectedItem)
        return; // No item selected

    QString peerIdToRemove = selectedItem->data(Qt::UserRole).toString();

    // Get the repo info again to ensure it's up-to-date
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (!m_repoInfo.isValid() || !m_repoInfo.isOwner) // Double-check ownership
    {
        QMessageBox::warning(this, "Access Denied", "You are not the owner of this repository.");
        return;
    }

    // Cannot remove the owner
    if (peerIdToRemove == m_repoInfo.ownerPeerId) // Which is m_myUsername
    {
        QMessageBox::warning(this, "Invalid Action", "Cannot remove the repository owner.");
        return;
    }

    // Cannot remove myself if I am *not* the owner but somehow triggered this action (UI should prevent this)
    // The check `peerIdToRemove == m_myUsername` below is relevant if I'm the owner and try to remove myself from the list.
    if (peerIdToRemove == m_networkManager->getMyUsername()) // Added networkManager null check
    {
        QMessageBox::warning(this, "Invalid Action", "You cannot remove yourself from the group list.");
        return;
    }

    // Check if the peer is actually in the group list (excluding the owner)
    if (!m_repoInfo.groupMembers.contains(peerIdToRemove)) // Only need to check if they are in the list
    {
        QMessageBox::warning(this, "Error", QString("'%1' is not listed as a collaborator for '%2'.").arg(peerIdToRemove, m_repoInfo.displayName));
        return;
    }

    // Confirm removal is handled by MainWindow, emit signal
    emit removeCollaboratorRequested(m_appId, peerIdToRemove);
}

void ProjectWindow::onGroupMemberSelectionChanged()
{
    // This slot is connected to the m_groupMembersList itemSelectionChanged signal.
    // It enables/disables the "Remove Collaborator" button.

    // Button is only visible if isOwner is true (handled in updateGroupMembers).
    // If visible, enable it only if a member *other than the owner or self* is selected.

    bool canRemove = false;
    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();

    if (selectedItem && m_repoInfo.isOwner) // Only enable if something is selected AND I am the owner
    {
        QString peerId = selectedItem->data(Qt::UserRole).toString();
        QString myUsername = m_networkManager ? m_networkManager->getMyUsername() : "";

        // Can remove if selected item is NOT the owner AND is NOT myself
        if (peerId != m_repoInfo.ownerPeerId && peerId != myUsername)
        {
            canRemove = true;
        }
    }
    m_removeCollaboratorButton->setEnabled(canRemove);
}

void ProjectWindow::refreshLog()
{
    // Refresh the commit log based on the currently selected branch in the combobox.
    loadCommitLog(m_branchComboBox->currentText().toStdString());
}

void ProjectWindow::refreshBranches()
{
    // Reload the branch list from the Git backend.
    loadBranchList();
}

void ProjectWindow::checkoutBranch()
{
    // Get the branch name selected in the combobox and attempt to checkout.
    QString branchName = m_branchComboBox->currentText();
    if (branchName.isEmpty())
    {
        QMessageBox::information(this, "Select Branch", "Please select a branch to checkout.");
        return;
    }

    std::string error;
    // The checkoutBranch backend function handles both local and remote branches (by creating a local tracking branch)
    if (m_gitBackend.checkoutBranch(branchName.toStdString(), error))
    {
        // QMessageBox::information(this, "Success", "Checked out branch: " + branchName); // Avoid excessive popups
        qDebug() << "Checked out branch:" << branchName;
        updateStatus(); // Refresh status label and logs after successful checkout
    }
    else
    {
        QMessageBox::warning(this, "Checkout Failed", QString::fromStdString(error));
    }
}

void ProjectWindow::viewRemoteBranchHistory()
{
    // This slot is triggered when the selected branch in the combobox changes.
    // It loads the commit log for the selected branch/ref without performing a full checkout.
    // It's also triggered programmatically when setting the index in loadBranchList.
    // Only load log if the combo box is enabled and has text.

    QString selectedRef = m_branchComboBox->currentText();
    if (m_branchComboBox->isEnabled() && !selectedRef.isEmpty())
    {
        loadCommitLog(selectedRef.toStdString());
    }
    else if (m_branchComboBox->isEnabled()) // Combo box is empty but enabled (e.g., new empty repo)
    {
        m_commitLogDisplay->clear();
        m_commitLogDisplay->setHtml("<i>Select a branch or tag to view history, or initialize the repository.</i>");
    }
    else
    {
        // If combobox is disabled, clear log
        m_commitLogDisplay->clear();
    }
}

void ProjectWindow::loadCommitLog(const std::string &ref)
{
    m_commitLogDisplay->clear(); // Clear previous log
    std::string error;
    // Call GitBackend to get the commit log for the specified reference (or HEAD if ref is empty)
    auto log = m_gitBackend.getCommitLog(100, error, ref); // Get up to 100 commits
    if (!error.empty())                                    // If an error occurred (even if some commits were retrieved)
    {
        m_commitLogDisplay->setHtml("<font color='red'>Error loading commit log: " + QString::fromStdString(error).toHtmlEscaped() + "</font>");
        return; // Stop here if there's an error message from getCommitLog
    }
    if (log.empty()) // No commits found for the ref (and no error)
    {
        m_commitLogDisplay->setHtml("<i>No commits found for this reference.</i>");
        return;
    }

    // Format the commit log for display
    QString html;
    for (const auto &commit : log)
    {
        html += QString("<b>commit %1</b><br>").arg(QString::fromStdString(commit.sha));
        html += QString("Author: %1 &lt;%2&gt;<br>").arg(QString::fromStdString(commit.author_name).toHtmlEscaped(), QString::fromStdString(commit.author_email).toHtmlEscaped());
        html += QString("Date:   %1<br><br>").arg(QString::fromStdString(commit.date));
        // Display summary, preserving line breaks if any
        QString summaryHtml = QString::fromStdString(commit.summary).toHtmlEscaped().replace("\n", "<br>");
        html += QString("<p style='margin-left: 20px; margin-top: 0; margin-bottom: 0;'>%1</p>").arg(summaryHtml);
        html += "<hr>"; // Horizontal rule between commits
    }
    m_commitLogDisplay->setHtml(html);
}

void ProjectWindow::loadBranchList()
{
    // Preserve current selection if possible
    QString currentBranchInCombo = m_branchComboBox->currentText();

    m_branchComboBox->clear(); // Clear existing items
    std::string error;
    // Get all branches (local and remote)
    auto branches = m_gitBackend.listBranches(GitBackend::BranchType::ALL, error);

    m_branchComboBox->setEnabled(error.empty()); // Enable/disable based on error
    m_checkoutButton->setEnabled(error.empty());

    if (!error.empty())
    {
        m_branchComboBox->addItem("Error loading branches: " + QString::fromStdString(error));
        qWarning() << "Error loading branch list:" << QString::fromStdString(error);
        return;
    }

    QStringList branchNames;
    for (const auto &branch : branches)
    {
        // Skip pseudo-references like origin/HEAD that don't make sense to checkout or view history directly
        if (QString::fromStdString(branch).endsWith("/HEAD"))
            continue;
        branchNames.append(QString::fromStdString(branch));
    }
    branchNames.sort();                      // Sort branch names alphabetically
    m_branchComboBox->addItems(branchNames); // Add sorted branches to the combobox

    // Attempt to set the current selection to the actual current branch of the repo
    std::string currentBranch = m_gitBackend.getCurrentBranch(error); // Get current HEAD branch name
    int index = m_branchComboBox->findText(QString::fromStdString(currentBranch));
    if (index != -1)
    {
        // This will trigger the currentTextChanged signal and call viewRemoteBranchHistory
        m_branchComboBox->setCurrentIndex(index);
    }
    else if (!currentBranchInCombo.isEmpty() && m_branchComboBox->findText(currentBranchInCombo) != -1)
    {
        // If actual current branch wasn't in the list (e.g., detached HEAD),
        // try to restore the previous selection if it still exists.
        // This will also trigger currentTextChanged.
        m_branchComboBox->setCurrentIndex(m_branchComboBox->findText(currentBranchInCombo));
    }
    else if (m_branchComboBox->count() > 0)
    {
        // Otherwise, just select the first item (triggers currentTextChanged)
        m_branchComboBox->setCurrentIndex(0);
    }
    else
    {
        // If the list is empty (e.g., new empty repo), explicitly load the log for HEAD.
        // currentTextChanged won't be triggered if the list is empty.
        loadCommitLog("");
    }
}