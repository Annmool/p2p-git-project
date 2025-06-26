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
#include <QStyle>       // Added for icons
#include <QInputDialog> // Added for add collaborator dialog

ProjectWindow::ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent)
    : QMainWindow(parent),
      m_appId(appId),
      m_repoManager(repoManager),      // Store pointer
      m_networkManager(networkManager) // Store pointer
{
    // Ensure managers are valid
    if (!m_repoManager || !m_networkManager)
    {
        QMessageBox::critical(this, "Fatal Error", "ProjectWindow initialized without valid managers.");
        // Handle this error appropriately, maybe close or disable functionality.
        // For now, proceed but operations will likely fail.
    }

    // Retrieve the latest repository info
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (m_repoInfo.appId.isEmpty())
    {
        QMessageBox::critical(this, "Error", "Could not find repository information for ID: " + appId);
        // Disable window or close
        QTimer::singleShot(0, this, &QWidget::close); // Close async
        return;
    }

    setupUi(); // Setup the UI elements

    std::string error;
    // Open the repository using the GitBackend instance owned by this window
    if (!m_gitBackend.openRepository(m_repoInfo.localPath.toStdString(), error))
    {
        QMessageBox::critical(this, "Error", "Could not open repository:\n" + QString::fromStdString(error));
        QTimer::singleShot(0, this, &QWidget::close); // Close async
        return;
    }

    // Set window title based on display name
    setWindowTitle("Project: " + m_repoInfo.displayName);

    // Initial UI updates
    updateStatus();       // Refresh branch/commit info display
    updateGroupMembers(); // Refresh member list and status icons

    // Connect signals for collaborator management buttons
    connect(m_addCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onAddCollaboratorClicked);
    connect(m_removeCollaboratorButton, &QPushButton::clicked, this, &ProjectWindow::onRemoveCollaboratorClicked);

    // Connect selection change on the members list to enable/disable remove button
    connect(m_groupMembersList, &QListWidget::currentItemChanged, this, &ProjectWindow::onGroupMemberSelectionChanged);

    // Set initial state of collaborator buttons based on ownership
    bool isOwner = (m_repoInfo.adminPeerId == m_networkManager->getMyUsername());
    m_addCollaboratorButton->setVisible(isOwner);    // Hide if not owner
    m_removeCollaboratorButton->setVisible(isOwner); // Hide if not owner
    m_removeCollaboratorButton->setEnabled(false);   // Initially disabled
}

ProjectWindow::~ProjectWindow()
{
    // m_gitBackend instance is a member, its destructor will be called automatically
    // when the ProjectWindow object is destroyed, closing the repository.
    // Managers (m_repoManager, m_networkManager) are NOT owned by this window, do not delete them.
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
    // Connect branch combo box change to refresh log for that branch
    connect(m_branchComboBox, &QComboBox::currentTextChanged, this, &ProjectWindow::viewRemoteBranchHistory);

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
    collabLayout->addWidget(m_groupChatDisplay, 1); // Give chat display stretch factor

    QHBoxLayout *chatInputLayout = new QHBoxLayout();
    m_groupChatInput = new QLineEdit();
    m_groupChatInput->setPlaceholderText("Type message to group...");
    m_groupChatSendButton = new QPushButton("Send");
    chatInputLayout->addWidget(m_groupChatInput, 1); // Give input stretch factor
    chatInputLayout->addWidget(m_groupChatSendButton);
    collabLayout->addLayout(chatInputLayout);

    // Connect signals for Collaboration Tab controls
    connect(m_groupChatSendButton, &QPushButton::clicked, this, &ProjectWindow::onSendGroupMessageClicked);
    connect(m_groupChatInput, &QLineEdit::returnPressed, this, &ProjectWindow::onSendGroupMessageClicked); // Send on Enter key

    // --- Add tabs to widget ---
    m_tabWidget->addTab(m_historyTab, "History");
    m_tabWidget->addTab(m_collabTab, "Collaboration");

    resize(800, 600); // Default window size
}

void ProjectWindow::updateStatus()
{
    // Refresh the repository info from the manager in case visibility/collaborators changed
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (m_repoInfo.appId.isEmpty())
    {
        m_statusLabel->setText("<font color='red'>Repository information not found!</font>");
        m_commitLogDisplay->clear();
        m_branchComboBox->clear();
        return;
    }

    std::string error;
    std::string branch = m_gitBackend.getCurrentBranch(error); // Get current branch via this window's backend
    // Use HTML formatting for the status label
    QString statusHtml = QString("<b>Path:</b> %1<br><b>Current Branch:</b> %2").arg(m_repoInfo.localPath, QString::fromStdString(branch).toHtmlEscaped());

    // Add visibility and ownership/origin info
    statusHtml += QString("<br><b>Visibility:</b> %1").arg(m_repoInfo.isPublic ? "Public" : "Private");
    if (m_repoInfo.adminPeerId == m_networkManager->getMyUsername())
    {
        statusHtml += "<br><b>Owner:</b> You";
    }
    else
    {
        statusHtml += QString("<br><b>Owner:</b> %1").arg(m_repoInfo.adminPeerId.toHtmlEscaped());
    }
    if (!m_repoInfo.originPeerId.isEmpty())
    {
        statusHtml += QString("<br><b>Cloned From:</b> %1").arg(m_repoInfo.originPeerId.toHtmlEscaped());
    }

    m_statusLabel->setText(statusHtml);

    // Refresh branch list and commit log for the current branch
    loadBranchList();
    // After loading branch list, the current text changed signal might trigger loadCommitLog
    // If not, explicitly call it for the current branch
    if (m_branchComboBox->currentText().isEmpty())
    {
        loadCommitLog(branch); // Load log for the branch name returned by getCurrentBranch
    }
    else
    {
        // If combobox has text, viewRemoteBranchHistory slot will be triggered by setCurrentIndex/currentTextChanged
    }
}

void ProjectWindow::updateGroupMembers()
{
    if (!m_networkManager)
        return;

    // Refresh the repository info to get the latest collaborator list
    m_repoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (m_repoInfo.appId.isEmpty())
    {
        m_groupMembersList->clear();
        m_groupMembersList->addItem("<font color='red'>Repository info not found.</font>");
        return;
    }

    m_groupMembersList->clear(); // Clear existing list items

    QList<QString> connectedPeers = m_networkManager->getConnectedPeerIds(); // Get list of currently connected peers
    QString myUsername = m_networkManager->getMyUsername();

    QStringList members = m_repoInfo.collaborators;
    if (!m_repoInfo.adminPeerId.isEmpty())
    { // Add owner if exists
        members.prepend(m_repoInfo.adminPeerId);
    }
    members.removeDuplicates(); // Owner might also be in collaborators list? Unlikely but safe.
    members.sort();             // Optional: Sort members alphabetically

    for (const QString &member : members)
    {
        QListWidgetItem *item = new QListWidgetItem(m_groupMembersList);

        bool isMe = (member == myUsername);
        bool isOwner = (member == m_repoInfo.adminPeerId);
        bool isConnected = isMe || connectedPeers.contains(member); // Owner is always 'connected' locally

        item->setText(member + (isOwner ? " (owner)" : ""));                                                                                   // Append (owner) text
        item->setIcon(isConnected ? style()->standardIcon(QStyle::SP_DialogYesButton) : style()->standardIcon(QStyle::SP_DialogCancelButton)); // Set icon
        item->setForeground(isConnected ? palette().color(QPalette::Text) : QBrush(Qt::gray));                                                 // Set color (gray for offline)

        item->setData(Qt::UserRole, member); // Store the actual peerId in item data for removal
    }

    // Re-evaluate remove button state based on new list/selection (if any)
    onGroupMemberSelectionChanged();
}

void ProjectWindow::displayGroupMessage(const QString &peerId, const QString &message)
{
    QString myUsername = m_networkManager ? m_networkManager->getMyUsername() : "";
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

    // Ensure we are a member of this repository to send group messages
    // The UI should probably prevent non-members from even seeing this tab or sending messages.
    // For now, check membership here.
    if (!m_repoManager || !m_networkManager)
        return;
    ManagedRepositoryInfo currentRepoInfo = m_repoManager->getRepositoryInfo(m_appId);
    if (currentRepoInfo.appId.isEmpty() || (!currentRepoInfo.collaborators.contains(m_networkManager->getMyUsername()) && currentRepoInfo.adminPeerId != m_networkManager->getMyUsername()))
    {
        QMessageBox::warning(this, "Access Denied", "You are not a member of this repository group and cannot send messages.");
        m_groupChatInput->clear();
        return;
    }

    // Emit signal to MainWindow to send the message to other group members
    emit groupMessageSent(m_appId, message);

    // Display the message locally in our chat log (MainWindow does this now)
    // displayGroupMessage(m_networkManager->getMyUsername(), message); // Handled by MainWindow

    m_groupChatInput->clear(); // Clear input field after sending
}

void ProjectWindow::onAddCollaboratorClicked()
{
    // This slot is connected to the "Add Collaborator" button in the ProjectWindow collab tab.
    // It should emit a signal to MainWindow to handle the workflow (showing peer list, sending message).
    emit addCollaboratorRequested(m_appId);
}

void ProjectWindow::onRemoveCollaboratorClicked()
{
    // This slot is connected to the "Remove Collaborator" button.
    // It gets the selected member and emits a signal to MainWindow to handle the removal.
    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();
    if (!selectedItem)
        return;

    QString peerIdToRemove = selectedItem->data(Qt::UserRole).toString();

    // Check if the selected item is the owner
    if (peerIdToRemove == m_repoInfo.adminPeerId)
    {
        QMessageBox::warning(this, "Invalid Action", "Cannot remove the repository owner.");
        return;
    }

    // Check if the selected item is me (if I'm a collaborator but not owner)
    if (peerIdToRemove == m_networkManager->getMyUsername())
    {
        QMessageBox::warning(this, "Invalid Action", "You cannot remove yourself from the collaborator list here. If you are the owner, you can remove others. If you are a collaborator, you can only remove the repository from your own managed list.");
        // Optional: Provide an option to remove the repo from their own list?
        // For now, just warn.
        return;
    }

    // Emit signal to MainWindow to handle the removal logic and confirmation
    emit removeCollaboratorRequested(m_appId, peerIdToRemove);
}

void ProjectWindow::onGroupMemberSelectionChanged()
{
    // This slot is connected to the m_groupMembersList itemSelectionChanged signal.
    // It enables/disables the "Remove Collaborator" button.

    bool isOwner = (m_repoInfo.adminPeerId == m_networkManager->getMyUsername());
    if (!isOwner)
    {
        // If I'm not the owner, the button is always hidden anyway
        return;
    }

    QListWidgetItem *selectedItem = m_groupMembersList->currentItem();
    bool canRemove = false;
    if (selectedItem)
    {
        QString peerId = selectedItem->data(Qt::UserRole).toString();
        // Can remove if selected item is NOT the owner AND is NOT myself (if I'm owner)
        if (peerId != m_repoInfo.adminPeerId && peerId != m_networkManager->getMyUsername())
        {
            canRemove = true;
        }
        // Special case: if I AM the owner, can I remove myself? No, the owner cannot be removed.
        // The check `peerId != m_networkManager->getMyUsername()` handles this when I am the owner.
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
        QMessageBox::information(this, "Success", "Checked out branch: " + branchName);
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
    // Only load log if the selected item is different from the current HEAD branch.
    // Or just load it always, the user chose to view this ref's history.

    // Check if the combo box text change was triggered by loadBranchList setting the current index
    // If so, we don't need to reload the log immediately, updateStatus will handle it.
    // A simple flag or checking if the current index is valid after loadBranchList could work.
    // For now, just load the log - it's harmless to reload if called twice.

    QString selectedRef = m_branchComboBox->currentText();
    if (!selectedRef.isEmpty())
    {
        loadCommitLog(selectedRef.toStdString());
    }
    else
    {
        m_commitLogDisplay->clear();
        m_commitLogDisplay->setText("Select a branch or tag to view history.");
    }
}

void ProjectWindow::loadCommitLog(const std::string &ref)
{
    m_commitLogDisplay->clear(); // Clear previous log
    std::string error;
    // Call GitBackend to get the commit log for the specified reference (or HEAD if ref is empty)
    auto log = m_gitBackend.getCommitLog(100, error, ref); // Get up to 100 commits
    if (!error.empty() && log.empty())                     // If an error occurred and no commits were retrieved
    {
        m_commitLogDisplay->setHtml("<font color='red'>Error loading commit log: " + QString::fromStdString(error).toHtmlEscaped() + "</font>");
        return;
    }
    if (log.empty() && error.empty())
    { // No commits found for the ref
        m_commitLogDisplay->setHtml("<i>No commits found for this reference.</i>");
        return;
    }

    // Format the commit log for display
    QString html;
    for (const auto &commit : log)
    {
        html += QString("<b>commit %1</b><br>").arg(QString::fromStdString(commit.sha));
        html += QString("Author: %1 <%2><br>").arg(QString::fromStdString(commit.author_name).toHtmlEscaped(), QString::fromStdString(commit.author_email).toHtmlEscaped());
        html += QString("Date:   %1<br><br>").arg(QString::fromStdString(commit.date));
        // Display summary, preserving line breaks if any (though summary is typically single line)
        html += QString("    %1<br><hr>").arg(QString::fromStdString(commit.summary).toHtmlEscaped().replace("\n", "<br>&nbsp;&nbsp;&nbsp;&nbsp;")); // Escape and indent subsequent lines
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
    if (!error.empty())
    {
        m_branchComboBox->addItem("Error loading branches: " + QString::fromStdString(error));
        m_branchComboBox->setEnabled(false); // Disable combo box on error
        m_checkoutButton->setEnabled(false);
        return;
    }
    m_branchComboBox->setEnabled(true); // Enable if successful
    m_checkoutButton->setEnabled(true);

    QStringList branchNames;
    for (const auto &branch : branches)
    {
        // Skip pseudo-references like origin/HEAD
        if (QString::fromStdString(branch).endsWith("/HEAD"))
            continue;
        branchNames.append(QString::fromStdString(branch));
    }
    branchNames.sort();                      // Sort branch names alphabetically
    m_branchComboBox->addItems(branchNames); // Add sorted branches to the combobox

    // Attempt to set the current selection to the actual current branch of the repo
    std::string currentBranch = m_gitBackend.getCurrentBranch(error);
    int index = m_branchComboBox->findText(QString::fromStdString(currentBranch));
    if (index != -1)
    {
        m_branchComboBox->setCurrentIndex(index);
    }
    else if (!currentBranchInCombo.isEmpty() && m_branchComboBox->findText(currentBranchInCombo) != -1)
    {
        // If actual current branch wasn't in the list (e.g., detached HEAD),
        // try to restore the previous selection if it still exists.
        m_branchComboBox->setCurrentIndex(m_branchComboBox->findText(currentBranchInCombo));
    }
    else if (m_branchComboBox->count() > 0)
    {
        // Otherwise, just select the first item
        m_branchComboBox->setCurrentIndex(0);
    }
    // Note: Setting the current index triggers viewRemoteBranchHistory, which loads the log.
}