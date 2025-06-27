#include "repo_management_panel.h"
#include "repository_manager.h" // Ensure ManagedRepositoryInfo is visible
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QDir>
#include <QMessageBox>
#include <QFileInfo> // Added
#include <algorithm> // Added for std::sort

RepoManagementPanel::RepoManagementPanel(QWidget *parent) : QWidget(parent)
{
    setupUi();
    // Connect UI signals to panel slots or signals
    connect(m_addRepoButton, &QPushButton::clicked, this, &RepoManagementPanel::addRepoClicked);             // Emits signal to MainWindow
    connect(m_modifyAccessButton, &QPushButton::clicked, this, &RepoManagementPanel::onModifyAccessClicked); // Calls local slot
    connect(m_deleteRepoButton, &QPushButton::clicked, this, &RepoManagementPanel::onDeleteClicked);         // Calls local slot
    // Connect list widget signals
    connect(m_managedReposListWidget, &QListWidget::itemDoubleClicked, this, &RepoManagementPanel::onRepoDoubleClicked);
    connect(m_managedReposListWidget, &QListWidget::itemSelectionChanged, this, &RepoManagementPanel::onRepoSelectionChanged);

    // Set initial button states
    m_modifyAccessButton->setEnabled(false);
    m_deleteRepoButton->setEnabled(false);
}

void RepoManagementPanel::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0); // Adjust margins
    mainLayout->setSpacing(6);                  // Adjust spacing

    QLabel *headerLabel = new QLabel("<b>Managed Repositories:</b>", this);
    headerLabel->setAlignment(Qt::AlignCenter); // Center the header
    mainLayout->addWidget(headerLabel);

    m_managedReposListWidget = new QListWidget(this);
    mainLayout->addWidget(m_managedReposListWidget, 1); // Give list widget stretch factor

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_addRepoButton = new QPushButton("Add Local Folder...", this);
    m_modifyAccessButton = new QPushButton("Modify Access...", this); // Used for Public/Private toggle and showing collaborators
    m_deleteRepoButton = new QPushButton("Remove from List", this);   // Removes management entry, not files
    buttonLayout->addWidget(m_addRepoButton);
    buttonLayout->addWidget(m_modifyAccessButton);
    buttonLayout->addWidget(m_deleteRepoButton);
    mainLayout->addLayout(buttonLayout);

    mainLayout->addWidget(new QLabel("<b>Operation Status:</b>", this));
    m_statusLog = new QTextEdit(this);
    m_statusLog->setReadOnly(true);
    m_statusLog->setMaximumHeight(100);      // Keep log area reasonably sized
    m_statusLog->setFontFamily("monospace"); // Monospace font for logs
    mainLayout->addWidget(m_statusLog);
}

void RepoManagementPanel::logStatus(const QString &message, bool isError)
{
    QColor color = isError ? Qt::red : Qt::darkGreen;
    m_statusLog->append(QString("<font color='%1'>%2</font>").arg(color.name(), message.toHtmlEscaped()));
}

QString RepoManagementPanel::getSelectedRepoId() const
{
    // Helper to get the App ID of the currently selected repository in the list.
    auto selectedItems = m_managedReposListWidget->selectedItems();
    if (selectedItems.isEmpty())
    {
        return QString(); // No item selected
    }
    return selectedItems.first()->data(Qt::UserRole).toString(); // Return the appId stored in UserRole data
}

// Updated signature to accept myPeerId
void RepoManagementPanel::updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId)
{
    // Preserve the currently selected item's App ID to restore selection after update
    QString previouslySelectedId = getSelectedRepoId();
    m_managedReposListWidget->clear(); // Clear all current list items

    if (repos.isEmpty())
    {
        m_managedReposListWidget->addItem("<i>No repositories managed yet. Click 'Add Local Folder...' to start.</i>");
    }
    else
    {
        // Sort repositories for consistent display order (e.g., by display name)
        QList<ManagedRepositoryInfo> sortedRepos = repos;
        std::sort(sortedRepos.begin(), sortedRepos.end(), [](const ManagedRepositoryInfo &a, const ManagedRepositoryInfo &b)
                  { return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0; });

        for (const auto &repoInfo : sortedRepos)
        {
            // Create HTML formatted text for the list item
            QString itemText = QString("<b>%1</b> <font color='gray'>(%2)</font>")
                                   .arg(repoInfo.displayName.toHtmlEscaped())
                                   .arg(repoInfo.isPublic ? "Public" : "Private");

            bool isOwnedByMe = (repoInfo.ownerPeerId == myPeerId);

            if (!isOwnedByMe) // If not owned by me, show the owner
            {
                itemText += QString("<br><small><i>Owner: %1</i></small>").arg(repoInfo.ownerPeerId.toHtmlEscaped());
                // For clones, indicate it's a clone using ownerRepoAppId or ownerPeerId
                itemText += QString("<br><small><i>Cloned from: %1</i></small>").arg(repoInfo.ownerPeerId.toHtmlEscaped());
                // Show if I'm a collaborator but not owner (only relevant for private repos)
                if (!repoInfo.isPublic && repoInfo.groupMembers.contains(myPeerId))
                {
                    itemText += QString("<br><small><i>Role: Collaborator</i></small>");
                }
            }
            else
            {
                // If owned by me
                itemText += QString("<br><small><i>Owner: You</i></small>");
                // Show collaborators count (excluding the owner)
                QStringList collaborators = repoInfo.groupMembers;
                collaborators.removeAll(myPeerId); // Exclude the owner from collaborator count
                if (!collaborators.isEmpty())
                {
                    itemText += QString("<br><small><i>%1 Collaborator(s)</i></small>").arg(collaborators.size());
                }
                else if (!repoInfo.isPublic)
                {
                    itemText += QString("<br><small><i>No Collaborators</i></small>");
                }
            }

            QListWidgetItem *item = new QListWidgetItem();
            // Using a QLabel as an item widget allows rich text (HTML) and word wrap
            QLabel *itemLabel = new QLabel(itemText);
            itemLabel->setWordWrap(true);
            item->setSizeHint(itemLabel->sizeHint()); // Set item height to fit the label

            m_managedReposListWidget->addItem(item);
            m_managedReposListWidget->setItemWidget(item, itemLabel); // Assign the label as the item widget

            // Store the repository's unique App ID in the item's data (Qt::UserRole)
            item->setData(Qt::UserRole, repoInfo.appId);
            // Set tooltip to show the full local path
            item->setToolTip(QDir::toNativeSeparators(repoInfo.localPath));

            // Restore selection if this item was previously selected
            if (repoInfo.appId == previouslySelectedId)
            {
                m_managedReposListWidget->setCurrentItem(item);
            }
        }
    }
    // Update button states after the list is refreshed and selection is potentially restored
    onRepoSelectionChanged();
}
void RepoManagementPanel::onRepoSelectionChanged()
{
    // This slot updates button enabled states based on whether an item is selected.
    bool hasSelection = !m_managedReposListWidget->selectedItems().isEmpty();
    // Buttons should be enabled if anything is selected.
    // Ownership checks for modify/delete actions are done in MainWindow *before* calling the handler slots.
    m_modifyAccessButton->setEnabled(hasSelection);
    m_deleteRepoButton->setEnabled(hasSelection);
}

void RepoManagementPanel::onRepoDoubleClicked(QListWidgetItem *item)
{
    // This slot is triggered when a list item is double-clicked.
    // It emits a signal to MainWindow to open the corresponding ProjectWindow.
    if (!item)
        return;
    // Get the App ID from the item's data and emit the signal.
    emit openRepoInGitPanel(item->data(Qt::UserRole).toString());
}

void RepoManagementPanel::onModifyAccessClicked()
{
    // This slot is connected to the "Modify Access" button.
    // It gets the selected repo's App ID and emits a signal to MainWindow.
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit modifyAccessClicked(selectedId); // Signal emitted to MainWindow
    }
}

void RepoManagementPanel::onDeleteClicked()
{
    // This slot is connected to the "Delete from List" button.
    // It gets the selected repo's App ID and emits a signal to MainWindow.
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit deleteRepoClicked(selectedId); // Signal emitted to MainWindow
    }
}