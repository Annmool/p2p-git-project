#include "repo_management_panel.h"
#include "repository_manager.h" // For ManagedRepositoryInfo
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QDir>
#include <QMessageBox>
#include <algorithm>

RepoManagementPanel::RepoManagementPanel(QWidget *parent) : QWidget(parent)
{
    setupUi();
    connect(m_addRepoButton, &QPushButton::clicked, this, &RepoManagementPanel::addRepoClicked);
    connect(m_modifyAccessButton, &QPushButton::clicked, this, &RepoManagementPanel::onModifyAccessClicked);
    connect(m_deleteRepoButton, &QPushButton::clicked, this, &RepoManagementPanel::onDeleteClicked);
    connect(m_managedReposListWidget, &QListWidget::itemDoubleClicked, this, &RepoManagementPanel::onRepoDoubleClicked);
    connect(m_managedReposListWidget, &QListWidget::itemSelectionChanged, this, &RepoManagementPanel::onRepoSelectionChanged);
}

void RepoManagementPanel::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addWidget(new QLabel("<b>Managed Repositories:</b>", this));
    m_managedReposListWidget = new QListWidget(this);
    mainLayout->addWidget(m_managedReposListWidget, 1);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_addRepoButton = new QPushButton("Add Local Folder...", this);
    m_modifyAccessButton = new QPushButton("Modify Access...", this);
    m_deleteRepoButton = new QPushButton("Delete from List", this);
    buttonLayout->addWidget(m_addRepoButton);
    buttonLayout->addWidget(m_modifyAccessButton);
    buttonLayout->addWidget(m_deleteRepoButton);
    mainLayout->addLayout(buttonLayout);

    mainLayout->addWidget(new QLabel("<b>Operation Status:</b>", this));
    m_statusLog = new QTextEdit(this);
    m_statusLog->setReadOnly(true);
    m_statusLog->setMaximumHeight(100);
    mainLayout->addWidget(m_statusLog);
}

void RepoManagementPanel::logStatus(const QString &message, bool isError)
{
    QColor color = isError ? Qt::red : Qt::darkGreen;
    m_statusLog->append(QString("<font color='%1'>%2</font>").arg(color.name(), message.toHtmlEscaped()));
}

QString RepoManagementPanel::getSelectedRepoId() const
{
    auto selectedItems = m_managedReposListWidget->selectedItems();
    if (selectedItems.isEmpty())
    {
        return QString();
    }
    return selectedItems.first()->data(Qt::UserRole).toString();
}

// FIX: Added the missing 'const QString &myPeerId' parameter and used correct members
void RepoManagementPanel::updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId)
{
    QString previouslySelectedId = getSelectedRepoId();
    m_managedReposListWidget->clear();

    if (repos.isEmpty())
    {
        m_managedReposListWidget->addItem("<i>No repositories managed yet.</i>");
    }
    else
    {
        for (const auto &repoInfo : repos)
        {
            QString itemText = QString("<b>%1</b> <font color='gray'>(%2)</font>")
                                   .arg(repoInfo.displayName.toHtmlEscaped())
                                   .arg(repoInfo.isPublic ? "Public" : "Private");

            if (repoInfo.ownerPeerId != myPeerId)
            {
                itemText += QString("<br><small><i>Owner: %1</i></small>").arg(repoInfo.ownerPeerId.toHtmlEscaped());
            }
            else
            {
                itemText += QString("<br><small><i>Owner: You</i></small>");
            }

            QListWidgetItem *item = new QListWidgetItem();
            QLabel *itemLabel = new QLabel(itemText);
            itemLabel->setWordWrap(true);
            item->setSizeHint(itemLabel->sizeHint());

            m_managedReposListWidget->addItem(item);
            m_managedReposListWidget->setItemWidget(item, itemLabel);

            item->setData(Qt::UserRole, repoInfo.appId);
            item->setToolTip(QDir::toNativeSeparators(repoInfo.localPath));

            if (repoInfo.appId == previouslySelectedId)
            {
                m_managedReposListWidget->setCurrentItem(item);
            }
        }
    }
    onRepoSelectionChanged();
}

void RepoManagementPanel::onRepoDoubleClicked(QListWidgetItem *item)
{
    if (!item)
        return;
    emit openRepoInGitPanel(item->data(Qt::UserRole).toString());
}

void RepoManagementPanel::onRepoSelectionChanged()
{
    bool hasSelection = !m_managedReposListWidget->selectedItems().isEmpty();
    m_modifyAccessButton->setEnabled(hasSelection);
    m_deleteRepoButton->setEnabled(hasSelection);
}

void RepoManagementPanel::onModifyAccessClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit modifyAccessClicked(selectedId);
    }
}

void RepoManagementPanel::onDeleteClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit deleteRepoClicked(selectedId);
    }
}