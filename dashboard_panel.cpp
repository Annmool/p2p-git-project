#include "dashboard_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QDir>
#include <algorithm>

DashboardPanel::DashboardPanel(QWidget *parent) : QWidget(parent)
{
    setupUi();
    connect(m_addRepoButton, &QPushButton::clicked, this, &DashboardPanel::addRepoClicked);
    connect(m_modifyAccessButton, &QPushButton::clicked, this, &DashboardPanel::onModifyAccessClicked);
    connect(m_deleteRepoButton, &QPushButton::clicked, this, &DashboardPanel::onDeleteClicked);
    connect(m_managedReposListWidget, &QListWidget::itemDoubleClicked, this, &DashboardPanel::onRepoDoubleClicked);
    connect(m_managedReposListWidget, &QListWidget::itemSelectionChanged, this, &DashboardPanel::onRepoSelectionChanged);
    
    m_modifyAccessButton->setEnabled(false);
    m_deleteRepoButton->setEnabled(false);
}

void DashboardPanel::setupUi()
{
    setObjectName("mainContentPanel");
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel* welcomeHeader = new QLabel("Hello! Welcome to ThisnThat", this);
    welcomeHeader->setProperty("heading", "1");
    mainLayout->addWidget(welcomeHeader);

    QLabel* subHeader = new QLabel("Ready to explore? Here's everything you can manage and create.", this);
    subHeader->setStyleSheet("color: #6c757d; font-size: 14px;");
    mainLayout->addWidget(subHeader);

    mainLayout->addSpacing(20);

    QLabel* projectsHeader = new QLabel("Your Projects", this);
    projectsHeader->setProperty("heading", "2");
    mainLayout->addWidget(projectsHeader);

    m_managedReposListWidget = new QListWidget(this);
    m_managedReposListWidget->setStyleSheet("QListWidget { border: 1px solid #dee2e6; border-radius: 8px; background-color: white; }");
    mainLayout->addWidget(m_managedReposListWidget, 1);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    m_addRepoButton = new QPushButton("Add Local Folder...", this);
    m_modifyAccessButton = new QPushButton("Modify Access...", this);
    m_deleteRepoButton = new QPushButton("Remove from List", this);
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

void DashboardPanel::logStatus(const QString &message, bool isError)
{
    QColor color = isError ? Qt::red : Qt::darkGreen;
    m_statusLog->append(QString("<font color='%1'>%2</font>").arg(color.name(), message.toHtmlEscaped()));
}

QString DashboardPanel::getSelectedRepoId() const
{
    auto selectedItems = m_managedReposListWidget->selectedItems();
    if (selectedItems.isEmpty()) { return QString(); }
    return selectedItems.first()->data(Qt::UserRole).toString();
}

void DashboardPanel::updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId)
{
    QString previouslySelectedId = getSelectedRepoId();
    m_managedReposListWidget->clear();

    if (repos.isEmpty())
    {
        m_managedReposListWidget->addItem("<i>No repositories managed yet. Click 'Add Local Folder...' to start.</i>");
    }
    else
    {
        QList<ManagedRepositoryInfo> sortedRepos = repos;
        std::sort(sortedRepos.begin(), sortedRepos.end(), [](const ManagedRepositoryInfo &a, const ManagedRepositoryInfo &b) {
            return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0;
        });

        for (const auto &repoInfo : sortedRepos)
        {
            QString itemText = QString("<b>%1</b> <font color='gray'>(%2)</font>")
                                   .arg(repoInfo.displayName.toHtmlEscaped())
                                   .arg(repoInfo.isPublic ? "Public" : "Private");
            
            if (!repoInfo.isOwner) {
                itemText += QString("<br><small><i>Owner: %1</i></small>").arg(repoInfo.ownerPeerId.toHtmlEscaped());
            } else {
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
            
            if (repoInfo.appId == previouslySelectedId) {
                m_managedReposListWidget->setCurrentItem(item);
            }
        }
    }
    onRepoSelectionChanged();
}

void DashboardPanel::onRepoSelectionChanged()
{
    bool hasSelection = !m_managedReposListWidget->selectedItems().isEmpty();
    m_modifyAccessButton->setEnabled(hasSelection);
    m_deleteRepoButton->setEnabled(hasSelection);
}

void DashboardPanel::onRepoDoubleClicked(QListWidgetItem *item)
{
    if (!item) return;
    emit openRepoInGitPanel(item->data(Qt::UserRole).toString());
}

void DashboardPanel::onModifyAccessClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty()) {
        emit modifyAccessClicked(selectedId);
    }
}

void DashboardPanel::onDeleteClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty()) {
        emit deleteRepoClicked(selectedId);
    }
}