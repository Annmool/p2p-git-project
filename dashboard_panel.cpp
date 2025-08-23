#include "dashboard_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QListWidget>
#include <QListWidgetItem>
#include <QTextEdit>
#include <QDir>
#include <QStackedWidget>
#include <algorithm>
#include "info_dot.h"

// A custom widget for each repository item to achieve the card layout
class RepoCardWidget : public QWidget
{
public:
    RepoCardWidget(const ManagedRepositoryInfo &info, const QString &myPeerId, QWidget *parent = nullptr) : QWidget(parent)
    {
        setObjectName("RepoCardWidget");
        this->setContentsMargins(0, 0, 0, 0);
        QVBoxLayout *mainLayout = new QVBoxLayout(this);
        mainLayout->setContentsMargins(12, 12, 12, 12);

        QLabel *nameLabel = new QLabel(info.displayName, this);
        nameLabel->setObjectName("repoNameLabel");

        QString roleText;
        if (info.ownerPeerId == myPeerId)
            roleText = "Role: Owner";
        else if (info.groupMembers.contains(myPeerId))
            roleText = "Role: Collaborator";
        else
            roleText = "Role: None";

        QString accessText = info.isPublic ? "Access: Public" : "Access: Private";
        QLabel *detailLabel = new QLabel(roleText + "  •  " + accessText, this);
        detailLabel->setObjectName("repoDetailLabel");

        mainLayout->addWidget(nameLabel);
        mainLayout->addWidget(detailLabel);
        mainLayout->addStretch();
    }
};

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

    m_welcomeHeader = new QLabel("Hello!", this);
    m_welcomeHeader->setProperty("heading", "1");
    mainLayout->addWidget(m_welcomeHeader);

    QLabel *subHeader = new QLabel("Ready to explore? Here's everything you can manage and create.", this);
    subHeader->setStyleSheet("color: #6c757d;");
    mainLayout->addWidget(subHeader);

    mainLayout->addSpacing(20);

    QHBoxLayout *projectsHeaderLayout = new QHBoxLayout();
    m_projectsHeaderLabel = new QLabel("Your Projects (0)", this);
    m_projectsHeaderLabel->setProperty("heading", "2");
    projectsHeaderLayout->addWidget(m_projectsHeaderLabel);
    projectsHeaderLayout->addStretch();
    m_addRepoButton = new QPushButton("Upload", this);
    m_addRepoButton->setObjectName("primaryButton");
    projectsHeaderLayout->addWidget(m_addRepoButton);
    projectsHeaderLayout->addWidget(makeInfoDot("Upload a new repository to start managing it in SyncIt.", this));
    mainLayout->addLayout(projectsHeaderLayout);

    m_projectsContentStack = new QStackedWidget(this);

    m_managedReposListWidget = new QListWidget(this);
    m_managedReposListWidget->setObjectName("repoListWidget");
    m_managedReposListWidget->setSpacing(5);

    m_noProjectsWidget = new QWidget(this);
    m_noProjectsWidget->setStyleSheet("background-color: white; border-radius: 8px; border: 1px dashed #E2E8F0;");
    QVBoxLayout *noProjectsLayout = new QVBoxLayout(m_noProjectsWidget);
    noProjectsLayout->setAlignment(Qt::AlignCenter);
    noProjectsLayout->setSpacing(10);

    QLabel *noProjectsImage = new QLabel(this);
    noProjectsImage->setPixmap(QPixmap(":/icons/folder.svg").scaled(48, 48, Qt::KeepAspectRatio, Qt::SmoothTransformation));
    noProjectsImage->setAlignment(Qt::AlignCenter);

    QLabel *noProjectsText = new QLabel("No projects yet, upload your first project", this);
    noProjectsText->setAlignment(Qt::AlignCenter);
    noProjectsText->setStyleSheet("color: #6c757d; font-size: 16px; border: none; background: transparent;");

    noProjectsLayout->addStretch();
    noProjectsLayout->addWidget(noProjectsImage);
    noProjectsLayout->addWidget(noProjectsText);
    noProjectsLayout->addStretch();

    m_projectsContentStack->addWidget(m_noProjectsWidget);
    m_projectsContentStack->addWidget(m_managedReposListWidget);

    mainLayout->addWidget(m_projectsContentStack, 1);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    m_modifyAccessButton = new QPushButton("Modify Access...", this);
    m_deleteRepoButton = new QPushButton("Remove from List", this);
    buttonLayout->addWidget(m_modifyAccessButton);
    buttonLayout->addWidget(makeInfoDot("Change who can see or edit this project.", this));
    buttonLayout->addWidget(m_deleteRepoButton);
    buttonLayout->addWidget(makeInfoDot("Remove the selected project from your list (does not delete files).", this));
    mainLayout->addLayout(buttonLayout);

    mainLayout->addWidget(new QLabel("<b>Operation Status:</b>", this));
    m_statusLog = new QTextEdit(this);
    m_statusLog->setReadOnly(true);
    m_statusLog->setMaximumHeight(100);
    mainLayout->addWidget(m_statusLog);
}

void DashboardPanel::setWelcomeMessage(const QString &username)
{
    m_welcomeHeader->setText("Hello " + username + "!");
}

void DashboardPanel::updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId)
{
    m_projectsHeaderLabel->setText(QString("Your Projects (%1)").arg(repos.size()));

    QString previouslySelectedId = getSelectedRepoId();
    m_managedReposListWidget->clear();

    if (repos.isEmpty())
    {
        m_projectsContentStack->setCurrentWidget(m_noProjectsWidget);
    }
    else
    {
        m_projectsContentStack->setCurrentWidget(m_managedReposListWidget);
        QList<ManagedRepositoryInfo> sortedRepos = repos;
        std::sort(sortedRepos.begin(), sortedRepos.end(), [](const ManagedRepositoryInfo &a, const ManagedRepositoryInfo &b)
                  { return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0; });

        for (const auto &repoInfo : sortedRepos)
        {
            QListWidgetItem *item = new QListWidgetItem(m_managedReposListWidget);
            RepoCardWidget *card = new RepoCardWidget(repoInfo, myPeerId, m_managedReposListWidget);

            item->setSizeHint(card->sizeHint());
            m_managedReposListWidget->addItem(item);
            m_managedReposListWidget->setItemWidget(item, card);
            item->setData(Qt::UserRole, repoInfo.appId);

            if (repoInfo.appId == previouslySelectedId)
            {
                m_managedReposListWidget->setCurrentItem(item);
            }
        }
    }
    onRepoSelectionChanged();
}

void DashboardPanel::logStatus(const QString &message, bool isError)
{
    QColor color = isError ? Qt::red : Qt::darkGreen;
    m_statusLog->append(QString("<font color='%1'>%2</font>").arg(color.name(), message.toHtmlEscaped()));
}

QString DashboardPanel::getSelectedRepoId() const
{
    auto selectedItems = m_managedReposListWidget->selectedItems();
    if (selectedItems.isEmpty())
    {
        return QString();
    }
    return selectedItems.first()->data(Qt::UserRole).toString();
}

void DashboardPanel::onRepoSelectionChanged()
{
    bool hasSelection = !m_managedReposListWidget->selectedItems().isEmpty();
    m_modifyAccessButton->setEnabled(hasSelection);
    m_deleteRepoButton->setEnabled(hasSelection);
}

void DashboardPanel::onRepoDoubleClicked(QListWidgetItem *item)
{
    if (!item)
        return;
    emit openRepoInGitPanel(item->data(Qt::UserRole).toString());
}

void DashboardPanel::onModifyAccessClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit modifyAccessClicked(selectedId);
    }
}

void DashboardPanel::onDeleteClicked()
{
    QString selectedId = getSelectedRepoId();
    if (!selectedId.isEmpty())
    {
        emit deleteRepoClicked(selectedId);
    }
}
