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
#include <QStyle>
#include <QInputDialog>
#include <QTimer>

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
}

ProjectWindow::~ProjectWindow() {}

void ProjectWindow::setupUi()
{
    setWindowTitle("Project: " + m_repoInfo.displayName);
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    m_tabWidget = new QTabWidget(this);
    mainLayout->addWidget(m_tabWidget);

    m_historyTab = new QWidget();
    QVBoxLayout *historyLayout = new QVBoxLayout(m_historyTab);
    
    m_statusLabel = new QLabel(this);
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

    connect(m_refreshLogButton, &QPushButton::clicked, this, &ProjectWindow::refreshLog);
    connect(m_refreshBranchesButton, &QPushButton::clicked, this, &ProjectWindow::refreshBranches);
    connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    connect(m_branchComboBox, &QComboBox::currentTextChanged, this, &ProjectWindow::viewRemoteBranchHistory);

    m_collabTab = new QWidget();
    QVBoxLayout *collabLayout = new QVBoxLayout(m_collabTab);

    collabLayout->addWidget(new QLabel("<b>Group Members:</b>"));
    m_groupMembersList = new QListWidget();
    m_groupMembersList->setMaximumHeight(120);
    collabLayout->addWidget(m_groupMembersList);
    
    QHBoxLayout *collabButtonLayout = new QHBoxLayout();
    m_addCollaboratorButton = new QPushButton("Add Collaborator...", this);
    m_removeCollaboratorButton = new QPushButton("Remove Collaborator", this);
    collabButtonLayout->addWidget(m_addCollaboratorButton);
    collabButtonLayout->addWidget(m_removeCollaboratorButton);
    collabLayout->addLayout(collabButtonLayout);

    collabLayout->addWidget(new QLabel("<b>Group Chat:</b>"));
    m_groupChatDisplay = new QTextEdit();
    m_groupChatDisplay->setReadOnly(true);
    collabLayout->addWidget(m_groupChatDisplay, 1);

    QHBoxLayout* chatInputLayout = new QHBoxLayout();
    m_groupChatInput = new QLineEdit();
    m_groupChatInput->setPlaceholderText("Type message to group...");
    m_groupChatSendButton = new QPushButton("Send");
    chatInputLayout->addWidget(m_groupChatInput, 1);
    chatInputLayout->addWidget(m_groupChatSendButton);
    collabLayout->addLayout(chatInputLayout);

    m_tabWidget->addTab(m_historyTab, "History");
    m_tabWidget->addTab(m_collabTab, "Collaboration");

    resize(800, 600);
}

void ProjectWindow::updateStatus()
{
    std::string error;
    std::string branch = m_gitBackend.getCurrentBranch(error);
    m_statusLabel->setText(QString("<b>Path:</b> %1<br><b>Current Branch:</b> %2").arg(m_repoInfo.localPath, QString::fromStdString(branch).toHtmlEscaped()));
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
    if (m_gitBackend.checkoutBranch(branchName.toStdString(), error))
    {
        QMessageBox::information(this, "Success", "Checked out branch: " + branchName);
        updateStatus();
    }
    else
    {
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
    if (!error.empty() && log.empty())
    {
        m_commitLogDisplay->setHtml("<font color='red'>" + QString::fromStdString(error).toHtmlEscaped() + "</font>");
        return;
    }
    QString html;
    for (const auto &commit : log)
    {
        html += QString("<b>commit %1</b><br>").arg(QString::fromStdString(commit.sha));
        html += QString("Author: %1 <%2><br>").arg(QString::fromStdString(commit.author_name).toHtmlEscaped(), QString::fromStdString(commit.author_email).toHtmlEscaped());
        html += QString("Date:   %1<br><br>").arg(QString::fromStdString(commit.date));
        html += QString("    %1<br><hr>").arg(QString::fromStdString(commit.summary).toHtmlEscaped());
    }
    m_commitLogDisplay->setHtml(html);
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