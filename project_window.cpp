#include "project_window.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>
#include <QLabel>
#include <QTextEdit>
#include <QComboBox>
#include <QPushButton>

ProjectWindow::ProjectWindow(const QString &repoPath, QWidget *parent)
    : QMainWindow(parent), m_repoPath(repoPath)
{
    setupUi();
    std::string error;
    if (!m_gitBackend.openRepository(repoPath.toStdString(), error))
    {
        QMessageBox::critical(this, "Error", "Could not open repository:\n" + QString::fromStdString(error));
        close();
        return;
    }
    updateStatus();
}

ProjectWindow::~ProjectWindow() {}

void ProjectWindow::setupUi()
{
    setWindowTitle("Git Project: " + m_repoPath);
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    m_statusLabel = new QLabel(this);
    mainLayout->addWidget(m_statusLabel);

    m_commitLogDisplay = new QTextEdit(this);
    m_commitLogDisplay->setReadOnly(true);
    m_commitLogDisplay->setFontFamily("monospace");
    mainLayout->addWidget(m_commitLogDisplay, 1);

    QHBoxLayout *controlsLayout = new QHBoxLayout();
    m_refreshLogButton = new QPushButton("Refresh Log", this);
    m_branchComboBox = new QComboBox(this);
    m_refreshBranchesButton = new QPushButton("Refresh Branches", this);
    m_checkoutButton = new QPushButton("Checkout / View History", this);
    controlsLayout->addWidget(m_refreshLogButton);
    controlsLayout->addWidget(m_branchComboBox, 1);
    controlsLayout->addWidget(m_refreshBranchesButton);
    controlsLayout->addWidget(m_checkoutButton);
    mainLayout->addLayout(controlsLayout);

    connect(m_refreshLogButton, &QPushButton::clicked, this, &ProjectWindow::refreshLog);
    connect(m_refreshBranchesButton, &QPushButton::clicked, this, &ProjectWindow::refreshBranches);
    connect(m_checkoutButton, &QPushButton::clicked, this, &ProjectWindow::checkoutBranch);
    connect(m_branchComboBox, &QComboBox::currentTextChanged, this, &ProjectWindow::viewRemoteBranchHistory);

    resize(800, 600);
}

void ProjectWindow::updateStatus()
{
    std::string error;
    std::string branch = m_gitBackend.getCurrentBranch(error);
    m_statusLabel->setText(QString("<b>Path:</b> %1<br><b>Current Branch:</b> %2").arg(m_repoPath, QString::fromStdString(branch).toHtmlEscaped()));
    loadBranchList();
    loadCommitLog();
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

    if (!branchName.contains('/'))
    {
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
    else
    {
        viewRemoteBranchHistory();
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