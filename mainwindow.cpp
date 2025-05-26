#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QHBoxLayout>
#include <QDateTime> // For formatting commit time

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // --- Path Input and Action Buttons ---
    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path or click Open/Initialize");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo"));
    pathActionLayout->addWidget(repoPathInput, 1);
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing", this);
    pathActionLayout->addWidget(openRepoButton);
    mainLayout->addLayout(pathActionLayout);

    // --- Current Repository Status ---
    currentRepoLabel = new QLabel("No repository open.", this);
    currentRepoLabel->setAlignment(Qt::AlignCenter);
    QFont boldFont = currentRepoLabel->font();
    boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont);
    mainLayout->addWidget(currentRepoLabel);

    // --- Commit Log Area ---
    QHBoxLayout *logHeaderLayout = new QHBoxLayout();
    QLabel *logLabel = new QLabel("Commit History:", this);
    logHeaderLayout->addWidget(logLabel);
    logHeaderLayout->addStretch(); // Push button to the right
    refreshLogButton = new QPushButton("Refresh Log", this);
    refreshLogButton->setEnabled(false); // Disabled until repo is open
    logHeaderLayout->addWidget(refreshLogButton);
    mainLayout->addLayout(logHeaderLayout);

    commitLogWidget = new QListWidget(this);
    commitLogWidget->setFont(QFont("Monospace")); // Good for OIDs and fixed-width data
    mainLayout->addWidget(commitLogWidget, 2); // Give it more stretch factor

    // --- Message Log ---
    messageLog = new QTextEdit(this);
    messageLog->setReadOnly(true);
    messageLog->setPlaceholderText("Status messages will appear here...");
    mainLayout->addWidget(messageLog, 1);

    setCentralWidget(centralWidget);
    setWindowTitle("P2P Git Client - Phase 0.2");

    // --- Connections ---
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);

    updateRepositoryStatus();
}

MainWindow::~MainWindow() {
}

void MainWindow::updateRepositoryStatus() {
    if (gitBackend.isRepositoryOpen()) {
        QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath());
        currentRepoLabel->setText("Current Repository: " + path);
        refreshLogButton->setEnabled(true);
        onRefreshLogClicked(); // Automatically refresh log when repo changes
    } else {
        currentRepoLabel->setText("No repository open.");
        refreshLogButton->setEnabled(false);
        commitLogWidget->clear(); // Clear log if no repo open
    }
}

void MainWindow::displayCommitLog(const std::vector<CommitInfo>& logData) {
    commitLogWidget->clear();
    if (logData.empty() && gitBackend.isRepositoryOpen()) {
        commitLogWidget->addItem("No commits in this repository yet.");
        return;
    }
    for (const auto& commit : logData) {
        QDateTime commitDateTime = QDateTime::fromSecsSinceEpoch(commit.commit_time);
        QString itemText = QString("%1 - %2 <%3> (%4)\n  %5")
                               .arg(QString::fromStdString(commit.oid_short))
                               .arg(QString::fromStdString(commit.author_name))
                               .arg(QString::fromStdString(commit.author_email))
                               .arg(commitDateTime.toString(Qt::ISODate))
                               .arg(QString::fromStdString(commit.summary));
        commitLogWidget->addItem(itemText);
    }
}

void MainWindow::onRefreshLogClicked() {
    if (!gitBackend.isRepositoryOpen()) {
        messageLog->append("<font color=\"orange\">Cannot refresh log: No repository open.</font>");
        commitLogWidget->clear();
        return;
    }
    std::string errorMsg;
    std::vector<CommitInfo> log = gitBackend.getCommitLog(50, errorMsg); // Get latest 50 commits

    if (!errorMsg.empty()) {
        messageLog->append("<font color=\"red\">Error getting commit log: " + QString::fromStdString(errorMsg) + "</font>");
    }
    displayCommitLog(log);
}

void MainWindow::onInitRepoClicked() {
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty()) {
        messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>");
        return;
    }
    std::string path = qPath.toStdString();
    std::string errorMessage;

    QDir dir(qPath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath + "</font>");
            return;
        }
    }

    if (gitBackend.initializeRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage) + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage) + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onOpenRepoClicked() {
    QString dirPath = QFileDialog::getExistingDirectory(
        this, tr("Open Git Repository"),
        repoPathInput->text().isEmpty() ? QDir::homePath() : repoPathInput->text(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
    );

    if (dirPath.isEmpty()) {
        messageLog->append("Open repository cancelled by user.");
        return;
    }
    repoPathInput->setText(dirPath);
    std::string path = dirPath.toStdString();
    std::string errorMessage;

    if (gitBackend.openRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage) + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage) + "</font>");
    }
    updateRepositoryStatus();
}