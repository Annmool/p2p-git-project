#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>
#include <QFont>      // For setting bold font
#include <QSplitter>  // Already included in .h but good practice if directly used

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    setupUi(); // Call the new UI setup method

    // --- Connections ---
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);
    // connect(branchComboBox, QOverload<int>::of(&QComboBox::activated), this, &MainWindow::onBranchSelectedFromCombo); // Optional: checkout on select

    updateRepositoryStatus(); // Initial status update
}

MainWindow::~MainWindow() {
    // Qt handles child widget deletion.
    // gitBackend's destructor handles libgit2 shutdown and freeing m_currentRepo.
}

void MainWindow::setupUi() {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // --- Top Bar: Path Input and Actions ---
    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path or click Open/Initialize");
    // Set an initial path if desired, or leave empty
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo_p2p"));
    pathActionLayout->addWidget(repoPathInput, 1); // Stretch factor for QLineEdit
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing", this);
    pathActionLayout->addWidget(openRepoButton);
    mainLayout->addLayout(pathActionLayout);

    // --- Status Bar: Current Repo and Branch ---
    QHBoxLayout *statusLayout = new QHBoxLayout();
    currentRepoLabel = new QLabel("No repository open.", this);
    currentRepoLabel->setAlignment(Qt::AlignLeft);
    QFont boldFont = currentRepoLabel->font();
    boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont);
    statusLayout->addWidget(currentRepoLabel, 1); // Stretch factor

    currentBranchLabel = new QLabel("Branch: -", this);
    currentBranchLabel->setAlignment(Qt::AlignRight);
    currentBranchLabel->setFont(boldFont);
    statusLayout->addWidget(currentBranchLabel);
    mainLayout->addLayout(statusLayout);


    // --- Main Content Area with Splitter ---
    QSplitter *mainSplitter = new QSplitter(Qt::Vertical, this);

    // --- Top Pane of Splitter: Commits and Branches ---
    QWidget *topPaneWidget = new QWidget(mainSplitter);
    QVBoxLayout *topPaneLayout = new QVBoxLayout(topPaneWidget);

    // Commit Log Area
    QLabel *commitLogTitleLabel = new QLabel("Commit History:", topPaneWidget); // Changed name for clarity
    topPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(topPaneWidget);
    commitLogDisplay->setReadOnly(true);
    commitLogDisplay->setFontFamily("monospace");
    commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap); // Prevent long lines from wrapping
    topPaneLayout->addWidget(commitLogDisplay, 1); // Stretch factor
    refreshLogButton = new QPushButton("Refresh Log", topPaneWidget);
    topPaneLayout->addWidget(refreshLogButton);

    // Branch Management Area
    QHBoxLayout *branchControlLayout = new QHBoxLayout(); // Changed name for clarity
    QLabel *branchSelectionLabel = new QLabel("Branches:", topPaneWidget); // Changed name
    branchControlLayout->addWidget(branchSelectionLabel);
    branchComboBox = new QComboBox(topPaneWidget);
    branchComboBox->setMinimumWidth(200); // Increased min width
    branchControlLayout->addWidget(branchComboBox, 1); // Stretch factor
    refreshBranchesButton = new QPushButton("Refresh Branches", topPaneWidget);
    branchControlLayout->addWidget(refreshBranchesButton);
    checkoutBranchButton = new QPushButton("Checkout Selected Branch", topPaneWidget); // Clarified text
    branchControlLayout->addWidget(checkoutBranchButton);
    topPaneLayout->addLayout(branchControlLayout);

    mainSplitter->addWidget(topPaneWidget);


    // --- Bottom Pane of Splitter: Message Log ---
    messageLog = new QTextEdit(mainSplitter);
    messageLog->setReadOnly(true);
    messageLog->setPlaceholderText("Status messages will appear here...");
    mainSplitter->addWidget(messageLog);

    // Set initial sizes for splitter panes
    QList<int> sizes;
    sizes << 300 << 100; // Example: top pane 300px, bottom pane 100px
    mainSplitter->setSizes(sizes);
    // Or use stretch factors if preferred (after adding widgets)
    // mainSplitter->setStretchFactor(0, 3); // Top pane gets 3/4 of space
    // mainSplitter->setStretchFactor(1, 1); // Bottom pane gets 1/4 of space


    mainLayout->addWidget(mainSplitter, 1); // Add splitter to main layout, make it stretch

    setCentralWidget(centralWidget);
    setWindowTitle("P2P Git Client - Branches"); // Updated title
    resize(800, 600); // Set a default window size
}


void MainWindow::updateRepositoryStatus() {
    bool repoIsOpen = gitBackend.isRepositoryOpen();

    refreshLogButton->setEnabled(repoIsOpen);
    refreshBranchesButton->setEnabled(repoIsOpen);
    checkoutBranchButton->setEnabled(repoIsOpen);
    branchComboBox->setEnabled(repoIsOpen);
    // initRepoButton and openRepoButton are always enabled for now

    if (repoIsOpen) {
        QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath());
        currentRepoLabel->setText("Current Repository: " + QDir::toNativeSeparators(path));
        loadBranchList(); // This will also update currentBranchLabel
        loadCommitLog();
    } else {
        currentRepoLabel->setText("No repository open.");
        currentBranchLabel->setText("Branch: -");
        commitLogDisplay->clear();
        branchComboBox->clear();
        messageLog->append("No repository is open. Initialize or open one.");
    }
}

void MainWindow::loadCommitLog() {
    commitLogDisplay->clear(); // Clear previous log
    if (!gitBackend.isRepositoryOpen()) {
        commitLogDisplay->setHtml("<i>No repository open to display log.</i>");
        return;
    }
    std::string error_message;
    std::vector<CommitInfo> log = gitBackend.getCommitLog(100, error_message); // Get up to 100 commits

    if (!error_message.empty() && log.empty()) {
        commitLogDisplay->setHtml("<font color=\"red\">Error loading commit log: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
    } else if (log.empty()) {
        commitLogDisplay->setHtml("<i>No commits in this branch yet.</i>");
    } else {
        QString htmlLog;
        for (const auto& entry : log) {
            htmlLog += QString("<b>%1</b> - %2 <%3> (%4)<br/>")
                           .arg(QString::fromStdString(entry.sha.substr(0, 7))) // Abbreviated SHA
                           .arg(QString::fromStdString(entry.author_name).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.author_email).toHtmlEscaped())
                           .arg(QString::fromStdString(entry.date));
            htmlLog += QString("    %1<br/><hr/>") // Indent summary
                           .arg(QString::fromStdString(entry.summary).toHtmlEscaped());
        }
        commitLogDisplay->setHtml(htmlLog);
    }
}

void MainWindow::loadBranchList() {
    branchComboBox->clear(); // Clear previous items
    if (!gitBackend.isRepositoryOpen()) return;

    std::string error_message;
    std::vector<std::string> branches = gitBackend.listBranches(error_message);

    if (!error_message.empty()) {
        messageLog->append("<font color=\"red\">Error listing branches: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
    } else {
        if (branches.empty()) {
            messageLog->append("No local branches found in this repository.");
        }
        for (const std::string& branch_name : branches) {
            branchComboBox->addItem(QString::fromStdString(branch_name));
        }
    }

    // Update current branch label and select in ComboBox
    std::string currentBranchName = gitBackend.getCurrentBranch(error_message);
    if (!error_message.empty() && currentBranchName.empty()){ // Error fetching current branch
         messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
         currentBranchLabel->setText("Branch: [Error]");
    } else if (!currentBranchName.empty()) {
        currentBranchLabel->setText("Branch: <b>" + QString::fromStdString(currentBranchName).toHtmlEscaped() + "</b>");
        int index = branchComboBox->findText(QString::fromStdString(currentBranchName));
        if (index != -1) {
            branchComboBox->setCurrentIndex(index);
        } else if (!branches.empty()){
            // If current branch isn't in the list (e.g. detached HEAD not listed by GIT_BRANCH_LOCAL)
            // but we got a name, we can still show it. Or select first available.
            // For now, if not found, combo box won't have it selected.
        }
    } else { // No current branch name returned (e.g. empty repo, or true error handled above)
        currentBranchLabel->setText("Branch: -");
    }
}


// --- SLOTS ---

void MainWindow::onInitRepoClicked() {
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a path for the new repository.");
        messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>");
        return;
    }
    std::string path = qPath.toStdString();
    std::string errorMessage;
    QDir dir(QDir::toNativeSeparators(qPath)); // Use native separators for QDir
    if (!dir.exists()) {
        if (!dir.mkpath(".")) { // mkpath needs a path relative to QDir's path, or an absolute one.
            messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>");
            QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath);
            return;
        }
    }
    if (gitBackend.initializeRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onOpenRepoClicked() {
    QString currentPathSuggestion = repoPathInput->text().trimmed();
    if (currentPathSuggestion.isEmpty() || !QDir(currentPathSuggestion).exists()){
        currentPathSuggestion = QDir::homePath();
    }

    QString dirPath = QFileDialog::getExistingDirectory(this, tr("Open Git Repository"),
                                                        currentPathSuggestion,
                                                        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (dirPath.isEmpty()) {
        messageLog->append("Open repository cancelled by user.");
        return;
    }
    repoPathInput->setText(QDir::toNativeSeparators(dirPath)); // Update input field
    std::string path = dirPath.toStdString();
    std::string errorMessage;
    if (gitBackend.openRepository(path, errorMessage)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    } else {
        messageLog->append("<font color=\"red\">" + QString::fromStdString(errorMessage).toHtmlEscaped() + "</font>");
    }
    updateRepositoryStatus();
}

void MainWindow::onRefreshLogClicked() {
    if (gitBackend.isRepositoryOpen()) {
        loadCommitLog();
        messageLog->append("Commit log refreshed.");
    } else {
        messageLog->append("No repository open to refresh log.");
    }
}

void MainWindow::onRefreshBranchesClicked() {
    if (gitBackend.isRepositoryOpen()) {
        loadBranchList();
        messageLog->append("Branch list refreshed.");
    } else {
        messageLog->append("No repository open to refresh branches.");
    }
}

void MainWindow::onCheckoutBranchClicked() {
    if (!gitBackend.isRepositoryOpen()){
        messageLog->append("<font color=\"red\">No repository open.</font>");
        return;
    }
    if (branchComboBox->currentText().isEmpty()) {
        messageLog->append("<font color=\"red\">No branch selected to checkout.</font>");
        QMessageBox::warning(this, "Checkout Error", "No branch selected from the dropdown.");
        return;
    }

    std::string branch_name = branchComboBox->currentText().toStdString();
    std::string error_message;

    if (gitBackend.checkoutBranch(branch_name, error_message)) {
        messageLog->append("<font color=\"green\">" + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
        updateRepositoryStatus(); // This will reload branches (and current branch) and log
    } else {
        messageLog->append("<font color=\"red\">Error checking out branch '" + QString::fromStdString(branch_name).toHtmlEscaped() + "': " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>");
        QMessageBox::critical(this, "Checkout Failed", "Could not checkout branch: " + QString::fromStdString(branch_name) + "\nError: " + QString::fromStdString(error_message));
    }
}