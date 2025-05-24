#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDir>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent) {
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *layout = new QVBoxLayout(centralWidget);

    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path for new repository (e.g., /home/user/my_new_repo)");
    repoPathInput->setText(QDir::homePath() + "/my_test_repo");

    initRepoButton = new QPushButton("Initialize Repository", this);
    messageLog = new QTextEdit(this);
    messageLog->setReadOnly(true);

    layout->addWidget(repoPathInput);
    layout->addWidget(initRepoButton);
    layout->addWidget(messageLog);

    setCentralWidget(centralWidget);
    setWindowTitle("P2P Git Client - Phase 0 (Ubuntu)");

    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked);
}

MainWindow::~MainWindow() {
    // Destructor body - can be empty if no dynamic memory owned by raw pointers here
}

void MainWindow::onInitRepoClicked() {
    QString qPath = repoPathInput->text().trimmed();
    if (qPath.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a path for the repository.");
        messageLog->append("Error: Repository path cannot be empty.");
        return;
    }

    std::string path = qPath.toStdString();
    std::string errorMessage;

    QDir dir(qPath);
    if (!dir.exists()) {
        if (!dir.mkpath(".")) {
            messageLog->append("Error: Could not create directory: " + qPath);
            QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath);
            return;
        }
    }

    if (gitBackend.initializeRepository(path, errorMessage)) {
        messageLog->append(QString::fromStdString(errorMessage));
    } else {
        messageLog->append(QString::fromStdString(errorMessage));
    }
}