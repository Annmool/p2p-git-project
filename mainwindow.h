#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout> // For horizontal layouts
#include <QLabel>
#include <QComboBox>   // For branches
#include <QSplitter>   // For resizable panes

#include "git_backend.h" // This now includes the CommitInfo struct

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onInitRepoClicked();
    void onOpenRepoClicked();
    void onRefreshLogClicked();
    void onRefreshBranchesClicked();
    void onCheckoutBranchClicked();

private:
    void setupUi(); // Helper to organize UI creation
    void updateRepositoryStatus(); // Updates UI based on open repo, loads log & branches
    void loadCommitLog();        // Fetches and displays commit log
    void loadBranchList();      // Fetches and displays branch list, updates current branch
    void loadCommitLogForBranch(const std::string& branchName); // New helper
    std::string m_currentlyDisplayedLogBranch; 

    // UI Elements
    QLineEdit *repoPathInput;
    QPushButton *initRepoButton;
    QPushButton *openRepoButton;
    QLabel *currentRepoLabel;
    QLabel *currentBranchLabel; // Label for current branch

    QTextEdit *commitLogDisplay;
    QPushButton *refreshLogButton;

    QComboBox *branchComboBox;
    QPushButton *refreshBranchesButton;
    QPushButton *checkoutBranchButton;

    QTextEdit *messageLog; // For general status messages

    GitBackend gitBackend;
};

#endif // MAINWINDOW_H