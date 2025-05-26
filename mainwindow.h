#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QLabel>
#include <QListWidget> // For displaying commit log

#include "git_backend.h" // Includes CommitInfo struct

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
    void onRefreshLogClicked(); // Slot for refresh log button

private:
    void updateRepositoryStatus();
    void displayCommitLog(const std::vector<CommitInfo>& log); // Helper to populate QListWidget

    // UI Elements
    QLineEdit *repoPathInput;
    QPushButton *initRepoButton;
    QPushButton *openRepoButton;
    QLabel *currentRepoLabel;

    QListWidget *commitLogWidget; // For displaying commit log
    QPushButton *refreshLogButton; // Button to refresh the log

    QTextEdit *messageLog; // General status messages

    GitBackend gitBackend;
};

#endif // MAINWINDOW_H