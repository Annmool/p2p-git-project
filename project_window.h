#ifndef PROJECT_WINDOW_H
#define PROJECT_WINDOW_H

#include <QMainWindow>
#include "git_backend.h"

QT_BEGIN_NAMESPACE
class QTextEdit;
class QComboBox;
class QPushButton;
class QLabel;
QT_END_NAMESPACE

class ProjectWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ProjectWindow(const QString &repoPath, QWidget *parent = nullptr);
    ~ProjectWindow();

private slots:
    void refreshLog();
    void refreshBranches();
    void checkoutBranch();
    void viewRemoteBranchHistory();

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = "");
    void loadBranchList();
    void updateStatus();

    GitBackend m_gitBackend;
    QString m_repoPath;

    QTextEdit *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshLogButton;
    QPushButton *m_refreshBranchesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;
};

#endif // PROJECT_WINDOW_H