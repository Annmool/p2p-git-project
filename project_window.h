#ifndef PROJECT_WINDOW_H
#define PROJECT_WINDOW_H

#include <QMainWindow>
#include "git_backend.h"
#include "repository_manager.h" // For ManagedRepositoryInfo
#include "network_manager.h"    // For access to connected peers

QT_BEGIN_NAMESPACE
class QTextEdit;
class QComboBox;
class QPushButton;
class QLabel;
class QTabWidget;
class QListWidget;
class QLineEdit;
QT_END_NAMESPACE

class ProjectWindow : public QMainWindow
{
    Q_OBJECT

public:
    // Constructor is updated to take pointers to the managers and the repo's unique ID
    explicit ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent = nullptr);
    ~ProjectWindow();

    QString getAppId() const { return m_appId; }
    void updateGroupMembers(); // Public method to refresh the member list

public slots:
    void displayGroupMessage(const QString& peerId, const QString& message);

signals:
    // Signal to send a message from this window's chat
    void groupMessageSent(const QString& appId, const QString& message);

private slots:
    void refreshLog();
    void refreshBranches();
    void checkoutBranch();
    void viewRemoteBranchHistory();
    void onSendGroupMessageClicked();

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = "");
    void loadBranchList();
    void updateStatus();

    // Backend and identity info
    GitBackend m_gitBackend;
    QString m_appId;
    ManagedRepositoryInfo m_repoInfo;
    RepositoryManager* m_repoManager; // Pointer to the main repo manager
    NetworkManager* m_networkManager; // Pointer to the main network manager

    // Main UI
    QTabWidget *m_tabWidget;

    // Git History Tab
    QWidget* m_historyTab;
    QTextEdit *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshLogButton;
    QPushButton *m_refreshBranchesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;

    // Collaboration Tab
    QWidget* m_collabTab;
    QListWidget* m_groupMembersList;
    QTextEdit* m_groupChatDisplay;
    QLineEdit* m_groupChatInput;
    QPushButton* m_groupChatSendButton;
};

#endif // PROJECT_WINDOW_H