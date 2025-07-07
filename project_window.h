#ifndef PROJECT_WINDOW_H
#define PROJECT_WINDOW_H

#include <QMainWindow>
#include "git_backend.h"
#include "repository_manager.h"
#include "network_manager.h"

QT_BEGIN_NAMESPACE
class QTextEdit;
class QComboBox;
class QPushButton;
class QLabel;
class QTabWidget;
class QListWidget;
class QLineEdit;
class QListWidgetItem;
QT_END_NAMESPACE

class ProjectWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent = nullptr);
    ~ProjectWindow();

    QString getAppId() const { return m_appId; }
    void updateGroupMembers();
    void updateStatus();

public slots:
    void displayGroupMessage(const QString& peerId, const QString& message);

signals:
    void groupMessageSent(const QString& ownerRepoAppId, const QString& message);
    void addCollaboratorRequested(const QString &localAppId);
    void removeCollaboratorRequested(const QString &localAppId, const QString &peerIdToRemove);

private slots:
    void refreshLog();
    void refreshBranches();
    void checkoutBranch();
    void viewRemoteBranchHistory();
    void onSendGroupMessageClicked();
    void onAddCollaboratorClicked();
    void onRemoveCollaboratorClicked();
    void onGroupMemberSelectionChanged();

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = "");
    void loadBranchList();

    GitBackend m_gitBackend;
    QString m_appId;
    ManagedRepositoryInfo m_repoInfo;
    RepositoryManager* m_repoManager;
    NetworkManager* m_networkManager;

    QTabWidget *m_tabWidget;
    QWidget* m_historyTab;
    QTextEdit *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshLogButton;
    QPushButton *m_refreshBranchesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;
    
    QWidget* m_collabTab;
    QListWidget* m_groupMembersList;
    QPushButton *m_addCollaboratorButton;
    QPushButton *m_removeCollaboratorButton;
    QTextEdit* m_groupChatDisplay;
    QLineEdit* m_groupChatInput;
    QPushButton* m_groupChatSendButton;
};

#endif // PROJECT_WINDOW_H