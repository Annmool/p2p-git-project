#ifndef PROJECT_WINDOW_H
#define PROJECT_WINDOW_H

#include <QMainWindow>
#include "git_backend.h"
#include "repository_manager.h"
#include "network_manager.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QFont>
#include <QDebug>
#include <QListWidget>
#include <QComboBox>
#include <QTextEdit>
#include <QTabWidget>
#include <QLineEdit>

class MainWindow;

class CommitWidget : public QWidget {
    Q_OBJECT
public:
    CommitWidget(const CommitInfo& info, QWidget* parent = nullptr);
signals:
    void viewFilesClicked(const QString& sha);
private slots:
    void onButtonClicked();
};

class ProjectWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent = nullptr);
    ~ProjectWindow();

    QString getAppId() const { return m_appId; }
    void updateGroupMembers();
    void updateStatus();
    
    void handleFetchBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);

public slots:
    void displayGroupMessage(const QString& peerId, const QString& message);

signals:
    void groupMessageSent(const QString& ownerRepoAppId, const QString& message);
    void addCollaboratorRequested(const QString &localAppId);
    void removeCollaboratorRequested(const QString &localAppId, const QString &peerIdToRemove);
    void fetchBundleRequested(const QString& ownerPeerId, const QString& repoDisplayName);
    void proposeChangesRequested(const QString& ownerPeerId, const QString& repoDisplayName, const QString& fromBranch);

private slots:
    void refreshLog();
    void refreshBranches();
    void onFetchClicked();
    void onProposeChangesClicked();
    void checkoutBranch();
    void viewRemoteBranchHistory();
    void onSendGroupMessageClicked();
    void onAddCollaboratorClicked();
    void onRemoveCollaboratorClicked();
    void onGroupMemberSelectionChanged();
    void onViewFilesClicked(const QString& sha);

    // NEW SLOTS for staging/committing
    void refreshStatus();
    void onStageAllClicked();
    void onUnstageAllClicked();
    void onFileContextMenuRequested(const QPoint& pos);
    void onCommitClicked();

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = "");
    void loadBranchList();
    QWidget* createChangesTab();

    GitBackend m_gitBackend;
    QString m_appId;
    ManagedRepositoryInfo m_repoInfo;
    RepositoryManager* m_repoManager;
    NetworkManager* m_networkManager;

    QTabWidget *m_tabWidget;
    QWidget* m_historyTab;
    QWidget* m_changesTab;
    QWidget* m_collabTab;

    // History Tab widgets
    QListWidget *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshLogButton;
    QPushButton *m_fetchButton;
    QPushButton *m_proposeChangesButton;
    QPushButton *m_refreshBranchesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;
    
    // Changes Tab widgets
    QListWidget* m_unstagedFilesList;
    QListWidget* m_stagedFilesList;
    QPushButton* m_stageAllButton;
    QPushButton* m_unstageAllButton;
    QPushButton* m_refreshStatusButton;
    QTextEdit* m_commitMessageInput;
    QPushButton* m_commitButton;

    // Collaboration Tab widgets
    QListWidget* m_groupMembersList;
    QPushButton *m_addCollaboratorButton;
    QPushButton *m_removeCollaboratorButton;
    QTextEdit* m_groupChatDisplay;
    QLineEdit* m_groupChatInput;
    QPushButton* m_groupChatSendButton;
};

#endif // PROJECT_WINDOW_H