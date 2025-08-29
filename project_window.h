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
#include <QTextEdit>

class MainWindow;

class CommitWidget : public QWidget
{
    Q_OBJECT
public:
    CommitWidget(const CommitInfo &info, QWidget *parent = nullptr);
signals:
    void viewFilesClicked(const QString &sha);
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
    // Show diffs between two commits and bring the Diffs tab to front
    void showDiffForRange(const QString &commitA, const QString &commitB);
    void focusDiffsTab();

    void handleFetchBundleCompleted(const QString &repoName, const QString &localBundlePath, bool success, const QString &message);

public slots:
    void displayGroupMessage(const QString &peerId, const QString &message);

signals:
    void groupMessageSent(const QString &ownerRepoAppId, const QString &message);
    void addCollaboratorRequested(const QString &localAppId);
    void removeCollaboratorRequested(const QString &localAppId, const QString &peerIdToRemove);
    void fetchBundleRequested(const QString &ownerPeerId, const QString &repoDisplayName);
    void proposeChangesRequested(const QString &ownerPeerId, const QString &repoDisplayName, const QString &fromBranch);

private slots:
    void refreshAll();
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
    void onViewFilesClicked(const QString &sha);

    // NEW SLOTS for staging/committing
    void refreshStatus();
    void onStageAllClicked();
    void onUnstageAllClicked();
    void onFileContextMenuRequested(const QPoint &pos);
    void onCommitClicked();

    // Diffs tab
    void onComputeDiffClicked();
    void onSwapCommitsClicked();
    void onDiffFileSelected(QListWidgetItem *item);

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = "");
    void loadBranchList();
    QWidget *createChangesTab();
    QWidget *createProposeTab();
    QWidget *createDiffsTab();
    void setDiffStatus(const QString &text, const QColor &color = QColor("#444"));
    bool verifyCommit(const QString &sha, QString &normalizedSha, QString &errorOut);
    bool checkRelatedHistories(const QString &a, const QString &b);
    QString runGit(const QStringList &args, int timeoutMs = 30000, int *exitCodeOut = nullptr);
    void populateProposeBranches();

    GitBackend m_gitBackend;
    QString m_appId;
    ManagedRepositoryInfo m_repoInfo;
    RepositoryManager *m_repoManager;
    NetworkManager *m_networkManager;

    QTabWidget *m_tabWidget;
    QWidget *m_historyTab;
    QWidget *m_changesTab;
    QWidget *m_proposeTab;
    QWidget *m_collabTab;
    QWidget *m_diffsTab;

    // History Tab widgets
    QListWidget *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshButton;
    QPushButton *m_fetchButton;
    QPushButton *m_proposeChangesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;

    // Changes Tab widgets
    QListWidget *m_unstagedFilesList;
    QListWidget *m_stagedFilesList;
    QPushButton *m_stageAllButton;
    QPushButton *m_unstageAllButton;
    QPushButton *m_refreshStatusButton;
    QTextEdit *m_commitMessageInput;
    QPushButton *m_commitButton;

    // Propose Tab widgets (for collaborators)
    QListWidget *m_proposedFilesList;
    QPushButton *m_addFilesButton;
    QPushButton *m_removeFilesButton;
    QComboBox *m_targetBranchDropdown;
    QTextEdit *m_proposalMessageInput;
    QPushButton *m_sendProposalButton;

    // Collaboration Tab widgets
    QListWidget *m_groupMembersList;
    QPushButton *m_addCollaboratorButton;
    QPushButton *m_removeCollaboratorButton;
    QTextEdit *m_groupChatDisplay;
    QLineEdit *m_groupChatInput;
    QPushButton *m_groupChatSendButton;

    // Diffs Tab widgets
    QLineEdit *m_commitAInput;
    QLineEdit *m_commitBInput;
    QPushButton *m_computeDiffButton;
    QPushButton *m_swapCommitsButton;
    QLabel *m_diffStatusLabel;
    QListWidget *m_diffFilesList;
    QTextEdit *m_diffViewer;

    // Diffs state
    QString m_diffCommitA;
    QString m_diffCommitB;
};

#endif // PROJECT_WINDOW_H