#ifndef PROJECT_WINDOW_H
#define PROJECT_WINDOW_H

#include <QMainWindow>
#include "git_backend.h"
#include "repository_manager.h" // For ManagedRepositoryInfo
#include "network_manager.h"    // For access to connected peers and username
#include <QMetaType>            // Needed for Q_DECLARE_METATYPE

QT_BEGIN_NAMESPACE
class QTextEdit;
class QComboBox;
class QPushButton;
class QLabel;
class QTabWidget;
class QListWidget;
class QLineEdit;
class QListWidgetItem; // Added for list item selection signal
QT_END_NAMESPACE

class RepositoryManager; // Forward declaration
class NetworkManager;    // Forward declaration

class ProjectWindow : public QMainWindow
{
    Q_OBJECT

public:
    // Constructor is updated to take pointers to the managers and the repo's unique LOCAL ID
    explicit ProjectWindow(const QString &appId, RepositoryManager *repoManager, NetworkManager *networkManager, QWidget *parent = nullptr);
    ~ProjectWindow(); // Destructor handles m_gitBackend automatically

    QString getAppId() const { return m_appId; }
    void updateGroupMembers(); // Public method to refresh the member list status icons
    void updateStatus();       // Public method to refresh repo status (branch, path, visibility, ownership)

public slots:
    void displayGroupMessage(const QString &peerId, const QString &message); // Display message in chat log

signals:
    // Signal to send a message from this window's chat
    // Pass ownerRepoAppId (the common group identifier) and message
    void groupMessageSent(const QString &ownerRepoAppId, const QString &message);
    // Signals to request collaborator management actions (handled by MainWindow)
    void addCollaboratorRequested(const QString &localAppId);                                   // Emitted when Add button clicked
    void removeCollaboratorRequested(const QString &localAppId, const QString &peerIdToRemove); // Emitted when Remove button clicked after confirmation

private slots:
    // History tab slots
    void refreshLog();              // Refresh log for current combo box selection
    void refreshBranches();         // Reload branch list
    void checkoutBranch();          // Attempt to checkout selected branch
    void viewRemoteBranchHistory(); // Load log for selected branch without checkout

    // Collaboration tab slots
    void onSendGroupMessageClicked();     // Handle sending group chat message
    void onAddCollaboratorClicked();      // Handle "Add Collaborator" button click
    void onRemoveCollaboratorClicked();   // Handle "Remove Collaborator" button click
    void onGroupMemberSelectionChanged(); // Handle selection change in the members list widget

private:
    void setupUi();
    void loadCommitLog(const std::string &ref = ""); // Load log for a specific ref (default is HEAD)
    void loadBranchList();                           // Load list of branches and tags

    // Backend and identity info (pointers owned by MainWindow)
    GitBackend m_gitBackend;          // Git backend instance for THIS repository
    QString m_appId;                  // Unique LOCAL application ID for this repository entry
    ManagedRepositoryInfo m_repoInfo; // Cache of the repository info (updated by updateStatus/updateGroupMembers)
    RepositoryManager *m_repoManager; // Pointer to the main repository manager (NOT owned)
    NetworkManager *m_networkManager; // Pointer to the main network manager (NOT owned)

    // Main UI
    QTabWidget *m_tabWidget;

    // Git History Tab
    QWidget *m_historyTab;
    QTextEdit *m_commitLogDisplay;
    QComboBox *m_branchComboBox;
    QPushButton *m_refreshLogButton;
    QPushButton *m_refreshBranchesButton;
    QPushButton *m_checkoutButton;
    QLabel *m_statusLabel;

    // Collaboration Tab
    QWidget *m_collabTab;
    QListWidget *m_groupMembersList;
    QPushButton *m_addCollaboratorButton;    // New button
    QPushButton *m_removeCollaboratorButton; // New button
    QTextEdit *m_groupChatDisplay;
    QLineEdit *m_groupChatInput;
    QPushButton *m_groupChatSendButton;
};

#endif // PROJECT_WINDOW_H