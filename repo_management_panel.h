#ifndef REPO_MANAGEMENT_PANEL_H
#define REPO_MANAGEMENT_PANEL_H

#include <QWidget>
#include "repository_manager.h" // For ManagedRepositoryInfo struct

QT_BEGIN_NAMESPACE
class QListWidget;
class QPushButton;
class QTextEdit;
class QListWidgetItem;
class QLabel;
QT_END_NAMESPACE

// Forward declaration for RepositoryManager if not using struct directly
// class RepositoryManager;

class RepoManagementPanel : public QWidget
{
    Q_OBJECT
public:
    explicit RepoManagementPanel(QWidget *parent = nullptr);
    // ~RepoManagementPanel() implicitly generated or added if needed

    QString getSelectedRepoId() const;                            // Helper to get the App ID of the selected repo
    void logStatus(const QString &message, bool isError = false); // Log messages to the status area

public slots:
    // Updated signature to accept myPeerId for display purposes
    void updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId); // Slot to update the displayed list of repositories

signals:
    // Signals emitted to MainWindow to request actions
    void addRepoClicked();                          // Emitted when "Add Local Folder..." button is clicked
    void modifyAccessClicked(const QString &appId); // Emitted when "Modify Access..." button is clicked (pass selected repo ID)
    void deleteRepoClicked(const QString &appId);   // Emitted when "Delete from List" button is clicked (pass selected repo ID)
    void openRepoInGitPanel(const QString &appId);  // Emitted when a repo item is double-clicked (pass selected repo ID)

private slots:
    // Slots to handle UI events within the panel
    void onRepoSelectionChanged();                   // Updates button states based on list selection
    void onRepoDoubleClicked(QListWidgetItem *item); // Handles double-clicking an item
    void onModifyAccessClicked();                    // Calls the corresponding signal
    void onDeleteClicked();                          // Calls the corresponding signal

private:
    void setupUi(); // Helper to set up the UI elements

    // UI elements
    QListWidget *m_managedReposListWidget;
    QPushButton *m_addRepoButton;
    QPushButton *m_modifyAccessButton;
    QPushButton *m_deleteRepoButton;
    QTextEdit *m_statusLog;
};

#endif // REPO_MANAGEMENT_PANEL_H