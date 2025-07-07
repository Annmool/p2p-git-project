#ifndef REPO_MANAGEMENT_PANEL_H
#define REPO_MANAGEMENT_PANEL_H

#include <QWidget>
#include "repository_manager.h" // For ManagedRepositoryInfo

QT_BEGIN_NAMESPACE
class QListWidget;
class QPushButton;
class QTextEdit;
class QListWidgetItem;
class QLabel;
QT_END_NAMESPACE

class RepoManagementPanel : public QWidget
{
    Q_OBJECT
public:
    explicit RepoManagementPanel(QWidget *parent = nullptr);

    QString getSelectedRepoId() const;
    void logStatus(const QString &message, bool isError = false);

public slots:
    // FIX: Add the second parameter to match the function call
    void updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId);

signals:
    void addRepoClicked();
    void modifyAccessClicked(const QString &appId);
    void deleteRepoClicked(const QString &appId);
    void openRepoInGitPanel(const QString &path); // Signal to open repo

private slots:
    void onRepoSelectionChanged();
    void onRepoDoubleClicked(QListWidgetItem *item);
    void onModifyAccessClicked(); // Private slots to handle button clicks
    void onDeleteClicked();

private:
    void setupUi();

    QListWidget *m_managedReposListWidget;
    QPushButton *m_addRepoButton;
    QPushButton *m_modifyAccessButton;
    QPushButton *m_deleteRepoButton;
    QTextEdit *m_statusLog;
};

#endif // REPO_MANAGEMENT_PANEL_H