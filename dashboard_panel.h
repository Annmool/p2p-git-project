#ifndef DASHBOARD_PANEL_H
#define DASHBOARD_PANEL_H

#include <QWidget>
#include "repository_manager.h" // For ManagedRepositoryInfo

QT_BEGIN_NAMESPACE
class QListWidget;
class QPushButton;
class QTextEdit;
class QListWidgetItem;
class QLabel;
QT_END_NAMESPACE

class DashboardPanel : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPanel(QWidget *parent = nullptr);

    void logStatus(const QString &message, bool isError = false);

public slots:
    void updateRepoList(const QList<ManagedRepositoryInfo> &repos, const QString &myPeerId);

signals:
    void addRepoClicked();
    void modifyAccessClicked(const QString &appId);
    void deleteRepoClicked(const QString &appId);
    void openRepoInGitPanel(const QString &appId);

private slots:
    void onRepoSelectionChanged();
    void onRepoDoubleClicked(QListWidgetItem *item);
    void onModifyAccessClicked();
    void onDeleteClicked();

private:
    void setupUi();
    QString getSelectedRepoId() const;

    QListWidget *m_managedReposListWidget;
    QPushButton *m_addRepoButton;
    QPushButton *m_modifyAccessButton;
    QPushButton *m_deleteRepoButton;
    QTextEdit *m_statusLog;
};

#endif // DASHBOARD_PANEL_H