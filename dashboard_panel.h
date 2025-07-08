#ifndef DASHBOARD_PANEL_H
#define DASHBOARD_PANEL_H

#include <QWidget>
#include "repository_manager.h"

QT_BEGIN_NAMESPACE
class QListWidget;
class QPushButton;
class QTextEdit;
class QListWidgetItem;
class QLabel;
class QStackedWidget;
QT_END_NAMESPACE

class DashboardPanel : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPanel(QWidget *parent = nullptr);

    void logStatus(const QString &message, bool isError = false);
    void setWelcomeMessage(const QString& username);

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

    // Member variable declarations
    QListWidget *m_managedReposListWidget;
    QPushButton *m_addRepoButton;
    QPushButton *m_modifyAccessButton;
    QPushButton *m_deleteRepoButton;
    QTextEdit *m_statusLog;
    QLabel* m_welcomeHeader;
    QLabel* m_projectsHeaderLabel;
    QStackedWidget *m_projectsContentStack;
    QWidget *m_noProjectsWidget;
};

#endif // DASHBOARD_PANEL_H