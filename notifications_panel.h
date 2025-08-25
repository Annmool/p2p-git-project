#ifndef NOTIFICATIONS_PANEL_H
#define NOTIFICATIONS_PANEL_H

#include <QWidget>
#include <QDateTime>
#include <QVariant>
#include <QList>
#include <QByteArray>

class QVBoxLayout;
class QScrollArea;

struct NotificationAction
{
    QString label;
    QVariantMap payload;
};

struct NotificationItem
{
    QString id;
    QString title;
    QString message;
    QDateTime created;
    bool unread{true};
    QList<NotificationAction> actions;
};

class NotificationsPanel : public QWidget
{
    Q_OBJECT
public:
    explicit NotificationsPanel(QWidget *parent = nullptr);
    void setStoragePath(const QString &path);
    void setEncryptionKey(const QByteArray &key32);
    // Expose mark for external callers who have the id (e.g., MainWindow)

signals:
    void unreadCountChanged(int count);
    void actionInvoked(const QString &notificationId, const QString &label, const QVariantMap &payload);

public slots:
    void addNotification(const QString &title, const QString &message, const QList<NotificationAction> &actions = {});
    void markAsRead(const QString &notificationId); // Updated to improve UI semantics
    void clearExpired();

private:
    void rebuildUi();
    void save();
    void load();
    void updateUnreadBadge();

    QString m_storagePath;
    QByteArray m_key32; // 32-byte key for secretbox
    QList<NotificationItem> m_items;
    QVBoxLayout *m_listLayout;
    QScrollArea *m_scroll;
};

#endif // NOTIFICATIONS_PANEL_H
