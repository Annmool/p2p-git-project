#include "notifications_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <sodium.h>
#include <algorithm>

NotificationsPanel::NotificationsPanel(QWidget *parent) : QWidget(parent), m_listLayout(nullptr), m_scroll(nullptr)
{
    setObjectName("NotificationsPanel");
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(8, 8, 8, 8);
    m_scroll = new QScrollArea(this);
    m_scroll->setWidgetResizable(true);
    auto *container = new QWidget(m_scroll);
    m_listLayout = new QVBoxLayout(container);
    m_listLayout->setContentsMargins(0, 0, 0, 0);
    m_listLayout->setSpacing(8);
    m_scroll->setWidget(container);
    outer->addWidget(m_scroll);

    // Periodic cleanup of expired notifications (older than 24h)
    auto *cleanupTimer = new QTimer(this);
    cleanupTimer->setInterval(60 * 60 * 1000); // hourly
    connect(cleanupTimer, &QTimer::timeout, this, &NotificationsPanel::clearExpired);
    cleanupTimer->start();
}

void NotificationsPanel::setStoragePath(const QString &path)
{
    m_storagePath = path;
    load();
}

void NotificationsPanel::setEncryptionKey(const QByteArray &key32)
{
    m_key32 = key32;
}

void NotificationsPanel::addNotification(const QString &title, const QString &message, const QList<NotificationAction> &actions)
{
    NotificationItem n;
    n.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
    n.title = title;
    n.message = message;
    n.created = QDateTime::currentDateTimeUtc();
    n.unread = true;
    n.actions = actions;
    m_items.prepend(n);
    rebuildUi();
    updateUnreadBadge();
    save();
}

void NotificationsPanel::markAsRead(const QString &notificationId)
{
    // Remove the notification entirely when marked as read
    m_items.erase(std::remove_if(m_items.begin(), m_items.end(), [&](const NotificationItem &n)
                                 { return n.id == notificationId; }),
                  m_items.end());
    rebuildUi();
    updateUnreadBadge();
    save();
}

void NotificationsPanel::clearExpired()
{
    const QDateTime cutoff = QDateTime::currentDateTimeUtc().addSecs(-24 * 60 * 60);
    m_items.erase(std::remove_if(m_items.begin(), m_items.end(), [&](const NotificationItem &n)
                                 { return n.created < cutoff; }),
                  m_items.end());
    rebuildUi();
    updateUnreadBadge();
    save();
}

void NotificationsPanel::rebuildUi()
{
    // Clear layout
    QLayoutItem *child;
    while ((child = m_listLayout->takeAt(0)) != nullptr)
    {
        if (auto *w = child->widget())
            w->deleteLater();
        delete child;
    }

    for (const auto &n : m_items)
    {
        auto *row = new QWidget(this);
        row->setObjectName("NotificationCard");
        auto *vl = new QVBoxLayout(row);
        vl->setContentsMargins(12, 12, 12, 12);
        auto *title = new QLabel(QString("%1%2").arg(n.unread ? "• " : "", n.title), row);
        title->setObjectName("notificationTitle");
        auto *msg = new QLabel(n.message, row);
        msg->setWordWrap(true);
        msg->setObjectName("notificationMessage");
        auto *meta = new QLabel(n.created.toLocalTime().toString(Qt::DefaultLocaleShortDate), row);
        meta->setObjectName("notificationMeta");
        auto *hl = new QHBoxLayout();
        // Actions
        for (const auto &a : n.actions)
        {
            auto *btn = new QPushButton(a.label, row);
            QObject::connect(btn, &QPushButton::clicked, this, [this, nid = n.id, a]()
                             { emit actionInvoked(nid, a.label, a.payload); });
            hl->addWidget(btn);
        }
        // Mark as read
        auto *mar = new QPushButton("Mark as read", row);
        QObject::connect(mar, &QPushButton::clicked, this, [this, nid = n.id]()
                         { markAsRead(nid); });
        hl->addStretch();
        hl->addWidget(mar);

        vl->addWidget(title);
        vl->addWidget(msg);
        vl->addWidget(meta);
        vl->addLayout(hl);
        m_listLayout->addWidget(row);
    }
    m_listLayout->addStretch();
}

static QByteArray deriveKey32(const QByteArray &material)
{
    QByteArray out(crypto_secretbox_KEYBYTES, 0);
    crypto_generichash(reinterpret_cast<unsigned char *>(out.data()), out.size(),
                       reinterpret_cast<const unsigned char *>(material.constData()), material.size(),
                       nullptr, 0);
    return out;
}

void NotificationsPanel::save()
{
    if (m_storagePath.isEmpty())
        return;
    QJsonArray arr;
    for (const auto &n : m_items)
    {
        QJsonObject o;
        o["id"] = n.id;
        o["title"] = n.title;
        o["message"] = n.message;
        o["created"] = n.created.toUTC().toString(Qt::ISODate);
        o["unread"] = n.unread;
        QJsonArray acts;
        for (const auto &a : n.actions)
        {
            QJsonObject ao;
            ao["label"] = a.label;
            ao["payload"] = QJsonObject::fromVariantMap(a.payload);
            acts.append(ao);
        }
        o["actions"] = acts;
        arr.append(o);
    }
    QJsonDocument doc(arr);
    QByteArray plain = doc.toJson(QJsonDocument::Compact);

    QByteArray key = m_key32.size() == crypto_secretbox_KEYBYTES ? m_key32 : deriveKey32(m_key32);
    QByteArray nonce(crypto_secretbox_NONCEBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char *>(nonce.data()), nonce.size());
    QByteArray cipher(crypto_secretbox_MACBYTES + plain.size(), 0);
    if (crypto_secretbox_easy(reinterpret_cast<unsigned char *>(cipher.data()),
                              reinterpret_cast<const unsigned char *>(plain.constData()), plain.size(),
                              reinterpret_cast<const unsigned char *>(nonce.constData()),
                              reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        return;
    }
    QFile f(m_storagePath);
    if (f.open(QIODevice::WriteOnly))
    {
        f.write("NS1");
        f.write(nonce);
        f.write(cipher);
        f.close();
    }
}

void NotificationsPanel::load()
{
    m_items.clear();
    if (m_storagePath.isEmpty())
        return;
    QFile f(m_storagePath);
    if (!f.exists())
        return;
    if (!f.open(QIODevice::ReadOnly))
        return;
    QByteArray magic = f.read(3);
    if (magic != "NS1")
    {
        f.close();
        return;
    }
    QByteArray nonce = f.read(crypto_secretbox_NONCEBYTES);
    QByteArray cipher = f.readAll();
    f.close();

    QByteArray key = m_key32.size() == crypto_secretbox_KEYBYTES ? m_key32 : deriveKey32(m_key32);
    if (cipher.size() < crypto_secretbox_MACBYTES)
        return;
    QByteArray plain(cipher.size() - crypto_secretbox_MACBYTES, 0);
    if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char *>(plain.data()),
                                   reinterpret_cast<const unsigned char *>(cipher.constData()), cipher.size(),
                                   reinterpret_cast<const unsigned char *>(nonce.constData()),
                                   reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        return;
    }
    QJsonDocument doc = QJsonDocument::fromJson(plain);
    if (!doc.isArray())
        return;
    for (const auto &it : doc.array())
    {
        if (!it.isObject())
            continue;
        QJsonObject o = it.toObject();
        NotificationItem n;
        n.id = o.value("id").toString();
        n.title = o.value("title").toString();
        n.message = o.value("message").toString();
        n.created = QDateTime::fromString(o.value("created").toString(), Qt::ISODate);
        n.unread = o.value("unread").toBool(true);
        QJsonArray acts = o.value("actions").toArray();
        for (const auto &ai : acts)
        {
            QJsonObject ao = ai.toObject();
            NotificationAction a;
            a.label = ao.value("label").toString();
            a.payload = ao.value("payload").toObject().toVariantMap();
            n.actions.append(a);
        }
        m_items.append(n);
    }
    rebuildUi();
    updateUnreadBadge();
}

void NotificationsPanel::updateUnreadBadge()
{
    int cnt = 0;
    for (const auto &n : m_items)
        if (n.unread)
            ++cnt;
    emit unreadCountChanged(cnt);
}
