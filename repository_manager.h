#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QUuid>
#include <QMetaType>

struct ManagedRepositoryInfo
{
    QString appId;
    QString displayName;
    QString localPath;
    bool isPublic;
    QString adminPeerId;
    QStringList collaborators;
    QString originPeerId;
    ManagedRepositoryInfo() : isPublic(false) {}
};
Q_DECLARE_METATYPE(ManagedRepositoryInfo)

class RepositoryManager : public QObject
{
    Q_OBJECT
public:
    explicit RepositoryManager(const QString &storageFilePath, QObject *parent = nullptr);
    ~RepositoryManager();

    bool addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId, const QString &originPeerId = "");
    bool removeManagedRepository(const QString &appId);
    bool setRepositoryVisibility(const QString &appId, bool isPublic);
    bool addCollaborator(const QString &appId, const QString &peerId);

    ManagedRepositoryInfo getRepositoryInfo(const QString &appId) const;
    ManagedRepositoryInfo getRepositoryInfoByPath(const QString &localPath) const;
    QList<ManagedRepositoryInfo> getAllManagedRepositories() const;
    QList<ManagedRepositoryInfo> getMyPubliclySharedRepositories(const QString &requestingPeer) const;
    QList<ManagedRepositoryInfo> getMyPrivateRepositories(const QString &myPeerId) const;

signals:
    void managedRepositoryListChanged();

private:
    bool loadRepositoriesFromFile();
    bool saveRepositoriesToFile() const;

    QString m_storageFilePath;
    QMap<QString, ManagedRepositoryInfo> m_managedRepositories;
};
#endif // REPOSITORY_MANAGER_H