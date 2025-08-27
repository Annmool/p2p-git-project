#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QUuid>
#include <QMetaType>
#include <QStringList>

// Defines all the data for a repository you are tracking.
struct ManagedRepositoryInfo
{
    QString appId;
    QString displayName;
    QString localPath;
    bool isPublic;
    QString ownerPeerId;
    QString ownerRepoAppId;
    QStringList groupMembers;
    bool isOwner;

    ManagedRepositoryInfo() : isPublic(false), isOwner(false) {}
    bool isValid() const { return !appId.isEmpty() && !localPath.isEmpty() && !ownerPeerId.isEmpty(); }

    bool operator==(const ManagedRepositoryInfo &other) const
    {
        return appId == other.appId;
    }
};
Q_DECLARE_METATYPE(ManagedRepositoryInfo)
Q_DECLARE_METATYPE(QList<ManagedRepositoryInfo>)

class RepositoryManager : public QObject
{
    Q_OBJECT
public:
    explicit RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent = nullptr);
    ~RepositoryManager();

    bool addManagedRepository(const QString &displayName, const QString &localPath, bool isPublic, const QString &ownerPeerId, const QString &ownerRepoAppId, const QStringList &initialGroupMembers, bool isOwner);
    bool removeManagedRepository(const QString &appId);
    bool setRepositoryVisibility(const QString &appId, bool isPublic);
    bool addCollaborator(const QString &appId, const QString &peerId);
    bool removeCollaborator(const QString &appId, const QString &peerId);
    bool updateGroupMembersAndOwnerAppId(const QString &localAppId, const QString &ownerRepoAppId, const QStringList &newGroupMembers);

    ManagedRepositoryInfo getRepositoryInfo(const QString &appId) const;
    ManagedRepositoryInfo getRepositoryInfoByPath(const QString &localPath) const;
    ManagedRepositoryInfo getRepositoryInfoByDisplayName(const QString &displayName) const;
    ManagedRepositoryInfo getCloneInfoByOwnerAndDisplayName(const QString &ownerPeerId, const QString &displayName) const;
    ManagedRepositoryInfo getRepositoryInfoByOwnerAndDisplayName(const QString &ownerPeerId, const QString &displayName) const;
    ManagedRepositoryInfo getRepositoryInfoByOwnerAppId(const QString &ownerRepoAppId) const;

    QList<ManagedRepositoryInfo> getRepositoriesIAmMemberOf() const;
    QList<ManagedRepositoryInfo> getMyPubliclyShareableRepos() const;
    QList<ManagedRepositoryInfo> getAllManagedRepositories() const;

signals:
    void managedRepositoryListChanged();

private:
    bool loadRepositoriesFromFile();
    bool saveRepositoriesToFile() const;

    QString m_storageFilePath;
    QMap<QString, ManagedRepositoryInfo> m_managedRepositories;
    QString m_myPeerId;
};

#endif // REPOSITORY_MANAGER_H