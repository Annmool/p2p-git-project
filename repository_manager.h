#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QUuid>
#include <QMetaType>

// This struct MUST contain the new fields.
struct ManagedRepositoryInfo
{
    QString appId;
    QString displayName;
    QString localPath;
    bool isPublic;
    QString adminPeerId;
    QString clonedFromPeerId;   // ID of the peer this was cloned from
    QString clonedFromRepoName; // Original display name on the source peer

    ManagedRepositoryInfo() : isPublic(false) {}

    ManagedRepositoryInfo(QString id, QString name, QString path, bool pub, QString adminId)
        : appId(id), displayName(name), localPath(path), isPublic(pub), adminPeerId(adminId) {}
};
Q_DECLARE_METATYPE(ManagedRepositoryInfo)

class RepositoryManager : public QObject
{
    Q_OBJECT

public:
    explicit RepositoryManager(const QString &storageFilePath, QObject *parent = nullptr);
    ~RepositoryManager();

    bool addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId,
                              const QString &clonedFromPeerId = "", const QString &clonedFromRepoName = "");

    bool removeManagedRepository(const QString &appId);
    bool setRepositoryVisibility(const QString &appId, bool isPublic);
    bool updateRepositoryDisplayName(const QString &appId, const QString &newDisplayName);
    Q_INVOKABLE ManagedRepositoryInfo getRepositoryInfo(const QString &appId) const;
    Q_INVOKABLE ManagedRepositoryInfo getRepositoryInfoByPath(const QString &localPath) const;
    Q_INVOKABLE QList<ManagedRepositoryInfo> getAllManagedRepositories() const;
    QList<ManagedRepositoryInfo> getMyPubliclySharedRepositories() const;

signals:
    void managedRepositoryListChanged();
    void repositoryMetadataUpdated(const QString &appId);

private:
    bool loadRepositoriesFromFile();
    bool saveRepositoriesToFile() const;

    QString m_storageFilePath;
    QList<ManagedRepositoryInfo> m_managedRepositoriesList;
    QMap<QString, ManagedRepositoryInfo> m_managedRepositoriesMap;
};

#endif // REPOSITORY_MANAGER_H