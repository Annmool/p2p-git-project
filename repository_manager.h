#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>      // For m_idToIndexMap
#include <QUuid>     // For generating unique IDs
#include <QMetaType> // For Q_DECLARE_METATYPE

// Define ManagedRepositoryInfo here
struct ManagedRepositoryInfo {
    QString appId;          // Unique ID for this app's management of the repo (e.g., QUuid)
    QString displayName;    // User-friendly name for display
    QString localPath;      // Absolute filesystem path to the local Git repository
    bool isPublic;          // Visibility: true for public, false for private
    QString adminPeerId;    // The username/ID of the peer who added/owns this entry

    // Default constructor
    ManagedRepositoryInfo() : isPublic(false) {}

    // Convenience constructor
    ManagedRepositoryInfo(QString id, QString name, QString path, bool pub, QString adminId)
        : appId(id), displayName(name), localPath(path), isPublic(pub), adminPeerId(adminId) {}
};
Q_DECLARE_METATYPE(ManagedRepositoryInfo) // Allows storing ManagedRepositoryInfo in QVariant


class RepositoryManager : public QObject {
    Q_OBJECT

public:
    // Constructor takes the full path to the JSON file where repo metadata will be stored
    explicit RepositoryManager(const QString& storageFilePath, QObject *parent = nullptr);
    ~RepositoryManager(); // Will call saveRepositories if changes were made

    // Adds a new repository to be managed. Returns true on success.
    // Generates a new unique appId.
    bool addManagedRepository(const QString& localPath, const QString& displayName, bool isPublic, const QString& adminPeerId);

    // Removes a repository from management using its unique appId.
    // Does not delete the repository from disk.
    bool removeManagedRepository(const QString& appId);

    // Updates the visibility of an existing managed repository.
    bool setRepositoryVisibility(const QString& appId, bool isPublic);

    // Updates the display name of an existing managed repository.
    bool updateRepositoryDisplayName(const QString& appId, const QString& newDisplayName);

    // Retrieves information for a specific repository by its appId.
    // Returns a default-constructed (empty) ManagedRepositoryInfo if not found.
    Q_INVOKABLE ManagedRepositoryInfo getRepositoryInfo(const QString& appId) const;

    // Retrieves information for a specific repository by its local filesystem path.
    // Returns a default-constructed (empty) ManagedRepositoryInfo if not found.
    Q_INVOKABLE ManagedRepositoryInfo getRepositoryInfoByPath(const QString& localPath) const;

    // Gets a list of all repositories managed by this application instance.
    Q_INVOKABLE QList<ManagedRepositoryInfo> getAllManagedRepositories() const;

    // Gets a list of repositories that are marked as public by this peer.
    // This is what would be announced during discovery.
    QList<ManagedRepositoryInfo> getMyPubliclySharedRepositories() const;

signals:
    // Emitted when the list of managed repositories changes (add, remove).
    void managedRepositoryListChanged();
    // Emitted when metadata (like visibility or name) of an existing repository changes.
    void repositoryMetadataUpdated(const QString& appId);

private:
    bool loadRepositoriesFromFile(); // Load from JSON file
    bool saveRepositoriesToFile() const; // Save to JSON file

    QString m_storageFilePath; // Full path to the JSON file
    QList<ManagedRepositoryInfo> m_managedRepositoriesList; // Ordered list
    QMap<QString, ManagedRepositoryInfo> m_managedRepositoriesMap; // For quick lookup by appId

    // Helper to find index if you were to use QList only with a map to index
    // int findRepoIndex(const QString& appId) const;
};

#endif // REPOSITORY_MANAGER_H