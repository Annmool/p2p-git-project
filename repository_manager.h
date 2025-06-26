#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QUuid>       // For QUuid
#include <QMetaType>   // For Q_DECLARE_METATYPE
#include <QStringList> // Added for collaborators list

// Structure to hold information about a repository managed by this peer
struct ManagedRepositoryInfo
{
    QString appId;             // Unique ID for this managed entry (UUID)
    QString displayName;       // User-friendly name
    QString localPath;         // Absolute path to the local repository directory
    bool isPublic;             // Is this repository publicly discoverable/cloneable by anyone?
    QString adminPeerId;       // The Peer ID who owns/manages THIS entry (local peer for owned, cloner for remote)
    QStringList collaborators; // List of Peer IDs who have been explicitly granted access (for private repos owned by adminPeerId)
    QString originPeerId;      // The Peer ID from whom this repo was cloned (empty if this is the original copy owned by adminPeerId)

    ManagedRepositoryInfo() : isPublic(false) {}                                                        // Default constructor
    bool isValid() const { return !appId.isEmpty() && !localPath.isEmpty() && !adminPeerId.isEmpty(); } // Check if info is valid (added adminPeerId)
};
// Declare the struct as a meta type so it can be used in signals/slots' queues
Q_DECLARE_METATYPE(ManagedRepositoryInfo)
Q_DECLARE_METATYPE(QList<ManagedRepositoryInfo>) // Also declare list type

class RepositoryManager : public QObject
{
    Q_OBJECT
public:
    // Updated constructor declaration to accept myPeerId
    explicit RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent = nullptr);
    ~RepositoryManager();

    // Management operations
    bool addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId, const QString &originPeerId = "");
    bool removeManagedRepository(const QString &appId);
    bool setRepositoryVisibility(const QString &appId, bool isPublic);
    bool addCollaborator(const QString &appId, const QString &peerId);    // Add a peer to the collaborator list for a repo I own
    bool removeCollaborator(const QString &appId, const QString &peerId); // Remove a peer from the collaborator list for a repo I own

    // Retrieval operations
    ManagedRepositoryInfo getRepositoryInfo(const QString &appId) const;                                            // Get info by unique App ID
    ManagedRepositoryInfo getRepositoryInfoByPath(const QString &localPath) const;                                  // Get info by local file path
    ManagedRepositoryInfo getRepositoryInfoByDisplayName(const QString &displayName) const;                         // Get info by display name (might not be unique)
    ManagedRepositoryInfo getRepositoryInfoByOrigin(const QString &originPeerId, const QString &displayName) const; // Get info of a clone from a specific peer/repo name

    QList<ManagedRepositoryInfo> getAllManagedRepositories() const; // Get all repositories managed by this peer
    // Get repos owned by this peer that are shareable with a specific peer (public or collaborator)
    QList<ManagedRepositoryInfo> getMyPubliclySharedRepositories(const QString &requestingPeer) const; // Note: Renamed internally to be more specific

    QList<ManagedRepositoryInfo> getMyPrivateRepositories(const QString &myPeerId) const; // Get repos owned by myPeerId that are NOT public

    // Get repos where this peer is the owner OR a collaborator (used for the main list display)
    QList<ManagedRepositoryInfo> getRepositoriesIAmMemberOf(const QString &myPeerId) const;

signals:
    // Signal emitted when the list of managed repositories changes
    void managedRepositoryListChanged();

private:
    // Persistence
    bool loadRepositoriesFromFile();
    bool saveRepositoriesToFile() const;

    QString m_storageFilePath;                                  // Path to the JSON storage file
    QMap<QString, ManagedRepositoryInfo> m_managedRepositories; // Map of App ID to Repository Info

    // Storing the local peer's username/ID for internal logic (ownership checks, etc.)
    QString m_myPeerId;
};

#endif // REPOSITORY_MANAGER_H