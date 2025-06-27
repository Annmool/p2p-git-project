#ifndef REPOSITORY_MANAGER_H
#define REPOSITORY_MANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QUuid>       // For QUuid
#include <QMetaType>   // For Q_DECLARE_METATYPE
#include <QStringList> // Added for groupMembers list

// Structure to hold information about a repository managed by this peer
struct ManagedRepositoryInfo
{
    QString appId;            // Unique ID for THIS managed entry (local to this peer)
    QString displayName;      // User-friendly name (consistent across group)
    QString localPath;        // Absolute path to the local repository directory
    bool isPublic;            // Is THIS peer publicly announcing this repo? (Only meaningful if isOwner == true)
    QString ownerPeerId;      // The ID of the peer who INITIATED this repo (the true owner)
    QString ownerRepoAppId;   // The App ID of the repo entry on the OWNER's side (common group identifier)
    QStringList groupMembers; // List of ALL peers who are members (owner + collaborators added by owner). From owner's last broadcast/message.
    bool isOwner;             // True if ownerPeerId == this peer's ID

    ManagedRepositoryInfo() : isPublic(false), isOwner(false) {} // Default constructor
    // Check if info is valid (added ownerPeerId check, ownerRepoAppId is optional for owned repos initially)
    bool isValid() const { return !appId.isEmpty() && !localPath.isEmpty() && !ownerPeerId.isEmpty(); }

    // Equality operator for easier comparison in lists/maps (optional but good practice)
    // Compares based on the unique local appId
    bool operator==(const ManagedRepositoryInfo &other) const
    {
        return appId == other.appId;
    }
};
// Declare the struct as a meta type so it can be used in signals/slots' queues
Q_DECLARE_METATYPE(ManagedRepositoryInfo)        // This macro MUST be in global or relevant namespace, NOT inside a class
Q_DECLARE_METATYPE(QList<ManagedRepositoryInfo>) // Also declare list type

// JSON Keys for serialization (update names)
const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_OWNER_PEER_ID = "ownerPeerId";
const QString JSON_KEY_OWNER_REPO_APP_ID = "ownerRepoAppId"; // New key for the owner's appId
const QString JSON_KEY_GROUP_MEMBERS = "groupMembers";
const QString JSON_KEY_IS_OWNER_FLAG = "isOwnerFlag";

class RepositoryManager : public QObject
{
    Q_OBJECT
public:
    // Constructor takes myPeerId
    explicit RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent = nullptr);
    ~RepositoryManager();

    // Management operations
    // Simplified add - distinguish owner vs clone via isOwner flag, adds ownerRepoAppId
    bool addManagedRepository(const QString &displayName, const QString &localPath, bool isPublic, const QString &ownerPeerId, const QString &ownerRepoAppId, const QStringList &initialGroupMembers, bool isOwner);
    bool removeManagedRepository(const QString &appId);

    // Set visibility (only if I am the owner)
    bool setRepositoryVisibility(const QString &appId, bool isPublic);

    // Add/Remove collaborators (only if I am the owner)
    bool addCollaborator(const QString &appId, const QString &peerId);
    bool removeCollaborator(const QString &appId, const QString &peerId);

    // Update group members list and ownerRepoAppId (used by cloner when receiving updates from owner)
    bool updateGroupMembersAndOwnerAppId(const QString &localAppId, const QString &ownerRepoAppId, const QStringList &newGroupMembers);

    // Retrieval operations
    ManagedRepositoryInfo getRepositoryInfo(const QString &appId) const;                    // Get info by unique Local App ID
    ManagedRepositoryInfo getRepositoryInfoByPath(const QString &localPath) const;          // Get info by local file path
    ManagedRepositoryInfo getRepositoryInfoByDisplayName(const QString &displayName) const; // Get info by display name (might not be unique, returns first)
    // New retrieval for clones based on owner and display name
    ManagedRepositoryInfo getCloneInfoByOwnerAndDisplayName(const QString &ownerPeerId, const QString &displayName) const;
    // Get info by the owner's App ID (useful for finding our local entry for a group)
    ManagedRepositoryInfo getRepositoryInfoByOwnerAppId(const QString &ownerRepoAppId) const;

    QList<ManagedRepositoryInfo> getAllManagedRepositories() const; // Get all repositories managed by this peer
    // Get repos owned by THIS peer that are publicly shareable
    QList<ManagedRepositoryInfo> getMyPubliclyShareableRepos() const;

    // Get repos where THIS peer is the owner OR a group member
    QList<ManagedRepositoryInfo> getRepositoriesIAmMemberOf() const;

signals:
    // Signal emitted when the list of managed repositories changes
    void managedRepositoryListChanged();

private:
    // Persistence
    bool loadRepositoriesFromFile();
    bool saveRepositoriesToFile() const;

    QString m_storageFilePath;                                  // Path to the JSON storage file
    QMap<QString, ManagedRepositoryInfo> m_managedRepositories; // Map of App ID to Repository Info

    QString m_myPeerId; // Storing the local peer's username/ID
};

#endif // REPOSITORY_MANAGER_H