#include "repository_manager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QUuid>
#include <algorithm> // Required for std::sort

// JSON Keys for serialization (kept consistent)
const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_ADMIN_PEER_ID = "adminPeerId";   // Owner of the repo entry
const QString JSON_KEY_COLLABORATORS = "collaborators"; // List of peers added as collaborators (by adminPeerId)
const QString JSON_KEY_ORIGIN_PEER_ID = "originPeerId"; // The peer from whom this repo was cloned (empty if owned locally)

// Updated constructor signature to accept myPeerId
RepositoryManager::RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath), m_myPeerId(myPeerId)
{
    // Ensure meta type is registered for ManagedRepositoryInfo if signals queue it
    qRegisterMetaType<ManagedRepositoryInfo>("ManagedRepositoryInfo");
    qRegisterMetaType<QList<ManagedRepositoryInfo>>("QList<ManagedRepositoryInfo>");

    loadRepositoriesFromFile(); // Load existing managed repositories on startup
}

RepositoryManager::~RepositoryManager()
{
    saveRepositoriesToFile(); // Save the current state when the manager is destroyed
}

bool RepositoryManager::addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId, const QString &originPeerId)
{
    // Use canonical path to avoid duplicates due to symlinks, case sensitivity, etc.
    QString canonicalPath = QDir(localPath).canonicalPath();

    // Check if a repository with the *same local path* already exists in the managed list
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (QDir(repo.localPath).canonicalPath() == canonicalPath)
        {
            qWarning() << "Repository at path" << localPath << "is already managed (by path).";
            return false; // Already exists by path
        }
    }

    // --- New Check: Check if a repository with the *same display name* already exists ---
    // Iterate through existing repos to see if any have this display name
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (repo.displayName == displayName)
        {
            qWarning() << "Repository with display name '" << displayName << "' is already managed.";
            return false; // Already exists by display name
        }
    }
    // --- End New Check ---

    ManagedRepositoryInfo newRepo;
    newRepo.appId = QUuid::createUuid().toString(QUuid::WithoutBraces); // Generate unique ID
    newRepo.localPath = canonicalPath;
    newRepo.displayName = displayName;
    newRepo.isPublic = isPublic;
    newRepo.adminPeerId = adminPeerId;   // The peer ID who 'manages' this entry (owner for local, cloner for remote)
    newRepo.originPeerId = originPeerId; // Peer ID from whom it was cloned (if any)

    // Collaborator list is initially empty unless added later by the admin.
    // When cloning, the COLLABORATOR_ADDED message handler will update this list *after* cloning is complete.

    m_managedRepositories.insert(newRepo.appId, newRepo); // Add to the map
    qDebug() << "Added managed repository:" << newRepo.displayName << " (" << newRepo.appId << ")";

    emit managedRepositoryListChanged(); // Notify UI and other parts of the application
    return saveRepositoriesToFile();     // Save changes to persistent storage
}

bool RepositoryManager::removeManagedRepository(const QString &appId)
{
    if (m_managedRepositories.contains(appId))
    {
        QString repoName = m_managedRepositories.value(appId).displayName;
        if (m_managedRepositories.remove(appId) > 0) // Remove from the map
        {
            qDebug() << "Removed managed repository:" << repoName << " (" << appId << ")";
            emit managedRepositoryListChanged(); // Notify UI
            return saveRepositoriesToFile();     // Save changes
        }
    }
    qWarning() << "Attempted to remove non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

bool RepositoryManager::setRepositoryVisibility(const QString &appId, bool isPublic)
{
    if (m_managedRepositories.contains(appId))
    {
        // Only the owner of this managed entry can change visibility
        // Ownership check should be done by the caller (MainWindow)
        m_managedRepositories[appId].isPublic = isPublic;
        qDebug() << "Set visibility for repo" << appId << "to public:" << isPublic;
        emit managedRepositoryListChanged(); // Notify UI
        return saveRepositoriesToFile();     // Save changes
    }
    qWarning() << "Attempted to set visibility for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

bool RepositoryManager::addCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        // Only the owner of this managed entry can add collaborators
        // Ownership check should be done by the caller (MainWindow/ProjectWindow)
        // Prevent adding duplicates
        if (!m_managedRepositories[appId].collaborators.contains(peerId))
        {
            // Prevent adding the owner as a collaborator (they are implicitly a member)
            if (m_managedRepositories[appId].adminPeerId == peerId)
            {
                qWarning() << "Attempted to add owner (" << peerId << ") as collaborator to repo" << appId;
                return false; // Owner is already a member, cannot be added as collaborator
            }

            m_managedRepositories[appId].collaborators.append(peerId);
            qDebug() << "Added collaborator" << peerId << "to repo" << appId;
            emit managedRepositoryListChanged(); // Notify UI (ProjectWindow, RepoManagementPanel)
            return saveRepositoriesToFile();     // Save changes
        }
        else
        {
            qDebug() << "Peer" << peerId << "is already a collaborator for repo" << appId;
            return false; // Already exists
        }
    }
    qWarning() << "Attempted to add collaborator for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

// New method to remove a collaborator
bool RepositoryManager::removeCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        // Only the owner of this managed entry can remove collaborators
        // Ownership check should be done by the caller (MainWindow/ProjectWindow)
        // Prevent removing the owner
        if (m_managedRepositories[appId].adminPeerId == peerId)
        {
            qWarning() << "Attempted to remove owner (" << peerId << ") as collaborator from repo" << appId;
            return false; // Cannot remove owner
        }

        // Remove the peerId from the collaborators list
        int countBefore = m_managedRepositories[appId].collaborators.size();
        m_managedRepositories[appId].collaborators.removeAll(peerId); // removeAll is safe if peerId isn't in list
        int countAfter = m_managedRepositories[appId].collaborators.size();

        if (countAfter < countBefore)
        {
            qDebug() << "Removed collaborator" << peerId << "from repo" << appId;
            emit managedRepositoryListChanged(); // Notify UI
            return saveRepositoriesToFile();     // Save changes
        }
        else
        {
            qDebug() << "Peer" << peerId << "was not found in collaborator list for repo" << appId;
            return false; // Peer was not in the list
        }
    }
    qWarning() << "Attempted to remove collaborator for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfo(const QString &appId) const
{
    // Retrieve repository info by its unique App ID
    return m_managedRepositories.value(appId, ManagedRepositoryInfo()); // Return empty struct if not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByPath(const QString &localPath) const
{
    // Retrieve repository info by its local file path (canonicalized)
    const QString canonicalPath = QDir(localPath).canonicalPath();
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (QDir(repoInfo.localPath).canonicalPath() == canonicalPath)
        {
            return repoInfo; // Found
        }
    }
    return ManagedRepositoryInfo(); // Not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByDisplayName(const QString &displayName) const
{
    // Retrieve repository info by its display name
    // Note: Display names might not be unique. This returns the first one found.
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (repoInfo.displayName == displayName)
        {
            return repoInfo; // Found
        }
    }
    return ManagedRepositoryInfo(); // Not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByOrigin(const QString &originPeerId, const QString &displayName) const
{
    // Retrieve repository info based on the peer it was cloned from AND its display name.
    // Useful for finding *our local clone* of a specific repo from a specific peer.
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (repoInfo.originPeerId == originPeerId && repoInfo.displayName == displayName)
        {
            return repoInfo; // Found our local clone of this repo from this origin
        }
    }
    return ManagedRepositoryInfo(); // Not found
}

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const
{
    // Return a list of all repositories currently being managed by this peer
    return m_managedRepositories.values(); // Returns a list of all values in the map
}

// Renamed and updated logic for clarity based on how it's used by NetworkManager
QList<ManagedRepositoryInfo> RepositoryManager::getMyPubliclySharedRepositories(const QString &requestingPeer) const
{
    // Return a list of repositories *owned by this peer* that are shareable with `requestingPeer`.
    // This is used by NetworkManager to build the list of repos to announce or share with a specific peer.
    // If requestingPeer is empty (e.g., for broadcast), only globally public repos owned by me are included.
    // If requestingPeer is non-empty, public repos owned by me + private repos owned by me where requestingPeer is a collaborator are included.

    QList<ManagedRepositoryInfo> repos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        // Only consider repos that are owned by the local peer
        if (repo.adminPeerId != m_myPeerId)
        {
            continue; // Cannot share repos owned by others
        }

        bool isShareableWithThisPeer = repo.isPublic; // Always shareable if public

        // If the repo is NOT public AND a specific requesting peer was provided...
        if (!repo.isPublic && !requestingPeer.isEmpty())
        {
            // ...AND the requesting peer is listed as a collaborator...
            if (repo.collaborators.contains(requestingPeer))
            {
                isShareableWithThisPeer = true; // ...then it is shareable with THIS specific peer.
            }
        }
        // Note: For broadcasts (requestingPeer is empty), private repos owned by me
        // are only shareable if they are ALSO public (handled by the first line).

        if (isShareableWithThisPeer)
        {
            repos.append(repo);
        }
    }
    return repos;
}

QList<ManagedRepositoryInfo> RepositoryManager::getMyPrivateRepositories(const QString &myPeerId) const
{
    // Return a list of repositories owned by `myPeerId` that are NOT public.
    QList<ManagedRepositoryInfo> privateRepos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (!repo.isPublic && repo.adminPeerId == myPeerId)
        {
            privateRepos.append(repo);
        }
    }
    return privateRepos;
}

QList<ManagedRepositoryInfo> RepositoryManager::getRepositoriesIAmMemberOf(const QString &myPeerId) const
{
    // Return a list of repositories where this peer is either the owner OR a collaborator.
    // This defines the set of repos that appear in the RepoManagementPanel list.
    QList<ManagedRepositoryInfo> memberRepos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (repo.adminPeerId == myPeerId || repo.collaborators.contains(myPeerId))
        {
            memberRepos.append(repo);
        }
    }
    return memberRepos;
}

bool RepositoryManager::loadRepositoriesFromFile()
{
    QFile loadFile(m_storageFilePath);
    if (!loadFile.exists())
    {
        qDebug() << "Repository storage file not found:" << m_storageFilePath;
        m_managedRepositories.clear(); // Start fresh if file doesn't exist
        return true;                   // Not an error if file doesn't exist on first run
    }

    if (!loadFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qWarning() << "Couldn't open repository storage file for reading:" << m_storageFilePath << loadFile.errorString();
        return false;
    }
    QJsonDocument loadDoc = QJsonDocument::fromJson(loadFile.readAll());
    loadFile.close();

    if (!loadDoc.isObject())
    {
        qWarning() << "Repository storage file is not a valid JSON object:" << m_storageFilePath;
        // Optionally backup corrupted file
        m_managedRepositories.clear(); // Clear existing in-memory state on load failure
        return false;
    }

    QJsonObject json = loadDoc.object();
    m_managedRepositories.clear(); // Clear current map before loading from file
    int loadedCount = 0;
    for (const QString &key : json.keys())
    {
        QJsonValue repoValue = json[key];
        if (!repoValue.isObject())
        {
            qWarning() << "Skipping invalid entry in repo storage file for key:" << key;
            continue; // Skip malformed entry
        }

        QJsonObject repoObject = repoValue.toObject();
        ManagedRepositoryInfo repo;
        repo.appId = key; // Key is the App ID
        repo.displayName = repoObject[JSON_KEY_DISPLAY_NAME].toString();
        repo.localPath = repoObject[JSON_KEY_LOCAL_PATH].toString();
        repo.isPublic = repoObject[JSON_KEY_IS_PUBLIC].toBool(false);
        repo.adminPeerId = repoObject[JSON_KEY_ADMIN_PEER_ID].toString();   // Should always exist
        repo.originPeerId = repoObject[JSON_KEY_ORIGIN_PEER_ID].toString(); // Optional

        QJsonValue collaboratorsValue = repoObject[JSON_KEY_COLLABORATORS];
        if (collaboratorsValue.isArray())
        {
            QJsonArray collaboratorsArray = collaboratorsValue.toArray();
            for (const QJsonValue &v : collaboratorsArray)
            {
                if (v.isString())
                {
                    repo.collaborators.append(v.toString());
                }
                else
                {
                    qWarning() << "Skipping non-string collaborator entry for repo" << key;
                }
            }
        }
        else if (!collaboratorsValue.isNull() && !collaboratorsValue.isUndefined())
        {
            qWarning() << "Collaborators field is not an array for repo" << key;
            // Treat as empty list, don't fail load
        }
        // If collaboratorsValue is null or undefined, repo.collaborators remains empty (correct default)

        // Basic validation: must have an App ID and local path
        if (!repo.appId.isEmpty() && !repo.localPath.isEmpty() && !repo.adminPeerId.isEmpty())
        { // adminPeerId should also exist
            m_managedRepositories.insert(repo.appId, repo);
            loadedCount++;
        }
        else
        {
            qWarning() << "Skipping entry with missing appId, localPath, or adminPeerId in repo storage file for key:" << key;
        }
    }
    qInfo() << "Loaded" << loadedCount << "managed repositories from" << m_storageFilePath;
    emit managedRepositoryListChanged(); // Notify UI after loading
    return true;                         // Load successful (even if some entries were skipped)
}

bool RepositoryManager::saveRepositoriesToFile() const
{
    QDir dir = QFileInfo(m_storageFilePath).dir();
    if (!dir.exists())
    {
        if (!dir.mkpath("."))
        {
            qWarning() << "Could not create directory for repository storage file:" << dir.absolutePath();
            return false;
        }
    }

    QFile saveFile(m_storageFilePath);
    // Use WriteOnly, Text, and Truncate to overwrite the file
    if (!saveFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        qWarning() << "Couldn't open repository storage file for writing:" << m_storageFilePath << saveFile.errorString();
        return false;
    }

    QJsonObject json;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        QJsonObject repoObject;
        repoObject[JSON_KEY_DISPLAY_NAME] = repo.displayName;
        repoObject[JSON_KEY_LOCAL_PATH] = repo.localPath;
        repoObject[JSON_KEY_IS_PUBLIC] = repo.isPublic;
        repoObject[JSON_KEY_ADMIN_PEER_ID] = repo.adminPeerId;
        repoObject[JSON_KEY_ORIGIN_PEER_ID] = repo.originPeerId;
        repoObject[JSON_KEY_COLLABORATORS] = QJsonArray::fromStringList(repo.collaborators); // Save collaborators as JSON array of strings
        json[repo.appId] = repoObject;                                                       // Use App ID as the key in the JSON object
    }

    QJsonDocument saveDoc(json);
    qint64 bytesWritten = saveFile.write(saveDoc.toJson(QJsonDocument::Indented)); // Use Indented for readability
    saveFile.close();

    if (bytesWritten == -1)
    {
        qWarning() << "Error writing data to repository storage file:" << m_storageFilePath << saveFile.errorString();
        return false;
    }
    qDebug() << "Saved" << m_managedRepositories.size() << "managed repositories to" << m_storageFilePath;
    return true; // Save successful
}