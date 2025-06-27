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

// JSON Keys imported from header

RepositoryManager::RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath), m_myPeerId(myPeerId)
{
    // Metatypes are declared in the header outside class scope, no need to re-declare here
    // qRegisterMetaType<ManagedRepositoryInfo>("ManagedRepositoryInfo");
    // qRegisterMetaType<QList<ManagedRepositoryInfo>>("QList<ManagedRepositoryInfo>");

    loadRepositoriesFromFile();
}

RepositoryManager::~RepositoryManager()
{
    saveRepositoriesToFile();
}

// Updated add method
bool RepositoryManager::addManagedRepository(const QString &displayName, const QString &localPath, bool isPublic, const QString &ownerPeerId, const QString &ownerRepoAppId, const QStringList &initialGroupMembers, bool isOwner)
{
    // Use canonical path
    QString canonicalPath = QDir(localPath).canonicalPath();

    // Check if a repository with the *same local path* already exists
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (QDir(repo.localPath).canonicalPath() == canonicalPath)
        {
            qWarning() << "Repository at path" << localPath << "is already managed (by path).";
            return false; // Already exists by path
        }
    }

    // Check if a repository with the *same owner's app ID* already exists (for clones/group members)
    // This uniquely identifies the group from the owner's perspective.
    if (!isOwner)
    {
        for (const auto &repo : qAsConst(m_managedRepositories))
        {
            if (!repo.isOwner && repo.ownerRepoAppId == ownerRepoAppId)
            {
                qWarning() << "Repository with owner's App ID" << ownerRepoAppId << "is already managed (as a clone).";
                return false; // Already exists as a clone of this specific repo group
            }
        }
    }
    // If isOwner is true, the ownerRepoAppId is the *new* appId being generated, so this check isn't needed.
    // Also, we allow multiple *different* repos from the same owner with the same display name,
    // but they will have different ownerRepoAppIds.

    ManagedRepositoryInfo newRepo;
    newRepo.appId = QUuid::createUuid().toString(QUuid::WithoutBraces); // Generate unique LOCAL ID
    newRepo.localPath = canonicalPath;
    newRepo.displayName = displayName;
    newRepo.isPublic = isPublic; // My setting for my repos, always false for clones added via clone action
    newRepo.ownerPeerId = ownerPeerId;
    newRepo.ownerRepoAppId = ownerRepoAppId;    // Store the owner's App ID for this repo
    newRepo.groupMembers = initialGroupMembers; // Should contain owner + known members
    newRepo.isOwner = isOwner;                  // Is THIS peer the owner?

    // If this peer is the owner, their own appId is the ownerRepoAppId
    if (newRepo.isOwner)
    {
        newRepo.ownerRepoAppId = newRepo.appId; // Set ownerRepoAppId to its own appId
        // Ensure owner is in the groupMembers list
        if (!newRepo.groupMembers.contains(m_myPeerId))
        {
            newRepo.groupMembers.append(m_myPeerId);
        }
    }
    else
    {
        // If not owner, initial public status is false
        newRepo.isPublic = false;
        // The initial groupMembers might come from the clone source (COLLABORATOR_ADDED message),
        // or just contain the owner and self initially.
        // Ensure self is in the groupMembers list for a clone
        if (!newRepo.groupMembers.contains(m_myPeerId))
        {
            newRepo.groupMembers.append(m_myPeerId);
        }
    }

    m_managedRepositories.insert(newRepo.appId, newRepo);
    qDebug() << "Added managed repository:" << newRepo.displayName << " (" << newRepo.appId << ") Owner:" << newRepo.ownerPeerId << "OwnerAppId:" << newRepo.ownerRepoAppId << "IsOwner:" << newRepo.isOwner;

    emit managedRepositoryListChanged();
    return saveRepositoriesToFile();
}

bool RepositoryManager::removeManagedRepository(const QString &appId)
{
    if (m_managedRepositories.contains(appId))
    {
        QString repoName = m_managedRepositories.value(appId).displayName;
        if (m_managedRepositories.remove(appId) > 0)
        {
            qDebug() << "Removed managed repository:" << repoName << " (" << appId << ")";
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
    }
    qWarning() << "Attempted to remove non-existent repository with App ID:" << appId;
    return false;
}

// Set visibility (only if I am the owner)
bool RepositoryManager::setRepositoryVisibility(const QString &appId, bool isPublic)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId];
        // Only the owner of this managed entry can change visibility
        if (!repo.isOwner)
        {
            qWarning() << "Attempted to set visibility for repo" << appId << "but local peer is not the owner.";
            return false;
        }

        if (repo.isPublic != isPublic)
        {
            repo.isPublic = isPublic;
            qDebug() << "Set visibility for owned repo" << appId << "to public:" << isPublic;
            emit managedRepositoryListChanged(); // Notify UI
            return saveRepositoriesToFile();     // Save changes
        }
        else
        {
            qDebug() << "Visibility for owned repo" << appId << "already set to" << isPublic;
            return true; // No change needed
        }
    }
    qWarning() << "Attempted to set visibility for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

// Add a peer to the groupMembers list (only if I am the owner)
bool RepositoryManager::addCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId]; // Get a mutable reference
        // Only the owner can add collaborators to their repo
        if (!repo.isOwner)
        {
            qWarning() << "Attempted to add collaborator to repo" << appId << "but local peer is not the owner.";
            return false;
        }

        if (!repo.groupMembers.contains(peerId))
        {
            repo.groupMembers.append(peerId);
            qDebug() << "Added collaborator" << peerId << "to repo" << appId << " (owner:" << repo.ownerPeerId << ")";
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
        else
        {
            qDebug() << "Peer" << peerId << "is already a group member for repo" << appId;
            return false; // Already exists
        }
    }
    qWarning() << "Attempted to add collaborator for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

// Remove a peer from the groupMembers list (only if I am the owner)
bool RepositoryManager::removeCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId]; // Get a mutable reference
                                                                    // Only the owner can remove collaborators from their repo
        if (!repo.isOwner)
        {
            qWarning() << "Attempted to remove collaborator from repo" << appId << "but local peer is not the owner.";
            return false;
        }

        // Cannot remove the owner
        if (repo.ownerPeerId == peerId)
        {
            qWarning() << "Attempted to remove owner (" << peerId << ") from group members list for repo" << appId;
            return false;
        }

        int countBefore = repo.groupMembers.size();
        repo.groupMembers.removeAll(peerId);
        int countAfter = repo.groupMembers.size();

        if (countAfter < countBefore)
        {
            qDebug() << "Removed collaborator" << peerId << "from repo" << appId;
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
        else
        {
            qDebug() << "Peer" << peerId << "was not found in group members list for repo" << appId;
            return false; // Peer was not in the list
        }
    }
    qWarning() << "Attempted to remove collaborator for non-existent repository with App ID:" << appId;
    return false; // Repo not found
}

// Update group members list and ownerRepoAppId (used by cloner when receiving updates from owner)
bool RepositoryManager::updateGroupMembersAndOwnerAppId(const QString &localAppId, const QString &ownerRepoAppId, const QStringList &newGroupMembers)
{
    if (m_managedRepositories.contains(localAppId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[localAppId]; // Get a mutable reference
        // This method is specifically for updating info on a *clone* entry
        if (repo.isOwner)
        {
            qWarning() << "Attempted to update group members/owner appId on an owned repo" << localAppId << "using updateGroupMembersAndOwnerAppId method.";
            return false;
        }

        bool changed = false;
        if (repo.groupMembers != newGroupMembers)
        {
            repo.groupMembers = newGroupMembers;
            changed = true;
            qDebug() << "Updated group members for repo" << localAppId << " (owner:" << repo.ownerPeerId << ")";
        }

        // Update ownerRepoAppId if it's different or was empty
        if (repo.ownerRepoAppId.isEmpty() || repo.ownerRepoAppId != ownerRepoAppId)
        {
            repo.ownerRepoAppId = ownerRepoAppId;
            changed = true;
            qDebug() << "Updated ownerRepoAppId for repo" << localAppId << "to" << ownerRepoAppId;
        }

        if (changed)
        {
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
        else
        {
            qDebug() << "Group members and ownerRepoAppId for repo" << localAppId << "are already up to date.";
            return false; // No change needed
        }
    }
    qWarning() << "Attempted to update group members/owner appId for non-existent repository with local App ID:" << localAppId;
    return false; // Repo not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfo(const QString &appId) const
{
    return m_managedRepositories.value(appId, ManagedRepositoryInfo());
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByPath(const QString &localPath) const
{
    const QString canonicalPath = QDir(localPath).canonicalPath();
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (QDir(repoInfo.localPath).canonicalPath() == canonicalPath)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByDisplayName(const QString &displayName) const
{
    // Return the first matching entry by display name
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (repoInfo.displayName == displayName)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

// New retrieval for clones based on owner and display name
ManagedRepositoryInfo RepositoryManager::getCloneInfoByOwnerAndDisplayName(const QString &ownerPeerId, const QString &displayName) const
{
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (!repoInfo.isOwner && repoInfo.ownerPeerId == ownerPeerId && repoInfo.displayName == displayName)
        {
            return repoInfo; // Found our local clone of this repo from this owner
        }
    }
    return ManagedRepositoryInfo(); // Not found
}

// Get info by the owner's App ID (useful for finding our local entry for a group)
ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByOwnerAppId(const QString &ownerRepoAppId) const
{
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        // The ownerRepoAppId is the common group identifier
        if (repoInfo.ownerRepoAppId == ownerRepoAppId)
        {
            return repoInfo; // Found our local entry for this group
        }
    }
    return ManagedRepositoryInfo(); // Not found
}

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const
{
    return m_managedRepositories.values();
}

// Get repos owned by THIS peer that are publicly shareable
QList<ManagedRepositoryInfo> RepositoryManager::getMyPubliclyShareableRepos() const
{
    QList<ManagedRepositoryInfo> repos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (repo.isOwner && repo.isPublic)
        {
            repos.append(repo);
        }
    }
    return repos;
}

// Get repos where THIS peer is the owner OR a group member
QList<ManagedRepositoryInfo> RepositoryManager::getRepositoriesIAmMemberOf() const
{
    QList<ManagedRepositoryInfo> memberRepos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        // Check if myPeerId is in the groupMembers list.
        // Since addManagedRepository for owners ensures the owner is in the list,
        // and updateGroupMembersAndOwnerAppId for clones ensures self is in the list,
        // checking groupMembers.contains(m_myPeerId) is sufficient for membership.
        if (repo.groupMembers.contains(m_myPeerId))
        {
            memberRepos.append(repo);
        }
    }
    // Sort the list before returning
    std::sort(memberRepos.begin(), memberRepos.end(), [](const ManagedRepositoryInfo &a, const ManagedRepositoryInfo &b)
              {
                  // Sort owners first, then alphabetically by display name
                  if (a.isOwner != b.isOwner) return a.isOwner > b.isOwner;
                  return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0; });

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
        repo.appId = key; // Key is the LOCAL App ID

        // Load basic info
        repo.displayName = repoObject[JSON_KEY_DISPLAY_NAME].toString();
        repo.localPath = repoObject[JSON_KEY_LOCAL_PATH].toString();
        repo.isPublic = repoObject[JSON_KEY_IS_PUBLIC].toBool(false);
        repo.ownerPeerId = repoObject[JSON_KEY_OWNER_PEER_ID].toString();
        repo.ownerRepoAppId = repoObject[JSON_KEY_OWNER_REPO_APP_ID].toString(); // Load owner's App ID

        // Determine isOwner based on loaded ownerPeerId and myPeerId
        repo.isOwner = (repo.ownerPeerId == m_myPeerId);

        // Load group members list
        QJsonValue groupMembersValue = repoObject[JSON_KEY_GROUP_MEMBERS];
        if (groupMembersValue.isArray())
        {
            QJsonArray groupMembersArray = groupMembersValue.toArray();
            for (const QJsonValue &v : groupMembersArray)
            {
                if (v.isString())
                {
                    repo.groupMembers.append(v.toString());
                }
                else
                {
                    qWarning() << "Skipping non-string group member entry for repo" << key;
                }
            }
        }
        else if (!groupMembersValue.isNull() && !groupMembersValue.isUndefined())
        {
            qWarning() << "Group members field is not an array for repo" << key;
        }

        // Basic validation: must have an App ID, local path, and ownerPeerId
        if (!repo.appId.isEmpty() && !repo.localPath.isEmpty() && !repo.ownerPeerId.isEmpty())
        {
            // Ensure ownerRepoAppId is set correctly for owned repos after loading
            if (repo.isOwner && repo.ownerRepoAppId.isEmpty())
            {
                repo.ownerRepoAppId = repo.appId; // Owner's App ID is their own local ID
                qWarning() << "Corrected missing ownerRepoAppId for owned repo:" << repo.displayName << "(" << repo.appId << ")";
            }
            // Ensure myPeerId is in groupMembers for this repo (consistency)
            if (!repo.groupMembers.contains(m_myPeerId))
            {
                repo.groupMembers.append(m_myPeerId);
                qWarning() << "Added self to group members list for repo:" << repo.displayName << "(" << repo.appId << ")";
            }

            m_managedRepositories.insert(repo.appId, repo);
            loadedCount++;
        }
        else
        {
            qWarning() << "Skipping entry with missing appId, localPath, or ownerPeerId in repo storage file for key:" << key;
        }
    }
    qInfo() << "Loaded" << loadedCount << "managed repositories from" << m_storageFilePath;
    // No emit managedRepositoryListChanged() here, MainWindow will call updateUiFromBackend after construction

    // Re-save if any corrections were made during loading (e.g., missing ownerRepoAppId or self in groupMembers)
    if (loadedCount != json.size())
    {                             // Simple check if some entries were skipped/invalid
        saveRepositoriesToFile(); // Save valid entries
    }

    return true;
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
        repoObject[JSON_KEY_OWNER_PEER_ID] = repo.ownerPeerId;
        repoObject[JSON_KEY_OWNER_REPO_APP_ID] = repo.ownerRepoAppId; // Save owner's App ID
        repoObject[JSON_KEY_GROUP_MEMBERS] = QJsonArray::fromStringList(repo.groupMembers);
        repoObject[JSON_KEY_IS_OWNER_FLAG] = repo.isOwner; // Explicitly save flag for clarity/validation

        json[repo.appId] = repoObject; // Use LOCAL App ID as the key in the JSON object
    }

    QJsonDocument saveDoc(json);
    qint64 bytesWritten = saveFile.write(saveDoc.toJson(QJsonDocument::Indented));
    saveFile.close();

    if (bytesWritten == -1)
    {
        qWarning() << "Error writing data to repository storage file:" << m_storageFilePath << saveFile.errorString();
        return false;
    }
    qDebug() << "Saved" << m_managedRepositories.size() << "managed repositories to" << m_storageFilePath;
    return true; // Save successful
}