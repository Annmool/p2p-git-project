#include "repository_manager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QUuid>
#include <algorithm>

const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_OWNER_PEER_ID = "ownerPeerId";
const QString JSON_KEY_OWNER_REPO_APP_ID = "ownerRepoAppId";
const QString JSON_KEY_GROUP_MEMBERS = "groupMembers";
const QString JSON_KEY_IS_OWNER_FLAG = "isOwnerFlag";
const QString JSON_KEY_ROLE_FOR_USER = "roleForUser"; // persisted human-readable role for the current user

RepositoryManager::RepositoryManager(const QString &storageFilePath, const QString &myPeerId, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath), m_myPeerId(myPeerId)
{
    loadRepositoriesFromFile();
}

RepositoryManager::~RepositoryManager()
{
    saveRepositoriesToFile();
}

bool RepositoryManager::addManagedRepository(const QString &displayName, const QString &localPath, bool isPublic, const QString &ownerPeerId, const QString &ownerRepoAppId, const QStringList &initialGroupMembers, bool isOwner)
{
    QString canonicalPath = QDir(localPath).canonicalPath();
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (QDir(repo.localPath).canonicalPath() == canonicalPath)
        {
            qWarning() << "Repository at path" << localPath << "is already managed.";
            return false;
        }
    }

    ManagedRepositoryInfo newRepo;
    newRepo.appId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    newRepo.localPath = canonicalPath;
    newRepo.displayName = displayName;
    newRepo.ownerPeerId = ownerPeerId;
    newRepo.groupMembers = initialGroupMembers;
    newRepo.isOwner = isOwner;

    if (newRepo.isOwner)
    {
        newRepo.ownerRepoAppId = newRepo.appId;
        newRepo.isPublic = isPublic;
        if (!newRepo.groupMembers.contains(m_myPeerId))
        {
            newRepo.groupMembers.append(m_myPeerId);
        }
    }
    else
    {
        newRepo.ownerRepoAppId = ownerRepoAppId;
        newRepo.isPublic = false;
        if (!newRepo.groupMembers.contains(m_myPeerId))
        {
            newRepo.groupMembers.append(m_myPeerId);
        }
    }

    m_managedRepositories.insert(newRepo.appId, newRepo);
    emit managedRepositoryListChanged();
    return saveRepositoriesToFile();
}

bool RepositoryManager::removeManagedRepository(const QString &appId)
{
    if (m_managedRepositories.remove(appId) > 0)
    {
        emit managedRepositoryListChanged();
        return saveRepositoriesToFile();
    }
    return false;
}

bool RepositoryManager::setRepositoryVisibility(const QString &appId, bool isPublic)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId];
        if (!repo.isOwner)
            return false;
        repo.isPublic = isPublic;
        emit managedRepositoryListChanged();
        return saveRepositoriesToFile();
    }
    return false;
}

bool RepositoryManager::addCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId];
        if (!repo.isOwner)
            return false;
        if (!repo.groupMembers.contains(peerId))
        {
            repo.groupMembers.append(peerId);
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
    }
    return false;
}

bool RepositoryManager::removeCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[appId];
        if (!repo.isOwner || repo.ownerPeerId == peerId)
            return false;
        if (repo.groupMembers.removeAll(peerId) > 0)
        {
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
    }
    return false;
}

bool RepositoryManager::updateGroupMembersAndOwnerAppId(const QString &localAppId, const QString &ownerRepoAppId, const QStringList &newGroupMembers)
{
    if (m_managedRepositories.contains(localAppId))
    {
        ManagedRepositoryInfo &repo = m_managedRepositories[localAppId];
        if (repo.isOwner)
            return false;

        bool changed = false;
        if (repo.groupMembers != newGroupMembers)
        {
            repo.groupMembers = newGroupMembers;
            changed = true;
        }
        if (repo.ownerRepoAppId != ownerRepoAppId)
        {
            repo.ownerRepoAppId = ownerRepoAppId;
            changed = true;
        }

        if (changed)
        {
            emit managedRepositoryListChanged();
            return saveRepositoriesToFile();
        }
    }
    return false;
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
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (repoInfo.displayName == displayName)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

ManagedRepositoryInfo RepositoryManager::getCloneInfoByOwnerAndDisplayName(const QString &ownerPeerId, const QString &displayName) const
{
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (!repoInfo.isOwner && repoInfo.ownerPeerId == ownerPeerId && repoInfo.displayName == displayName)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByOwnerAppId(const QString &ownerRepoAppId) const
{
    for (const auto &repoInfo : qAsConst(m_managedRepositories))
    {
        if (repoInfo.ownerRepoAppId == ownerRepoAppId)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const
{
    return m_managedRepositories.values();
}

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

QList<ManagedRepositoryInfo> RepositoryManager::getRepositoriesIAmMemberOf() const
{
    QList<ManagedRepositoryInfo> memberRepos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (repo.groupMembers.contains(m_myPeerId))
        {
            memberRepos.append(repo);
        }
    }
    std::sort(memberRepos.begin(), memberRepos.end(), [](const ManagedRepositoryInfo &a, const ManagedRepositoryInfo &b)
              {
                  if (a.isOwner != b.isOwner) return a.isOwner > b.isOwner;
                  return a.displayName.compare(b.displayName, Qt::CaseInsensitive) < 0; });
    return memberRepos;
}

bool RepositoryManager::loadRepositoriesFromFile()
{
    QFile loadFile(m_storageFilePath);
    if (!loadFile.exists())
    {
        return true;
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
        return false;
    }

    QJsonObject json = loadDoc.object();
    m_managedRepositories.clear();
    for (const QString &key : json.keys())
    {
        QJsonObject repoObject = json[key].toObject();
        ManagedRepositoryInfo repo;
        repo.appId = key;
        repo.displayName = repoObject[JSON_KEY_DISPLAY_NAME].toString();
        repo.localPath = repoObject[JSON_KEY_LOCAL_PATH].toString();
        repo.isPublic = repoObject[JSON_KEY_IS_PUBLIC].toBool(false);
        repo.ownerPeerId = repoObject[JSON_KEY_OWNER_PEER_ID].toString();
        repo.ownerRepoAppId = repoObject[JSON_KEY_OWNER_REPO_APP_ID].toString();
        repo.isOwner = (repo.ownerPeerId == m_myPeerId);
        // Backfill a readable role string for convenience in logs/UI
        QString role = repo.isOwner ? "Owner" : (repo.groupMembers.contains(m_myPeerId) ? "Collaborator" : "None");
        Q_UNUSED(role);

        QJsonArray groupMembersArray = repoObject[JSON_KEY_GROUP_MEMBERS].toArray();
        for (const QJsonValue &v : groupMembersArray)
        {
            repo.groupMembers.append(v.toString());
        }

        m_managedRepositories.insert(repo.appId, repo);
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
        repoObject[JSON_KEY_OWNER_REPO_APP_ID] = repo.ownerRepoAppId;
        repoObject[JSON_KEY_GROUP_MEMBERS] = QJsonArray::fromStringList(repo.groupMembers);
        repoObject[JSON_KEY_IS_OWNER_FLAG] = repo.isOwner;
        repoObject[JSON_KEY_ROLE_FOR_USER] = repo.isOwner ? "Owner" : (repo.groupMembers.contains(m_myPeerId) ? "Collaborator" : "None");

        json[repo.appId] = repoObject;
    }

    saveFile.write(QJsonDocument(json).toJson(QJsonDocument::Indented));
    saveFile.close();
    return true;
}