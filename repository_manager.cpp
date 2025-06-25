#include "repository_manager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QUuid>

const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_ADMIN_PEER_ID = "adminPeerId";
const QString JSON_KEY_COLLABORATORS = "collaborators";
const QString JSON_KEY_ORIGIN_PEER_ID = "originPeerId";

RepositoryManager::RepositoryManager(const QString &storageFilePath, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath)
{
    loadRepositoriesFromFile();
}

RepositoryManager::~RepositoryManager()
{
    saveRepositoriesToFile();
}

bool RepositoryManager::addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId, const QString &originPeerId)
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
    newRepo.isPublic = isPublic;
    newRepo.adminPeerId = adminPeerId;
    newRepo.originPeerId = originPeerId;

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
        m_managedRepositories[appId].isPublic = isPublic;
        emit managedRepositoryListChanged();
        return saveRepositoriesToFile();
    }
    return false;
}

bool RepositoryManager::addCollaborator(const QString &appId, const QString &peerId)
{
    if (m_managedRepositories.contains(appId) && !m_managedRepositories[appId].collaborators.contains(peerId))
    {
        m_managedRepositories[appId].collaborators.append(peerId);
        emit managedRepositoryListChanged();
        return saveRepositoriesToFile();
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

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const
{
    return m_managedRepositories.values();
}

QList<ManagedRepositoryInfo> RepositoryManager::getMyPubliclySharedRepositories(const QString &requestingPeer) const
{
    QList<ManagedRepositoryInfo> repos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        if (repo.isPublic || repo.collaborators.contains(requestingPeer))
        {
            repos.append(repo);
        }
    }
    return repos;
}

QList<ManagedRepositoryInfo> RepositoryManager::getMyPrivateRepositories(const QString &myPeerId) const
{
    QList<ManagedRepositoryInfo> privateRepos;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        // Only return private repos that this user actually owns
        if (!repo.isPublic && repo.adminPeerId == myPeerId)
        {
            privateRepos.append(repo);
        }
    }
    return privateRepos;
}

bool RepositoryManager::loadRepositoriesFromFile()
{
    QFile loadFile(m_storageFilePath);
    if (!loadFile.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;
    QJsonDocument loadDoc = QJsonDocument::fromJson(loadFile.readAll());
    if (!loadDoc.isObject())
        return false;

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
        repo.adminPeerId = repoObject[JSON_KEY_ADMIN_PEER_ID].toString();
        repo.originPeerId = repoObject[JSON_KEY_ORIGIN_PEER_ID].toString();
        QJsonArray collaboratorsArray = repoObject[JSON_KEY_COLLABORATORS].toArray();
        for (const QJsonValue &v : collaboratorsArray)
        {
            repo.collaborators.append(v.toString());
        }
        m_managedRepositories.insert(repo.appId, repo);
    }
    emit managedRepositoryListChanged();
    return true;
}

bool RepositoryManager::saveRepositoriesToFile() const
{
    QDir dir = QFileInfo(m_storageFilePath).dir();
    if (!dir.exists())
        dir.mkpath(".");

    QFile saveFile(m_storageFilePath);
    if (!saveFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
        return false;

    QJsonObject json;
    for (const auto &repo : qAsConst(m_managedRepositories))
    {
        QJsonObject repoObject;
        repoObject[JSON_KEY_DISPLAY_NAME] = repo.displayName;
        repoObject[JSON_KEY_LOCAL_PATH] = repo.localPath;
        repoObject[JSON_KEY_IS_PUBLIC] = repo.isPublic;
        repoObject[JSON_KEY_ADMIN_PEER_ID] = repo.adminPeerId;
        repoObject[JSON_KEY_ORIGIN_PEER_ID] = repo.originPeerId;
        repoObject[JSON_KEY_COLLABORATORS] = QJsonArray::fromStringList(repo.collaborators);
        json[repo.appId] = repoObject;
    }
    saveFile.write(QJsonDocument(json).toJson(QJsonDocument::Indented));
    return true;
}