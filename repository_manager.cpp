#include "repository_manager.h"
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo>
#include <QDebug>
#include <QUuid>
#include <algorithm> // <<< IMPROVEMENT: Include for std::remove_if

// JSON Keys to match ManagedRepositoryInfo in the .h
const QString JSON_KEY_APP_ID = "appId";
const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_ADMIN_PEER_ID = "adminPeerId";
const QString JSON_KEY_CLONED_FROM_PEER = "clonedFromPeerId";
const QString JSON_KEY_CLONED_FROM_REPO = "clonedFromRepoName";

RepositoryManager::RepositoryManager(const QString &storageFilePath, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath)
{
    if (!loadRepositoriesFromFile())
    {
        qWarning() << "RepositoryManager: Could not load repositories from" << storageFilePath << "- starting fresh.";
    }
}

RepositoryManager::~RepositoryManager()
{
    saveRepositoriesToFile();
}

bool RepositoryManager::addManagedRepository(const QString &localPath, const QString &displayName, bool isPublic, const QString &adminPeerId, const QString &clonedFromPeerId, const QString &clonedFromRepoName)
{
    QDir dir(localPath);
    if (!dir.exists())
    {
        qWarning() << "RepositoryManager: Path does not exist, cannot add:" << localPath;
        return false;
    }

    // <<< FIX: Always use the canonical path for comparison to avoid duplicates.
    const QString canonicalPath = dir.canonicalPath();

    for (const auto &repoInfo : qAsConst(m_managedRepositoriesMap))
    {
        if (repoInfo.localPath == canonicalPath)
        {
            qWarning() << "RepositoryManager: Repository at path" << localPath << "is already managed with ID:" << repoInfo.appId;
            return false;
        }
    }

    ManagedRepositoryInfo newRepo;
    newRepo.appId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    newRepo.localPath = canonicalPath; // <<< FIX: Store the canonical path.
    newRepo.displayName = displayName.isEmpty() ? QFileInfo(localPath).fileName() : displayName;
    newRepo.isPublic = isPublic;
    newRepo.adminPeerId = adminPeerId;
    newRepo.clonedFromPeerId = clonedFromPeerId;
    newRepo.clonedFromRepoName = clonedFromRepoName;

    m_managedRepositoriesList.append(newRepo);
    m_managedRepositoriesMap.insert(newRepo.appId, newRepo);

    qDebug() << "RepositoryManager: Added new repository:" << newRepo.displayName << "(" << newRepo.appId << ")";
    emit managedRepositoryListChanged();
    saveRepositoriesToFile();
    return true;
}

bool RepositoryManager::removeManagedRepository(const QString &appId)
{
    if (!m_managedRepositoriesMap.contains(appId))
    {
        qWarning() << "RepositoryManager: Could not find repository with AppID to remove:" << appId;
        return false;
    }

    ManagedRepositoryInfo removedRepo = m_managedRepositoriesMap.take(appId);

    // <<< IMPROVEMENT: Use modern C++ `std::remove_if` for cleaner, safer removal from the list.
    auto new_end = std::remove_if(m_managedRepositoriesList.begin(), m_managedRepositoriesList.end(),
                                  [&](const ManagedRepositoryInfo &repo)
                                  {
                                      return repo.appId == appId;
                                  });
    m_managedRepositoriesList.erase(new_end, m_managedRepositoriesList.end());

    qDebug() << "RepositoryManager: Removed repository" << removedRepo.displayName << "(" << appId << ")";
    emit managedRepositoryListChanged();
    saveRepositoriesToFile();
    return true;
}

bool RepositoryManager::setRepositoryVisibility(const QString &appId, bool isPublic)
{
    if (!m_managedRepositoriesMap.contains(appId))
        return false;

    // Update the primary data source (the map)
    if (m_managedRepositoriesMap[appId].isPublic == isPublic)
        return true; // No change needed
    m_managedRepositoriesMap[appId].isPublic = isPublic;

    // <<< IMPROVEMENT: Use a range-based for loop with a reference to safely update the list.
    for (auto &repo : m_managedRepositoriesList)
    {
        if (repo.appId == appId)
        {
            repo.isPublic = isPublic;
            break;
        }
    }

    qDebug() << "RepositoryManager: Visibility for" << m_managedRepositoriesMap[appId].displayName
             << "set to" << (isPublic ? "Public" : "Private");
    emit managedRepositoryListChanged(); // Use this to signal UI and network layer
    saveRepositoriesToFile();
    return true;
}

bool RepositoryManager::updateRepositoryDisplayName(const QString &appId, const QString &newDisplayName)
{
    if (newDisplayName.isEmpty() || !m_managedRepositoriesMap.contains(appId))
        return false;

    if (m_managedRepositoriesMap[appId].displayName == newDisplayName)
        return true; // No change needed
    m_managedRepositoriesMap[appId].displayName = newDisplayName;

    // <<< IMPROVEMENT: Use a range-based for loop with a reference to safely update the list.
    for (auto &repo : m_managedRepositoriesList)
    {
        if (repo.appId == appId)
        {
            repo.displayName = newDisplayName;
            break;
        }
    }

    qDebug() << "RepositoryManager: Display name for AppID" << appId << "updated to" << newDisplayName;
    emit managedRepositoryListChanged();
    saveRepositoriesToFile();
    return true;
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfo(const QString &appId) const
{
    return m_managedRepositoriesMap.value(appId, ManagedRepositoryInfo());
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByPath(const QString &localPath) const
{
    // <<< FIX: Use canonical path for lookup to ensure correctness.
    const QString canonicalPath = QDir(localPath).canonicalPath();
    for (const auto &repoInfo : qAsConst(m_managedRepositoriesMap))
    {
        if (repoInfo.localPath == canonicalPath)
        {
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo();
}

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const
{
    return m_managedRepositoriesList;
}

QList<ManagedRepositoryInfo> RepositoryManager::getMyPubliclySharedRepositories() const
{
    QList<ManagedRepositoryInfo> publicRepos;
    for (const auto &repo : qAsConst(m_managedRepositoriesList))
    {
        if (repo.isPublic)
        {
            publicRepos.append(repo);
        }
    }
    return publicRepos;
}

// --- Persistence ---
bool RepositoryManager::loadRepositoriesFromFile()
{
    QFile loadFile(m_storageFilePath);
    if (!loadFile.exists())
    {
        return true;
    }
    if (!loadFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        qWarning() << "RepositoryManager: Couldn't open storage file for reading:" << loadFile.errorString();
        return false;
    }

    QJsonDocument loadDoc = QJsonDocument::fromJson(loadFile.readAll());
    loadFile.close();

    if (!loadDoc.isArray())
    {
        qWarning() << "RepositoryManager: JSON root is not an array in:" << m_storageFilePath;
        return false;
    }

    m_managedRepositoriesList.clear();
    m_managedRepositoriesMap.clear();
    for (const QJsonValue &val : loadDoc.array())
    {
        QJsonObject repoObject = val.toObject();
        ManagedRepositoryInfo repo;
        repo.appId = repoObject[JSON_KEY_APP_ID].toString();
        repo.localPath = repoObject[JSON_KEY_LOCAL_PATH].toString();
        repo.displayName = repoObject[JSON_KEY_DISPLAY_NAME].toString();
        repo.isPublic = repoObject[JSON_KEY_IS_PUBLIC].toBool();
        repo.adminPeerId = repoObject[JSON_KEY_ADMIN_PEER_ID].toString();
        repo.clonedFromPeerId = repoObject[JSON_KEY_CLONED_FROM_PEER].toString();
        repo.clonedFromRepoName = repoObject[JSON_KEY_CLONED_FROM_REPO].toString();

        // <<< IMPROVEMENT: More lenient check for backwards compatibility
        if (!repo.appId.isEmpty() && !repo.localPath.isEmpty())
        {
            m_managedRepositoriesList.append(repo);
            m_managedRepositoriesMap.insert(repo.appId, repo);
        }
        else
        {
            qWarning() << "RepositoryManager: Skipped loading a repo due to missing AppID or LocalPath.";
        }
    }
    qInfo() << "RepositoryManager: Loaded" << m_managedRepositoriesList.size() << "repositories from" << m_storageFilePath;
    return true;
}

bool RepositoryManager::saveRepositoriesToFile() const
{
    QFile saveFile(m_storageFilePath);
    QDir dir = QFileInfo(saveFile).dir();
    if (!dir.exists() && !dir.mkpath("."))
    {
        qWarning() << "RepositoryManager: Could not create directory for storage file:" << dir.path();
        return false;
    }

    if (!saveFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        qWarning() << "RepositoryManager: Couldn't open storage file for writing:" << saveFile.errorString();
        return false;
    }

    QJsonArray reposArray;
    for (const auto &repo : qAsConst(m_managedRepositoriesList))
    {
        QJsonObject repoObject;
        repoObject[JSON_KEY_APP_ID] = repo.appId;
        repoObject[JSON_KEY_LOCAL_PATH] = repo.localPath;
        repoObject[JSON_KEY_DISPLAY_NAME] = repo.displayName;
        repoObject[JSON_KEY_IS_PUBLIC] = repo.isPublic;
        repoObject[JSON_KEY_ADMIN_PEER_ID] = repo.adminPeerId;
        repoObject[JSON_KEY_CLONED_FROM_PEER] = repo.clonedFromPeerId;
        repoObject[JSON_KEY_CLONED_FROM_REPO] = repo.clonedFromRepoName;
        reposArray.append(repoObject);
    }
    saveFile.write(QJsonDocument(reposArray).toJson(QJsonDocument::Indented));
    saveFile.close();
    qDebug() << "RepositoryManager: Saved" << m_managedRepositoriesList.size() << "repositories to" << m_storageFilePath;
    return true;
}