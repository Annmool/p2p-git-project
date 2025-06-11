#include "repository_manager.h" // Assumes this .h has the appId, adminPeerId, etc.
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QDir>
#include <QFileInfo> // For getting default display name
#include <QDebug>
#include <QUuid>     // For generating new appIds

// JSON Keys to match ManagedRepositoryInfo in the .h
const QString JSON_KEY_APP_ID = "appId";
const QString JSON_KEY_DISPLAY_NAME = "displayName";
const QString JSON_KEY_LOCAL_PATH = "localPath";
const QString JSON_KEY_IS_PUBLIC = "isPublic";
const QString JSON_KEY_ADMIN_PEER_ID = "adminPeerId";

RepositoryManager::RepositoryManager(const QString& storageFilePath, QObject *parent)
    : QObject(parent), m_storageFilePath(storageFilePath) {
    if (!loadRepositoriesFromFile()) {
        qWarning() << "RepositoryManager: Could not load repositories from" << storageFilePath << "- starting fresh.";
    }
}

RepositoryManager::~RepositoryManager() {
    saveRepositoriesToFile(); // Ensure data is saved on exit/destruction
}

bool RepositoryManager::addManagedRepository(const QString& localPath, const QString& displayName, bool isPublic, const QString& adminPeerId) {
    QDir dir(localPath);
    if (!dir.exists()) {
        qWarning() << "RepositoryManager: Path does not exist, cannot add:" << localPath;
        return false;
    }
    // Ensure this path isn't already managed
    for(const auto& repoInfo : qAsConst(m_managedRepositoriesMap)){
        if(repoInfo.localPath == localPath){
            qWarning() << "RepositoryManager: Repository at path" << localPath << "is already managed with ID:" << repoInfo.appId;
            return false; // Or update existing, but add implies new
        }
    }

    ManagedRepositoryInfo newRepo;
    newRepo.appId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    newRepo.localPath = QDir(localPath).absolutePath(); // Store absolute canonical path
    newRepo.displayName = displayName.isEmpty() ? QFileInfo(localPath).fileName() : displayName;
    newRepo.isPublic = isPublic;
    newRepo.adminPeerId = adminPeerId;

    m_managedRepositoriesList.append(newRepo); // Keep order for saving
    m_managedRepositoriesMap.insert(newRepo.appId, newRepo);

    qDebug() << "RepositoryManager: Added new repository:" << newRepo.displayName << "(" << newRepo.appId << ")";
    emit managedRepositoryListChanged();
    saveRepositoriesToFile();
    return true;
}

bool RepositoryManager::removeManagedRepository(const QString& appId) {
    if (m_managedRepositoriesMap.contains(appId)) {
        ManagedRepositoryInfo removedRepo = m_managedRepositoriesMap.take(appId); // Remove from map
        // Remove from list
        for (int i = 0; i < m_managedRepositoriesList.size(); ++i) {
            if (m_managedRepositoriesList[i].appId == appId) {
                m_managedRepositoriesList.removeAt(i);
                break;
            }
        }
        qDebug() << "RepositoryManager: Removed repository" << removedRepo.displayName << "(" << appId << ")";
        emit managedRepositoryListChanged();
        saveRepositoriesToFile();
        return true;
    }
    qWarning() << "RepositoryManager: Could not find repository with AppID to remove:" << appId;
    return false;
}

bool RepositoryManager::setRepositoryVisibility(const QString& appId, bool isPublic) {
    if (m_managedRepositoriesMap.contains(appId)) {
        if (m_managedRepositoriesMap[appId].isPublic != isPublic) {
            m_managedRepositoriesMap[appId].isPublic = isPublic;
            // Update in the list as well
            for (int i = 0; i < m_managedRepositoriesList.size(); ++i) {
                if (m_managedRepositoriesList[i].appId == appId) {
                    m_managedRepositoriesList[i].isPublic = isPublic;
                    break;
                }
            }
            qDebug() << "RepositoryManager: Visibility for" << m_managedRepositoriesMap[appId].displayName
                     << "set to" << (isPublic ? "Public" : "Private");
            emit repositoryMetadataUpdated(appId);
            // managedRepositoryListChanged might also be relevant if public list changes affect discovery
            emit managedRepositoryListChanged(); 
            saveRepositoriesToFile();
        }
        return true;
    }
    qWarning() << "RepositoryManager: Could not find repository with AppID to set visibility:" << appId;
    return false;
}

bool RepositoryManager::updateRepositoryDisplayName(const QString& appId, const QString& newDisplayName) {
    if (newDisplayName.isEmpty()) {
        qWarning() << "RepositoryManager: New display name cannot be empty for AppID:" << appId;
        return false;
    }
    if (m_managedRepositoriesMap.contains(appId)) {
        if (m_managedRepositoriesMap[appId].displayName != newDisplayName) {
            m_managedRepositoriesMap[appId].displayName = newDisplayName;
            // Update in the list as well
            for (int i = 0; i < m_managedRepositoriesList.size(); ++i) {
                if (m_managedRepositoriesList[i].appId == appId) {
                    m_managedRepositoriesList[i].displayName = newDisplayName;
                    break;
                }
            }
            qDebug() << "RepositoryManager: Display name for AppID" << appId << "updated to" << newDisplayName;
            emit repositoryMetadataUpdated(appId);
            saveRepositoriesToFile();
        }
        return true;
    }
    qWarning() << "RepositoryManager: Could not find repository with AppID to update name:" << appId;
    return false;
}


ManagedRepositoryInfo RepositoryManager::getRepositoryInfo(const QString& appId) const {
    return m_managedRepositoriesMap.value(appId, ManagedRepositoryInfo()); // Returns default if not found
}

ManagedRepositoryInfo RepositoryManager::getRepositoryInfoByPath(const QString& localPath) const {
    QString canonicalPath = QDir(localPath).canonicalPath(); // Ensure consistent path format
    for(const auto& repoInfo : qAsConst(m_managedRepositoriesMap)){ // Iterate map values
        if(QDir(repoInfo.localPath).canonicalPath() == canonicalPath){
            return repoInfo;
        }
    }
    return ManagedRepositoryInfo(); // Return default if not found
}

QList<ManagedRepositoryInfo> RepositoryManager::getAllManagedRepositories() const {
    return m_managedRepositoriesList; // Return the ordered list
}

QList<ManagedRepositoryInfo> RepositoryManager::getMyPubliclySharedRepositories() const {
    QList<ManagedRepositoryInfo> publicRepos;
    for (const auto& repo : qAsConst(m_managedRepositoriesList)) { // Iterate ordered list
        if (repo.isPublic) {
            publicRepos.append(repo);
        }
    }
    return publicRepos;
}

// --- Persistence ---
bool RepositoryManager::loadRepositoriesFromFile() {
    QFile loadFile(m_storageFilePath);
    if (!loadFile.exists()) {
        qDebug() << "RepositoryManager: Storage file does not exist, starting fresh:" << m_storageFilePath;
        return true; 
    }
    if (!loadFile.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "RepositoryManager: Couldn't open storage file for reading:" << loadFile.errorString();
        return false;
    }

    QByteArray saveData = loadFile.readAll();
    loadFile.close();
    QJsonDocument loadDoc(QJsonDocument::fromJson(saveData));

    if (loadDoc.isNull()) {
        qWarning() << "RepositoryManager: Failed to create JSON document from file (possibly empty or malformed):" << m_storageFilePath;
        // If the file is empty, treat as starting fresh rather than an error.
        if (saveData.isEmpty()) return true; 
        return false;
    }
    if (!loadDoc.isArray()) {
        qWarning() << "RepositoryManager: JSON root is not an array in:" << m_storageFilePath;
        return false; 
    }

    QJsonArray reposArray = loadDoc.array();
    m_managedRepositoriesList.clear();
    m_managedRepositoriesMap.clear();
    for (int i = 0; i < reposArray.size(); ++i) {
        QJsonObject repoObject = reposArray[i].toObject();
        ManagedRepositoryInfo repo;
        repo.appId = repoObject[JSON_KEY_APP_ID].toString();
        repo.localPath = repoObject[JSON_KEY_LOCAL_PATH].toString();
        repo.displayName = repoObject[JSON_KEY_DISPLAY_NAME].toString();
        repo.isPublic = repoObject[JSON_KEY_IS_PUBLIC].toBool();
        repo.adminPeerId = repoObject[JSON_KEY_ADMIN_PEER_ID].toString(); // Load adminPeerId
        
        if (!repo.appId.isEmpty() && !repo.localPath.isEmpty() && !repo.adminPeerId.isEmpty()) {
            m_managedRepositoriesList.append(repo);
            m_managedRepositoriesMap.insert(repo.appId, repo);
        } else {
            qWarning() << "RepositoryManager: Skipped loading a repo due to missing AppID, LocalPath, or AdminPeerID.";
        }
    }
    qInfo() << "RepositoryManager: Loaded" << m_managedRepositoriesList.size() << "repositories from" << m_storageFilePath;
    return true;
}

bool RepositoryManager::saveRepositoriesToFile() const {
    QFile saveFile(m_storageFilePath);
    QDir dir = QFileInfo(saveFile).dir(); // Get directory of the file
    if(!dir.exists()){
        if(!dir.mkpath(".")){ // Create the directory if it doesn't exist
            qWarning() << "RepositoryManager: Could not create directory for storage file:" << dir.path();
            return false;
        }
    }

    if (!saveFile.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        qWarning() << "RepositoryManager: Couldn't open storage file for writing:" << saveFile.errorString();
        return false;
    }

    QJsonArray reposArray;
    for (const auto& repo : qAsConst(m_managedRepositoriesList)) { // Save from the ordered list
        QJsonObject repoObject;
        repoObject[JSON_KEY_APP_ID] = repo.appId;
        repoObject[JSON_KEY_LOCAL_PATH] = repo.localPath;
        repoObject[JSON_KEY_DISPLAY_NAME] = repo.displayName;
        repoObject[JSON_KEY_IS_PUBLIC] = repo.isPublic;
        repoObject[JSON_KEY_ADMIN_PEER_ID] = repo.adminPeerId; // Save adminPeerId
        reposArray.append(repoObject);
    }
    QJsonDocument saveDoc(reposArray);
    qint64 bytesWritten = saveFile.write(saveDoc.toJson(QJsonDocument::Indented)); // Use Indented for readability
    saveFile.close();

    if(bytesWritten == -1){
         qWarning() << "RepositoryManager: Failed to write to storage file.";
        return false;
    }
    qDebug() << "RepositoryManager: Saved" << m_managedRepositoriesList.size() << "repositories to" << m_storageFilePath;
    return true;
}