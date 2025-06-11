#include "identity_manager.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio> // For std::remove

#include <QStandardPaths>
#include <QDir>
#include <QDebug> // For qDebug, qWarning, qCritical
#include <QRegExp> // For sanitizing filenames

#if defined(__linux__) || defined(__APPLE__)
#include <sys/stat.h> // For S_IRUSR, S_IWUSR, and chmod mode constants
#include <unistd.h>   // For chmod function itself
#include <cerrno>     // For errno
#include <cstring>    // For strerror
#endif

// Constructor definition matching the header
IdentityManager::IdentityManager(const QString& peerNameForPath, const std::string& appNameStdStr)
    : m_keysInitialized(false) {
    // Initialize libsodium. This should be called once before using any other libsodium functions.
    if (sodium_init() == -1) { // -1 indicates failure
        qCritical() << "IdentityManager: CRITICAL - libsodium could not be initialized! This is a critical error.";
        return; // m_keysInitialized remains false
    }

    QString appName = QString::fromStdString(appNameStdStr); // Convert appName to QString if needed internally

    QString appDataBaseLocation = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (appDataBaseLocation.isEmpty()) {
        appDataBaseLocation = QDir::homePath() + "/." + appName; // Use appName here
        qWarning() << "IdentityManager: AppLocalDataLocation empty, using fallback:" << appDataBaseLocation;
    }
    
    QDir baseAppDir(appDataBaseLocation); // This is like ~/.local/share/
    if (!baseAppDir.exists(appName)) {    // Check for YourAppName subdir, e.g., ~/.local/share/P2PGitClient
        if (!baseAppDir.mkdir(appName)) {
             qWarning() << "IdentityManager: Could not create application base directory:" << baseAppDir.filePath(appName);
             // If this fails, keys might be stored directly in appDataBaseLocation or fail. For now, continue.
        }
    }
    // Now, cd into the application-specific directory
    if (baseAppDir.cd(appName)) {
        // Successfully cd'd into appName directory
    } else {
        // If cd fails (shouldn't if mkdir succeeded or it existed), use the original appDataBaseLocation
        // This part of logic might need refinement if baseAppDir itself *is* appName
        qWarning() << "IdentityManager: Could not cd into app specific dir, using:" << appDataBaseLocation;
    }


    QString sanitizedPeerName = peerNameForPath;
    if (sanitizedPeerName.isEmpty()) {
        sanitizedPeerName = "default_identity_keys"; // A more descriptive default
    }
    // Sanitize peerNameForPath to be a valid directory name for the key's subdirectory
    sanitizedPeerName.remove(QRegExp(QStringLiteral("[^a-zA-Z0-9_.-]"))); 
    if (sanitizedPeerName.isEmpty()) {
        sanitizedPeerName = "default_sanitized_identity_keys";
    }

    // Create the peer-specific subdirectory inside the baseAppDir (which is now ~/.local/share/YourAppName/)
    if (!baseAppDir.exists(sanitizedPeerName)) {
        if (!baseAppDir.mkdir(sanitizedPeerName)) {
            qWarning() << "IdentityManager: Could not create peer-specific key directory:" << baseAppDir.filePath(sanitizedPeerName);
            // Fallback: store keys directly in the application's base data directory
            m_dataPath = baseAppDir.absolutePath().toStdString();
        } else {
             m_dataPath = baseAppDir.filePath(sanitizedPeerName).toStdString();
        }
    } else {
        m_dataPath = baseAppDir.filePath(sanitizedPeerName).toStdString();
    }

    m_publicKeyFilePath = m_dataPath + "/id_ed25519.pub";
    m_privateKeyFilePath = m_dataPath + "/id_ed25519";

    qDebug() << "IdentityManager: Key storage path set for peer '" << peerNameForPath << "' to: " << QString::fromStdString(m_dataPath);
}

IdentityManager::~IdentityManager() {
    sodium_memzero(m_privateKey, ID_SECRET_KEY_BYTES);
    sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
}

bool IdentityManager::initializeKeys() {
    if (m_keysInitialized) {
        return true;
    }

    if (loadKeyPair()) {
        m_keysInitialized = true;
        qInfo() << "IdentityManager: Successfully loaded existing key pair from" << QString::fromStdString(m_privateKeyFilePath);
        return true;
    } else {
        qInfo() << "IdentityManager: No existing key pair found or failed to load. Generating new one...";
        if (generateKeyPair()) {
            if (saveKeyPair()) {
                m_keysInitialized = true;
                qInfo() << "IdentityManager: Successfully generated and saved new key pair to" << QString::fromStdString(m_privateKeyFilePath);
                qDebug() << "My Public Key (Hex prefix):" << QString::fromStdString(getMyPublicKeyHex()).left(10) << "...";
                return true;
            } else {
                qCritical() << "IdentityManager: CRITICAL - Generated key pair but FAILED to save it.";
            }
        } else {
            qCritical() << "IdentityManager: CRITICAL - FAILED to generate key pair!";
        }
    }
    qWarning() << "IdentityManager: Keys are NOT initialized.";
    return false;
}

bool IdentityManager::generateKeyPair() {
    if (crypto_sign_keypair(m_publicKey, m_privateKey) != 0) {
        qWarning() << "IdentityManager: libsodium crypto_sign_keypair() failed.";
        return false;
    }
    return true;
}

bool IdentityManager::saveKeyPair() const {
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty()){
        qWarning() << "IdentityManager: Key file paths are not set, cannot save.";
        return false;
    }
    // Save public key
    std::ofstream pubFile(m_publicKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!pubFile.is_open()) {
        qWarning() << "IdentityManager: Could not open public key file for writing:" << QString::fromStdString(m_publicKeyFilePath) << "Error:" << strerror(errno);
        return false;
    }
    pubFile.write(reinterpret_cast<const char*>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    if (!pubFile.good()) { 
        qWarning() << "IdentityManager: Error writing to public key file:" << QString::fromStdString(m_publicKeyFilePath);
        pubFile.close();
        std::remove(m_publicKeyFilePath.c_str()); 
        return false;
    }
    pubFile.close();

    // Save private key
    std::ofstream privFile(m_privateKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!privFile.is_open()) {
        qWarning() << "IdentityManager: Could not open private key file for writing:" << QString::fromStdString(m_privateKeyFilePath) << "Error:" << strerror(errno);
        std::remove(m_publicKeyFilePath.c_str()); 
        return false;
    }
    privFile.write(reinterpret_cast<const char*>(m_privateKey), ID_SECRET_KEY_BYTES);
    if (!privFile.good()) { 
        qWarning() << "IdentityManager: Error writing to private key file:" << QString::fromStdString(m_privateKeyFilePath);
        privFile.close();
        std::remove(m_publicKeyFilePath.c_str());
        std::remove(m_privateKeyFilePath.c_str()); 
        return false;
    }
    privFile.close();

    #if defined(__linux__) || defined(__APPLE__)
    if (chmod(m_privateKeyFilePath.c_str(), S_IRUSR | S_IWUSR) != 0) { // 0600
        qWarning() << "IdentityManager: Failed to set 0600 permissions on private key file:" << QString::fromStdString(m_privateKeyFilePath)
                   << "Error:" << strerror(errno);
    }
    if (chmod(m_publicKeyFilePath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0) { // 0644 for public key
        qWarning() << "IdentityManager: Failed to set 0644 permissions on public key file:" << QString::fromStdString(m_publicKeyFilePath)
                   << "Error:" << strerror(errno);
    }
    #endif

    return true;
}

bool IdentityManager::loadKeyPair() {
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty()){
        return false; 
    }

    std::ifstream pubFile(m_publicKeyFilePath, std::ios::in | std::ios::binary);
    if (!pubFile.is_open()) {
        // This is normal if keys haven't been generated yet, so not necessarily a warning.
        // qDebug() << "IdentityManager: Public key file not found (normal on first run):" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }
    pubFile.read(reinterpret_cast<char*>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    bool pubReadOk = (pubFile.gcount() == ID_PUBLIC_KEY_BYTES);
    pubFile.close();

    if (!pubReadOk) {
        qWarning() << "IdentityManager: Failed to read complete public key from:" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }

    std::ifstream privFile(m_privateKeyFilePath, std::ios::in | std::ios::binary);
    if (!privFile.is_open()) {
        // qDebug() << "IdentityManager: Private key file not found (normal on first run):" << QString::fromStdString(m_privateKeyFilePath);
        return false;
    }
    privFile.read(reinterpret_cast<char*>(m_privateKey), ID_SECRET_KEY_BYTES);
    bool privReadOk = (privFile.gcount() == ID_SECRET_KEY_BYTES);
    privFile.close();

    if (!privReadOk) {
        qWarning() << "IdentityManager: Failed to read complete private key from:" << QString::fromStdString(m_privateKeyFilePath);
        sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
        return false;
    }

    return true;
}

std::string IdentityManager::getMyPublicKeyHex() const {
    if (!m_keysInitialized) {
        // qWarning() << "IdentityManager: Attempted to get public key, but keys are not initialized.";
        return "";
    }
    return bytesToHex(m_publicKey, ID_PUBLIC_KEY_BYTES);
}

bool IdentityManager::areKeysInitialized() const {
    return m_keysInitialized;
}

std::string IdentityManager::bytesToHex(const unsigned char* bytes, size_t size) {
    if (!bytes || size == 0) return "";
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

std::vector<unsigned char> IdentityManager::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        qWarning() << "IdentityManager::hexToBytes: Hex string must have an even number of characters.";
        return bytes;
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned long val = std::stoul(byteString, nullptr, 16);
            if (val > 255) {
                 qWarning() << "IdentityManager::hexToBytes: Hex byte value out of range:" << QString::fromStdString(byteString);
                 bytes.clear(); return bytes;
            }
            bytes.push_back(static_cast<unsigned char>(val));
        } catch (const std::exception& e) {
            qWarning() << "IdentityManager::hexToBytes: Error parsing hex byte '" << QString::fromStdString(byteString) << "':" << e.what();
            bytes.clear(); return bytes;
        }
    }
    return bytes;
}