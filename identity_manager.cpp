#include "identity_manager.h"
#include <fstream>      // For std::ofstream, std::ifstream
#include <sstream>      // For std::stringstream (hex conversion)
#include <iomanip>      // For std::setw, std::setfill (hex conversion)
#include <cstdio>       // For std::remove (deleting public key on private key save failure)

#include <QStandardPaths> // For getting a writable application data location
#include <QDir>           // For creating directories
#include <QDebug>         // For Qt-style logging (qDebug, qWarning, qCritical)

// For chmod POSIX call
#if defined(__linux__) || defined(__APPLE__) // Common POSIX systems
#include <sys/stat.h> // For S_IRUSR, S_IWUSR, and chmod mode constants
#include <unistd.h>   // For chmod function itself
#include <cerrno>     // For errno
#include <cstring>    // For strerror
#endif

IdentityManager::IdentityManager(const std::string& dataPathSubdir) // Changed param name for clarity
    : m_keysInitialized(false) {
    // Initialize libsodium. This should be called once before using any other libsodium functions.
    if (sodium_init() == -1) { // -1 indicates failure
        qCritical() << "FATAL: libsodium could not be initialized! This is a critical error.";
        // Application may not function correctly without cryptography.
        // Consider throwing an exception or setting a critical error flag.
        return; // m_keysInitialized remains false
    }

    QString appDataLocation = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (appDataLocation.isEmpty()) {
        // Fallback if AppLocalDataLocation is not available (e.g., very minimal environment)
        appDataLocation = QDir::homePath() + "/." + QString::fromStdString(dataPathSubdir);
        qWarning() << "IdentityManager: Could not find standard AppLocalDataLocation, falling back to home directory:" << appDataLocation;
    } else {
        // Append our application/identity specific subdirectory
        appDataLocation += "/" + QString::fromStdString(dataPathSubdir);
    }

    QDir dataDir(appDataLocation);
    if (!dataDir.exists()) {
        if (!dataDir.mkpath(".")) { // "." means create the path stored in dataDir
            qWarning() << "IdentityManager: Could not create data directory:" << appDataLocation;
            // Keys will likely fail to save/load, m_keysInitialized will stay false.
            return;
        }
    }
    m_dataPath = dataDir.absolutePath().toStdString(); // Use absolute path
    m_publicKeyFilePath = m_dataPath + "/id_sign.pub";  // Using .sign to indicate signing key type
    m_privateKeyFilePath = m_dataPath + "/id_sign";     // Private key

    qDebug() << "IdentityManager: Key storage path set to:" << QString::fromStdString(m_dataPath);
}

IdentityManager::~IdentityManager() {
    // For m_privateKey and m_publicKey (which are stack arrays of unsigned char),
    // libsodium recommends sodium_memzero to wipe them if they held sensitive data.
    // This is good practice, though effectiveness depends on compiler optimizations.
    sodium_memzero(m_privateKey, SECRET_KEY_BYTES);
    sodium_memzero(m_publicKey, PUBLIC_KEY_BYTES);
    // Note: If these were dynamically allocated with sodium_malloc, you'd use sodium_free.
}

bool IdentityManager::initializeKeys() {
    if (m_keysInitialized) {
        return true;
    }

    if (loadKeyPair()) {
        m_keysInitialized = true;
        qInfo() << "IdentityManager: Successfully loaded existing key pair.";
        qDebug() << "My Public Key (Hex):" << QString::fromStdString(getMyPublicKeyHex()).left(16) << "..."; // Log only a prefix
        return true;
    } else {
        qInfo() << "IdentityManager: No existing key pair found or failed to load. Generating new one...";
        if (generateKeyPair()) {
            if (saveKeyPair()) {
                m_keysInitialized = true;
                qInfo() << "IdentityManager: Successfully generated and saved new key pair.";
                qDebug() << "My Public Key (Hex):" << QString::fromStdString(getMyPublicKeyHex()).left(16) << "...";
                return true;
            } else {
                qWarning() << "IdentityManager: CRITICAL - Generated key pair but FAILED to save it to" << QString::fromStdString(m_privateKeyFilePath);
            }
        } else {
            qWarning() << "IdentityManager: CRITICAL - FAILED to generate key pair!";
        }
    }
    qWarning() << "IdentityManager: Keys are NOT initialized.";
    return false;
}

bool IdentityManager::generateKeyPair() {
    // crypto_sign_keypair generates a key pair for digital signatures (e.g., Ed25519)
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
        qWarning() << "IdentityManager: Could not open public key file for writing:" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }
    pubFile.write(reinterpret_cast<const char*>(m_publicKey), PUBLIC_KEY_BYTES);
    if (!pubFile.good()) { // Check for write errors
        qWarning() << "IdentityManager: Error writing to public key file:" << QString::fromStdString(m_publicKeyFilePath);
        pubFile.close();
        std::remove(m_publicKeyFilePath.c_str()); // Attempt cleanup
        return false;
    }
    pubFile.close();

    // Save private key
    std::ofstream privFile(m_privateKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!privFile.is_open()) {
        qWarning() << "IdentityManager: Could not open private key file for writing:" << QString::fromStdString(m_privateKeyFilePath);
        std::remove(m_publicKeyFilePath.c_str()); // Cleanup: remove public key if private key saving fails
        return false;
    }
    privFile.write(reinterpret_cast<const char*>(m_privateKey), SECRET_KEY_BYTES);
    if (!privFile.good()) { // Check for write errors
        qWarning() << "IdentityManager: Error writing to private key file:" << QString::fromStdString(m_privateKeyFilePath);
        privFile.close();
        std::remove(m_publicKeyFilePath.c_str());
        std::remove(m_privateKeyFilePath.c_str()); // Attempt cleanup
        return false;
    }
    privFile.close();

    // Set strict permissions for private key file (0600: owner read/write, no access for group/others)
    #if defined(__linux__) || defined(__APPLE__)
    if (chmod(m_privateKeyFilePath.c_str(), S_IRUSR | S_IWUSR) != 0) {
        qWarning() << "IdentityManager: Failed to set 0600 permissions on private key file:" << QString::fromStdString(m_privateKeyFilePath)
                   << "Error:" << strerror(errno);
        // This is a warning; the file is saved, but permissions are not ideal.
    }
    #endif

    return true;
}

bool IdentityManager::loadKeyPair() {
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty()){
        return false; // Paths not set
    }

    std::ifstream pubFile(m_publicKeyFilePath, std::ios::in | std::ios::binary);
    if (!pubFile.is_open()) {
        //qDebug() << "IdentityManager: Public key file not found or not accessible:" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }
    pubFile.read(reinterpret_cast<char*>(m_publicKey), PUBLIC_KEY_BYTES);
    bool pubReadOk = (pubFile.gcount() == PUBLIC_KEY_BYTES);
    pubFile.close();

    if (!pubReadOk) {
        qWarning() << "IdentityManager: Failed to read complete public key from:" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }

    std::ifstream privFile(m_privateKeyFilePath, std::ios::in | std::ios::binary);
    if (!privFile.is_open()) {
        //qDebug() << "IdentityManager: Private key file not found or not accessible:" << QString::fromStdString(m_privateKeyFilePath);
        return false;
    }
    privFile.read(reinterpret_cast<char*>(m_privateKey), SECRET_KEY_BYTES);
    bool privReadOk = (privFile.gcount() == SECRET_KEY_BYTES);
    privFile.close();

    if (!privReadOk) {
        qWarning() << "IdentityManager: Failed to read complete private key from:" << QString::fromStdString(m_privateKeyFilePath);
        // If private key is bad, invalidate public key too for safety by zeroing it.
        sodium_memzero(m_publicKey, PUBLIC_KEY_BYTES);
        return false;
    }

    return true; // Both keys loaded successfully
}

std::string IdentityManager::getMyPublicKeyHex() const {
    if (!m_keysInitialized) {
        qWarning() << "IdentityManager: Attempted to get public key, but keys are not initialized.";
        return "";
    }
    return bytesToHex(m_publicKey, PUBLIC_KEY_BYTES);
}

// --- Static Helper Functions ---
std::string IdentityManager::bytesToHex(const unsigned char* bytes, size_t size) {
    if (!bytes || size == 0) return "";
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]); // Ensure cast to unsigned int for stream
    }
    return ss.str();
}

std::vector<unsigned char> IdentityManager::hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        qWarning() << "IdentityManager::hexToBytes: Hex string must have an even number of characters.";
        return bytes; // Return empty on error
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            // Use stoul for potentially larger intermediate value before casting
            unsigned long val = std::stoul(byteString, nullptr, 16);
            if (val > 255) { // Check for overflow before casting to unsigned char
                 qWarning() << "IdentityManager::hexToBytes: Hex byte value out of range:" << QString::fromStdString(byteString);
                 bytes.clear(); return bytes;
            }
            bytes.push_back(static_cast<unsigned char>(val));
        } catch (const std::invalid_argument& ia) {
            qWarning() << "IdentityManager::hexToBytes: Invalid character in hex string:" << QString::fromStdString(byteString) << ia.what();
            bytes.clear(); return bytes;
        } catch (const std::out_of_range& oor) {
            qWarning() << "IdentityManager::hexToBytes: Hex string value out of range:" << QString::fromStdString(byteString) << oor.what();
            bytes.clear(); return bytes;
        }
    }
    return bytes;
}