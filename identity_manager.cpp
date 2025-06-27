// identity_manager.cpp
#include "identity_manager.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>

#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QRegExp> // Use QRegularExpression instead for modern Qt

#if defined(__linux__) || defined(__APPLE__)
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring> // For strerror
#endif

// Include sodium.h directly if using specific constants not in library header
// #include <sodium.h> // Already included in header

IdentityManager::IdentityManager(const QString &peerNameForPath, const std::string &appNameStdStr)
    : m_keysInitialized(false)
{
    // Initialize libsodium if not already initialized
    if (sodium_init() == -1)
    {
        qCritical() << "IdentityManager: CRITICAL - libsodium could not be initialized!";
        // Future: Handle this fatal error more gracefully
        return;
    }

    QString appName = QString::fromStdString(appNameStdStr);
    // Use AppConfigLocation for user-specific data like keys
    QString appConfigLocation = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);

    // Fallback location if AppConfigLocation is empty or unavailable
    if (appConfigLocation.isEmpty())
    {
        // Use home directory with a dot-prefixed folder name
        appConfigLocation = QDir::homePath() + "/." + appName.toLower().replace(" ", "_");
        qWarning() << "IdentityManager: AppConfigLocation empty, using fallback:" << appConfigLocation;
    }

    // Create base application configuration directory
    QDir baseAppDir(appConfigLocation);
    if (!baseAppDir.exists())
    {
        if (!baseAppDir.mkpath("."))
        {
            qWarning() << "IdentityManager: Could not create application base directory:" << baseAppDir.absolutePath();
            // This might be a fatal error if we can't save keys, but let's continue and hope for the best
        }
    }

    // Sanitize the peer name to create a safe directory name
    QString sanitizedPeerName = peerNameForPath;
    // Use QRegularExpression for modern pattern matching
    sanitizedPeerName.replace(QRegularExpression(QStringLiteral("[^a-zA-Z0-9_.-]")), "_"); // Replace invalid chars with underscore
    sanitizedPeerName.remove(QRegularExpression(QStringLiteral("^[.-]")));                 // Remove leading dots or hyphens
    sanitizedPeerName.remove(QRegularExpression(QStringLiteral("[.-]$")));                 // Remove trailing dots or hyphens

    if (sanitizedPeerName.isEmpty())
        sanitizedPeerName = "default_identity"; // Fallback if name becomes empty after sanitization

    // Create peer-specific directory for keys
    QString peerKeyDirPath = baseAppDir.filePath("P2PGitClient/" + sanitizedPeerName); // Use a nested path like AppName/PeerName
    QDir peerKeyDir(peerKeyDirPath);
    if (!peerKeyDir.exists())
    {
        if (!peerKeyDir.mkpath("."))
        {
            qWarning() << "IdentityManager: Could not create peer-specific key directory:" << peerKeyDirPath;
            // Fatal error possibility, cannot save keys
            m_dataPath.clear(); // Mark data path as invalid
            return;             // Cannot proceed without a valid save path
        }
    }

    m_dataPath = peerKeyDirPath.toStdString();
    m_publicKeyFilePath = m_dataPath + "/id_ed25519.pub";
    m_privateKeyFilePath = m_dataPath + "/id_ed25519";
    qDebug() << "IdentityManager: Key storage path for peer '" << peerNameForPath << "' set to: " << QString::fromStdString(m_dataPath);
}

IdentityManager::~IdentityManager()
{
    // Zero out sensitive key data in memory
    sodium_memzero(m_privateKey, ID_SECRET_KEY_BYTES);
    sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
}

QByteArray IdentityManager::getMyPrivateKeyBytes() const
{
    if (!m_keysInitialized)
    {
        qWarning() << "IdentityManager: Attempted to get private key before initialization.";
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char *>(m_privateKey), ID_SECRET_KEY_BYTES);
}

QByteArray IdentityManager::getMyPublicKeyBytes() const
{
    if (!m_keysInitialized)
    {
        qWarning() << "IdentityManager: Attempted to get public key before initialization.";
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char *>(m_publicKey), ID_PUBLIC_KEY_BYTES);
}

bool IdentityManager::initializeKeys()
{
    if (m_keysInitialized)
        return true;

    if (m_dataPath.empty())
    {
        qCritical() << "IdentityManager: Key data path is not valid. Cannot initialize keys.";
        return false;
    }

    // Attempt to load existing keys
    if (loadKeyPair())
    {
        m_keysInitialized = true;
        qInfo() << "IdentityManager: Loaded existing key pair from" << QString::fromStdString(m_privateKeyFilePath);
        return true;
    }
    else
    {
        // If loading failed (likely because files don't exist), generate new keys
        qInfo() << "IdentityManager: Existing key pair not found or failed to load. Generating new key pair for path" << QString::fromStdString(m_privateKeyFilePath);
        if (generateKeyPair())
        {
            // Save the newly generated keys
            if (saveKeyPair())
            {
                m_keysInitialized = true;
                qInfo() << "IdentityManager: Generated and saved new key pair.";
                return true;
            }
            else
            {
                qCritical() << "IdentityManager: FAILED to save newly generated key pair.";
                // Zero out keys if saving failed to avoid leaving unsaved keys in memory without initialized flag
                sodium_memzero(m_privateKey, ID_SECRET_KEY_BYTES);
                sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
            }
        }
        else
        {
            qCritical() << "IdentityManager: FAILED to generate new key pair!";
        }
    }
    qWarning() << "IdentityManager: Keys NOT initialized.";
    return false;
}

bool IdentityManager::generateKeyPair()
{
    // crypto_sign_keypair generates a new public/private key pair for Ed25519
    if (crypto_sign_keypair(m_publicKey, m_privateKey) != 0)
    {
        qWarning() << "IdentityManager: libsodium crypto_sign_keypair() failed.";
        return false;
    }
    qDebug() << "IdentityManager: Successfully generated new key pair.";
    return true;
}

bool IdentityManager::saveKeyPair() const
{
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty())
    {
        qWarning() << "IDM: Key paths not set. Cannot save.";
        return false;
    }

    // Save Public Key (readable by owner, maybe group/others depending on system umask/permissions)
    std::ofstream pubFile(m_publicKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!pubFile.is_open())
    {
        qWarning() << "IDM: Could not open public key file for writing:" << QString::fromStdString(m_publicKeyFilePath) << "Error:" << strerror(errno);
        return false;
    }
    pubFile.write(reinterpret_cast<const char *>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    if (!pubFile.good())
    {
        qWarning() << "IDM: Error writing public key to file:" << QString::fromStdString(m_publicKeyFilePath);
        pubFile.close();
        std::remove(m_publicKeyFilePath.c_str()); // Attempt to clean up partial file
        return false;
    }
    pubFile.close();
    qDebug() << "IDM: Saved public key to" << QString::fromStdString(m_publicKeyFilePath);

    // Save Private Key (should only be readable by the owner)
    std::ofstream privFile(m_privateKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!privFile.is_open())
    {
        qWarning() << "IDM: Could not open private key file for writing:" << QString::fromStdString(m_privateKeyFilePath) << "Error:" << strerror(errno);
        std::remove(m_publicKeyFilePath.c_str()); // Clean up public key file as well
        return false;
    }
    privFile.write(reinterpret_cast<const char *>(m_privateKey), ID_SECRET_KEY_BYTES);
    if (!privFile.good())
    {
        qWarning() << "IDM: Error writing private key to file:" << QString::fromStdString(m_privateKeyFilePath);
        privFile.close();
        std::remove(m_publicKeyFilePath.c_str());
        std::remove(m_privateKeyFilePath.c_str()); // Attempt to clean up partial file
        return false;
    }
    privFile.close();
    qDebug() << "IDM: Saved private key to" << QString::fromStdString(m_privateKeyFilePath);

    // Set file permissions on POSIX systems (Linux, macOS, etc.)
#if defined(__linux__) || defined(__APPLE__)
    // Private key: Owner read/write (0600)
    if (chmod(m_privateKeyFilePath.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
        qWarning() << "IDM: Failed to set permissions 0600 on private key:" << strerror(errno);
    }
    // Public key: Owner read/write, Group read, Others read (0644)
    if (chmod(m_publicKeyFilePath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
    {
        qWarning() << "IDM: Failed to set permissions 0644 on public key:" << strerror(errno);
    }
#endif

    return true;
}

bool IdentityManager::loadKeyPair()
{
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty())
        return false; // Paths not set

    // Load Public Key
    std::ifstream pubFile(m_publicKeyFilePath, std::ios::in | std::ios::binary);
    if (!pubFile.is_open())
    {
        // qWarning() << "IDM: Could not open public key file for reading:" << QString::fromStdString(m_publicKeyFilePath);
        return false; // File might not exist, not necessarily an error
    }
    pubFile.read(reinterpret_cast<char *>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    bool pubReadOk = (pubFile.gcount() == ID_PUBLIC_KEY_BYTES);
    pubFile.close(); // Close file

    if (!pubReadOk)
    {
        qWarning() << "IDM: Failed to read correct number of bytes for public key from:" << QString::fromStdString(m_publicKeyFilePath);
        sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES); // Zero out incomplete data
        return false;
    }
    // qInfo() << "IDM: Loaded public key from" << QString::fromStdString(m_publicKeyFilePath);

    // Load Private Key
    std::ifstream privFile(m_privateKeyFilePath, std::ios::in | std::ios::binary);
    if (!privFile.is_open())
    {
        qWarning() << "IDM: Could not open private key file for reading:" << QString::fromStdString(m_privateKeyFilePath) << ". Public key loaded, but cannot use without private key.";
        sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES); // Zero out public key if private key is missing/unreadable
        return false;
    }
    privFile.read(reinterpret_cast<char *>(m_privateKey), ID_SECRET_KEY_BYTES);
    bool privReadOk = (privFile.gcount() == ID_SECRET_KEY_BYTES);
    privFile.close(); // Close file

    if (!privReadOk)
    {
        qWarning() << "IDM: Failed to read correct number of bytes for private key from:" << QString::fromStdString(m_privateKeyFilePath);
        sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES); // Zero out keys if private key failed to load
        sodium_memzero(m_privateKey, ID_SECRET_KEY_BYTES);
        return false;
    }
    // qInfo() << "IDM: Loaded private key from" << QString::fromStdString(m_privateKeyFilePath);

    return true; // Both keys loaded successfully
}

std::string IdentityManager::getMyPublicKeyHex() const
{
    if (!m_keysInitialized)
    {
        qWarning() << "IdentityManager: Attempted to get public key hex before initialization.";
        return "";
    }
    return bytesToHex(m_publicKey, ID_PUBLIC_KEY_BYTES);
}

bool IdentityManager::areKeysInitialized() const { return m_keysInitialized; }

std::string IdentityManager::bytesToHex(const unsigned char *bytes, size_t size)
{
    if (!bytes || size == 0)
        return "";
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i)
    {
        ss << std::setw(2) << static_cast<unsigned int>(bytes[i]);
    }
    return ss.str();
}

std::vector<unsigned char> IdentityManager::hexToBytes(const std::string &hex)
{
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0)
    {
        qWarning() << "IDM: HexToBytes: Input hex string has uneven length.";
        return bytes; // Return empty vector for invalid input
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteStr = hex.substr(i, 2);
        try
        {
            // Use stoul with explicit base 16
            unsigned long val = std::stoul(byteStr, nullptr, 16);
            // Check if the value fits in a byte
            if (val > 255)
            {
                // This case should not happen with 2-character hex, but defensive check
                qWarning() << "IDM: HexToBytes: Parsed value > 255 for hex substring '" << QString::fromStdString(byteStr) << "'";
                bytes.clear(); // Clear partial result
                return bytes;
            }
            bytes.push_back(static_cast<unsigned char>(val));
        }
        catch (const std::exception &e)
        {
            qWarning() << "IDM: HexToBytes: Error parsing hex substring '" << QString::fromStdString(byteStr) << "':" << e.what();
            bytes.clear(); // Clear partial result
            return bytes;
        }
    }
    return bytes;
}