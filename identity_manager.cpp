#include "identity_manager.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstdio>

#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QRegularExpression>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/stat.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#endif

IdentityManager::IdentityManager(const QString &peerNameForPath, const std::string &appNameStdStr)
    : m_keysInitialized(false)
{
    if (sodium_init() == -1)
    {
        qCritical() << "IdentityManager: CRITICAL - libsodium could not be initialized!";
        return;
    }

    QString appName = QString::fromStdString(appNameStdStr);
    QString appDataBaseLocation = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    if (appDataBaseLocation.isEmpty())
    {
        appDataBaseLocation = QDir::homePath() + "/." + appName;
        qWarning() << "IdentityManager: AppLocalDataLocation empty, using fallback:" << appDataBaseLocation;
    }

    // --- FIX: Correctly create the nested directory path ---
    QString sanitizedPeerName = peerNameForPath;
    if (sanitizedPeerName.isEmpty())
        sanitizedPeerName = "default_identity_keys";

    sanitizedPeerName.remove(QRegularExpression(QStringLiteral("[^a-zA-Z0-9_.-]")));
    if (sanitizedPeerName.isEmpty())
        sanitizedPeerName = "default_sanitized_identity_keys";

    // Construct the full desired path first
    QString fullPath = QDir(appDataBaseLocation).filePath(appName + "/" + sanitizedPeerName);

    QDir keyDir(fullPath);
    if (!keyDir.exists())
    {
        // Use mkpath on the QDir object. It will create all necessary parent directories.
        if (!keyDir.mkpath("."))
        {
            qWarning() << "IdentityManager: Could not create full key directory path:" << keyDir.absolutePath();
            // m_dataPath will remain empty, causing initialization to fail safely.
            return;
        }
    }

    // Now that the path is guaranteed to exist, set the member variables.
    m_dataPath = keyDir.absolutePath().toStdString();
    m_publicKeyFilePath = m_dataPath + "/id_ed25519.pub";
    m_privateKeyFilePath = m_dataPath + "/id_ed25519";
    qDebug() << "IdentityManager: Key storage path for peer '" << peerNameForPath << "' set to: " << QString::fromStdString(m_dataPath);
    // --- END OF FIX ---
}

IdentityManager::~IdentityManager()
{
    sodium_memzero(m_privateKey, ID_SECRET_KEY_BYTES);
    sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
}

QByteArray IdentityManager::getMyPrivateKeyBytes() const
{
    if (!m_keysInitialized)
        return QByteArray();
    return QByteArray(reinterpret_cast<const char *>(m_privateKey), ID_SECRET_KEY_BYTES);
}

QByteArray IdentityManager::getMyCurve25519PublicKey() const
{
    if (!m_keysInitialized)
        return QByteArray();
    unsigned char curvePk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(curvePk, m_publicKey) != 0)
    {
        qWarning() << "IdentityManager: Failed to convert ed25519 public key to curve25519.";
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char *>(curvePk), crypto_box_PUBLICKEYBYTES);
}

QByteArray IdentityManager::getMyCurve25519SecretKey() const
{
    if (!m_keysInitialized)
        return QByteArray();
    unsigned char curveSk[crypto_box_SECRETKEYBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(curveSk, m_privateKey) != 0)
    {
        qWarning() << "IdentityManager: Failed to convert ed25519 secret key to curve25519.";
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char *>(curveSk), crypto_box_SECRETKEYBYTES);
}

bool IdentityManager::initializeKeys()
{
    if (m_keysInitialized)
        return true;

    // Add a check here. If m_dataPath is empty because the directory creation failed,
    // we cannot proceed.
    if (m_dataPath.empty())
    {
        qCritical() << "IdentityManager: Key data path is not valid. Cannot initialize keys.";
        return false;
    }

    if (loadKeyPair())
    {
        m_keysInitialized = true;
        qInfo() << "IdentityManager: Loaded existing key pair from" << QString::fromStdString(m_privateKeyFilePath);
        return true;
    }
    else
    {
        qInfo() << "IdentityManager: Generating new key pair for path" << QString::fromStdString(m_privateKeyFilePath);
        if (generateKeyPair())
        {
            if (saveKeyPair())
            {
                m_keysInitialized = true;
                qInfo() << "IdentityManager: Generated and saved new key pair.";
                return true;
            }
            else
            {
                qCritical() << "IdentityManager: FAILED to save newly generated key pair.";
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
    if (crypto_sign_keypair(m_publicKey, m_privateKey) != 0)
    {
        qWarning() << "IdentityManager: libsodium crypto_sign_keypair() failed.";
        return false;
    }
    return true;
}

bool IdentityManager::saveKeyPair() const
{
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty())
    {
        qWarning() << "IDM: Key paths not set.";
        return false;
    }
    std::ofstream pubFile(m_publicKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!pubFile.is_open())
    {
        qWarning() << "IDM: Could not open pubkey file:" << QString::fromStdString(m_publicKeyFilePath) << strerror(errno);
        return false;
    }
    pubFile.write(reinterpret_cast<const char *>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    if (!pubFile.good())
    {
        qWarning() << "IDM: Err writing pubkey:" << QString::fromStdString(m_publicKeyFilePath);
        pubFile.close();
        std::remove(m_publicKeyFilePath.c_str());
        return false;
    }
    pubFile.close();
    std::ofstream privFile(m_privateKeyFilePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!privFile.is_open())
    {
        qWarning() << "IDM: Could not open privkey file:" << QString::fromStdString(m_privateKeyFilePath) << strerror(errno);
        std::remove(m_publicKeyFilePath.c_str());
        return false;
    }
    privFile.write(reinterpret_cast<const char *>(m_privateKey), ID_SECRET_KEY_BYTES);
    if (!privFile.good())
    {
        qWarning() << "IDM: Err writing privkey:" << QString::fromStdString(m_privateKeyFilePath);
        privFile.close();
        std::remove(m_publicKeyFilePath.c_str());
        std::remove(m_privateKeyFilePath.c_str());
        return false;
    }
    privFile.close();
#if defined(__linux__) || defined(__APPLE__)
    if (chmod(m_privateKeyFilePath.c_str(), S_IRUSR | S_IWUSR) != 0)
    {
        qWarning() << "IDM: Failed chmod 0600 private key:" << strerror(errno);
    }
    if (chmod(m_publicKeyFilePath.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH) != 0)
    {
        qWarning() << "IDM: Failed chmod 0644 public key:" << strerror(errno);
    }
#endif
    return true;
}

bool IdentityManager::loadKeyPair()
{
    if (m_publicKeyFilePath.empty() || m_privateKeyFilePath.empty())
        return false;
    std::ifstream pubFile(m_publicKeyFilePath, std::ios::in | std::ios::binary);
    if (!pubFile.is_open())
        return false;
    pubFile.read(reinterpret_cast<char *>(m_publicKey), ID_PUBLIC_KEY_BYTES);
    bool pubReadOk = (pubFile.gcount() == ID_PUBLIC_KEY_BYTES);
    pubFile.close();
    if (!pubReadOk)
    {
        qWarning() << "IDM: Failed read pubkey:" << QString::fromStdString(m_publicKeyFilePath);
        return false;
    }
    std::ifstream privFile(m_privateKeyFilePath, std::ios::in | std::ios::binary);
    if (!privFile.is_open())
        return false;
    privFile.read(reinterpret_cast<char *>(m_privateKey), ID_SECRET_KEY_BYTES);
    bool privReadOk = (privFile.gcount() == ID_SECRET_KEY_BYTES);
    privFile.close();
    if (!privReadOk)
    {
        qWarning() << "IDM: Failed read privkey:" << QString::fromStdString(m_privateKeyFilePath);
        sodium_memzero(m_publicKey, ID_PUBLIC_KEY_BYTES);
        return false;
    }
    return true;
}

std::string IdentityManager::getMyPublicKeyHex() const
{
    if (!m_keysInitialized)
        return "";
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
        qWarning() << "IDM: HexToBytes: Even chars needed.";
        return bytes;
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteStr = hex.substr(i, 2);
        try
        {
            unsigned long val = std::stoul(byteStr, nullptr, 16);
            if (val > 255)
            {
                qWarning() << "IDM: HexToBytes: val>255:" << QString::fromStdString(byteStr);
                bytes.clear();
                return bytes;
            }
            bytes.push_back(static_cast<unsigned char>(val));
        }
        catch (const std::exception &e)
        {
            qWarning() << "IDM: HexToBytes: Err parsing '" << QString::fromStdString(byteStr) << "':" << e.what();
            bytes.clear();
            return bytes;
        }
    }
    return bytes;
}