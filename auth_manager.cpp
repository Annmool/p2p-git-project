#include "auth_manager.h"

#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QDateTime>
#include <QRandomGenerator>
#include <QFileDialog>
#include <QTextStream>
#include <QUuid>

#include <sodium.h>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/stat.h>
#include <unistd.h>
#endif

static constexpr int PW_NONCE_BYTES = crypto_secretbox_NONCEBYTES; // 24
static constexpr int PW_KEY_BYTES = crypto_secretbox_KEYBYTES;     // 32
static constexpr int PW_SALT_BYTES = crypto_pwhash_SALTBYTES;      // 16

// ---- Utilities ----
QString AuthManager::toB64UrlNoPad(const QByteArray &bin)
{
    return QString::fromLatin1(bin.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QByteArray AuthManager::fromB64UrlNoPad(const QString &s)
{
    return QByteArray::fromBase64(s.toLatin1(), QByteArray::Base64UrlEncoding);
}

const QByteArray &AuthManager::recoveryXorMask()
{
    // 16-byte static mask (demo)
    static QByteArray mask = QByteArray::fromHex("a4c1f2e9356b7d88c0ffee12ab34cd56").left(16);
    return mask;
}

// ---- Paths ----
QString AuthManager::profileFilePath(const QString &username)
{
    QString base = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir dir(base);
    return dir.filePath(QString("P2PGitClient/%1/profile.json").arg(username));
}

bool AuthManager::userExists(const QString &username)
{
    QFileInfo fi(profileFilePath(username));
    return fi.exists() && fi.isFile();
}

// ---- Profile I/O ----
bool AuthManager::readProfile(const QString &username, QJsonObject &obj, QString &errorOut)
{
    QFile f(profileFilePath(username));
    if (!f.open(QIODevice::ReadOnly))
    {
        errorOut = QString("Could not open profile: %1").arg(f.errorString());
        return false;
    }
    auto jd = QJsonDocument::fromJson(f.readAll());
    if (!jd.isObject())
    {
        errorOut = "Invalid profile format";
        return false;
    }
    obj = jd.object();
    return true;
}

bool AuthManager::writeProfile(const QString &username, const QJsonObject &obj, QString &errorOut)
{
    QString path = profileFilePath(username);
    QDir().mkpath(QFileInfo(path).absolutePath());

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        errorOut = QString("Could not write profile: %1").arg(f.errorString());
        return false;
    }
    f.write(QJsonDocument(obj).toJson(QJsonDocument::Indented));
    f.close();

#if defined(__linux__) || defined(__APPLE__)
    chmod(path.toLocal8Bit().constData(), S_IRUSR | S_IWUSR);
#endif
    return true;
}

// ---- Crypto helpers for password ----
bool AuthManager::deriveKeyFromUuid(const QByteArray &uuidBytes, const QByteArray &salt, QByteArray &keyOut, QString &errorOut)
{
    if (uuidBytes.size() != 16 || salt.size() != PW_SALT_BYTES)
    {
        errorOut = "Invalid UUID/salt size";
        return false;
    }
    keyOut.resize(PW_KEY_BYTES);
    if (crypto_pwhash(reinterpret_cast<unsigned char *>(keyOut.data()), keyOut.size(),
                      uuidBytes.constData(), static_cast<unsigned long long>(uuidBytes.size()),
                      reinterpret_cast<const unsigned char *>(salt.constData()),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0)
    {
        errorOut = "Key derivation failed";
        return false;
    }
    return true;
}

bool AuthManager::encryptPassword(const QString &password, const QByteArray &uuidBytes,
                                  QByteArray &saltOut, QByteArray &nonceOut, QByteArray &cipherOut, QString &errorOut)
{
    saltOut.resize(PW_SALT_BYTES);
    randombytes_buf(saltOut.data(), saltOut.size());

    QByteArray key;
    if (!deriveKeyFromUuid(uuidBytes, saltOut, key, errorOut))
        return false;

    nonceOut.resize(PW_NONCE_BYTES);
    randombytes_buf(nonceOut.data(), nonceOut.size());

    QByteArray plain = password.toUtf8();
    cipherOut.resize(plain.size() + crypto_secretbox_MACBYTES);
    if (crypto_secretbox_easy(reinterpret_cast<unsigned char *>(cipherOut.data()),
                              reinterpret_cast<const unsigned char *>(plain.constData()),
                              static_cast<unsigned long long>(plain.size()),
                              reinterpret_cast<const unsigned char *>(nonceOut.constData()),
                              reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        errorOut = "Encryption failed";
        return false;
    }
    return true;
}

bool AuthManager::decryptPassword(const QByteArray &uuidBytes, const QByteArray &salt,
                                  const QByteArray &nonce, const QByteArray &cipher,
                                  QString &passwordOut, QString &errorOut)
{
    QByteArray key;
    if (!deriveKeyFromUuid(uuidBytes, salt, key, errorOut))
        return false;

    if (cipher.size() < crypto_secretbox_MACBYTES)
    {
        errorOut = "Cipher too short";
        return false;
    }
    QByteArray plain(cipher.size() - crypto_secretbox_MACBYTES, 0);
    if (crypto_secretbox_open_easy(reinterpret_cast<unsigned char *>(plain.data()),
                                   reinterpret_cast<const unsigned char *>(cipher.constData()),
                                   static_cast<unsigned long long>(cipher.size()),
                                   reinterpret_cast<const unsigned char *>(nonce.constData()),
                                   reinterpret_cast<const unsigned char *>(key.constData())) != 0)
    {
        errorOut = "Decryption failed";
        return false;
    }
    passwordOut = QString::fromUtf8(plain);
    return true;
}

// ---- Recovery token helpers ----
QString AuthManager::makeRecoveryToken(const QByteArray &uuidBytes)
{
    QByteArray masked = uuidBytes;
    const QByteArray &mask = recoveryXorMask();
    for (int i = 0; i < masked.size() && i < mask.size(); ++i)
        masked[i] = masked[i] ^ mask[i];
    return toB64UrlNoPad(masked);
}

bool AuthManager::decodeRecoveryToken(const QString &token, QByteArray &uuidBytesOut, QString &errorOut)
{
    if (token.size() > 30)
    {
        errorOut = "Recovery token too long";
        return false;
    }
    QByteArray masked = fromB64UrlNoPad(token);
    if (masked.size() != 16)
    {
        errorOut = "Invalid token format";
        return false;
    }
    const QByteArray &mask = recoveryXorMask();
    uuidBytesOut = masked;
    for (int i = 0; i < uuidBytesOut.size() && i < mask.size(); ++i)
        uuidBytesOut[i] = uuidBytesOut[i] ^ mask[i];
    return true;
}

// ---- Public ops ----
bool AuthManager::registerUser(const QString &username,
                               const QString &password,
                               QString &errorOut,
                               QString &recoveryTokenOut,
                               QString &profilePathOut)
{
    if (username.trimmed().isEmpty() || password.isEmpty())
    {
        errorOut = "Username and password are required";
        return false;
    }
    if (userExists(username))
    {
        errorOut = "Profile already exists, please login";
        return false;
    }

    if (sodium_init() == -1)
    {
        errorOut = "Crypto library init failed";
        return false;
    }

    // Generate binary UUID (16 bytes)
    QUuid uuid = QUuid::createUuid();
    QByteArray uuidBytes = uuid.toRfc4122(); // 16 bytes
    QString uuidStr = uuid.toString(QUuid::WithoutBraces);

    QByteArray salt, nonce, cipher;
    if (!encryptPassword(password, uuidBytes, salt, nonce, cipher, errorOut))
        return false;

    // Prepare JSON
    QJsonObject obj;
    obj["username"] = username;
    obj["uuid"] = uuidStr; // stored for comparison
    obj["pw_salt"] = toB64UrlNoPad(salt);
    obj["pw_nonce"] = toB64UrlNoPad(nonce);
    obj["pw_cipher"] = toB64UrlNoPad(cipher);
    obj["created"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);

    if (!writeProfile(username, obj, errorOut))
        return false;

    profilePathOut = profileFilePath(username);
    recoveryTokenOut = makeRecoveryToken(uuidBytes); // <=30 chars
    return true;
}

bool AuthManager::loginUser(const QString &username,
                            const QString &password,
                            QString &errorOut)
{
    if (sodium_init() == -1)
    {
        errorOut = "Crypto library init failed";
        return false;
    }

    if (!userExists(username))
    {
        errorOut = "Profile not found. Please register first.";
        return false;
    }

    QJsonObject obj;
    if (!readProfile(username, obj, errorOut))
        return false;

    QString uuidStr = obj.value("uuid").toString();
    QByteArray salt = fromB64UrlNoPad(obj.value("pw_salt").toString());
    QByteArray nonce = fromB64UrlNoPad(obj.value("pw_nonce").toString());
    QByteArray cipher = fromB64UrlNoPad(obj.value("pw_cipher").toString());

    QUuid uuid(uuidStr);
    if (!uuid.isNull())
    {
        QByteArray uuidBytes = uuid.toRfc4122();
        QString decryptedPw;
        if (!decryptPassword(uuidBytes, salt, nonce, cipher, decryptedPw, errorOut))
            return false;
        if (decryptedPw != password)
        {
            errorOut = "Invalid password";
            return false;
        }
        return true;
    }
    errorOut = "Corrupt profile";
    return false;
}

bool AuthManager::recoverPassword(const QString &username,
                                  const QString &recoveryToken,
                                  QString &passwordOut,
                                  QString &errorOut)
{
    if (sodium_init() == -1)
    {
        errorOut = "Crypto library init failed";
        return false;
    }

    if (!userExists(username))
    {
        errorOut = "Profile not found. Please register first.";
        return false;
    }

    QJsonObject obj;
    if (!readProfile(username, obj, errorOut))
        return false;

    QString uuidStr = obj.value("uuid").toString();
    QByteArray salt = fromB64UrlNoPad(obj.value("pw_salt").toString());
    QByteArray nonce = fromB64UrlNoPad(obj.value("pw_nonce").toString());
    QByteArray cipher = fromB64UrlNoPad(obj.value("pw_cipher").toString());

    // Decode recovery token -> uuid bytes
    QByteArray tokenUuidBytes;
    if (!decodeRecoveryToken(recoveryToken, tokenUuidBytes, errorOut))
        return false;

    // Compare with stored UUID
    QUuid stored(uuidStr);
    QByteArray storedUuidBytes = stored.toRfc4122();
    if (storedUuidBytes != tokenUuidBytes)
    {
        errorOut = "Recovery key does not match this profile";
        return false;
    }

    // Decrypt password
    if (!decryptPassword(storedUuidBytes, salt, nonce, cipher, passwordOut, errorOut))
        return false;

    return true;
}

QString AuthManager::saveRecoveryTokenToFile(const QString &username,
                                             const QString &recoveryToken,
                                             QWidget *parent)
{
    QString defaultName = QString("SyncIt_RecoveryKey_%1.key").arg(username);
    QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString path = QFileDialog::getSaveFileName(parent, "Save Recovery Key", QDir(dir).filePath(defaultName), "Key Files (*.key);;All Files (*)");
    if (path.isEmpty())
        return QString();

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
        return QString();

    QTextStream ts(&f);
    ts << "# SyncIt Recovery Key for user: " << username << "\n";
    ts << recoveryToken << "\n";
    f.close();

#if defined(__linux__) || defined(__APPLE__)
    chmod(path.toLocal8Bit().constData(), S_IRUSR | S_IWUSR);
#endif

    return path;
}
