#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include <QString>
#include <QByteArray>
#include <QJsonObject>

class QWidget;

class AuthManager
{
public:
    // Returns true if a profile exists for username
    static bool userExists(const QString &username);

    // Registers a new user. On success: returns true, sets recoveryToken and profilePath.
    static bool registerUser(const QString &username,
                             const QString &password,
                             QString &errorOut,
                             QString &recoveryTokenOut,
                             QString &profilePathOut);

    // Validates username/password using stored encrypted password.
    static bool loginUser(const QString &username,
                          const QString &password,
                          QString &errorOut);

    // Decrypts the recovery token and compares against stored UUID, and if matched,
    // outputs the decrypted password.
    static bool recoverPassword(const QString &username,
                                const QString &recoveryToken,
                                QString &passwordOut,
                                QString &errorOut);

    // Save the recovery token to a user-selected path; returns chosen path or empty on cancel/failure.
    static QString saveRecoveryTokenToFile(const QString &username,
                                           const QString &recoveryToken,
                                           QWidget *parent = nullptr);

    // Utility: locate profile.json for user
    static QString profileFilePath(const QString &username);

private:
    // Serialize/deserialize helpers
    static bool readProfile(const QString &username, QJsonObject &obj, QString &errorOut);
    static bool writeProfile(const QString &username, const QJsonObject &obj, QString &errorOut);

    // Password encryption using libsodium secretbox with a key derived from UUID via pwhash
    static bool deriveKeyFromUuid(const QByteArray &uuidBytes, const QByteArray &salt, QByteArray &keyOut, QString &errorOut);
    static bool encryptPassword(const QString &password, const QByteArray &uuidBytes,
                                QByteArray &saltOut, QByteArray &nonceOut, QByteArray &cipherOut, QString &errorOut);
    static bool decryptPassword(const QByteArray &uuidBytes, const QByteArray &salt,
                                const QByteArray &nonce, const QByteArray &cipher,
                                QString &passwordOut, QString &errorOut);

    // Recovery token: compact reversible encoding of UUID (<=30 chars)
    static QString makeRecoveryToken(const QByteArray &uuidBytes);
    static bool decodeRecoveryToken(const QString &token, QByteArray &uuidBytesOut, QString &errorOut);

    // Base64Url helpers
    static QString toB64UrlNoPad(const QByteArray &bin);
    static QByteArray fromB64UrlNoPad(const QString &s);

    // Fixed 16-byte XOR mask for recovery token (demo-only; do not use in production)
    static const QByteArray &recoveryXorMask();
};

#endif // AUTH_MANAGER_H
