#ifndef IDENTITY_MANAGER_H
#define IDENTITY_MANAGER_H

#include <string>
#include <vector>
#include <sodium.h>
#include <QString>
#include <QByteArray>

const size_t ID_PUBLIC_KEY_BYTES = crypto_sign_PUBLICKEYBYTES;
const size_t ID_SECRET_KEY_BYTES = crypto_sign_SECRETKEYBYTES;

class IdentityManager
{
public:
    explicit IdentityManager(const QString &peerNameForPath = QString("DefaultPeerIdentity"), const std::string &appName = "P2PGitClient");
    ~IdentityManager();

    bool initializeKeys();
    std::string getMyPublicKeyHex() const;
    QByteArray getMyPublicKeyBytes() const;
    QByteArray getMyPrivateKeyBytes() const;
    // Curve25519 (X25519) keys derived from Ed25519 for crypto_box
    QByteArray getMyCurve25519PublicKey() const;
    QByteArray getMyCurve25519SecretKey() const;
    bool areKeysInitialized() const;

    static std::string bytesToHex(const unsigned char *bytes, size_t size);
    static std::vector<unsigned char> hexToBytes(const std::string &hex);

private:
    bool generateKeyPair();
    bool saveKeyPair() const;
    bool loadKeyPair();

    std::string m_dataPath;
    std::string m_publicKeyFilePath;
    std::string m_privateKeyFilePath;

    unsigned char m_publicKey[ID_PUBLIC_KEY_BYTES];
    unsigned char m_privateKey[ID_SECRET_KEY_BYTES];
    bool m_keysInitialized;
};

#endif // IDENTITY_MANAGER_H