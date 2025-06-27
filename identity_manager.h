#ifndef IDENTITY_MANAGER_H
#define IDENTITY_MANAGER_H

#include <string>
#include <vector>
#include <sodium.h> // Include libsodium header for constants and functions
#include <QString>
#include <QByteArray>
#include <QRegularExpression> // Use QRegularExpression
#include <QMetaType>          // Needed for Q_DECLARE_METATYPE outside class

// Define key size constants using libsodium macros
const size_t ID_PUBLIC_KEY_BYTES = crypto_sign_PUBLICKEYBYTES;
const size_t ID_SECRET_KEY_BYTES = crypto_sign_SECRETKEYBYTES;

class IdentityManager
{
public:
    // Constructor takes a unique name for the peer to generate/load keys for
    // and the application name for defining storage paths.
    explicit IdentityManager(const QString &peerNameForPath = QString("DefaultPeerIdentity"), const std::string &appName = "P2PGitClient");
    ~IdentityManager(); // Destructor to zero out sensitive data

    // Initialize keys: loads existing if found, otherwise generates and saves new ones.
    // Returns true on success, false on failure (e.g., libsodium init failed, file errors).
    bool initializeKeys();

    // Retrieve keys in different formats. Returns empty if not initialized.
    std::string getMyPublicKeyHex() const;
    QByteArray getMyPublicKeyBytes() const;
    QByteArray getMyPrivateKeyBytes() const;

    // Check if keys have been successfully initialized.
    bool areKeysInitialized() const;

    // Utility functions for hex conversion. Static as they don't depend on instance state.
    static std::string bytesToHex(const unsigned char *bytes, size_t size);
    static std::vector<unsigned char> hexToBytes(const std::string &hex);

private:
    // Internal helpers for key management
    bool generateKeyPair();   // Generates a new key pair using libsodium
    bool saveKeyPair() const; // Saves the current key pair to files
    bool loadKeyPair();       // Loads a key pair from files

    // File paths for key storage
    std::string m_dataPath; // Base directory for key storage
    std::string m_publicKeyFilePath;
    std::string m_privateKeyFilePath;

    // Buffers to hold the key data
    unsigned char m_publicKey[ID_PUBLIC_KEY_BYTES];
    unsigned char m_privateKey[ID_SECRET_KEY_BYTES]; // Corrected member declaration
    bool m_keysInitialized;                          // Corrected member declaration
};

// Q_DECLARE_METATYPE and operator overloads should NOT be inside the class.
// Q_DECLARE_METATYPE for DiscoveredPeerInfo belongs in network_manager.h
// Q_DECLARE_METATYPE for ManagedRepositoryInfo belongs in repository_manager.h
// QUuid operators are standard in QtCore and don't need re-declaration here.

#endif // IDENTITY_MANAGER_H