#ifndef IDENTITY_MANAGER_H
#define IDENTITY_MANAGER_H

#include <string>
#include <vector>
#include <sodium.h> // libsodium header

// For storing keys as hex strings or similar
const size_t PUBLIC_KEY_BYTES = crypto_sign_PUBLICKEYBYTES;
const size_t SECRET_KEY_BYTES = crypto_sign_SECRETKEYBYTES;
const size_t SIGNATURE_BYTES = crypto_sign_BYTES;

class IdentityManager {
public:
    IdentityManager(const std::string& dataPath); // Path to store/load keys
    ~IdentityManager();

    bool initializeKeys(); // Generates if not found, loads if found

    std::string getMyPublicKeyHex() const;
    // std::string getMyPrivateKeyHex() const; // Be careful exposing private key

    // For signing messages (optional for now, but good to have placeholders)
    // std::string signMessage(const std::string& message) const;
    // static bool verifySignature(const std::string& publicKeyHex, const std::string& message, const std::string& signatureHex);

    // Helper to convert byte arrays to hex and vice-versa
    static std::string bytesToHex(const unsigned char* bytes, size_t size);
    static std::vector<unsigned char> hexToBytes(const std::string& hex);


private:
    bool generateKeyPair();
    bool saveKeyPair() const;
    bool loadKeyPair();

    std::string m_dataPath;
    std::string m_publicKeyFilePath;
    std::string m_privateKeyFilePath;

    unsigned char m_publicKey[PUBLIC_KEY_BYTES];
    unsigned char m_privateKey[SECRET_KEY_BYTES]; // IMPORTANT: Handle with care

    bool m_keysInitialized = false;
};

#endif // IDENTITY_MANAGER_H