#include "network_manager.h"
#include "repository_manager.h"
#include "identity_manager.h"
#include <QNetworkInterface>
#include <QNetworkDatagram>
#include <QDataStream>
#include <QDateTime>
#include <QDebug>
#include <QUuid>
#include <QFile>
#include <QStandardPaths>
#include <QJsonDocument>
#include <QJsonObject>
#include <sodium.h>
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <functional>

// Check if SODIUM_VERSION_MAJOR is defined, otherwise assume an older version or set a default
#if defined(SODIUM_VERSION_MAJOR) && SODIUM_VERSION_MAJOR >= 1 && SODIUM_VERSION_MINOR >= 10
#endif

const qint64 PEER_TIMEOUT_MS = 15000;
const int BROADCAST_INTERVAL_MS = 5000;
const int PENDING_CONNECTION_TIMEOUT_MS = 30000;
const int FILE_TRANSFER_CHUNK_SIZE = 65536; // 64KB

NetworkManager::NetworkManager(const QString &myUsername,
                               IdentityManager *identityManager,
                               RepositoryManager *repoManager,
                               QObject *parent)
    : QObject(parent),
      m_myUsername(myUsername),
      m_identityManager(identityManager),
      m_repoManager_ptr(repoManager)
{
    if (!m_identityManager || !m_repoManager_ptr)
    {
        qCritical() << "NetworkManager initialized without valid IdentityManager or RepositoryManager!";
        // Future: throw exception or set invalid state
    }

    // Ensure libsodium is initialized (IdentityManager does this, but good practice)
    if (sodium_init() == -1)
    {
        qCritical() << "NetworkManager: CRITICAL - libsodium could not be initialized!";
        // Future: Handle this fatal error
    }

    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &NetworkManager::onNewTcpConnection);

    m_udpSocket = new QUdpSocket(this);
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &NetworkManager::onUdpReadyRead);

    m_broadcastTimer = new QTimer(this);
    connect(m_broadcastTimer, &QTimer::timeout, this, &NetworkManager::onBroadcastTimerTimeout);

    m_peerCleanupTimer = new QTimer(this);
    connect(m_peerCleanupTimer, &QTimer::timeout, this, &NetworkManager::onPeerCleanupTimerTimeout);
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2);

    qRegisterMetaType<DiscoveredPeerInfo>("DiscoveredPeerInfo");
}

NetworkManager::~NetworkManager()
{
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();

    // Delete remaining transfers if any
    qDeleteAll(m_incomingTransfers);
    m_incomingTransfers.clear();
    qDeleteAll(m_outgoingTransfers);
    m_outgoingTransfers.clear();

    m_socketBuffers.clear();
    m_socketToPeerUsernameMap.clear();
    m_handshakeSent.clear();
    m_peerPublicKeys.clear();

    // Delete pending connection timers
    qDeleteAll(m_pendingConnections);
    m_pendingConnections.clear();

    // Child QObjects (timers, sockets, server) are deleted by parent QObject
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString() << ":" << socket->peerPort();
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

            m_allTcpSockets.append(socket);
            // Use a temporary ID until handshake completes
            m_socketToPeerUsernameMap.insert(socket, "AwaitingID:" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));

            // Start handshake timer
            QTimer *timer = new QTimer(socket); // Parent the timer to the socket for automatic cleanup
            timer->setSingleShot(true);
            connect(timer, &QTimer::timeout, this, [this, socket]()
                    {
                        qWarning() << "Handshake timeout for incoming connection from" << getPeerDisplayString(socket);
                        rejectPendingTcpConnection(socket); // Use reject function to clean up timer
                    });
            m_pendingConnections.insert(socket, timer);
            timer->start(PENDING_CONNECTION_TIMEOUT_MS);

            // Send our identity immediately upon receiving an incoming connection
            sendIdentityOverTcp(socket);

            // Emit signal to MainWindow to ask user to accept
            // Try to find a known username for this address/port from discovery info
            QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
            // Use the discovered username in the request if available, otherwise leave it generic.
            emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
        }
    }
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
    {
        qWarning() << "onTcpSocketReadyRead called with invalid sender.";
        return;
    }
    processIncomingTcpData(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    // Check if the socket is still in the pending state map
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Accepting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket); // Remove from pending map
        if (timer)
            timer->deleteLater(); // Delete the timer

        // Send our identity handshake again if it wasn't sent already (redundant with current flow, but safe)
        if (!m_handshakeSent.contains(pendingSocket))
        {
            sendIdentityOverTcp(pendingSocket);
        }

        // Process any data that might have been received while pending
        if (m_socketBuffers.contains(pendingSocket) && !m_socketBuffers[pendingSocket].isEmpty())
        {
            qDebug() << "Processing buffered data for newly accepted connection.";
            processIncomingTcpData(pendingSocket);
        }
    }
    else
    {
        qWarning() << "Attempted to accept a connection that was not pending:" << getPeerDisplayString(pendingSocket);
        // If it's not pending, it's either already established or disconnected.
        // If connected, the handshake must have completed automatically.
        // If disconnected, the onTcpSocketDisconnected handler will clean it up.
        // No action needed here for non-pending sockets.
    }
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Rejecting pending connection from" << getPeerDisplayString(pendingSocket);
        QTimer *timer = m_pendingConnections.take(pendingSocket); // Remove from pending map
        if (timer)
            timer->deleteLater();            // Delete the timer
        pendingSocket->disconnectFromHost(); // This will trigger onTcpSocketDisconnected
    }
    else
    {
        qWarning() << "Attempted to reject a connection that was not pending:" << getPeerDisplayString(pendingSocket);
        // Socket is already handled (established or disconnected)
    }
}

// Helper to extract group info from a secure message payload
bool NetworkManager::extractGroupInfoFromPayload(const QVariantMap &payload, QString &ownerRepoAppId, QString &repoDisplayName, QString &ownerPeerId, QStringList &groupMembers)
{
    ownerRepoAppId = payload.value("ownerRepoAppId").toString();
    repoDisplayName = payload.value("repoDisplayName").toString();
    ownerPeerId = payload.value("ownerPeerId").toString();
    groupMembers = payload.value("groupMembers").toStringList();

    // Basic validation
    return !ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty() && !ownerPeerId.isEmpty() && !groupMembers.isEmpty();
}

void NetworkManager::handleEncryptedPayload(const QString &peerId, const QVariantMap &payload)
{
    QString messageType = payload.value("__messageType").toString();
    if (messageType.isEmpty())
    {
        qWarning() << "Received encrypted payload with no messageType from" << peerId;
        return;
    }

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;

    // Special handling for specific secure message types
    if (messageType == "COLLABORATOR_ADDED")
    {
        QString ownerRepoAppId, repoDisplayName, ownerPeerId;
        QStringList groupMembers;
        if (extractGroupInfoFromPayload(payload, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers))
        {
            emit collaboratorAddedReceived(peerId, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers);
        }
        else
        {
            qWarning() << "NetworkManager: Invalid COLLABORATOR_ADDED payload from" << peerId;
            // Log to network panel if accessible, or emit a signal for MainWindow to handle
        }
    }
    else
    {
        // For unknown or generic secure message types, just emit the signal with the raw payload
        emit secureMessageReceived(peerId, messageType, payload);
    }
}

void NetworkManager::processIncomingTcpData(QTcpSocket *socket)
{
    QByteArray &buffer = m_socketBuffers[socket];
    QDataStream in(&buffer, QIODevice::ReadOnly);
    in.setVersion(QDataStream::Qt_5_15);

    while (socket->bytesAvailable() > 0 || buffer.size() > 0)
    {
        if (socket->bytesAvailable() > 0)
        {
            buffer.append(socket->readAll());
        }

        // --- Handle File Transfers ---
        if (m_incomingTransfers.contains(socket))
        {
            IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
            qint64 bytesAvailableInBuffer = buffer.size();
            qint64 remainingBytesInFile = transfer->totalSize - transfer->bytesReceived;
            qint64 bytesToWrite = qMin(bytesAvailableInBuffer, remainingBytesInFile);

            if (bytesToWrite > 0)
            {
                qint64 bytesWritten = transfer->file->write(buffer.constData(), bytesToWrite);
                if (bytesWritten > 0)
                {
                    buffer.remove(0, static_cast<int>(bytesWritten));
                    transfer->bytesReceived += bytesWritten;
                    // qApp->processEvents(); // Process events occasionally during large transfers
                    emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
                }
                else if (bytesWritten == -1) // Error writing
                {
                    qWarning() << "Error writing to bundle file:" << transfer->file->errorString();
                    transfer->file->close();
                    emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, false, "Error writing to local file.");
                    // Clean up transfer and potentially the socket
                    delete m_incomingTransfers.take(socket);
                    // Disconnect transfer-specific sockets immediately on completion/failure
                    if (socket->property("is_transfer_socket").toBool())
                    {
                        socket->disconnectFromHost(); // This triggers onTcpSocketDisconnected and deletes socket/timer
                    }
                    return; // Stop processing data for this socket
                }
                // If bytesWritten is 0, it might indicate a temporary full buffer or other issue, just continue loop/wait for more data
            }

            // Check if transfer is complete
            if (transfer->bytesReceived >= transfer->totalSize)
            {
                qDebug() << "File transfer completed for" << transfer->repoName;
                transfer->file->close();
                emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, true, "Transfer successful.");
                // Clean up transfer object
                delete m_incomingTransfers.take(socket);
                // Disconnect transfer-specific sockets immediately on completion/failure
                if (socket->property("is_transfer_socket").toBool())
                {
                    socket->disconnectFromHost(); // This triggers onTcpSocketDisconnected and deletes socket/timer
                }
                continue; // Transfer complete, continue processing buffer for potential next messages
            }
            else
            {
                // Transfer is ongoing, need more data or need to process pending data
                // If buffer is empty but transfer not complete, wait for more bytes
                if (buffer.isEmpty() && socket->bytesAvailable() == 0)
                    return;
                // If buffer is not empty but not enough bytes for a full chunk, just continue loop
            }
        }

        // --- Handle Structured Messages ---
        // If there is enough data for the message size header
        if (buffer.size() < sizeof(quint32))
        {
            return; // Not enough data for message size
        }

        // Peek the total message size
        quint32 messageSize;
        QDataStream sizeStream(buffer);
        sizeStream.setVersion(QDataStream::Qt_5_15);
        sizeStream >> messageSize;

        // If the buffer contains the full message + header
        if (buffer.size() >= sizeof(quint32) + messageSize)
        {
            // Read the full message data
            QByteArray messageData = buffer.mid(sizeof(quint32), messageSize);
            buffer.remove(0, sizeof(quint32) + messageSize); // Remove processed message from buffer

            QDataStream messageStream(messageData);
            messageStream.setVersion(QDataStream::Qt_5_15);

            QString messageType;
            messageStream >> messageType;

            // Process known message types
            if (messageType == "IDENTITY_HANDSHAKE_V2")
            {
                QString peerUsername, peerKeyHex;
                messageStream >> peerUsername >> peerKeyHex;

                qDebug() << "Received IDENTITY_HANDSHAKE_V2 from" << peerUsername;
                QString currentTempId = m_socketToPeerUsernameMap.value(socket, "");
                bool isIncomingPending = m_pendingConnections.contains(socket);
                bool isOutgoingAttempt = socket->property("is_outgoing_attempt").toBool();

                if (isIncomingPending)
                {
                    qDebug() << "Handshake received for connection that was pending acceptance.";
                    // The acceptPendingTcpConnection/rejectPendingTcpConnection functions manage the timer.
                    // If handshake arrives before decision, the timer might still be active but the entry is in m_pendingConnections.
                    QTimer *timer = m_pendingConnections.take(socket); // Remove from pending map if still there
                    if (timer)
                        timer->deleteLater();
                }
                else if (isOutgoingAttempt)
                {
                    qDebug() << "Handshake received for outgoing connection.";
                    socket->setProperty("is_outgoing_attempt", false); // Mark as not an attempt anymore
                }
                else
                {
                    qWarning() << "Received IDENTITY_HANDSHAKE_V2 from" << peerUsername << "on socket not marked as pending or outgoing attempt. Assuming established, but check flow.";
                }

                // Check for username collision among established peers
                bool collision = false;
                for (auto it = m_socketToPeerUsernameMap.constBegin(); it != m_socketToPeerUsernameMap.constEnd(); ++it)
                {
                    if (it.value() == peerUsername && it.key() != socket && !it.value().startsWith("AwaitingID"))
                    {
                        qWarning() << "Username collision detected! Peer '" << peerUsername << "' is already connected on another socket. Disconnecting new socket.";
                        collision = true;
                        break;
                    }
                }

                if (collision)
                {
                    socket->disconnectFromHost(); // Disconnect the new socket
                    continue;                     // Process next data in buffer
                }

                m_socketToPeerUsernameMap.insert(socket, peerUsername);                          // Map socket to validated username
                m_peerPublicKeys.insert(peerUsername, QByteArray::fromHex(peerKeyHex.toUtf8())); // Store public key

                // If we haven't sent our handshake on this socket yet, send it now
                if (!m_handshakeSent.contains(socket))
                {
                    sendIdentityOverTcp(socket);
                }

                // Check if this socket was an outgoing attempt and now established
                if (isOutgoingAttempt)
                {
                    // Find the expected username from the temporary map entry
                    QString tempExpectedUser = currentTempId;
                    if (tempExpectedUser.startsWith("ConnectingTo:"))
                    {
                        tempExpectedUser.remove("ConnectingTo:");
                    }
                    else
                    {
                        tempExpectedUser.clear();
                    }

                    if (!tempExpectedUser.isEmpty() && tempExpectedUser != peerUsername)
                    {
                        qWarning() << "Outgoing connection handshake mismatch: Expected" << tempExpectedUser << "but got" << peerUsername << ". Disconnecting.";
                        emit tcpConnectionStatusChanged(tempExpectedUser, peerKeyHex, false, "Peer ID mismatch during handshake.");
                        socket->disconnectFromHost();
                        continue;
                    }
                    // If handshake matches or no specific peer was expected for this socket
                    emit tcpConnectionStatusChanged(peerUsername, peerKeyHex, true, "Connected.");
                }

                // Emit new connection signal
                emit newTcpPeerConnected(socket, peerUsername, peerKeyHex);
            }
            else if (messageType == "REQUEST_REPO_BUNDLE")
            {
                QString requestingPeerUsername, repoName, clientWantsToSaveAt;
                messageStream >> requestingPeerUsername >> repoName >> clientWantsToSaveAt;

                qDebug() << "Received REQUEST_REPO_BUNDLE for" << repoName << "from" << requestingPeerUsername;
                // Update map if needed (e.g., if this socket was a transfer socket)
                m_socketToPeerUsernameMap.insert(socket, requestingPeerUsername);
                emit repoBundleRequestedByPeer(socket, requestingPeerUsername, repoName, clientWantsToSaveAt);
            }
            else if (messageType == "SEND_REPO_BUNDLE_START")
            {
                QString repoName;
                qint64 totalSize;
                messageStream >> repoName >> totalSize;

                qDebug() << "Received SEND_REPO_BUNDLE_START for" << repoName << "size" << totalSize;

                if (m_incomingTransfers.contains(socket))
                {
                    qWarning() << "Received duplicate SEND_REPO_BUNDLE_START for socket. Ignoring new start message.";
                    continue;
                }

                QString tempBundleDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/P2PGitBundles/" + QUuid::createUuid().toString();
                QDir tempDir(tempBundleDir);
                if (!tempDir.mkpath("."))
                {
                    qWarning() << "Could not create temp dir for bundle transfer:" << tempBundleDir;
                    emit repoBundleCompleted(repoName, "", false, "Could not create temporary directory for bundle.");
                    socket->disconnectFromHost(); // Disconnect on critical error
                    continue;                     // Stop processing
                }
                QString tempPath = tempDir.filePath(repoName + ".bundle"); // Use repo name in temp file path

                QFile *file = new QFile(tempPath, this); // Parent file to NetworkManager
                if (file->open(QIODevice::WriteOnly))
                {
                    auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, file, totalSize, 0};
                    m_incomingTransfers.insert(socket, transfer);
                    emit repoBundleTransferStarted(repoName, tempPath);
                }
                else
                {
                    qWarning() << "Could not open temp file for bundle transfer:" << tempPath << file->errorString();
                    emit repoBundleCompleted(repoName, tempPath, false, "Could not open local file for writing bundle.");
                    delete file;                  // Delete the file object
                    socket->disconnectFromHost(); // Disconnect on file error
                    continue;                     // Stop processing
                }
            }
            else if (messageType == "SEND_REPO_BUNDLE_END")
            {
                QString repoName;          // Read repo name, though transfer is socket-specific
                messageStream >> repoName; // This read is necessary to consume the data

                qDebug() << "Received SEND_REPO_BUNDLE_END for" << repoName;
                // The file transfer is considered complete when bytesReceived == totalSize.
                // The SEND_REPO_BUNDLE_END message is just a confirmation/final marker.
                // We don't need to do anything specific here if the transfer object exists
                // and bytesReceived already equals totalSize (handled in the file transfer block).
                // If this message arrives *before* the full file data, it indicates an issue.

                if (m_incomingTransfers.contains(socket))
                {
                    IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
                    if (transfer->bytesReceived < transfer->totalSize)
                    {
                        qWarning() << "Received SEND_REPO_BUNDLE_END prematurely for" << transfer->repoName << ". Expected" << transfer->totalSize << "bytes, got" << transfer->bytesReceived << ". Transfer failed.";
                        transfer->file->close();
                        emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, false, "Transfer ended prematurely by peer.");
                        delete m_incomingTransfers.take(socket);
                    }
                    else
                    {
                        // Transfer should already be marked complete and object removed,
                        // unless there was a race condition or processing delay.
                        qDebug() << "Received SEND_REPO_BUNDLE_END for" << transfer->repoName << ". Transfer bytes match, assuming already processed completion.";
                        // Ensure the transfer object is indeed removed if it wasn't already
                        if (m_incomingTransfers.contains(socket))
                        {
                            IncomingFileTransfer *t = m_incomingTransfers.take(socket);
                            t->file->close();
                            delete t;
                        }
                    }
                }
                else
                {
                    qWarning() << "Received unexpected SEND_REPO_BUNDLE_END for socket with no active incoming transfer.";
                }

                // Disconnect transfer-specific sockets after receiving END, as their job is done
                if (socket->property("is_transfer_socket").toBool())
                {
                    socket->disconnectFromHost(); // This triggers onTcpSocketDisconnected
                }
            }
            else if (messageType == "BROADCAST_MESSAGE")
            {
                QString message;
                messageStream >> message;

                QString peerUsername = m_socketToPeerUsernameMap.value(socket);
                if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID"))
                {
                    emit broadcastMessageReceived(socket, peerUsername, message);
                }
                else
                {
                    qWarning() << "Received BROADCAST_MESSAGE from unidentified peer.";
                }
            }
            else if (messageType == "GROUP_CHAT_MESSAGE")
            {
                // Expecting payload: ownerRepoAppId, message
                QString ownerRepoAppId, message;
                messageStream >> ownerRepoAppId >> message;

                QString senderPeerUsername = m_socketToPeerUsernameMap.value(socket);
                if (!senderPeerUsername.isEmpty() && !senderPeerUsername.startsWith("AwaitingID"))
                {
                    // Emit signal with sender, ownerRepoAppId, and message
                    emit groupMessageReceived(senderPeerUsername, ownerRepoAppId, message); // Corrected signal parameters
                }
                else
                {
                    qWarning() << "Received GROUP_CHAT_MESSAGE from unidentified peer.";
                }
            }
            else if (messageType == "ENCRYPTED_PAYLOAD")
            {
                QByteArray nonce, ciphertext;
                messageStream >> nonce >> ciphertext;

                QString peerId = m_socketToPeerUsernameMap.value(socket);
                if (peerId.isEmpty() || peerId.startsWith("AwaitingID") || peerId.startsWith("ConnectingTo") || peerId.startsWith("Transfer:"))
                {
                    qWarning() << "Received encrypted payload from unknown or un-handshaked peer" << getPeerDisplayString(socket) << ". Disconnecting to prevent buffer issues.";
                    socket->disconnectFromHost();
                    continue;
                }

                if (!m_peerPublicKeys.contains(peerId))
                {
                    qWarning() << "Cannot decrypt message from" << peerId << ": Public key not available. Disconnecting.";
                    socket->disconnectFromHost();
                    continue;
                }

                QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();
                QByteArray peerPubKey = m_peerPublicKeys.value(peerId);

                if (nonce.size() != crypto_box_NONCEBYTES || ciphertext.size() < crypto_box_MACBYTES)
                {
                    qWarning() << "Received encrypted payload with invalid size from" << peerId << ". Nonce size:" << nonce.size() << "Expected:" << crypto_box_NONCEBYTES << "Ciphertext size:" << ciphertext.size() << "Min Expected:" << crypto_box_MACBYTES;
                    continue; // Skip this message, try next
                }

                QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

                if (crypto_box_open_easy(
                        reinterpret_cast<unsigned char *>(decryptedMessage.data()),
                        reinterpret_cast<const unsigned char *>(ciphertext.constData()),
                        ciphertext.size(),
                        reinterpret_cast<const unsigned char *>(nonce.constData()),
                        reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
                        reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
                {
                    qWarning() << "Failed to decrypt message from" << peerId;
                    // Don't disconnect immediately on decryption failure, could be temporary key sync issue or single bad message.
                    continue; // Skip this message, try next
                }

                // Decryption successful, parse as JSON
                QJsonDocument doc = QJsonDocument::fromJson(decryptedMessage);
                if (doc.isObject())
                {
                    handleEncryptedPayload(peerId, doc.object().toVariantMap()); // Process the decrypted payload
                }
                else
                {
                    qWarning() << "Decrypted message from" << peerId << " is not a JSON object.";
                }
            }
            else
            {
                // Unknown message type
                qWarning() << "Unknown message type received:" << messageType << "from" << getPeerDisplayString(socket) << ". Disconnecting to prevent buffer issues.";
                socket->disconnectFromHost(); // Disconnect to clear buffer and state
                return;                       // Stop processing data for this socket
            }
        }
        else
        {
            // Not enough data for the next full message yet. Wait for more bytes.
            break;
        }

        // Loop back to process next message in buffer or more data from socket
    }
}

bool NetworkManager::isConnectionPending(QTcpSocket *socket) const
{
    return m_pendingConnections.contains(socket);
}

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    // Check if an 'established' connection already exists with this peer.
    // We can look up the peer ID if we have discovered info for this address/port.
    QString peerId = findUsernameForAddress(host); // May be empty if peer wasn't discovered

    // If peerId is known, check for an established connection
    QTcpSocket *existingSocket = nullptr;
    if (!peerId.isEmpty())
    {
        existingSocket = getSocketForPeer(peerId);
    }
    else
    {
        // If peerId is not known from discovery, we can't check getSocketForPeer
        // But we still might have a non-established socket connecting or pending acceptance.
        // For a clone, we ideally want a dedicated socket anyway.
        // Let's simplify and always create a new transfer socket for cloning *unless*
        // there is already a dedicated transfer socket to this specific address/port.
        for (QTcpSocket *sock : qAsConst(m_allTcpSockets))
        {
            if (sock->peerAddress() == host && sock->peerPort() == port && sock->property("is_transfer_socket").toBool() && sock->state() != QAbstractSocket::UnconnectedState)
            {
                qWarning() << "Transfer socket already exists or is connecting to" << host << ":" << port << ". Not starting a new one.";
                // In a real app, you'd manage pending/active transfers and queue requests.
                // For now, we just assume only one clone transfer per address at a time.
                emit repoBundleCompleted(repoName, localPath, false, "Transfer already in progress to this peer.");
                return; // Don't start a new connection if one is already exists for transfer
            }
        }
    }

    // Create a new socket specifically for the transfer
    QTcpSocket *socket = new QTcpSocket(this);       // Parented to NetworkManager
    socket->setProperty("is_transfer_socket", true); // Mark this socket as transfer-specific
    m_allTcpSockets.append(socket);                  // Add to list of all sockets
                                                     // Use a temporary name until handshake completes (transfer sockets do handshake too)
    m_socketToPeerUsernameMap.insert(socket, "Transfer:Cloning_" + repoName + "_from_" + host.toString());

    // Connect signals for the transfer socket
    connect(socket, &QTcpSocket::connected, this, [=]()
            {
                qDebug() << "Transfer socket connected to" << host << ":" << port << ". Sending identity handshake first.";
                sendIdentityOverTcp(socket); // Send identity handshake
                // The bundle request will be sent AFTER receiving the peer's handshake
                // in processIncomingTcpData, where we confirm the peer's identity.
                // We need a way to trigger the bundle request *after* handshake.
                // Let's add a temporary property to the socket or a map entry for pending bundle requests on new transfer sockets.

                // Temporarily store the bundle request details with the socket
                QVariantMap pendingBundleRequest;
                pendingBundleRequest["repoDisplayName"] = repoName;
                pendingBundleRequest["requesterLocalPath"] = localPath;
                socket->setProperty("pending_bundle_request", QVariant::fromValue(pendingBundleRequest)); });

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    // Start connection attempt
    qDebug() << "Attempting to connect new transfer socket to" << host << ":" << port;
    socket->connectToHost(host, port);

    // Set a connection timeout for the transfer socket
    QTimer *connectTimer = new QTimer(socket); // Parent to socket
    connectTimer->setSingleShot(true);
    connect(connectTimer, &QTimer::timeout, this, [=]()
            {
                if (socket->state() == QAbstractSocket::ConnectingState)
                {
                    qWarning() << "Transfer socket connection to" << host << ":" << port << "timed out.";
                    socket->abort(); // Abort the connection attempt
                    emit repoBundleCompleted(repoName, localPath, false, "Connection to peer timed out.");
                    // onTcpSocketDisconnected will clean up the socket and timer
                } });
    connectTimer->start(15000); // 15 second connection timeout
}

QString NetworkManager::getPeerDisplayString(QTcpSocket *socket)
{
    if (!socket)
        return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    QString addressPort = socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());

    if (!username.isEmpty())
    {
        if (username.startsWith("AwaitingID:"))
        {
            return "Incoming (" + addressPort + ")";
        }
        if (username.startsWith("ConnectingTo:"))
        {
            QString targetUser = username;
            targetUser.remove("ConnectingTo:");
            return "Connecting to " + targetUser + " (" + addressPort + ")";
        }
        if (username.startsWith("Transfer:"))
        {
            return "Transfer (" + addressPort + ")";
        }
        // Established connection
        return username + " (" + addressPort + ")";
    }
    // Fallback if no username is mapped yet
    return addressPort;
}

QTcpSocket *NetworkManager::getSocketForPeer(const QString &peerUsername)
{
    for (QTcpSocket *sock : qAsConst(m_allTcpSockets))
    {
        // Check if socket is connected, not pending, not a transfer socket, and username matches
        QString username = m_socketToPeerUsernameMap.value(sock, "");
        if (username == peerUsername &&
            !m_pendingConnections.contains(sock) &&           // Not a pending incoming connection
            !sock->property("is_transfer_socket").toBool() && // Not a dedicated transfer socket
            sock->state() == QAbstractSocket::ConnectedState)
        {
            return sock;
        }
    }
    return nullptr; // No established, non-transfer socket found for this peer
}

void NetworkManager::sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to send bundle request on disconnected socket.";
        return;
    }
    // Ensure this is NOT a transfer socket already performing a request
    if (targetPeerSocket->property("is_transfer_socket").toBool())
    {
        qWarning() << "Attempted to send bundle request on socket already marked as a transfer socket.";
        // This might be valid if re-using a transfer socket for multiple bundles? Not implemented.
        // For now, assume transfer sockets do one bundle then disconnect.
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    // Message format: Type, RequestingPeerUsername, RepoDisplayName, RequesterLocalPath (for receiver's info)
    out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoDisplayName << requesterLocalPath;

    if (targetPeerSocket->write(block) == -1)
    {
        qWarning() << "Failed to write REQUEST_REPO_BUNDLE to socket:" << targetPeerSocket->errorString();
    }
    else
    {
        qDebug() << "Sent REQUEST_REPO_BUNDLE for" << repoDisplayName << "to" << getPeerDisplayString(targetPeerSocket);
    }
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId);
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QMap<QString, QVariant> &payload)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Cannot send encrypted message: Socket is null or not connected.";
        return;
    }

    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || peerId.startsWith("AwaitingID") || peerId.startsWith("ConnectingTo") || peerId.startsWith("Transfer:"))
    {
        qWarning() << "Cannot send encrypted message to" << getPeerDisplayString(socket) << ": Peer not fully identified.";
        return;
    }

    if (!m_identityManager || !m_identityManager->areKeysInitialized())
    {
        qWarning() << "Cannot send encrypted message: IdentityManager not initialized.";
        return;
    }

    if (!m_peerPublicKeys.contains(peerId))
    {
        qWarning() << "Cannot send encrypted message to" << peerId << ": Public key not available.";
        // Disconnect peer if we need to send encrypted messages but don't have their key?
        // Or assume key will arrive via handshake? For now, just warn.
        return;
    }

    QJsonObject jsonPayload = QJsonObject::fromVariantMap(payload);
    // Add message type inside the encrypted payload for routing after decryption
    jsonPayload["__messageType"] = messageType;

    QByteArray plaintext = QJsonDocument(jsonPayload).toJson(QJsonDocument::Compact);
    QByteArray ciphertext(plaintext.size() + crypto_box_MACBYTES, 0);
    QByteArray nonce(crypto_box_NONCEBYTES, 0);

    // Generate a random nonce for this message
#ifdef USE_DETERMINISTIC_RANDOM // For testing, use deterministic nonce
                                // You would need a seed for this, e.g., derived from a shared secret or connection ID
                                // This is NOT suitable for production. For production, use randombytes_buf.
                                // unsigned char seed[crypto_box_SEEDBYTES]; // Example
                                // ... seed initialization ...
                                // randombytes_buf_deterministic(reinterpret_cast<unsigned char *>(nonce.data()), crypto_box_NONCEBYTES, seed);
    qWarning() << "Using deterministic random for nonce (TESTING ONLY!)";
    // Placeholder deterministic nonce generation for example
    memset(nonce.data(), 0xAA, crypto_box_NONCEBYTES); // Example constant nonce - INSECURE!
#else
    // Use cryptographically secure random bytes for nonce (REQUIRED for production)
    randombytes_buf(nonce.data(), crypto_box_NONCEBYTES);
#endif

    QByteArray mySecretKey = m_identityManager->getMyPrivateKeyBytes();
    QByteArray peerPubKey = m_peerPublicKeys.value(peerId);

    if (crypto_box_easy(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            reinterpret_cast<const unsigned char *>(plaintext.constData()),
            plaintext.size(),
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
            reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
    {
        qWarning() << "Failed to encrypt message of type" << messageType << "for" << peerId;
        return; // Encryption failed
    }

    // Prepare the outer message block with header and encrypted payload
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    // Outer message type indicates it's an encrypted payload, followed by nonce and ciphertext
    out << QString("ENCRYPTED_PAYLOAD") << nonce << ciphertext;

    // Add message size header
    QByteArray messageWithHeader;
    QDataStream headerOut(&messageWithHeader, QIODevice::WriteOnly);
    headerOut.setVersion(QDataStream::Qt_5_15);
    headerOut << (quint32)block.size(); // Write size of the data block
    messageWithHeader.append(block);    // Append the data block

    if (socket->write(messageWithHeader) == -1)
    {
        qWarning() << "Failed to write encrypted message to" << getPeerDisplayString(socket) << ":" << socket->errorString();
        // Handle write error - socket might be broken
    }
    else
    {
        qDebug() << "Sent encrypted message of type" << messageType << "to" << getPeerDisplayString(socket) << "(" << messageWithHeader.size() << " bytes)";
    }
}

bool NetworkManager::startTcpServer(quint16 port)
{
    if (!m_identityManager || !m_identityManager->areKeysInitialized() || m_myUsername.isEmpty() || !m_repoManager_ptr)
    {
        qWarning() << "Cannot start TCP server: Dependencies not initialized.";
        emit tcpServerStatusChanged(false, port, "Dependencies not initialized.");
        return false;
    }

    if (m_tcpServer->isListening())
    {
        qDebug() << "TCP Server already listening on port" << m_tcpServer->serverPort();
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        startUdpDiscovery(); // Ensure discovery is also running
        return true;
    }

    // Try to listen on the specified port or any available port (port 0)
    if (m_tcpServer->listen(QHostAddress::Any, port))
    {
        quint16 boundPort = m_tcpServer->serverPort(); // Get the actual bound port if port was 0
        qInfo() << "TCP Server listening on port" << boundPort;
        emit tcpServerStatusChanged(true, boundPort, "");
        startUdpDiscovery(); // Start UDP discovery once server is listening
        return true;
    }
    else
    {
        QString errorString = m_tcpServer->errorString();
        qCritical() << "Failed to start TCP server:" << errorString;
        emit tcpServerStatusChanged(false, port, errorString);
        return false;
    }
}

void NetworkManager::stopTcpServer()
{
    if (m_tcpServer && m_tcpServer->isListening())
    {
        quint16 p = m_tcpServer->serverPort();
        m_tcpServer->close();
        qInfo() << "TCP Server stopped listening on port" << p;
        emit tcpServerStatusChanged(false, p);
        // Note: We don't disconnect peers here. Peers stay connected until they disconnect or server stops entirely (e.g. app exit).
        // disconnectAllTcpPeers() is called on app exit in MainWindow::closeEvent.
    }
    stopUdpDiscovery(); // Stop UDP discovery when server stops
}

quint16 NetworkManager::getTcpServerPort() const
{
    return (m_tcpServer && m_tcpServer->isListening()) ? m_tcpServer->serverPort() : 0;
}

bool NetworkManager::connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername)
{
    // Prevent connecting to self if address is local
    QList<QHostAddress> localAddresses = QNetworkInterface::allAddresses();
    bool isLocalAddress = false;
    for (const auto &addr : localAddresses)
    {
        // Handle IPv4 mapped IPv6 addresses
        if (addr.protocol() == QAbstractSocket::IPv6Protocol && addr.toIPv4Address() != 0)
        {
            if (QHostAddress(addr.toIPv4Address()) == hostAddress)
            {
                isLocalAddress = true;
                break;
            }
        }
        // Handle standard IPv4 and IPv6 local addresses
        else if (addr == hostAddress)
        {
            isLocalAddress = true;
            break;
        }
    }

    if (isLocalAddress && port == getTcpServerPort()) // Check if port also matches my server port
    {
        qWarning() << "Attempted to connect to myself.";
        emit tcpConnectionStatusChanged(expectedPeerUsername.isEmpty() ? hostAddress.toString() : expectedPeerUsername, "", false, "Cannot connect to self.");
        return false;
    }

    // Check if an established connection already exists with this peer username
    if (!expectedPeerUsername.isEmpty() && getSocketForPeer(expectedPeerUsername) != nullptr)
    {
        qDebug() << "Already connected to peer" << expectedPeerUsername;
        // Get current public key hex if available
        QString peerPubKeyHex = m_peerPublicKeys.contains(expectedPeerUsername) ? m_peerPublicKeys.value(expectedPeerUsername).toHex() : "";
        emit tcpConnectionStatusChanged(expectedPeerUsername, peerPubKeyHex, true, "Already connected.");
        return true;
    }

    // Check if a connection attempt is already in progress to this address/port
    for (QTcpSocket *sock : qAsConst(m_allTcpSockets))
    {
        if (sock->peerAddress() == hostAddress && sock->peerPort() == port && sock->state() == QAbstractSocket::ConnectingState)
        {
            qDebug() << "Connection attempt already in progress to" << hostAddress << ":" << port;
            // Optionally emit status changed or log message
            emit tcpConnectionStatusChanged(expectedPeerUsername.isEmpty() ? hostAddress.toString() : expectedPeerUsername, "", false, "Connection already in progress.");
            return false; // Don't start a duplicate attempt
        }
    }

    QTcpSocket *socket = new QTcpSocket(this); // Parented to NetworkManager
    // Mark this as an outgoing attempt, will be cleared on handshake completion
    socket->setProperty("is_outgoing_attempt", true);
    m_allTcpSockets.append(socket); // Add to list of all sockets
    // Temporarily map socket to the expected peer username
    m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + expectedPeerUsername);

    // Connect signals
    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            {
                qDebug() << "Outgoing socket connected to" << getPeerDisplayString(socket) << ". Sending identity.";
                sendIdentityOverTcp(socket); // Send identity handshake immediately upon connection
                                             // Handshake response will be processed in onTcpSocketReadyRead / processIncomingTcpData
            });

    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    // Set a connection timeout
    QTimer *connectTimer = new QTimer(socket); // Parent to socket
    connectTimer->setSingleShot(true);
    connect(connectTimer, &QTimer::timeout, this, [=]()
            {
                if (socket->state() == QAbstractSocket::ConnectingState)
                {
                    qWarning() << "Outgoing connection attempt to" << hostAddress << ":" << port << "timed out.";
                    QString peerNameFromMap = m_socketToPeerUsernameMap.value(socket, "");
                    if(peerNameFromMap.startsWith("ConnectingTo:")) peerNameFromMap.remove("ConnectingTo:");
                    else peerNameFromMap = hostAddress.toString(); // Use address if no specific name was mapped

                    socket->abort(); // Abort the connection attempt
                    emit tcpConnectionStatusChanged(peerNameFromMap, "", false, "Connection timed out.");
                    // onTcpSocketDisconnected will clean up the socket and timer
                } });
    connectTimer->start(15000); // 15 second timeout

    qDebug() << "Attempting outgoing connection to" << hostAddress << ":" << port << " expecting peer" << expectedPeerUsername;
    socket->connectToHost(hostAddress, port);

    // Emit status change immediately for UI feedback (Connecting state)
    emit tcpConnectionStatusChanged(expectedPeerUsername.isEmpty() ? hostAddress.toString() : expectedPeerUsername, "", false, "Connecting...");

    return true; // Connection attempt initiated
}

void NetworkManager::disconnectAllTcpPeers()
{
    qDebug() << "Disconnecting all TCP peers (" << m_allTcpSockets.size() << " sockets)...";
    // Iterate over a copy of the list as disconnecting modifies the list
    QList<QTcpSocket *> socketsToDisconnect = m_allTcpSockets;
    for (QTcpSocket *sock : socketsToDisconnect)
    {
        if (sock && sock->state() != QAbstractSocket::UnconnectedState)
        {
            // Check if the socket is still in m_allTcpSockets before disconnecting
            if (m_allTcpSockets.contains(sock))
            {
                qDebug() << "Disconnecting socket:" << getPeerDisplayString(sock);
                sock->disconnectFromHost(); // This triggers onTcpSocketDisconnected
            }
        }
    }
    m_allTcpSockets.clear(); // Should be empty after disconnection signals are processed, but clear for safety
}

bool NetworkManager::hasActiveTcpConnections() const
{
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        // An "active" connection is one where handshake is complete and it's not a temp transfer socket
        QString username = m_socketToPeerUsernameMap.value(socket, "");
        if (!username.isEmpty() && !username.startsWith("AwaitingID:") && !username.startsWith("Transfer:") && !username.startsWith("ConnectingTo:") && socket->state() == QAbstractSocket::ConnectedState)
        {
            return true;
        }
    }
    return false;
}

bool NetworkManager::startUdpDiscovery(quint16 udpPort)
{
    m_udpDiscoveryPort = udpPort;
    if (!m_identityManager || !m_identityManager->areKeysInitialized() || m_myUsername.isEmpty() || !m_repoManager_ptr)
    {
        qWarning() << "Cannot start UDP discovery: Dependencies not initialized.";
        return false;
    }

    // Close socket if already bound to a different port
    if (m_udpSocket->state() != QAbstractSocket::UnconnectedState && m_udpSocket->localPort() != m_udpDiscoveryPort)
    {
        m_udpSocket->close();
    }

    if (m_udpSocket->state() == QAbstractSocket::UnconnectedState)
    {
        // Try to bind to the discovery port
        if (!m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
        {
            qWarning() << "Failed to bind UDP Discovery socket to port" << m_udpDiscoveryPort << ":" << m_udpSocket->errorString();
            // Try binding to any available port as fallback? Or is a fixed port required?
            // Let's assume a fixed port is needed for peers to find each other.
            // If binding fails, emit an error status? The TCP status covers this.
            return false;
        }
        qInfo() << "UDP Discovery socket bound to port" << m_udpSocket->localPort();
    }
    else
    {
        qDebug() << "UDP socket is already bound on port" << m_udpSocket->localPort();
    }

    // Start the broadcast timer regardless of whether the socket was just bound or already was
    if (!m_broadcastTimer->isActive())
    {
        m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast(); // Send an immediate broadcast upon starting
    }

    return true; // UDP discovery started (socket bound and timer active)
}

void NetworkManager::stopUdpDiscovery()
{
    qDebug() << "Stopping UDP Discovery.";
    m_broadcastTimer->stop(); // Stop the timer
    if (m_udpSocket && m_udpSocket->state() != QAbstractSocket::UnconnectedState)
    {
        m_udpSocket->close(); // Close the UDP socket
        qDebug() << "UDP socket closed.";
    }
    // Clear discovered peers that are no longer seen? Cleanup timer handles this.
}

void NetworkManager::sendDiscoveryBroadcast()
{
    // Check if TCP server is listening (required for broadcasting a port),
    // if identity is ready, repo manager available, and UDP socket is bound.
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myUsername.isEmpty() || !m_identityManager || !m_repoManager_ptr || m_udpSocket->state() != QAbstractSocket::BoundState)
    {
        // Log warnings if key components are not ready, but don't necessarily fail silently.
        if (!m_tcpServer || !m_tcpServer->isListening())
            qWarning() << "Cannot send broadcast: TCP server not listening.";
        if (m_myUsername.isEmpty() || !m_identityManager || !m_identityManager->areKeysInitialized())
            qWarning() << "Cannot send broadcast: Identity not ready.";
        if (!m_repoManager_ptr)
            qWarning() << "Cannot send broadcast: RepoManager not available.";
        if (m_udpSocket->state() != QAbstractSocket::BoundState)
            qWarning() << "Cannot send broadcast: UDP socket not bound.";
        return;
    }

    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    // Get list of repos owned by THIS peer that are publicly shareable
    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclyShareableRepos(); // Use the new method
    QStringList publicRepoNames;
    for (const auto &repoInfo : publicRepos)
        publicRepoNames.append(repoInfo.displayName); // Send just the display names

    // Discovery message format: Magic Header, Username, TCP Port, Public Key Hex, List of Public Repo Names
    out << QString("P2PGIT_DISCOVERY_V3")
        << m_myUsername
        << m_tcpServer->serverPort()
        << QString::fromStdString(m_identityManager->getMyPublicKeyHex())
        << publicRepoNames;

    // Send the datagram to the broadcast address on the discovery port
    qint64 sentBytes = m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
    if (sentBytes == -1)
    {
        qWarning() << "Failed to send UDP broadcast:" << m_udpSocket->errorString();
    }
    else
    {
        qDebug() << "Sent UDP discovery broadcast (" << sentBytes << " bytes).";
    }
}

void NetworkManager::onUdpReadyRead()
{
    while (m_udpSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        datagram.resize(int(m_udpSocket->pendingDatagramSize()));
        QHostAddress senderAddress;
        quint16 senderPort;
        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress, &senderPort);

        // Ignore broadcasts from self (check by IP address and port, or better, by public key)
        // Check by public key is more reliable if hairpinning is an issue or on multi-homed hosts.
        QString myPubKeyHex = m_identityManager ? QString::fromStdString(m_identityManager->getMyPublicKeyHex()) : QString();

        QDataStream in(datagram);
        in.setVersion(QDataStream::Qt_5_15);

        // Start a transaction to safely read the datagram contents
        in.startTransaction();

        QString magicHeader;
        in >> magicHeader;

        if (magicHeader == "P2PGIT_DISCOVERY_V3")
        {
            QString receivedUsername, receivedPublicKeyHex;
            quint16 receivedTcpPort;
            QStringList receivedPublicRepoNames;

            in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex >> receivedPublicRepoNames;

            // Commit the transaction only if parsing was successful
            if (in.commitTransaction())
            {
                // Ignore broadcast if the public key matches mine
                if (!myPubKeyHex.isEmpty() && receivedPublicKeyHex == myPubKeyHex)
                {
                    qDebug() << "Ignoring broadcast from self:" << receivedUsername;
                    continue; // Process next datagram
                }

                // Create or update DiscoveredPeerInfo
                DiscoveredPeerInfo info;
                info.id = receivedUsername;
                info.address = senderAddress;
                info.tcpPort = receivedTcpPort;
                info.publicKeyHex = receivedPublicKeyHex;
                info.publicRepoNames = receivedPublicRepoNames; // List of public repos announced by this peer
                info.lastSeen = QDateTime::currentMSecsSinceEpoch();

                bool isNewPeer = !m_discoveredPeers.contains(receivedUsername);
                bool infoChanged = false;

                // Check if existing info is different (address, port, public key, repo list)
                if (!isNewPeer)
                {
                    const DiscoveredPeerInfo &existing = m_discoveredPeers.value(receivedUsername);
                    if (existing.address != senderAddress || existing.tcpPort != receivedTcpPort || existing.publicKeyHex != receivedPublicKeyHex || existing.publicRepoNames != receivedPublicRepoNames)
                    {
                        infoChanged = true;
                    }
                }

                m_discoveredPeers.insert(receivedUsername, info); // Add or update the entry

                // Store peer's public key for potential encrypted communication
                if (!receivedPublicKeyHex.isEmpty() && !m_peerPublicKeys.contains(receivedUsername))
                {
                    m_peerPublicKeys.insert(receivedUsername, QByteArray::fromHex(receivedPublicKeyHex.toUtf8()));
                    qDebug() << "Stored public key for peer:" << receivedUsername;
                }
                else if (!receivedPublicKeyHex.isEmpty() && m_peerPublicKeys.contains(receivedUsername) && m_peerPublicKeys.value(receivedUsername) != QByteArray::fromHex(receivedPublicKeyHex.toUtf8()))
                {
                    qWarning() << "Received broadcast from known peer" << receivedUsername << "with a different public key. This could indicate an issue.";
                    // Decide how to handle this: replace key? warn? disconnect?
                    // For now, replace the key.
                    m_peerPublicKeys.insert(receivedUsername, QByteArray::fromHex(receivedPublicKeyHex.toUtf8()));
                    infoChanged = true; // Mark info as changed since PK changed
                }

                // Emit signal if it's a new peer or existing info changed
                if (isNewPeer || infoChanged)
                {
                    qDebug() << "Discovered/Updated peer:" << receivedUsername << "@" << senderAddress.toString() << ":" << receivedTcpPort;
                    emit lanPeerDiscoveredOrUpdated(info);
                }
            }
            else
            {
                qWarning() << "Failed to commit transaction after reading discovery header from" << senderAddress.toString() << ". Incomplete data?";
                // Rollback is automatic if commitTransaction returns false
            }
        }
        else
        {
            qWarning() << "Received unknown UDP datagram type:" << magicHeader << "from" << senderAddress.toString();
            in.rollbackTransaction(); // Rollback the transaction for unknown types
        }
    }
}

void NetworkManager::onBroadcastTimerTimeout()
{
    sendDiscoveryBroadcast();
}

void NetworkManager::onPeerCleanupTimerTimeout()
{
    qint64 now = QDateTime::currentMSecsSinceEpoch();
    QMutableMapIterator<QString, DiscoveredPeerInfo> i(m_discoveredPeers);
    while (i.hasNext())
    {
        i.next();
        // Remove peer if last seen is too old AND we are NOT currently connected to them via an established socket.
        // Connected peers shouldn't time out from the *discovered* list, although their 'lastSeen' might become old.
        // We only remove from the discovered list if they time out AND we have no active connection.
        if (now - i.value().lastSeen > PEER_TIMEOUT_MS && getSocketForPeer(i.key()) == nullptr)
        {
            qDebug() << "Peer" << i.key() << "timed out from discovery.";
            emit lanPeerLost(i.key());
            i.remove();                       // Remove from discovered peers map
            m_peerPublicKeys.remove(i.key()); // Remove their public key as well
        }
    }
}

void NetworkManager::sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args)
{
    if (!peerSocket || peerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to send message on disconnected or null socket.";
        return;
    }

    QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
    if (peerUsername.isEmpty() || peerUsername.startsWith("AwaitingID") || peerUsername.startsWith("ConnectingTo") || peerUsername.startsWith("Transfer:"))
    {
        qWarning() << "Attempted to send message of type" << messageType << "on a socket that is not an established peer connection:" << getPeerDisplayString(peerSocket);
        // Decide if we should disconnect such sockets. For now, just warn and return.
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    // Write message type and arguments
    out << messageType;
    for (const QVariant &arg : args)
    {
        out << arg;
    }

    // Add message size header
    QByteArray messageWithHeader;
    QDataStream headerOut(&messageWithHeader, QIODevice::WriteOnly);
    headerOut.setVersion(QDataStream::Qt_5_15);
    headerOut << (quint32)block.size(); // Write size of the data block
    messageWithHeader.append(block);    // Append the data block

    if (peerSocket->write(messageWithHeader) == -1)
    {
        qWarning() << "Failed to write message of type" << messageType << "to" << getPeerDisplayString(peerSocket) << ":" << peerSocket->errorString();
        // Handle write error - socket might be broken
    }
    else
    {
        qDebug() << "Sent message type" << messageType << "to" << getPeerDisplayString(peerSocket) << "(" << messageWithHeader.size() << " bytes)";
    }
}

// Updated signature to take ownerRepoAppId and message
void NetworkManager::sendGroupChatMessage(const QString &ownerRepoAppId, const QString &message)
{
    if (!m_repoManager_ptr)
        return;

    // Find the managed repository locally using the ownerRepoAppId
    // This ensures we get the correct group members list from our perspective.
    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfoByOwnerAppId(ownerRepoAppId);

    if (!repoInfo.isValid())
    {
        qWarning() << "Attempted to send group chat for unknown repo group App ID:" << ownerRepoAppId;
        return;
    }

    // Get the list of members in this group
    QStringList members = repoInfo.groupMembers;
    members.removeDuplicates();

    qDebug() << "Sending group chat message for repo group" << ownerRepoAppId << "to members:" << members;

    // Send the message to all members who are currently connected (excluding self)
    for (const QString &memberId : members)
    {
        if (memberId == m_myUsername)
            continue; // Don't send to self

        QTcpSocket *memberSocket = getSocketForPeer(memberId); // Find an established socket for the member
        if (memberSocket)
        {
            qDebug() << "Sending group chat message to member" << memberId << "for repo group" << ownerRepoAppId;
            // Message payload for group chat: ownerRepoAppId, message
            sendMessageToPeer(memberSocket, "GROUP_CHAT_MESSAGE", {ownerRepoAppId, message});
        }
        else
        {
            qDebug() << "Member" << memberId << "is not currently connected. Cannot send group chat message.";
            // Future: Queue messages for offline peers?
        }
    }
}

void NetworkManager::sendIdentityOverTcp(QTcpSocket *socket)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager || !m_identityManager->areKeysInitialized())
    {
        qWarning() << "Cannot send identity: Socket invalid or identity not ready.";
        // Decide if we should disconnect the socket if we can't send identity. Yes, likely.
        if (socket && socket->state() != QAbstractSocket::UnconnectedState)
        {
            socket->disconnectFromHost();
        }
        return;
    }

    // Check if identity was already sent on this socket
    if (m_handshakeSent.contains(socket))
    {
        qDebug() << "Identity already sent for socket" << getPeerDisplayString(socket);
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    // Handshake message format: Type, Username, Public Key Hex
    out << QString("IDENTITY_HANDSHAKE_V2") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());

    // Add message size header
    QByteArray messageWithHeader;
    QDataStream headerOut(&messageWithHeader, QIODevice::WriteOnly);
    headerOut.setVersion(QDataStream::Qt_5_15);
    headerOut << (quint32)block.size(); // Write size of the data block
    messageWithHeader.append(block);    // Append the data block

    if (socket->write(messageWithHeader) == -1)
    {
        qWarning() << "Failed to write IDENTITY_HANDSHAKE_V2 to socket:" << socket->errorString();
        // Handle write error - socket might be broken
        socket->disconnectFromHost();
    }
    else
    {
        m_handshakeSent.insert(socket); // Mark that we have sent our handshake on this socket
        qDebug() << "Sent IDENTITY_HANDSHAKE_V2 to" << getPeerDisplayString(socket);

        // If this is an outgoing transfer socket, send the pending bundle request AFTER handshake is sent
        if (socket->property("is_transfer_socket").toBool() && socket->property("pending_bundle_request").isValid())
        {
            QVariantMap pendingRequest = socket->property("pending_bundle_request").value<QVariantMap>();
            QString repoDisplayName = pendingRequest.value("repoDisplayName").toString();
            QString requesterLocalPath = pendingRequest.value("requesterLocalPath").toString();
            socket->setProperty("pending_bundle_request", QVariant()); // Clear the property

            if (!repoDisplayName.isEmpty())
            {
                qDebug() << "Sending pending bundle request after handshake for transfer socket.";
                sendRepoBundleRequest(socket, repoDisplayName, requesterLocalPath);
            }
        }
    }
}

QString NetworkManager::findUsernameForAddress(const QHostAddress &address)
{
    QHostAddress addrToCompare = address;
    // Normalize IPv4 mapped IPv6 addresses for comparison
    if (address.protocol() == QAbstractSocket::IPv6Protocol && address.toIPv4Address() != 0)
    {
        addrToCompare = QHostAddress(address.toIPv4Address());
    }
    for (const auto &peerInfo : qAsConst(m_discoveredPeers))
    {
        QHostAddress peerAddrToCompare = peerInfo.address;
        // Normalize IPv4 mapped IPv6 addresses for comparison
        if (peerAddrToCompare.protocol() == QAbstractSocket::IPv6Protocol && peerAddrToCompare.toIPv4Address() != 0)
        {
            peerAddrToCompare = QHostAddress(peerAddrToCompare.toIPv4Address());
        }

        if (peerAddrToCompare == addrToCompare)
        {
            return peerInfo.id; // Return the known username for this address
        }
    }
    return QString(); // No known username found for this address
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
    {
        qWarning() << "Attempted to start bundle transfer on disconnected or null socket.";
        return;
    }
    if (m_outgoingTransfers.contains(targetPeerSocket))
    {
        qWarning() << "Already an outgoing transfer active on socket" << getPeerDisplayString(targetPeerSocket);
        // Handle this case - maybe queue the transfer or report error
        // For now, just return.
        return;
    }

    QFile *bundleFile = new QFile(bundleFilePath); // Parent file to NetworkManager
    if (!bundleFile->open(QIODevice::ReadOnly))
    {
        qWarning() << "Failed to open bundle file for sending:" << bundleFilePath << bundleFile->errorString();
        delete bundleFile; // Delete the file object
        return;
    }

    qint64 fileSize = bundleFile->size();
    if (fileSize == 0)
    {
        qWarning() << "Bundle file is empty:" << bundleFilePath;
        bundleFile->close();
        delete bundleFile;
        QFile::remove(bundleFilePath); // Clean up the empty bundle file
        return;
    }

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    // Message format: Type, RepoDisplayName, TotalSize
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << fileSize;

    // Add message size header to the START block
    QByteArray startMessageWithHeader;
    QDataStream startHeaderOut(&startMessageWithHeader, QIODevice::WriteOnly);
    startHeaderOut.setVersion(QDataStream::Qt_5_15);
    startHeaderOut << (quint32)startBlock.size(); // Write size of the data block
    startMessageWithHeader.append(startBlock);    // Append the data block

    qDebug() << "Sending SEND_REPO_BUNDLE_START for" << repoDisplayName << "size" << fileSize << "to" << getPeerDisplayString(targetPeerSocket);
    qint64 writtenBytes = targetPeerSocket->write(startMessageWithHeader);

    if (writtenBytes == -1)
    {
        qWarning() << "Error writing SEND_REPO_BUNDLE_START to socket:" << targetPeerSocket->errorString();
        bundleFile->close();
        delete bundleFile;
        QFile::remove(bundleFilePath);          // Clean up the bundle file
        targetPeerSocket->disconnectFromHost(); // Disconnect on write error
        return;
    }

    // Create the outgoing transfer object
    auto *transfer = new OutgoingFileTransfer{bundleFile, repoDisplayName, bundleFilePath, fileSize, 0};
    m_outgoingTransfers.insert(targetPeerSocket, transfer); // Map socket to outgoing transfer

    // Connect bytesWritten signal to send file data chunks
    // Use a lambda capturing 'transfer' and 'targetPeerSocket'
    connect(targetPeerSocket, &QIODevice::bytesWritten, this, [this, targetPeerSocket, transfer](qint64 bytes)
            {
                // Ensure this lambda is only executed for the intended transfer
                if (!m_outgoingTransfers.contains(targetPeerSocket) || m_outgoingTransfers.value(targetPeerSocket) != transfer)
                {
                    qWarning() << "bytesWritten signal for unexpected transfer socket or transfer object.";
                    return;
                }

                // Update bytes sent count (this includes the header bytes initially, which is fine)
                transfer->bytesSent += bytes;

                // Send more data from the file if the socket's write buffer is empty
                while (targetPeerSocket->bytesToWrite() == 0 && !transfer->file->atEnd())
                {
                    // Read a chunk from the file
                    char buffer[FILE_TRANSFER_CHUNK_SIZE]; // Define a chunk size
                    qint64 bytesRead = transfer->file->read(buffer, sizeof(buffer));

                    if (bytesRead > 0)
                    {
                        // Write the chunk to the socket
                        qint64 chunkWritten = targetPeerSocket->write(buffer, bytesRead);
                        if (chunkWritten == -1)
                        {
                            qWarning() << "Error writing bundle chunk to socket:" << targetPeerSocket->errorString();
                            handleOutgoingTransferError(targetPeerSocket, "Error writing bundle data.");
                            return; // Stop sending data for this transfer
                        }
                        // Note: chunkWritten might be less than bytesRead if socket buffer is full.
                        // The bytesWritten signal will be emitted again when space is available.
                        // The loop condition `targetPeerSocket->bytesToWrite() == 0` handles this.
                    }
                    else if (bytesRead == -1) // Error reading from file
                    {
                        qWarning() << "Error reading from bundle file:" << transfer->file->errorString();
                        handleOutgoingTransferError(targetPeerSocket, "Error reading bundle file.");
                        return; // Stop sending data
                    }
                    // If bytesRead is 0, it means end of file or nothing more to read for now.
                }

                // Check if all file data has been written to the socket's buffer
                // (This does not mean it has been sent over the network yet)
                if (transfer->file->atEnd() && targetPeerSocket->bytesToWrite() == 0)
                {
                    qDebug() << "Finished writing all file data for bundle:" << transfer->repoName << " to socket buffer.";

                    // Send the END message after all file data is in the socket's write buffer
                    QByteArray endBlock;
                    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
                    endOut.setVersion(QDataStream::Qt_5_15);
                    endOut << QString("SEND_REPO_BUNDLE_END") << transfer->repoName; // Send repo name as confirmation

                    // Add message size header to the END block
                    QByteArray endMessageWithHeader;
                    QDataStream endHeaderOut(&endMessageWithHeader, QIODevice::WriteOnly);
                    endHeaderOut.setVersion(QDataStream::Qt_5_15);
                    endHeaderOut << (quint32)endBlock.size(); // Write size of the data block
                    endMessageWithHeader.append(endBlock);    // Append the data block

                    qint64 endWritten = targetPeerSocket->write(endMessageWithHeader);
                    if (endWritten == -1)
                    {
                        qWarning() << "Error writing SEND_REPO_BUNDLE_END to socket:" << targetPeerSocket->errorString();
                         handleOutgoingTransferError(targetPeerSocket, "Error writing end message."); // Handle error
                    }
                    else
                    {
                        qDebug() << "Sent SEND_REPO_BUNDLE_END for" << transfer->repoName << "(" << endMessageWithHeader.size() << " bytes).";
                         // Disconnect the bytesWritten signal once the END message is sent
                         // Use disconnect with specific sender and signal to avoid disconnecting other slots
                         disconnect(targetPeerSocket, &QIODevice::bytesWritten, this, nullptr); // Disconnect all slots connected from 'this' to bytesWritten of this socket
                         // Or disconnect the specific lambda if possible (more complex, requires storing the connection)

                         // The transfer is logically complete from the sender's side once END is written.
                         // Clean up the transfer object and the bundle file.
                         if (m_outgoingTransfers.remove(targetPeerSocket))
                         {
                              transfer->file->close();
                              delete transfer->file;
                              delete transfer; // Deletes the OutgoingFileTransfer object
                         }

                         // Emit bundle sent signal
                         QString recipientUsername = m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer");
                         emit repoBundleSent(transfer->repoName, recipientUsername);

                         // Clean up the source bundle file
                         QFile::remove(transfer->bundleFilePath);
                         qDebug() << "Cleaned up source bundle file:" << transfer->bundleFilePath;

                         // Disconnect transfer-specific sockets after completion
                         if (targetPeerSocket->property("is_transfer_socket").toBool())
                         {
                             targetPeerSocket->disconnectFromHost(); // This triggers onTcpSocketDisconnected
                         }
                    }
                } });

    // The first chunk of file data will be sent automatically after the START message
    // when the bytesWritten signal is emitted for the START message.
}

void NetworkManager::handleOutgoingTransferError(QTcpSocket *socket, const QString &message)
{
    qWarning() << "Outgoing transfer error for socket:" << getPeerDisplayString(socket) << ":" << message;
    if (m_outgoingTransfers.contains(socket))
    {
        OutgoingFileTransfer *transfer = m_outgoingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file;
        }
        // Attempt to clean up the source bundle file
        QFile::remove(transfer->bundleFilePath);
        qDebug() << "Cleaned up source bundle file after error:" << transfer->bundleFilePath;

        // Note: The temporary directory containing the bundle might remain.
        // A separate cleanup process for old temp directories might be needed.

        delete transfer; // Delete the transfer object
    }
    // Disconnect the socket if it's not already disconnected by the error
    if (socket && socket->state() != QAbstractSocket::UnconnectedState)
    {
        socket->disconnectFromHost(); // Triggers onTcpSocketDisconnected
    }
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    qDebug() << "Socket disconnected:" << getPeerDisplayString(socket);

    // Clean up pending connection timer if this was a pending incoming socket
    if (m_pendingConnections.contains(socket))
    {
        QTimer *timer = m_pendingConnections.take(socket);
        if (timer)
            timer->deleteLater();
        qDebug() << "Cleaned up pending timer for disconnected socket.";
    }

    // Clean up incoming file transfer if one was active on this socket
    if (m_incomingTransfers.contains(socket))
    {
        qWarning() << "Incoming file transfer interrupted due to disconnection.";
        IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file; // Delete the file object
        }
        // Attempt to clean up the incomplete bundle file
        QFile::remove(transfer->tempLocalPath);
        qDebug() << "Cleaned up incomplete bundle file:" << transfer->tempLocalPath;

        emit repoBundleCompleted(transfer->repoName, transfer->tempLocalPath, false, "Connection disconnected during bundle transfer.");
        delete transfer; // Delete the transfer object
        qDebug() << "Cleaned up incoming transfer for disconnected socket.";
    }

    // Clean up outgoing file transfer if one was active on this socket
    if (m_outgoingTransfers.contains(socket))
    {
        qWarning() << "Outgoing file transfer interrupted due to disconnection.";
        OutgoingFileTransfer *transfer = m_outgoingTransfers.take(socket);
        if (transfer->file)
        {
            if (transfer->file->isOpen())
                transfer->file->close();
            delete transfer->file; // Delete the file object
        }
        // Attempt to clean up the source bundle file
        QFile::remove(transfer->bundleFilePath);
        qDebug() << "Cleaned up source bundle file after disconnection:" << transfer->bundleFilePath;

        delete transfer; // Delete the transfer object
        qDebug() << "Cleaned up outgoing transfer for disconnected socket.";
    }

    m_socketBuffers.remove(socket); // Remove buffer for this socket
    m_handshakeSent.remove(socket); // Remove handshake sent flag for this socket

    // Get the peer username BEFORE removing from the map
    QString peerUsername = m_socketToPeerUsernameMap.value(socket);

    // Remove socket from the list of all sockets and the username map
    m_allTcpSockets.removeAll(socket);
    m_socketToPeerUsernameMap.remove(socket);

    // If this was an established, non-temporary peer connection, emit signal
    // Check if the username was a valid established peer ID (not a temp placeholder)
    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID:") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo:"))
    {
        qDebug() << "Established peer disconnected:" << peerUsername;
        // Also remove their public key if they disconnect? Maybe keep it for a while.
        // m_peerPublicKeys.remove(peerUsername); // Decision: Keep key until peer cleanup timer removes discovered peer

        emit tcpPeerDisconnected(socket, peerUsername);
        // MainWindow handles UI updates based on this signal
    }
    else
    {
        qDebug() << "Temporary or non-established socket disconnected:" << peerUsername;
        // For non-established sockets, no need to emit tcpPeerDisconnected
        // If it was an outgoing connecting socket that timed out, status changed was already emitted by the timer.
        // If it was a pending incoming socket that was rejected, status changed was already emitted by rejectPendingTcpConnection.
        // If it was a transfer socket, completion/error was already emitted by bundle handlers.
    }

    socket->deleteLater(); // Schedule socket for deletion
    qDebug() << "Socket scheduled for deletion.";
}

void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError); // Socket error enum value
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    qWarning() << "Socket Error on" << getPeerDisplayString(socket) << ":" << socket->errorString();

    // The socket will usually emit disconnected() after an error, which handles cleanup.
    // We can emit a status change for logging here if it's an established peer.
    QString peerUsername = m_socketToPeerUsernameMap.value(socket, "");
    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID:") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo:"))
    {
        emit tcpConnectionStatusChanged(peerUsername, "", false, socket->errorString());
    }
    else if (peerUsername.startsWith("ConnectingTo:"))
    {
        // If it was an outgoing connection attempt, update status (connection failed)
        QString targetUser = peerUsername;
        targetUser.remove("ConnectingTo:");
        emit tcpConnectionStatusChanged(targetUser, "", false, socket->errorString());
    }

    // onTcpSocketDisconnected will be called next and handle socket cleanup
}

void NetworkManager::addSharedRepoToPeer(const QString &peerId, const QString &repoName)
{
    if (m_discoveredPeers.contains(peerId))
    {
        DiscoveredPeerInfo info = m_discoveredPeers.value(peerId);
        // Add the repository name to the peer's list of publicly advertised/shareable repos if it's not already there
        // This list is used by the UI to show what repos are available from a peer.
        if (!info.publicRepoNames.contains(repoName))
        {
            info.publicRepoNames.append(repoName);
            // Sort the list for consistent display (optional)
            std::sort(info.publicRepoNames.begin(), info.publicRepoNames.end());
            m_discoveredPeers.insert(peerId, info); // Update the entry in the map
            qDebug() << "Updated discovered peer" << peerId << "with new shareable repo:" << repoName;
            emit lanPeerDiscoveredOrUpdated(info); // Notify UI that this peer's info changed
        }
    }
    else
    {
        qWarning() << "Attempted to add shared repo" << repoName << "to unknown discovered peer" << peerId;
        // Should we create a minimal discovered peer entry here? Maybe not, discovery broadcast handles this.
    }
}
QList<QString> NetworkManager::getConnectedPeerIds() const
{
    QList<QString> connectedPeers;
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        QString username = m_socketToPeerUsernameMap.value(socket, "");
        // Only include established, non-temporary connections
        if (!username.isEmpty() && !username.startsWith("AwaitingID:") &&
            !username.startsWith("ConnectingTo:") && !username.startsWith("Transfer:") &&
            socket->state() == QAbstractSocket::ConnectedState)
        {
            connectedPeers.append(username);
        }
    }
    return connectedPeers;
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}

void NetworkManager::broadcastTcpMessage(const QString &message)
{
    if (message.isEmpty())
    {
        qWarning() << "Attempted to broadcast an empty message.";
        return;
    }

    // Send to all connected peers with established connections
    for (QTcpSocket *socket : qAsConst(m_allTcpSockets))
    {
        QString peerUsername = m_socketToPeerUsernameMap.value(socket, "");
        if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID:") &&
            !peerUsername.startsWith("ConnectingTo:") && !peerUsername.startsWith("Transfer:") &&
            socket->state() == QAbstractSocket::ConnectedState)
        {
            sendMessageToPeer(socket, "BROADCAST_MESSAGE", {message});
        }
    }
}