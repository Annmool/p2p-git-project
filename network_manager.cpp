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
#include <QDir>
#include <sodium.h>

const qint64 PEER_TIMEOUT_MS = 15000;
const int BROADCAST_INTERVAL_MS = 5000;
const int PENDING_CONNECTION_TIMEOUT_MS = 30000;

NetworkManager::NetworkManager(const QString &myUsername,
                               IdentityManager *identityManager,
                               RepositoryManager *repoManager,
                               QObject *parent)
    : QObject(parent),
      m_myUsername(myUsername),
      m_identityManager(identityManager),
      m_repoManager_ptr(repoManager)
{
    m_tcpServer = new QTcpServer(this);
    connect(m_tcpServer, &QTcpServer::newConnection, this, &NetworkManager::onNewTcpConnection);
    m_udpSocket = new QUdpSocket(this);
    connect(m_udpSocket, &QUdpSocket::readyRead, this, &NetworkManager::onUdpReadyRead);
    m_broadcastTimer = new QTimer(this);
    connect(m_broadcastTimer, &QTimer::timeout, this, &NetworkManager::onBroadcastTimerTimeout);
    m_peerCleanupTimer = new QTimer(this);
    connect(m_peerCleanupTimer, &QTimer::timeout, this, &NetworkManager::onPeerCleanupTimerTimeout);
    m_peerCleanupTimer->start(PEER_TIMEOUT_MS / 2);
}

NetworkManager::~NetworkManager()
{
    stopTcpServer();
    stopUdpDiscovery();
    disconnectAllTcpPeers();
    qDeleteAll(m_incomingTransfers);
}

void NetworkManager::onNewTcpConnection()
{
    while (m_tcpServer->hasPendingConnections())
    {
        QTcpSocket *socket = m_tcpServer->nextPendingConnection();
        if (socket)
        {
            qDebug() << "Incoming connection from" << socket->peerAddress().toString();
            connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
            connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
            connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
            if (!m_allTcpSockets.contains(socket))
                m_allTcpSockets.append(socket);

            // Keep as pending until user accepts via UI. We'll still parse data to detect
            // temporary transfer sockets and auto-allow those.
            m_pendingConnections.insert(socket, new QTimer(socket));
            m_pendingConnections[socket]->setSingleShot(true);
            connect(m_pendingConnections[socket], &QTimer::timeout, this, [this, socket]()
                    { rejectPendingTcpConnection(socket); });
            m_pendingConnections[socket]->start(PENDING_CONNECTION_TIMEOUT_MS);

            // Defer prompting the user: allow a short grace period so if this is a temporary
            // transfer (REQUEST_REPO_BUNDLE), we won't show a connection dialog.
            QTimer *intentTimer = new QTimer(socket);
            intentTimer->setSingleShot(true);
            connect(intentTimer, &QTimer::timeout, this, [this, socket]()
                    {
                if (!socket) return;
                // If it's turned into a transfer socket, do not prompt.
                if (socket->property("is_transfer_socket").toBool()) return;
                // If still pending, prompt the user now.
                if (m_pendingConnections.contains(socket)) {
                    QString discoveredUsername = findUsernameForAddress(socket->peerAddress());
                    emit incomingTcpConnectionRequest(socket, socket->peerAddress(), socket->peerPort(), discoveredUsername);
                } });
            intentTimer->start(5000);
        }
    }
}

void NetworkManager::onTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    m_socketBuffers[socket].append(socket->readAll());
    processIncomingTcpData(socket);
}

void NetworkManager::acceptPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "User accepted connection from" << pendingSocket->peerAddress().toString();
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();
        sendIdentityOverTcp(pendingSocket);
        if (m_socketBuffers.contains(pendingSocket) && !m_socketBuffers[pendingSocket].isEmpty())
        {
            processIncomingTcpData(pendingSocket);
        }
    }
}

void NetworkManager::handleEncryptedPayload(const QString &peerId, const QVariantMap &payload)
{
    QString messageType = payload.value("__messageType").toString();
    if (messageType.isEmpty())
    {
        qWarning() << "Decrypted payload missing __messageType from" << peerId;
        return;
    }

    qDebug() << "Handling encrypted payload of type" << messageType << "from" << peerId;

    if (messageType == "COLLABORATOR_ADDED")
    {
        QString ownerRepoAppId, repoDisplayName, ownerPeerId;
        QStringList groupMembers;
        ownerRepoAppId = payload.value("ownerRepoAppId").toString();
        repoDisplayName = payload.value("repoDisplayName").toString();
        ownerPeerId = payload.value("ownerPeerId").toString();
        groupMembers = payload.value("groupMembers").toStringList();
        if (!ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty() && !ownerPeerId.isEmpty())
        {
            emit collaboratorAddedReceived(peerId, ownerRepoAppId, repoDisplayName, ownerPeerId, groupMembers);
        }
    }
    else if (messageType == "COLLABORATOR_REMOVED")
    {
        QString ownerRepoAppId = payload.value("ownerRepoAppId").toString();
        QString repoDisplayName = payload.value("repoDisplayName").toString();
        if (!ownerRepoAppId.isEmpty() && !repoDisplayName.isEmpty())
        {
            emit collaboratorRemovedReceived(peerId, ownerRepoAppId, repoDisplayName);
        }
    }
    else if (messageType == "PROPOSAL_CHUNK_BEGIN") // No change in logic
    {
        QString transferId = payload.value("transferId").toString();
        QString repoName = payload.value("repoName").toString();
        QString forBranch = payload.value("forBranch").toString();
        qint64 totalSize = payload.value("totalSize").toLongLong();
        if (transferId.isEmpty() || repoName.isEmpty() || totalSize <= 0)
            return;
        QString targetPath = m_incomingProposalSavePaths.value(peerId).value(repoName); // No change in logic
        if (targetPath.isEmpty())
        {
            targetPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
        }
        QDir parentDir = QFileInfo(targetPath).dir();
        if (!parentDir.exists())
            parentDir.mkpath(".");
        auto *transfer = new IncomingFileTransfer;
        transfer->state = IncomingFileTransfer::Receiving;
        transfer->repoName = repoName;
        transfer->tempLocalPath = targetPath;
        transfer->file.setFileName(targetPath); // No change in logic
        transfer->totalSize = totalSize;
        transfer->bytesReceived = 0;
        transfer->properties.insert("forBranch", forBranch);
        transfer->properties.insert("type", QString("proposal-chunked"));
        if (transfer->file.open(QIODevice::WriteOnly | QIODevice::Truncate)) // Added truncate flag
        {
            m_encryptedIncomingProposalTransfers.insert(transferId, transfer);
            emit repoBundleTransferStarted(repoName, totalSize);
        }
        else
        {
            delete transfer;
        }
    }
    else if (messageType == "PROPOSAL_CHUNK_DATA")
    {
        QString transferId = payload.value("transferId").toString();
        qint64 offset = payload.value("offset").toLongLong();
        QByteArray data = QByteArray::fromBase64(payload.value("data").toByteArray());
        IncomingFileTransfer *transfer = m_encryptedIncomingProposalTransfers.value(transferId, nullptr);
        if (!transfer)
            return;
        // Seek only if out-of-order (should be sequential)
        if (transfer->file.pos() != offset)
            transfer->file.seek(offset);
        qint64 written = transfer->file.write(data);
        if (written > 0) // No change in logic
        {
            transfer->bytesReceived = qMax(transfer->bytesReceived, offset + written); // Changed to use qMax
            emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
        }
    }
    else if (messageType == "PROPOSAL_CHUNK_END")
    {
        QString transferId = payload.value("transferId").toString();
        IncomingFileTransfer *transfer = m_encryptedIncomingProposalTransfers.take(transferId);
        if (!transfer)
            return;
        QString repoName = transfer->repoName;
        QString forBranch = transfer->properties.value("forBranch").toString();
        transfer->file.close();
        bool success = (transfer->bytesReceived == transfer->totalSize); // No change in logic
        if (!success)                                                    // Added logging for size mismatch
        {
            qWarning() << "Chunked proposal size mismatch for" << repoName << ":" << transfer->bytesReceived << "/" << transfer->totalSize << "; saved at" << transfer->tempLocalPath;
        }
        else
        {
            qDebug() << "Chunked proposal received completely for" << repoName << "at" << transfer->tempLocalPath;
        }
        emit repoBundleCompleted(repoName, transfer->tempLocalPath, success, success ? "Diff file downloaded successfully." : "Size mismatch.");
        emit changeProposalReceived(peerId, repoName, forBranch, transfer->tempLocalPath);
        delete transfer;
    }
    else
    {
        emit secureMessageReceived(peerId, messageType, payload);
    }
}

void NetworkManager::startSendingProposalChunked(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile diffFile(bundlePath);
    if (!diffFile.open(QIODevice::ReadOnly))
    {
        qWarning() << "Failed to open diff file for proposal (chunked):" << bundlePath;
        return;
    }
    qint64 fileSize = diffFile.size();
    if (fileSize <= 0)
    {
        qWarning() << "Refusing to send empty/invalid diff file (chunked):" << bundlePath << "size:" << fileSize;
        diffFile.close();
        QFile::remove(bundlePath);
        return;
    }
    QString transferId = QUuid::createUuid().toString(QUuid::WithoutBraces);

    // Notify receiver to prepare file
    QVariantMap beginMeta;
    beginMeta["transferId"] = transferId;
    beginMeta["repoName"] = repoDisplayName;
    beginMeta["forBranch"] = fromBranch;
    beginMeta["totalSize"] = fileSize;
    sendEncryptedMessage(targetPeerSocket, "PROPOSAL_CHUNK_BEGIN", beginMeta);

    const qint64 chunkSize = 10 * 1024; // 10KB
    qint64 offset = 0;
    QByteArray buffer;
    buffer.resize(chunkSize);
    while (!diffFile.atEnd())
    {
        qint64 bytesRead = diffFile.read(buffer.data(), chunkSize);
        if (bytesRead <= 0)
            break;
        QVariantMap chunk;
        chunk["transferId"] = transferId;
        chunk["offset"] = offset;
        chunk["data"] = QByteArray(buffer.constData(), bytesRead).toBase64();
        sendEncryptedMessage(targetPeerSocket, "PROPOSAL_CHUNK_DATA", chunk);
        offset += bytesRead;
        emit repoBundleChunkReceived(repoDisplayName, offset, fileSize);
    }
    diffFile.close();

    QVariantMap endMeta;
    endMeta["transferId"] = transferId;
    endMeta["repoName"] = repoDisplayName;
    sendEncryptedMessage(targetPeerSocket, "PROPOSAL_CHUNK_END", endMeta);

    qDebug() << "Chunked diff file transfer completed for proposal - repo:" << repoDisplayName;
    QFile::remove(bundlePath);
}

void NetworkManager::processIncomingTcpData(QTcpSocket *socket)
{
    QByteArray &buffer = m_socketBuffers[socket];
    QDataStream in(buffer);
    in.setVersion(QDataStream::Qt_5_15);

    while (true)
    {
        if (m_incomingTransfers.contains(socket))
        {
            IncomingFileTransfer *transfer = m_incomingTransfers.value(socket);
            qint64 bytesToWrite = qMin((qint64)buffer.size(), transfer->totalSize - transfer->bytesReceived);
            if (bytesToWrite > 0)
            {
                transfer->file.write(buffer.constData(), bytesToWrite);
                buffer.remove(0, static_cast<int>(bytesToWrite));
                transfer->bytesReceived += bytesToWrite;
                emit repoBundleChunkReceived(transfer->repoName, transfer->bytesReceived, transfer->totalSize);
            }
            if (transfer->bytesReceived < transfer->totalSize)
                return;
        }

        // First, ensure we have at least a complete message type string available
        in.startTransaction();
        QString messageType;
        in >> messageType;
        if (!in.commitTransaction())
        {
            // Not enough bytes yet to read the message type
            return;
        }

        if (messageType == "IDENTITY_HANDSHAKE_V2")
        {
            in.startTransaction();
            QString peerUsername, peerKeyHex;
            in >> peerUsername >> peerKeyHex;
            if (!in.commitTransaction())
                return;

            QString expectedPeerId = m_socketToPeerUsernameMap.value(socket, "");

            if (expectedPeerId.isEmpty() || expectedPeerId.startsWith("ConnectingTo:") || expectedPeerId == peerUsername)
            {
                m_socketToPeerUsernameMap.insert(socket, peerUsername);
                // Convert peer's Ed25519 verify key to Curve25519 for crypto_box
                QByteArray edPk = QByteArray::fromHex(peerKeyHex.toUtf8());
                if (edPk.size() == crypto_sign_PUBLICKEYBYTES)
                {
                    unsigned char curvePk[crypto_box_PUBLICKEYBYTES];
                    if (crypto_sign_ed25519_pk_to_curve25519(curvePk, reinterpret_cast<const unsigned char *>(edPk.constData())) == 0)
                    {
                        m_peerCurve25519PublicKeys.insert(peerUsername, QByteArray(reinterpret_cast<const char *>(curvePk), crypto_box_PUBLICKEYBYTES));
                        // Flush any queued encrypted messages for this peer now that we have their pubkey
                        flushQueuedEncryptedMessagesForPeer(peerUsername);
                    }
                    else
                    {
                        qWarning() << "Failed to convert peer" << peerUsername << "ed25519 pk to curve25519; encrypted messages will fail.";
                    }
                }
                else
                {
                    qWarning() << "Unexpected peer public key size for" << peerUsername << ":" << edPk.size();
                }

                // Only respond with our identity after the user has accepted this incoming connection.
                if (!m_handshakeSent.contains(socket) && !m_pendingConnections.contains(socket))
                {
                    sendIdentityOverTcp(socket);
                }
                // Announce only for accepted main connections (not pending and not transfer)
                bool isTransfer = socket->property("is_transfer_socket").toBool();
                bool isPending = m_pendingConnections.contains(socket);
                if (!isTransfer && !isPending)
                {
                    emit newTcpPeerConnected(socket, peerUsername, peerKeyHex);
                }

                // --- LOGIC WITH THE FIX ---
                if (socket->property("is_transfer_socket").toBool())
                {
                    // FIX: Use .value<QVariantMap>() instead of .toVariantMap()
                    QVariantMap pendingRequest = socket->property("pending_bundle_request").value<QVariantMap>();
                    if (!pendingRequest.isEmpty())
                    {
                        QString repoName = pendingRequest.value("repoName").toString();
                        QString localPath = pendingRequest.value("localPath").toString();
                        qDebug() << "Handshake complete on transfer socket. Now sending repo bundle request for" << repoName;

                        QByteArray block;
                        QDataStream out(&block, QIODevice::WriteOnly);
                        out.setVersion(QDataStream::Qt_5_15);
                        out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoName << localPath;
                        socket->write(block);

                        socket->setProperty("pending_bundle_request", QVariant());
                    }
                    // Also handle pending proposals
                    QVariantMap pendingProposal = socket->property("pending_proposal_request").value<QVariantMap>();
                    if (!pendingProposal.isEmpty())
                    {
                        QString r = pendingProposal.value("repoName").toString();
                        QString br = pendingProposal.value("fromBranch").toString();
                        QString bp = pendingProposal.value("bundlePath").toString();
                        QString msg = pendingProposal.value("message").toString();
                        qDebug() << "Handshake complete on transfer socket. Now sending proposal for" << r << "branch" << br;
                        sendChangeProposal(socket, r, br, bp, msg);
                        socket->setProperty("pending_proposal_request", QVariant());
                    }
                }
                // --- END OF FIX ---
            }
            else
            {
                qWarning() << "Identity mismatch! Expected" << expectedPeerId << "but got" << peerUsername;
                socket->disconnectFromHost();
            }
        }
        else if (messageType == "REQUEST_REPO_BUNDLE")
        {
            in.startTransaction();
            QString requestingPeer, repoName, temp;
            in >> requestingPeer >> repoName >> temp;
            if (!in.commitTransaction())
                return;
            if (!m_socketToPeerUsernameMap.contains(socket) || m_socketToPeerUsernameMap.value(socket).startsWith("ConnectingTo:"))
            {
                m_socketToPeerUsernameMap.insert(socket, requestingPeer);
            }
            handleRepoRequest(socket, requestingPeer, repoName);
        }
        else if (messageType == "SEND_REPO_BUNDLE_START")
        {
            in.startTransaction();
            QString repoName;
            qint64 totalSize;
            in >> repoName >> totalSize;
            if (!in.commitTransaction())
                return;
            QString tempPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
            auto *transfer = new IncomingFileTransfer{IncomingFileTransfer::Receiving, repoName, tempPath, QFile(tempPath), totalSize, 0};
            if (transfer->file.open(QIODevice::WriteOnly))
            {
                m_incomingTransfers.insert(socket, transfer);
                emit repoBundleTransferStarted(repoName, totalSize);
            }
            else
            {
                qWarning() << "Could not open temp file for bundle transfer:" << tempPath;
                delete transfer;
            }
        }
        else if (messageType == "SEND_REPO_BUNDLE_END")
        {
            in.startTransaction();
            QString repoName;
            in >> repoName;
            if (!in.commitTransaction())
                return;
            if (m_incomingTransfers.contains(socket))
            {
                IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                transfer->file.close();
                bool success = (transfer->bytesReceived == transfer->totalSize);
                emit repoBundleCompleted(repoName, transfer->tempLocalPath, success, success ? "Transfer complete." : "Size mismatch.");
                delete transfer;
                if (socket->property("is_transfer_socket").toBool())
                {
                    socket->disconnectFromHost();
                }
            }
        }
        else if (messageType == "PROPOSAL_META_ACK")
        {
            in.startTransaction();
            QString repoName, forBranch, savePath;
            in >> repoName >> forBranch >> savePath;
            if (!in.commitTransaction())
                return;
            // Owner confirmed. Set target path and begin streaming (sender side uses pending map)
            // This branch is processed by the SENDER (collaborator) when owner acknowledges on the same socket.
            // We stored the pending proposal on this socket when we sent META.
            QVariantMap pending = m_pendingProposalsBySocket.value(socket);
            if (!pending.isEmpty() && pending.value("repoName").toString() == repoName)
            {
                // Persist owner-chosen path in case we want to hint, but actual write target is on owner side
                startSendingProposal(socket, repoName, pending.value("fromBranch").toString(), pending.value("bundlePath").toString());
                m_pendingProposalsBySocket.remove(socket);
            }
        }
        else if (messageType == "PROPOSE_CHANGES_BUNDLE_START")
        {
            in.startTransaction();
            QString repoName;
            QString forBranch;
            qint64 totalSize;
            in >> repoName >> forBranch >> totalSize;
            if (!in.commitTransaction())
                return;

            // Decide where to save: use pre-set target path if provided; else a temp bundle
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            QString targetPath;
            if (!peerUsername.isEmpty() && m_incomingProposalSavePaths.contains(peerUsername))
            {
                targetPath = m_incomingProposalSavePaths.value(peerUsername).value(repoName);
            }
            if (targetPath.isEmpty())
            {
                targetPath = QStandardPaths::writableLocation(QStandardPaths::TempLocation) + "/" + QUuid::createUuid().toString() + ".bundle";
            }
            // Ensure the parent directory exists
            QDir parentDir = QFileInfo(targetPath).dir();
            if (!parentDir.exists())
                parentDir.mkpath(".");

            auto *transfer = new IncomingFileTransfer;
            transfer->state = IncomingFileTransfer::Receiving;
            transfer->repoName = repoName;
            transfer->tempLocalPath = targetPath;
            transfer->file.setFileName(targetPath);
            transfer->totalSize = totalSize;
            transfer->bytesReceived = 0;
            transfer->properties.insert("forBranch", forBranch);
            transfer->properties.insert("type", QString("proposal"));
            if (transfer->file.open(QIODevice::WriteOnly))
            {
                m_incomingTransfers.insert(socket, transfer);
                // Reuse progress signals
                emit repoBundleTransferStarted(repoName, totalSize);
            }
            else
            {
                qWarning() << "Could not open target path for proposal bundle:" << targetPath;
                delete transfer;
            }
        }
        else if (messageType == "PROPOSE_CHANGES_BUNDLE_END")
        {
            in.startTransaction();
            QString repoName;
            in >> repoName;
            if (!in.commitTransaction())
                return;

            if (m_incomingTransfers.contains(socket))
            {
                IncomingFileTransfer *transfer = m_incomingTransfers.take(socket);
                QString forBranch = transfer->properties.value("forBranch").toString();
                transfer->file.close();
                bool success = (transfer->bytesReceived == transfer->totalSize);
                QString fromPeer = m_socketToPeerUsernameMap.value(socket, QString());
                if (success)
                {
                    emit changeProposalReceived(fromPeer, repoName, forBranch, transfer->tempLocalPath);
                }
                else
                {
                    QFile::remove(transfer->tempLocalPath);
                }
                delete transfer;
            }
        }
        else if (messageType == "BROADCAST_MESSAGE")
        {
            in.startTransaction();
            QByteArray messageBa;
            in >> messageBa;
            if (!in.commitTransaction())
                return;
            QString message = QString::fromUtf8(messageBa);
            QString peerUsername = m_socketToPeerUsernameMap.value(socket);
            if (!peerUsername.isEmpty())
                emit broadcastMessageReceived(socket, peerUsername, message);
        }
        else if (messageType == "GROUP_CHAT_MESSAGE")
        {
            in.startTransaction();
            QByteArray repoAppIdBa;
            in >> repoAppIdBa;
            if (!in.commitTransaction())
                return;

            // Try to read [fromPeerId, message]; fall back to [message] only for legacy sends
            QByteArray fromPeerBa, messageBa;
            in.startTransaction();
            in >> fromPeerBa >> messageBa;
            bool threeField = in.commitTransaction();
            if (!threeField)
            {
                in.startTransaction();
                in >> messageBa;
                if (!in.commitTransaction())
                    return;
            }

            QString repoAppId = QString::fromUtf8(repoAppIdBa);
            QString message = QString::fromUtf8(messageBa);
            QString immediateSender = m_socketToPeerUsernameMap.value(socket);
            QString logicalSender = threeField ? QString::fromUtf8(fromPeerBa) : immediateSender;
            if (!logicalSender.isEmpty())
                emit groupMessageReceived(logicalSender, repoAppId, message);

            // If we're the owner for this repo, relay to other connected members (hub-and-spoke)
            if (m_repoManager_ptr)
            {
                ManagedRepositoryInfo info = m_repoManager_ptr->getRepositoryInfoByOwnerAppId(repoAppId);
                if (info.isValid() && info.isOwner)
                {
                    QStringList members = info.groupMembers;
                    members.removeDuplicates();
                    for (const QString &memberId : members)
                    {
                        if (memberId == logicalSender || memberId == m_myUsername)
                            continue;
                        QTcpSocket *memberSocket = getSocketForPeer(memberId);
                        if (memberSocket)
                        {
                            sendMessageToPeer(memberSocket, "GROUP_CHAT_MESSAGE", {repoAppId, logicalSender, message});
                        }
                    }
                }
            }
        }
        else if (messageType == "ENCRYPTED_PAYLOAD")
        {
            in.startTransaction();
            QByteArray nonce, ciphertext;
            in >> nonce >> ciphertext;
            if (!in.commitTransaction())
            {
                qWarning() << "Encrypted payload transaction not committed (partial read).";
                return;
            }

            QString peerId = m_socketToPeerUsernameMap.value(socket);
            if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
            {
                qWarning() << "Received encrypted payload from unknown peer or peer with no public key. peerId=" << peerId;
                continue;
            }

            QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();
            QByteArray peerPubKey = m_peerCurve25519PublicKeys.value(peerId);

            QByteArray decryptedMessage(ciphertext.size() - crypto_box_MACBYTES, 0);

            if (ciphertext.size() < crypto_box_MACBYTES)
            {
                qWarning() << "Ciphertext too small for crypto_box_open_easy, size=" << ciphertext.size();
                continue;
            }
            if (crypto_box_open_easy(
                    reinterpret_cast<unsigned char *>(decryptedMessage.data()),
                    reinterpret_cast<const unsigned char *>(ciphertext.constData()),
                    ciphertext.size(),
                    reinterpret_cast<const unsigned char *>(nonce.constData()),
                    reinterpret_cast<const unsigned char *>(peerPubKey.constData()),
                    reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
            {
                qWarning() << "Failed to decrypt message from" << peerId;
                continue;
            }

            QJsonDocument doc = QJsonDocument::fromJson(decryptedMessage);
            if (doc.isObject())
            {
                handleEncryptedPayload(peerId, doc.object().toVariantMap());
            }
            else
            {
                qWarning() << "Decrypted message was not valid JSON object, raw size=" << decryptedMessage.size();
            }
        }
        else
        {
            qWarning() << "Unknown or unexpected message type received:" << messageType << "from" << getPeerDisplayString(socket);
            return;
        }

        buffer.remove(0, buffer.size() - in.device()->bytesAvailable());
        if (in.atEnd())
            return;
    }
}
bool NetworkManager::isConnectionPending(QTcpSocket *socket) const { return m_pendingConnections.contains(socket); }

void NetworkManager::requestBundleFromPeer(const QString &peerId, const QString &repoName, const QString &localPath)
{
    // First, check if we already have a connection to this peer
    QTcpSocket *existingSocket = getSocketForPeer(peerId);

    if (existingSocket && existingSocket->state() == QAbstractSocket::ConnectedState)
    {
        // Use the existing connection
        qDebug() << "Using existing connection to peer" << peerId << "for bundle request";
        sendRepoBundleRequest(existingSocket, repoName, localPath);
        return;
    }

    // No existing connection, need to create a new one
    qDebug() << "No existing connection to peer" << peerId << ", creating new transfer connection";

    // Get peer info to connect
    DiscoveredPeerInfo peerInfo = getDiscoveredPeerInfo(peerId);
    if (peerInfo.id.isEmpty())
    {
        qDebug() << "Cannot find peer info for" << peerId;
        emit repoBundleCompleted(repoName, "", false, "Could not find peer information");
        return;
    }

    // Create new connection using the existing method
    connectAndRequestBundle(peerInfo.address, peerInfo.tcpPort, m_myUsername, repoName, localPath);
}

void NetworkManager::connectAndRequestBundle(const QHostAddress &host, quint16 port, const QString &myUsername, const QString &repoName, const QString &localPath)
{
    QTcpSocket *socket = new QTcpSocket(this);
    // Mark this socket so we know its purpose
    socket->setProperty("is_transfer_socket", true);

    // Store the bundle request details as a property on the socket.
    // We will send this request *after* the handshake is complete.
    QVariantMap pendingRequest;
    pendingRequest["repoName"] = repoName;
    pendingRequest["localPath"] = localPath;
    socket->setProperty("pending_bundle_request", QVariant::fromValue(pendingRequest));

    // For handshake validation, we need to know who we are connecting to.
    // Try to find the peer's ID from the discovery list.
    QString ownerId = findUsernameForAddress(host);
    if (!ownerId.isEmpty())
    {
        m_socketToPeerUsernameMap.insert(socket, ownerId);
    }
    else
    {
        // If not found (e.g., direct connection), use a temporary placeholder.
        m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + host.toString());
    }

    m_allTcpSockets.append(socket);

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            {
        qDebug() << "Transfer socket connected. Sending initial identity handshake.";
        // The first step is ALWAYS to handshake. The actual bundle request will be sent
        // later, once the owner's identity is confirmed.
        sendIdentityOverTcp(socket); });

    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    qDebug() << "Attempting to connect dedicated transfer socket to" << host.toString() << ":" << port;
    socket->connectToHost(host, port);
}

QString NetworkManager::getPeerDisplayString(QTcpSocket *socket)
{
    if (!socket)
        return "InvalidSocket";
    QString username = m_socketToPeerUsernameMap.value(socket, "");
    if (!username.isEmpty() && !username.startsWith("AwaitingID") && !username.startsWith("ConnectingTo") && !username.startsWith("Transfer:"))
    {
        return username + " (" + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()) + ")";
    }
    return socket->peerAddress().toString() + ":" + QString::number(socket->peerPort());
}

QTcpSocket *NetworkManager::getSocketForPeer(const QString &peerUsername)
{
    // Prefer a primary (non-transfer, non-pending) socket for this peer
    QTcpSocket *fallback = nullptr;
    for (auto it = m_socketToPeerUsernameMap.constBegin(); it != m_socketToPeerUsernameMap.constEnd(); ++it)
    {
        QTcpSocket *sock = it.key();
        const QString &id = it.value();
        if (id != peerUsername)
            continue;
        if (sock->property("is_transfer_socket").toBool())
        {
            // Remember as a last resort, but prefer non-transfer below
            if (!fallback)
                fallback = sock;
            continue;
        }
        if (m_pendingConnections.contains(sock))
        {
            // Skip sockets still pending user acceptance
            if (!fallback)
                fallback = sock;
            continue;
        }
        if (id.startsWith("AwaitingID") || id.startsWith("ConnectingTo") || id.startsWith("Transfer:"))
        {
            if (!fallback)
                fallback = sock;
            continue;
        }
        // This is an established primary socket for the peer
        return sock;
    }
    // Fallback to any socket mapped to this peer if no ideal candidate was found
    return fallback;
}

void NetworkManager::sendRepoBundleRequest(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &requesterLocalPath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("REQUEST_REPO_BUNDLE") << m_myUsername << repoDisplayName << requesterLocalPath;
    targetPeerSocket->write(block);
}

bool NetworkManager::startTcpServer(quint16 port)
{
    if (m_tcpServer->isListening())
    {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort(), "Already listening.");
        return true;
    }
    if (m_tcpServer->listen(QHostAddress::Any, port))
    {
        emit tcpServerStatusChanged(true, m_tcpServer->serverPort());
        startUdpDiscovery(); // Automatically start discovery when server starts
        return true;
    }
    emit tcpServerStatusChanged(false, port, m_tcpServer->errorString());
    return false;
}

void NetworkManager::stopTcpServer()
{
    if (m_tcpServer && m_tcpServer->isListening())
    {
        quint16 p = m_tcpServer->serverPort();
        m_tcpServer->close();
        emit tcpServerStatusChanged(false, p);
    }
}

quint16 NetworkManager::getTcpServerPort() const
{
    return (m_tcpServer && m_tcpServer->isListening()) ? m_tcpServer->serverPort() : 0;
}

bool NetworkManager::connectToTcpPeer(const QHostAddress &hostAddress, quint16 port, const QString &expectedPeerUsername)
{
    if (getSocketForPeer(expectedPeerUsername))
        return true;

    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_outgoing_attempt", true);

    if (!m_allTcpSockets.contains(socket))
        m_allTcpSockets.append(socket);
    m_socketToPeerUsernameMap.insert(socket, "ConnectingTo:" + expectedPeerUsername);

    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            { sendIdentityOverTcp(socket); });
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);

    socket->connectToHost(hostAddress, port);
    return true;
}

void NetworkManager::disconnectAllTcpPeers()
{
    QList<QTcpSocket *> socketsToDisconnect = m_allTcpSockets;
    for (QTcpSocket *sock : socketsToDisconnect)
    {
        if (sock)
            sock->disconnectFromHost();
    }
}

bool NetworkManager::hasActiveTcpConnections() const
{
    return !m_socketToPeerUsernameMap.values().filter(QRegExp("^(?!AwaitingID|Transfer:|ConnectingTo).*")).isEmpty();
}

bool NetworkManager::startUdpDiscovery(quint16 udpPort)
{
    m_udpDiscoveryPort = udpPort;
    if (!m_identityManager || !m_repoManager_ptr)
        return false;
    if (m_udpSocket->bind(QHostAddress::AnyIPv4, m_udpDiscoveryPort, QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint))
    {
        if (!m_broadcastTimer->isActive())
            m_broadcastTimer->start(BROADCAST_INTERVAL_MS);
        sendDiscoveryBroadcast();
        return true;
    }
    return false;
}

void NetworkManager::stopUdpDiscovery()
{
    m_broadcastTimer->stop();
    if (m_udpSocket && m_udpSocket->state() != QAbstractSocket::UnconnectedState)
        m_udpSocket->close();
    m_discoveredPeers.clear();
}

void NetworkManager::sendDiscoveryBroadcast()
{
    if (!m_tcpServer || !m_tcpServer->isListening() || m_myUsername.isEmpty() || !m_identityManager || !m_repoManager_ptr)
        return;
    QByteArray datagram;
    QDataStream out(&datagram, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    QList<ManagedRepositoryInfo> publicRepos = m_repoManager_ptr->getMyPubliclyShareableRepos();

    QStringList publicRepoNames;
    for (const auto &repoInfo : publicRepos)
        publicRepoNames.append(repoInfo.displayName);
    out << QString("P2PGIT_DISCOVERY_V3") << m_myUsername << m_tcpServer->serverPort() << QString::fromStdString(m_identityManager->getMyPublicKeyHex()) << publicRepoNames;
    m_udpSocket->writeDatagram(datagram, QHostAddress::Broadcast, m_udpDiscoveryPort);
}

void NetworkManager::onUdpReadyRead()
{
    while (m_udpSocket->hasPendingDatagrams())
    {
        QByteArray datagram;
        datagram.resize(int(m_udpSocket->pendingDatagramSize()));
        QHostAddress senderAddress;
        m_udpSocket->readDatagram(datagram.data(), datagram.size(), &senderAddress);
        QDataStream in(datagram);
        in.setVersion(QDataStream::Qt_5_15);
        QString magicHeader;
        in >> magicHeader;
        if (magicHeader != "P2PGIT_DISCOVERY_V3")
            continue;
        QString receivedUsername, receivedPublicKeyHex;
        quint16 receivedTcpPort;
        QList<QString> receivedPublicRepoNames;
        in >> receivedUsername >> receivedTcpPort >> receivedPublicKeyHex >> receivedPublicRepoNames;
        if (in.status() == QDataStream::Ok && receivedUsername != m_myUsername)
        {
            DiscoveredPeerInfo info;
            info.id = receivedUsername;
            info.address = senderAddress;
            info.tcpPort = receivedTcpPort;
            info.publicKeyHex = receivedPublicKeyHex;
            info.publicRepoNames = receivedPublicRepoNames;
            info.lastSeen = QDateTime::currentMSecsSinceEpoch();

            m_discoveredPeers[receivedUsername] = info;
            emit lanPeerDiscoveredOrUpdated(info);
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
        if (now - i.value().lastSeen > PEER_TIMEOUT_MS)
        {
            emit lanPeerLost(i.key());
            i.remove();
        }
    }
}

void NetworkManager::sendMessageToPeer(QTcpSocket *peerSocket, const QString &messageType, const QVariantList &args)
{
    if (!peerSocket || peerSocket->state() != QAbstractSocket::ConnectedState)
        return;

    QString peerUsername = m_socketToPeerUsernameMap.value(peerSocket, "");
    // Don't send on sockets that are pending acceptance or special-purpose
    if (peerSocket->property("is_transfer_socket").toBool() ||
        m_pendingConnections.contains(peerSocket) ||
        peerUsername.startsWith("AwaitingID") ||
        peerUsername.startsWith("ConnectingTo") ||
        peerUsername.startsWith("Transfer:"))
        return;

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << messageType;
    for (const QVariant &arg : args)
    {
        // Write QStrings as UTF-8 byte arrays so the receiver can reliably decode with fromUtf8()
        if (arg.userType() == QMetaType::QString)
        {
            out << arg.toString().toUtf8();
        }
        else if (arg.canConvert<QByteArray>())
        {
            out << arg.toByteArray();
        }
        else
        {
            out << arg;
        }
    }
    peerSocket->write(block);
}

void NetworkManager::broadcastTcpMessage(const QString &message)
{
    for (QTcpSocket *s : qAsConst(m_allTcpSockets))
    {
        sendMessageToPeer(s, "BROADCAST_MESSAGE", {message});
    }
}

void NetworkManager::sendGroupChatMessage(const QString &repoAppId, const QString &message)
{
    if (!m_repoManager_ptr)
        return;

    // repoAppId may be either a local appId (owner) or an ownerRepoAppId (for non-owners).
    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfo(repoAppId);
    if (repoInfo.appId.isEmpty())
    {
        // Try resolving as ownerRepoAppId for clones and non-owner instances
        repoInfo = m_repoManager_ptr->getRepositoryInfoByOwnerAppId(repoAppId);
    }
    if (repoInfo.appId.isEmpty())
        return;

    QStringList members = repoInfo.groupMembers;
    members.removeDuplicates();

    for (const QString &memberId : members)
    {
        if (memberId == m_myUsername)
            continue;

        QTcpSocket *memberSocket = getSocketForPeer(memberId);
        if (memberSocket)
        {
            // Include explicit sender to allow reliable fan-out and correct attribution
            sendMessageToPeer(memberSocket, "GROUP_CHAT_MESSAGE", {repoAppId, m_myUsername, message});
        }
    }
}

void NetworkManager::sendIdentityOverTcp(QTcpSocket *socket)
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState || m_myUsername.isEmpty() || !m_identityManager)
        return;
    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);

    // Keep any 'ConnectingTo:' marker until the identity handshake completes on this socket.
    // This prevents the UI from treating a socket as "connected" before the peer's app-level
    // identity handshake has been exchanged and validated.
    Q_UNUSED(socket);

    out << QString("IDENTITY_HANDSHAKE_V2") << m_myUsername << QString::fromStdString(m_identityManager->getMyPublicKeyHex());
    socket->write(block);
    m_handshakeSent.insert(socket);
}

QString NetworkManager::findUsernameForAddress(const QHostAddress &address)
{
    QHostAddress addrToCompare = address;
    if (address.protocol() == QAbstractSocket::IPv6Protocol && address.toIPv4Address())
    {
        addrToCompare = QHostAddress(address.toIPv4Address());
    }
    for (const auto &peerInfo : qAsConst(m_discoveredPeers))
    {
        if (peerInfo.address == addrToCompare)
        {
            return peerInfo.id;
        }
    }
    return QString();
}

void NetworkManager::startSendingBundle(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &bundleFilePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundleFilePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("SEND_REPO_BUNDLE_START") << repoDisplayName << bundleFile.size();
    targetPeerSocket->write(startBlock);

    char buffer[65536];
    while (!bundleFile.atEnd())
    {
        qint64 bytesRead = bundleFile.read(buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            targetPeerSocket->write(buffer, bytesRead);
            if (!targetPeerSocket->waitForBytesWritten(-1))
            {
                bundleFile.close();
                return;
            }
        }
    }
    bundleFile.close();

    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("SEND_REPO_BUNDLE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);

    QString recipient = m_socketToPeerUsernameMap.value(targetPeerSocket, "Unknown Peer");
    emit repoBundleSent(repoDisplayName, recipient);
    // Notify receiver to add repo to managed list
    QVariantMap payload;
    payload["repoDisplayName"] = repoDisplayName;
    payload["senderPeerId"] = m_myUsername;
    payload["localPathHint"] = ""; // receiver can choose location
    // Include canonical chat channel id and current members so collaborators can chat
    if (m_repoManager_ptr)
    {
        ManagedRepositoryInfo ownerRepoInfo = m_repoManager_ptr->getRepositoryInfoByDisplayName(repoDisplayName);
        if (ownerRepoInfo.isValid() && ownerRepoInfo.isOwner)
        {
            payload["ownerRepoAppId"] = ownerRepoInfo.appId;
            payload["groupMembers"] = ownerRepoInfo.groupMembers;
        }
    }
    sendEncryptedMessage(targetPeerSocket, "ADD_MANAGED_REPO", payload);
    QFile::remove(bundleFilePath);
}

void NetworkManager::rejectPendingTcpConnection(QTcpSocket *pendingSocket)
{
    if (m_pendingConnections.contains(pendingSocket))
    {
        qDebug() << "Rejecting or timing out connection from" << pendingSocket->peerAddress().toString();
        QTimer *timer = m_pendingConnections.take(pendingSocket);
        if (timer)
            timer->deleteLater();
        pendingSocket->disconnectFromHost();
    }
}

void NetworkManager::onTcpSocketDisconnected()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;

    if (socket->property("is_transfer_socket").toBool())
    {
        m_socketBuffers.remove(socket);
        m_socketToPeerUsernameMap.remove(socket);
        if (m_incomingTransfers.contains(socket))
            delete m_incomingTransfers.take(socket);
        m_allTcpSockets.removeAll(socket);
        socket->deleteLater();
        return;
    }

    m_allTcpSockets.removeAll(socket);
    m_socketBuffers.remove(socket);
    m_handshakeSent.remove(socket);
    if (m_pendingConnections.contains(socket))
    {
        QTimer *timer = m_pendingConnections.take(socket);
        if (timer)
            timer->deleteLater();
    }
    if (m_incomingTransfers.contains(socket))
        delete m_incomingTransfers.take(socket);

    QString peerUsername = m_socketToPeerUsernameMap.take(socket);
    if (!peerUsername.isEmpty() && !peerUsername.startsWith("AwaitingID") && !peerUsername.startsWith("Transfer:") && !peerUsername.startsWith("ConnectingTo"))
    {
        m_peerCurve25519PublicKeys.remove(peerUsername);
        emit tcpPeerDisconnected(socket, peerUsername);
    }
    socket->deleteLater();
}

void NetworkManager::onTcpSocketError(QAbstractSocket::SocketError socketError)
{
    Q_UNUSED(socketError);
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (!socket)
        return;
    qWarning() << "Socket Error on" << getPeerDisplayString(socket) << ":" << socket->errorString();
    socket->disconnectFromHost();
}

void NetworkManager::addSharedRepoToPeer(const QString &peerId, const QString &repoName)
{
    if (m_discoveredPeers.contains(peerId))
    {
        if (!m_discoveredPeers[peerId].publicRepoNames.contains(repoName))
        {
            m_discoveredPeers[peerId].publicRepoNames.append(repoName);
            emit lanPeerDiscoveredOrUpdated(m_discoveredPeers.value(peerId));
        }
    }
}

QList<QString> NetworkManager::getConnectedPeerIds() const
{
    QList<QString> ids;
    for (auto it = m_socketToPeerUsernameMap.constBegin(); it != m_socketToPeerUsernameMap.constEnd(); ++it)
    {
        QTcpSocket *socket = it.key();
        const QString &id = it.value();
        if (m_pendingConnections.contains(socket))
            continue; // exclude pending
        if (socket->property("is_transfer_socket").toBool())
            continue; // exclude temp
        if (id.startsWith("AwaitingID") || id.startsWith("Transfer:") || id.startsWith("ConnectingTo"))
            continue;
        ids.append(id);
    }
    return ids;
}

void NetworkManager::sendEncryptedMessage(QTcpSocket *socket, const QString &messageType, const QVariantMap &payload)
{
    if (!socket)
        return;
    QString peerId = m_socketToPeerUsernameMap.value(socket);
    if (peerId.isEmpty() || !m_peerCurve25519PublicKeys.contains(peerId))
    {
        // Queue the encrypted intent so we can send it once the handshake completes and
        // we have the peer's Curve25519 public key.
        qWarning() << "Peer public key not available yet for" << peerId << "; queuing message of type" << messageType;
        m_queuedEncryptedMessages[peerId].append(qMakePair(messageType, payload));
        return;
    }

    QByteArray recipientPubKey = m_peerCurve25519PublicKeys.value(peerId);
    QByteArray mySecretKey = m_identityManager->getMyCurve25519SecretKey();

    QVariantMap fullPayload = payload;
    fullPayload["__messageType"] = messageType;
    QByteArray plaintextMessage = QJsonDocument(QJsonObject::fromVariantMap(fullPayload)).toJson(QJsonDocument::Compact);

    QByteArray nonce(crypto_box_NONCEBYTES, 0);
    randombytes_buf(reinterpret_cast<unsigned char *>(nonce.data()), crypto_box_NONCEBYTES);

    QByteArray ciphertext(crypto_box_MACBYTES + plaintextMessage.size(), 0);

    if (crypto_box_easy(
            reinterpret_cast<unsigned char *>(ciphertext.data()),
            reinterpret_cast<const unsigned char *>(plaintextMessage.constData()),
            plaintextMessage.size(),
            reinterpret_cast<const unsigned char *>(nonce.constData()),
            reinterpret_cast<const unsigned char *>(recipientPubKey.constData()),
            reinterpret_cast<const unsigned char *>(mySecretKey.constData())) != 0)
    {
        qWarning() << "Failed to encrypt message for" << peerId;
        return;
    }

    QByteArray block;
    QDataStream out(&block, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_5_15);
    out << QString("ENCRYPTED_PAYLOAD") << nonce << ciphertext;
    socket->write(block);
}

void NetworkManager::flushQueuedEncryptedMessagesForPeer(const QString &peerId)
{
    auto it = m_queuedEncryptedMessages.find(peerId);
    if (it == m_queuedEncryptedMessages.end())
        return;
    QList<QPair<QString, QVariantMap>> queued = it.value();
    m_queuedEncryptedMessages.remove(peerId);
    QTcpSocket *s = getSocketForPeer(peerId);
    for (const auto &p : queued)
    {
        sendEncryptedMessage(s, p.first, p.second);
    }
}

void NetworkManager::handleRepoRequest(QTcpSocket *socket, const QString &requestingPeer, const QString &repoName)
{
    if (!m_repoManager_ptr)
        return;
    bool canAccess = false;
    ManagedRepositoryInfo repoInfo = m_repoManager_ptr->getRepositoryInfoByDisplayName(repoName);
    if (!repoInfo.appId.isEmpty())
    {
        if (repoInfo.isPublic || repoInfo.groupMembers.contains(requestingPeer))
        {
            canAccess = true;
        }
    }
    if (canAccess)
    {
        // If this request arrived on a brand-new inbound socket that's still pending acceptance,
        // treat it as a temporary transfer socket (auto-allow and close after sending).
        // If it arrived on an already accepted primary connection, DO NOT flip it to transfer,
        // otherwise the UI will consider the peer disconnected and chat will break.
        if (m_pendingConnections.contains(socket))
        {
            // Mark as transfer only for pending, ad-hoc sockets
            socket->setProperty("is_transfer_socket", true);
            // Cancel pending timer to auto-allow this transfer connection
            QTimer *t = m_pendingConnections.take(socket);
            if (t)
                t->deleteLater();
        }
        emit repoBundleRequestedByPeer(socket, requestingPeer, repoName, "");
    }
    else
    {
        qWarning() << "Access denied for repo" << repoName << "to peer" << requestingPeer;
        socket->disconnectFromHost();
    }
}

void NetworkManager::sendChangeProposal(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundlePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;

    // First, send an encrypted metadata message so owner can choose a save path and explicitly acknowledge
    QVariantMap meta;
    meta["repoName"] = repoDisplayName;
    meta["forBranch"] = fromBranch;
    meta["size"] = bundleFile.size();
    if (!proposalMessage.isEmpty())
        meta["message"] = proposalMessage;
    sendEncryptedMessage(targetPeerSocket, "PROPOSAL_META", meta);
    // Queue pending proposal to start after owner's ACK arrives
    QVariantMap pending;
    pending["repoName"] = repoDisplayName;
    pending["fromBranch"] = fromBranch;
    pending["bundlePath"] = bundlePath;
    m_pendingProposalsBySocket[targetPeerSocket] = pending;
}

DiscoveredPeerInfo NetworkManager::getDiscoveredPeerInfo(const QString &peerId) const
{
    return m_discoveredPeers.value(peerId, DiscoveredPeerInfo());
}

QMap<QString, DiscoveredPeerInfo> NetworkManager::getDiscoveredPeers() const
{
    return m_discoveredPeers;
}

void NetworkManager::setIncomingProposalSavePath(const QString &peerId, const QString &repoDisplayName, const QString &targetFilePath)
{
    m_incomingProposalSavePaths[peerId][repoDisplayName] = targetFilePath;
}

void NetworkManager::sendProposalToPeer(const QString &peerId, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath, const QString &proposalMessage)
{
    QTcpSocket *sock = getSocketForPeer(peerId);
    if (sock && sock->state() == QAbstractSocket::ConnectedState)
    {
        sendChangeProposal(sock, repoDisplayName, fromBranch, bundlePath, proposalMessage);
        return;
    }

    // Create a temporary transfer socket and queue the proposal to be sent after handshake
    DiscoveredPeerInfo info = getDiscoveredPeerInfo(peerId);
    if (info.id.isEmpty())
    {
        qWarning() << "Cannot find peer to send proposal:" << peerId;
        return;
    }
    QTcpSocket *socket = new QTcpSocket(this);
    socket->setProperty("is_transfer_socket", true);
    QVariantMap pendingProposal;
    pendingProposal["type"] = "proposal";
    pendingProposal["repoName"] = repoDisplayName;
    pendingProposal["fromBranch"] = fromBranch;
    pendingProposal["bundlePath"] = bundlePath;
    pendingProposal["message"] = proposalMessage;
    socket->setProperty("pending_proposal_request", QVariant::fromValue(pendingProposal));

    m_socketToPeerUsernameMap.insert(socket, info.id);
    m_allTcpSockets.append(socket);
    connect(socket, &QTcpSocket::connected, this, [this, socket]()
            { sendIdentityOverTcp(socket); });
    connect(socket, &QTcpSocket::readyRead, this, &NetworkManager::onTcpSocketReadyRead);
    connect(socket, &QTcpSocket::disconnected, this, &NetworkManager::onTcpSocketDisconnected);
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QTcpSocket::errorOccurred), this, &NetworkManager::onTcpSocketError);
    socket->connectToHost(info.address, info.tcpPort);
}

void NetworkManager::startSendingProposal(QTcpSocket *targetPeerSocket, const QString &repoDisplayName, const QString &fromBranch, const QString &bundlePath)
{
    if (!targetPeerSocket || targetPeerSocket->state() != QAbstractSocket::ConnectedState)
        return;
    QFile bundleFile(bundlePath);
    if (!bundleFile.open(QIODevice::ReadOnly))
        return;

    QByteArray startBlock;
    QDataStream startOut(&startBlock, QIODevice::WriteOnly);
    startOut.setVersion(QDataStream::Qt_5_15);
    startOut << QString("PROPOSE_CHANGES_BUNDLE_START") << repoDisplayName << fromBranch << bundleFile.size();
    targetPeerSocket->write(startBlock);

    char buffer[65536];
    while (!bundleFile.atEnd())
    {
        qint64 bytesRead = bundleFile.read(buffer, sizeof(buffer));
        if (bytesRead > 0)
        {
            targetPeerSocket->write(buffer, bytesRead);
            if (!targetPeerSocket->waitForBytesWritten(-1))
            {
                bundleFile.close();
                return;
            }
        }
    }
    bundleFile.close();

    QByteArray endBlock;
    QDataStream endOut(&endBlock, QIODevice::WriteOnly);
    endOut.setVersion(QDataStream::Qt_5_15);
    endOut << QString("PROPOSE_CHANGES_BUNDLE_END") << repoDisplayName;
    targetPeerSocket->write(endBlock);
}