#include "network_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QTreeWidget>
#include <QListWidget>
#include <QLineEdit>
#include <QTextEdit>
#include <QStyle>
#include <QMenu>
#include <QAction>
#include <QHeaderView>
#include <QCryptographicHash>
#include <QComboBox>
#include <QSplitter>
#include "info_dot.h"

NetworkPanel::NetworkPanel(QWidget *parent) : QWidget(parent)
{
    setupUi();
    m_peerDisconnectedIcon = this->style()->standardIcon(QStyle::SP_DialogCancelButton);
    m_peerConnectedIcon = this->style()->standardIcon(QStyle::SP_DialogYesButton);

    connect(toggleDiscoveryButton, &QPushButton::clicked, this, &NetworkPanel::toggleDiscoveryRequested);
    connect(connectToPeerButton, &QPushButton::clicked, this, &NetworkPanel::onConnectClicked);
    connect(cloneRepoButton, &QPushButton::clicked, this, &NetworkPanel::onCloneClicked);
    connect(sendMessageButton, &QPushButton::clicked, this, &NetworkPanel::onSendMessageClicked);
    connect(discoveredPeersTreeWidget, &QTreeWidget::currentItemChanged, this, &NetworkPanel::onDiscoveredPeerOrRepoSelected);
    connect(discoveredPeersTreeWidget, &QTreeWidget::customContextMenuRequested, this, &NetworkPanel::showContextMenu);
}

void NetworkPanel::setNetworkManager(NetworkManager *manager)
{
    m_networkManager = manager;
}

void NetworkPanel::setMyPeerInfo(const QString &username, const QString &publicKeyHex)
{
    m_myUsername = username;

    // Calculate public key hash (same way as shown for other peers)
    QString pkHashStr = QCryptographicHash::hash(publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);

    // Display full public key in a more readable format
    QString formattedKey = publicKeyHex;
    if (publicKeyHex.length() > 32)
    {
        // Insert line breaks for better readability
        formattedKey = "";
        for (int i = 0; i < publicKeyHex.length(); i += 32)
        {
            if (i > 0)
                formattedKey += "<br>";
            formattedKey += publicKeyHex.mid(i, 32);
        }
    }

    myPeerInfoLabel->setText(QString("<b>My Peer ID:</b> %1<br><b>Public Key Hash:</b> <span style='font-family: monospace; color: #0F4C4A; font-weight: bold;'>%2</span><br><b>Public Key:</b><br><span style='font-family: monospace; font-size: 11px;'>%3</span>")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(pkHashStr)
                                 .arg(formattedKey));
}

void NetworkPanel::logMessage(const QString &message, const QColor &color)
{
    networkLogDisplay->append(QString("<font color='%1'>%2</font>").arg(color.name(), message.toHtmlEscaped()));
}

void NetworkPanel::logBroadcastMessage(const QString &peerId, const QString &message)
{
    QString formattedMessage = QString("<b>%1:</b> %2")
                                   .arg(peerId == m_myUsername ? "Me" : peerId.toHtmlEscaped())
                                   .arg(message.toHtmlEscaped());
    networkLogDisplay->append(formattedMessage);
}

void NetworkPanel::logGroupChatMessage(const QString &repoName, const QString &peerId, const QString &message)
{
    QString formattedMessage = QString("<font color='blue'>[%1]</font> <b>%2:</b> %3")
                                   .arg(repoName.toHtmlEscaped())
                                   .arg(peerId == m_myUsername ? "Me" : peerId.toHtmlEscaped())
                                   .arg(message.toHtmlEscaped());
    networkLogDisplay->append(formattedMessage);
}

void NetworkPanel::updatePeerList(const QMap<QString, DiscoveredPeerInfo> &discoveredPeers, const QList<QString> &connectedPeerIds)
{
    // Cache the current connected peers for fast UI checks
    m_lastConnectedPeerIds = connectedPeerIds;
    // ================== THE FIX STARTS HERE ==================

    // 1. Preserve the current selection's identifying information
    QString selectedPeerId;
    QString selectedRepoName;
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem)
    {
        if (currentItem->parent())
        { // It's a repo item
            selectedRepoName = currentItem->data(0, Qt::UserRole).toString();
            selectedPeerId = currentItem->parent()->text(0);
        }
        else
        { // It's a peer item
            selectedPeerId = currentItem->text(0);
        }
    }

    // Block signals to prevent the UI from flickering or buttons from disabling prematurely
    discoveredPeersTreeWidget->blockSignals(true);

    discoveredPeersTreeWidget->clear();

    for (const auto &peerInfo : discoveredPeers)
    {
        QTreeWidgetItem *peerItem = new QTreeWidgetItem(discoveredPeersTreeWidget);
        peerItem->setText(0, peerInfo.id);

        bool isConnected = connectedPeerIds.contains(peerInfo.id);
        peerItem->setIcon(0, isConnected ? m_peerConnectedIcon : m_peerDisconnectedIcon);
        peerItem->setForeground(0, isConnected ? QBrush(QColor("lime")) : QBrush(palette().color(QPalette::Text)));

        QString pkHashStr = QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
        peerItem->setText(1, QString("(%1) [PKH:%2]").arg(peerInfo.address.toString(), pkHashStr));

        peerItem->setExpanded(true); // Keep items expanded by default

        for (const QString &repoName : peerInfo.publicRepoNames)
        {
            QTreeWidgetItem *repoItem = new QTreeWidgetItem(peerItem);
            repoItem->setText(0, "  " + repoName);
            repoItem->setData(0, Qt::UserRole, repoName);        // Store repo name
            repoItem->setData(0, Qt::UserRole + 1, peerInfo.id); // Store parent peer ID
            repoItem->setText(1, "Public");

            // 2. Check if this repopulated item matches the one we saved
            if (peerInfo.id == selectedPeerId && repoName == selectedRepoName)
            {
                discoveredPeersTreeWidget->setCurrentItem(repoItem);
            }
        }

        // 2. (cont'd) Check if the peer item itself was the one selected
        if (peerInfo.id == selectedPeerId && selectedRepoName.isEmpty())
        {
            discoveredPeersTreeWidget->setCurrentItem(peerItem);
        }
    }

    // Re-enable signals after the update is complete
    discoveredPeersTreeWidget->blockSignals(false);

    // Manually trigger an update of the button states based on the (potentially restored) selection
    onDiscoveredPeerOrRepoSelected(discoveredPeersTreeWidget->currentItem());
    // Also ensure Add Collaborator button reflects current connection state
    QTreeWidgetItem *sel = discoveredPeersTreeWidget->currentItem();
    if (sel && !sel->parent())
    {
        bool enable = m_lastConnectedPeerIds.contains(sel->text(0));
        addCollaboratorButton->setEnabled(enable);
        addCollaboratorButton->setStyleSheet(QString("background-color: #F8FAFC; color: %1; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 14px; font-weight: bold; min-width: 160px;")
                                                 .arg(enable ? "#0F4C4A" : "#94A3B8"));
    }

    // =================== THE FIX ENDS HERE ===================
}

void NetworkPanel::updateServerStatus(bool listening, quint16 port, const QString &error)
{
    if (listening)
    {
        tcpServerStatusLabel->setText(QString("TCP Server: <font color='lime'><b>Listening on port %1</b></font>").arg(port));
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        if (!m_myUsername.isEmpty())
        {
            // A safer way to update text without relying on previous content
            QString pkPrefix = myPeerInfoLabel->property("pkPrefix").toString();
            myPeerInfoLabel->setText(QString("<b>My Peer ID:</b> %1<br><b>PubKey (prefix):</b> %2...<br><b>TCP Port:</b> %3")
                                         .arg(m_myUsername.toHtmlEscaped())
                                         .arg(pkPrefix)
                                         .arg(port));
        }
    }
    else
    {
        tcpServerStatusLabel->setText("TCP Server: <font color='red'><b>Inactive</b></font>");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        if (!error.isEmpty())
        {
            logMessage("TCP Server error/stopped: " + error, Qt::red);
        }
    }
}

void NetworkPanel::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    QLabel *networkHeader = new QLabel("<b>P2P Network</b>", this);
    networkHeader->setObjectName("networkHeaderLabel");
    mainLayout->addWidget(networkHeader);

    myPeerInfoLabel = new QLabel("<b>My Peer ID:</b><br><b>Public Key:</b>", this);
    myPeerInfoLabel->setObjectName("myPeerInfoLabel");
    myPeerInfoLabel->setWordWrap(true);
    myPeerInfoLabel->setMinimumHeight(120); // Ensure enough height for full key display
    myPeerInfoLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);
    mainLayout->addWidget(myPeerInfoLabel);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", this);
    toggleDiscoveryButton->setObjectName("toggleDiscoveryButton");
    mainLayout->addWidget(toggleDiscoveryButton);

    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", this);
    tcpServerStatusLabel->setObjectName("tcpServerStatusLabel");
    mainLayout->addWidget(tcpServerStatusLabel);

    QLabel *peersHeader = new QLabel("<b>Discovered Peers & Repos on LAN:</b>", this);
    peersHeader->setObjectName("peersHeaderLabel");
    mainLayout->addWidget(peersHeader);

    discoveredPeersTreeWidget = new QTreeWidget(this);
    discoveredPeersTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->header()->setSectionResizeMode(0, QHeaderView::Stretch);

    mainLayout->addWidget(discoveredPeersTreeWidget, 1);

    QHBoxLayout *actionButtonLayout = new QHBoxLayout();
    connectToPeerButton = new QPushButton("Connect to Peer", this);
    connectToPeerButton->setObjectName("connectToPeerButton");
    cloneRepoButton = new QPushButton("Clone Repository", this);
    cloneRepoButton->setObjectName("cloneRepoButton");
    actionButtonLayout->addWidget(connectToPeerButton);
    actionButtonLayout->addWidget(cloneRepoButton);
    // Add as Collaborator button on the same row
    addCollaboratorButton = new QPushButton("Add as Collaborator", this);
    addCollaboratorButton->setEnabled(false);
    addCollaboratorButton->setStyleSheet("background-color: #F8FAFC; color: #94A3B8; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 14px; font-weight: bold; min-width: 160px;");
    actionButtonLayout->addWidget(addCollaboratorButton);
    mainLayout->addLayout(actionButtonLayout);

    connect(addCollaboratorButton, &QPushButton::clicked, this, [this]()
            {
        QTreeWidgetItem *item = discoveredPeersTreeWidget->currentItem();
        if (item && !item->parent()) {
            QString peerId = item->text(0);
            logMessage(QString("Add as Collaborator clicked for '%1'").arg(peerId), QColor("#0F4C4A"));
            emit addCollaboratorRequested(peerId);
        } else {
            logMessage("Add as Collaborator clicked but no connected peer is selected.", Qt::red);
        } });

    auto updateAddCollabState = [this]()
    {
        QTreeWidgetItem *item = discoveredPeersTreeWidget->currentItem();
        bool enable = false;
        if (item && !item->parent())
        {
            enable = m_lastConnectedPeerIds.contains(item->text(0));
        }
        addCollaboratorButton->setEnabled(enable);
        addCollaboratorButton->setStyleSheet(QString("background-color: #F8FAFC; color: %1; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 14px; font-weight: bold; min-width: 160px;")
                                                 .arg(enable ? "#0F4C4A" : "#94A3B8"));
        if (item && !item->parent())
        {
            logMessage(QString("Selection changed to '%1' — connected: %2").arg(item->text(0)).arg(enable ? "yes" : "no"), QColor("#666666"));
        }
    };

    connect(discoveredPeersTreeWidget, &QTreeWidget::itemSelectionChanged, this, updateAddCollabState);
    // Also update state when selection changes via currentItemChanged signal
    connect(discoveredPeersTreeWidget, &QTreeWidget::currentItemChanged, this, [updateAddCollabState](QTreeWidgetItem *, QTreeWidgetItem *)
            { updateAddCollabState(); });

    QLabel *logHeader = new QLabel("<b>Network Log / Broadcasts:</b>", this);
    logHeader->setObjectName("logHeaderLabel");
    mainLayout->addWidget(logHeader);

    networkLogDisplay = new QTextEdit(this);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    mainLayout->addWidget(networkLogDisplay, 1);

    QHBoxLayout *messageSendLayout = new QHBoxLayout();
    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Enter message to broadcast to all connected peers...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Broadcast", this);
    sendMessageButton->setObjectName("sendMessageButton");
    messageSendLayout->addWidget(sendMessageButton);
    mainLayout->addLayout(messageSendLayout);
}

void NetworkPanel::onDiscoveredPeerOrRepoSelected(QTreeWidgetItem *current)
{
    connectToPeerButton->setEnabled(false);
    cloneRepoButton->setEnabled(false);
    if (!current)
        return;

    if (current->parent())
    {
        // It's a repo, enable cloning
        cloneRepoButton->setEnabled(true);
    }
    else
    {
        // It's a peer, enable connecting if not already connected
        {
            bool isConnected = m_lastConnectedPeerIds.contains(current->text(0));
            connectToPeerButton->setEnabled(!isConnected);
            // Update Add Collaborator state here too
            addCollaboratorButton->setEnabled(isConnected);
            addCollaboratorButton->setStyleSheet(QString("background-color: #F8FAFC; color: %1; border: 1px solid #CBD5E1; border-radius: 6px; font-size: 14px; font-weight: bold; min-width: 160px;")
                                                     .arg(isConnected ? "#0F4C4A" : "#94A3B8"));
        }
    }
}

void NetworkPanel::onConnectClicked()
{
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem && !currentItem->parent())
    {
        emit connectToPeerRequested(currentItem->text(0));
    }
}

void NetworkPanel::onCloneClicked()
{
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem && currentItem->parent())
    {
        QString repoName = currentItem->data(0, Qt::UserRole).toString();
        QString peerId = currentItem->parent()->text(0);
        emit cloneRepoRequested(peerId, repoName);
    }
}

void NetworkPanel::onSendMessageClicked()
{
    QString message = messageInput->text().trimmed();
    if (message.isEmpty())
        return;
    emit sendBroadcastMessageRequested(message);
    messageInput->clear();
}

// Removed right-click context menu for add collaborator. Now handled by dedicated button below peer list.

void NetworkPanel::showContextMenu(const QPoint &pos)
{
    Q_UNUSED(pos);
    // Intentionally left blank: right-click menu removed in favor of the dedicated button.
}
