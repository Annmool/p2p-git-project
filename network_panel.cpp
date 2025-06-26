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
#include <QInputDialog>
#include <QMessageBox>

NetworkPanel::NetworkPanel(QWidget *parent) : QWidget(parent)
{
    setupUi();
    // Load icons
    m_peerDisconnectedIcon = this->style()->standardIcon(QStyle::SP_DialogCancelButton);
    m_peerConnectedIcon = this->style()->standardIcon(QStyle::SP_DialogYesButton);

    // Connect UI signals to panel slots
    connect(toggleDiscoveryButton, &QPushButton::clicked, this, &NetworkPanel::toggleDiscoveryRequested);
    connect(connectToPeerButton, &QPushButton::clicked, this, &NetworkPanel::onConnectClicked);
    connect(cloneRepoButton, &QPushButton::clicked, this, &NetworkPanel::onCloneClicked);
    connect(sendMessageButton, &QPushButton::clicked, this, &NetworkPanel::onSendMessageClicked);
    // Connect tree widget selection changes
    connect(discoveredPeersTreeWidget, &QTreeWidget::currentItemChanged, this, &NetworkPanel::onDiscoveredPeerOrRepoSelected);
    // Connect context menu request
    discoveredPeersTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(discoveredPeersTreeWidget, &QTreeWidget::customContextMenuRequested, this, &NetworkPanel::showContextMenu);

    // Set initial button states
    connectToPeerButton->setEnabled(false);
    cloneRepoButton->setEnabled(false);
}

void NetworkPanel::setNetworkManager(NetworkManager *manager)
{
    m_networkManager = manager;
}

void NetworkPanel::setMyPeerInfo(const QString &username, const QString &publicKeyHex)
{
    m_myUsername = username;
    QString pkHashStr = QCryptographicHash::hash(publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
    myPeerInfoLabel->setText(QString("<b>My Peer ID:</b> %1<br><b>PubKey (prefix):</b> %2...<br><b>TCP Port:</b> (Inactive)").arg(m_myUsername.toHtmlEscaped(), pkHashStr));
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
    QString selectedPeerId;
    if (discoveredPeersTreeWidget->currentItem())
    {
        QTreeWidgetItem *current = discoveredPeersTreeWidget->currentItem();
        if (!current->parent())
        {
            selectedPeerId = current->text(0);
        }
        else
        {
            selectedPeerId = current->parent()->text(0);
        }
    }

    discoveredPeersTreeWidget->clear();
    QStringList peerIds = discoveredPeers.keys();
    peerIds.sort();

    for (const QString &peerId : peerIds)
    {
        const DiscoveredPeerInfo &peerInfo = discoveredPeers.value(peerId);

        QTreeWidgetItem *peerItem = new QTreeWidgetItem(discoveredPeersTreeWidget);
        peerItem->setText(0, peerInfo.id);

        bool isConnected = connectedPeerIds.contains(peerInfo.id);
        peerItem->setIcon(0, isConnected ? m_peerConnectedIcon : m_peerDisconnectedIcon);
        peerItem->setForeground(0, isConnected ? QBrush(palette().color(QPalette::Text)) : QBrush(Qt::gray));

        QString pkHashStr = QCryptographicHash::hash(peerInfo.publicKeyHex.toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
        peerItem->setText(1, QString("%1:%2 [PKH:%3]").arg(peerInfo.address.toString(), QString::number(peerInfo.tcpPort), pkHashStr));
        peerItem->setData(0, Qt::UserRole, peerInfo.id);

        QStringList shareableRepoNames = peerInfo.publicRepoNames;
        shareableRepoNames.sort();
        for (const QString &repoName : shareableRepoNames)
        {
            QTreeWidgetItem *repoItem = new QTreeWidgetItem(peerItem);
            repoItem->setText(0, "  " + repoName);
            repoItem->setText(1, "Accessible"); // Label as "Accessible" for all repos in publicRepoNames
            repoItem->setData(0, Qt::UserRole, repoName);
            repoItem->setData(0, Qt::UserRole + 1, peerInfo.id);
        }
        peerItem->setExpanded(true);

        if (peerInfo.id == selectedPeerId)
        {
            discoveredPeersTreeWidget->setCurrentItem(peerItem);
        }
    }
    onDiscoveredPeerOrRepoSelected(discoveredPeersTreeWidget->currentItem());
}

void NetworkPanel::updateServerStatus(bool listening, quint16 port, const QString &error)
{
    if (listening)
    {
        tcpServerStatusLabel->setText(QString("TCP Server: <font color='lime'><b>Listening on port %1</b></font>").arg(port));
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        QString currentText = myPeerInfoLabel->text();
        int brIndex = currentText.lastIndexOf("<br>");
        if (brIndex != -1)
        {
            currentText = currentText.left(brIndex);
        }
        myPeerInfoLabel->setText(currentText + QString("<br><b>TCP Port:</b> %1").arg(port));
    }
    else
    {
        tcpServerStatusLabel->setText("TCP Server: <font color='red'><b>Inactive</b></font>");
        toggleDiscoveryButton->setText("Start Discovery & TCP Server");
        QString currentText = myPeerInfoLabel->text();
        int brIndex = currentText.lastIndexOf("<br>");
        if (brIndex != -1)
        {
            currentText = currentText.left(brIndex);
        }
        myPeerInfoLabel->setText(currentText + QString("<br><b>TCP Port:</b> (Inactive)"));

        if (!error.isEmpty())
        {
            logMessage("TCP Server error/stopped: " + error, Qt::red);
        }
    }
}

void NetworkPanel::setupUi()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(6);

    QLabel *headerLabel = new QLabel("<b>P2P Network</b>", this);
    headerLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(headerLabel);

    myPeerInfoLabel = new QLabel("<b>My Peer ID:</b><br><b>PubKey (prefix):</b><br><b>TCP Port:</b>", this);
    myPeerInfoLabel->setWordWrap(true);
    myPeerInfoLabel->setAlignment(Qt::AlignCenter);
    myPeerInfoLabel->setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; border-radius: 3px; }");
    mainLayout->addWidget(myPeerInfoLabel);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", this);
    mainLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", this);
    tcpServerStatusLabel->setAlignment(Qt::AlignCenter);
    mainLayout->addWidget(tcpServerStatusLabel);

    mainLayout->addWidget(new QLabel("<b>Discovered Peers & Repos on LAN:</b>", this));
    discoveredPeersTreeWidget = new QTreeWidget(this);
    discoveredPeersTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    discoveredPeersTreeWidget->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    mainLayout->addWidget(discoveredPeersTreeWidget, 1);

    QHBoxLayout *actionButtonLayout = new QHBoxLayout();
    connectToPeerButton = new QPushButton("Connect to Peer", this);
    cloneRepoButton = new QPushButton("Clone Repository", this);
    actionButtonLayout->addWidget(connectToPeerButton);
    actionButtonLayout->addWidget(cloneRepoButton);
    mainLayout->addLayout(actionButtonLayout);

    QSplitter *logChatSplitter = new QSplitter(Qt::Vertical, this);

    QWidget *logWidget = new QWidget(logChatSplitter);
    QVBoxLayout *logLayout = new QVBoxLayout(logWidget);
    logLayout->setContentsMargins(0, 0, 0, 0);
    logLayout->addWidget(new QLabel("<b>Network Log / Broadcasts:</b>", logWidget));
    networkLogDisplay = new QTextEdit(logWidget);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    networkLogDisplay->setMinimumHeight(100);
    logLayout->addWidget(networkLogDisplay);

    logChatSplitter->addWidget(logWidget);

    mainLayout->addWidget(logChatSplitter, 1);

    QHBoxLayout *messageSendLayout = new QHBoxLayout();
    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Enter message to broadcast to all connected peers...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Broadcast", this);
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
        cloneRepoButton->setEnabled(true);
    }
    else
    {
        QString peerId = current->text(0);
        if (m_networkManager)
        {
            bool isConnected = m_networkManager->getSocketForPeer(peerId) != nullptr;
            connectToPeerButton->setEnabled(!isConnected);
        }
    }
}

void NetworkPanel::onConnectClicked()
{
    QTreeWidgetItem *currentItem = discoveredPeersTreeWidget->currentItem();
    if (currentItem && !currentItem->parent())
    {
        QString peerId = currentItem->text(0);
        if (peerId == m_myUsername)
        {
            QMessageBox::information(this, "Connect to Self", "You cannot connect to yourself.");
            return;
        }
        emit connectToPeerRequested(peerId);
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

    if (!m_networkManager || !m_networkManager->hasActiveTcpConnections())
    {
        QMessageBox::information(this, "No Connected Peers", "You are not currently connected to any peers. Broadcast message will not be sent.");
        return;
    }

    emit sendBroadcastMessageRequested(message);
    messageInput->clear();
}

void NetworkPanel::showContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = discoveredPeersTreeWidget->itemAt(pos);
    if (!item || item->parent())
        return;

    QString peerId = item->text(0);
    if (peerId == m_myUsername)
        return;

    if (!m_networkManager)
        return;

    bool isConnected = m_networkManager->getSocketForPeer(peerId) != nullptr;

    QMenu contextMenu(this);
    QAction *addCollabAction = contextMenu.addAction(style()->standardIcon(QStyle::SP_DialogApplyButton), "Add as Collaborator to My Repo...");
    addCollabAction->setEnabled(isConnected);

    QAction *selectedAction = contextMenu.exec(discoveredPeersTreeWidget->mapToGlobal(pos));

    if (selectedAction == addCollabAction)
    {
        emit addCollaboratorRequested(peerId);
    }
}