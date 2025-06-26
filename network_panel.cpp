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
    myPeerInfoLabel->setText(QString("<b>My Peer ID:</b> %1<br><b>PubKey (prefix):</b> %2...")
                                 .arg(m_myUsername.toHtmlEscaped())
                                 .arg(publicKeyHex.left(10)));
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
    QString selectedPeer;
    if (discoveredPeersTreeWidget->currentItem() && !discoveredPeersTreeWidget->currentItem()->parent())
    {
        selectedPeer = discoveredPeersTreeWidget->currentItem()->text(0);
    }

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

        for (const QString &repoName : peerInfo.publicRepoNames)
        {
            QTreeWidgetItem *repoItem = new QTreeWidgetItem(peerItem);
            repoItem->setText(0, "  " + repoName);
            repoItem->setData(0, Qt::UserRole, repoName);
            repoItem->setData(0, Qt::UserRole + 1, peerInfo.id);
            repoItem->setText(1, "Public");
        }
        peerItem->setExpanded(true);
        if (peerInfo.id == selectedPeer)
        {
            discoveredPeersTreeWidget->setCurrentItem(peerItem);
        }
    }
}

void NetworkPanel::updateServerStatus(bool listening, quint16 port, const QString &error)
{
    if (listening)
    {
        tcpServerStatusLabel->setText(QString("TCP Server: <font color='lime'><b>Listening on port %1</b></font>").arg(port));
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        if (!m_myUsername.isEmpty())
        {
            myPeerInfoLabel->setText(QString("<b>My Peer ID:</b> %1<br><b>PubKey (prefix):</b> %2...<br><b>TCP Port:</b> %3")
                                         .arg(m_myUsername.toHtmlEscaped())
                                         .arg(myPeerInfoLabel->text().split("...").first().split(":").last().trimmed())
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
    mainLayout->addWidget(new QLabel("<b>P2P Network</b>", this));

    myPeerInfoLabel = new QLabel("<b>My Peer ID:</b><br><b>PubKey (prefix):</b>", this);
    myPeerInfoLabel->setWordWrap(true);
    mainLayout->addWidget(myPeerInfoLabel);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", this);
    mainLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", this);
    mainLayout->addWidget(tcpServerStatusLabel);

    mainLayout->addWidget(new QLabel("<b>Discovered Peers & Repos on LAN:</b>", this));
    discoveredPeersTreeWidget = new QTreeWidget(this);
    discoveredPeersTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    mainLayout->addWidget(discoveredPeersTreeWidget, 1);

    QHBoxLayout *actionButtonLayout = new QHBoxLayout();
    connectToPeerButton = new QPushButton("Connect to Peer", this);
    cloneRepoButton = new QPushButton("Clone Repository", this);
    actionButtonLayout->addWidget(connectToPeerButton);
    actionButtonLayout->addWidget(cloneRepoButton);
    mainLayout->addLayout(actionButtonLayout);

    mainLayout->addWidget(new QLabel("<b>Network Log / Broadcasts:</b>", this));
    networkLogDisplay = new QTextEdit(this);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    mainLayout->addWidget(networkLogDisplay, 1);
    
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
        if (m_networkManager)
        {
            bool isConnected = m_networkManager->getSocketForPeer(current->text(0)) != nullptr;
            connectToPeerButton->setEnabled(!isConnected);
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
    if (message.isEmpty()) return;
    emit sendBroadcastMessageRequested(message);
    messageInput->clear();
}

void NetworkPanel::showContextMenu(const QPoint &pos)
{
    QTreeWidgetItem *item = discoveredPeersTreeWidget->itemAt(pos);
    if (!item || item->parent())
        return;

    QString peerId = item->text(0);
    if (!m_networkManager) return;

    bool isConnected = m_networkManager->getSocketForPeer(peerId) != nullptr;
    
    QMenu contextMenu(this);
    QAction *addCollabAction = contextMenu.addAction(style()->standardIcon(QStyle::SP_DialogApplyButton), "Add as Collaborator...");
    addCollabAction->setEnabled(isConnected);
    
    QAction *selectedAction = contextMenu.exec(discoveredPeersTreeWidget->mapToGlobal(pos));

    if (selectedAction == addCollabAction)
    {
        emit addCollaboratorRequested(peerId);
    }
}