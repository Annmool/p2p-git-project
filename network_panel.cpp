#include "network_panel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
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
    connect(connectedTcpPeersList, &QListWidget::customContextMenuRequested, this, &NetworkPanel::showContextMenu);
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

void NetworkPanel::logChatMessage(const QString &peerId, const QString &message)
{
    QString formattedMessage = QString("<b>%1:</b> %2")
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

void NetworkPanel::updateConnectedPeersList(const QList<QString> &connectedPeerIds)
{
    connectedTcpPeersList->clear();
    for (const QString &peerId : connectedPeerIds)
    {
        QListWidgetItem *item = new QListWidgetItem(peerId, connectedTcpPeersList);
        item->setData(Qt::UserRole, peerId);
    }
}

void NetworkPanel::updateServerStatus(bool listening, quint16 port, const QString &error)
{
    if (listening)
    {
        tcpServerStatusLabel->setText(QString("TCP Server: <font color='lime'><b>Listening on port %1</b></font>").arg(port));
        toggleDiscoveryButton->setText("Stop Discovery & TCP Server");
        if (!m_myUsername.isEmpty())
        { // Ensure myUsername is set before using it
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
    QVBoxLayout *networkVLayout = new QVBoxLayout(this);
    networkVLayout->addWidget(new QLabel("<b>P2P Network</b>", this));

    myPeerInfoLabel = new QLabel("<b>My Peer ID:</b><br><b>PubKey (prefix):</b>", this);
    myPeerInfoLabel->setWordWrap(true);
    networkVLayout->addWidget(myPeerInfoLabel);

    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", this);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", this);
    networkVLayout->addWidget(tcpServerStatusLabel);

    networkVLayout->addWidget(new QLabel("<b>Discovered Peers & Repos on LAN:</b>", this));
    discoveredPeersTreeWidget = new QTreeWidget(this);
    discoveredPeersTreeWidget->setHeaderLabels(QStringList() << "Peer / Repository" << "Details");
    discoveredPeersTreeWidget->setColumnCount(2);
    discoveredPeersTreeWidget->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    networkVLayout->addWidget(discoveredPeersTreeWidget, 1);

    QHBoxLayout *actionButtonLayout = new QHBoxLayout();
    connectToPeerButton = new QPushButton("Connect to Peer", this);
    cloneRepoButton = new QPushButton("Clone Repository", this);
    actionButtonLayout->addWidget(connectToPeerButton);
    actionButtonLayout->addWidget(cloneRepoButton);
    networkVLayout->addLayout(actionButtonLayout);

    networkVLayout->addWidget(new QLabel("<b>Established TCP Connections:</b>", this));
    connectedTcpPeersList = new QListWidget(this);
    connectedTcpPeersList->setContextMenuPolicy(Qt::CustomContextMenu);
    connectedTcpPeersList->setMaximumHeight(80);
    networkVLayout->addWidget(connectedTcpPeersList);

    QHBoxLayout *messageSendLayout = new QHBoxLayout();
    messageInput = new QLineEdit(this);
    messageInput->setPlaceholderText("Enter message to broadcast...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Send", this);
    messageSendLayout->addWidget(sendMessageButton);
    networkVLayout->addLayout(messageSendLayout);

    networkVLayout->addWidget(new QLabel("<b>Network Log:</b>", this));
    networkLogDisplay = new QTextEdit(this);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    networkVLayout->addWidget(networkLogDisplay, 1);
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
    if (!message.isEmpty())
    {
        emit sendMessageRequested(message);
        logChatMessage(m_myUsername, message);
        messageInput->clear();
    }
}

void NetworkPanel::showContextMenu(const QPoint &pos)
{
    QListWidgetItem *item = connectedTcpPeersList->itemAt(pos);
    if (!item)
        return;

    QMenu contextMenu(this);
    QAction *addCollabAction = contextMenu.addAction(style()->standardIcon(QStyle::SP_DialogApplyButton), "Add as Collaborator...");
    QAction *selectedAction = contextMenu.exec(connectedTcpPeersList->mapToGlobal(pos));

    if (selectedAction == addCollabAction)
    {
        QString peerId = item->data(Qt::UserRole).toString();
        emit addCollaboratorRequested(peerId);
    }
}
