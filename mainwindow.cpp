#include "mainwindow.h"
#include <QFileDialog>
#include <QMessageBox> // For the approval dialog
#include <QDir>
#include <QFont>
#include <QSplitter>
#include <QTcpSocket>
#include <QInputDialog>
#include <QHostAddress>
#include <QHostInfo>


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_currentlyDisplayedLogBranch(""), m_myPeerName("DefaultUser") {
    // ... (Peer Name Input Dialog - same as before) ...
    bool ok_name; QString name = QInputDialog::getText(this, tr("Enter Your Peer Name"), tr("Peer Name:"), QLineEdit::Normal, QHostInfo::localHostName(), &ok_name);
    if (ok_name && !name.isEmpty()) { m_myPeerName = name; } else { m_myPeerName = QHostInfo::localHostName(); if(m_myPeerName.isEmpty()) m_myPeerName = "AnonymousPeer";}

    setupUi();

    // ... (Existing Git and Network Connections - same as before) ...
    connect(initRepoButton, &QPushButton::clicked, this, &MainWindow::onInitRepoClicked); // ... other git connects
    connect(openRepoButton, &QPushButton::clicked, this, &MainWindow::onOpenRepoClicked);
    connect(refreshLogButton, &QPushButton::clicked, this, &MainWindow::onRefreshLogClicked);
    connect(refreshBranchesButton, &QPushButton::clicked, this, &MainWindow::onRefreshBranchesClicked);
    connect(checkoutBranchButton, &QPushButton::clicked, this, &MainWindow::onCheckoutBranchClicked);
    connect(toggleDiscoveryButton, &QPushButton::clicked, this, &MainWindow::onToggleDiscoveryAndTcpServerClicked);
    connect(sendMessageButton, &QPushButton::clicked, this, &MainWindow::onSendMessageClicked);
    connect(discoveredPeersList, &QListWidget::itemDoubleClicked, this, &MainWindow::onDiscoveredPeerDoubleClicked);

    connect(&networkManager, &NetworkManager::tcpServerStatusChanged, this, &MainWindow::handleTcpServerStatusChanged);
    connect(&networkManager, &NetworkManager::incomingTcpConnectionRequest, this, &MainWindow::handleIncomingTcpConnectionRequest); // <<< NEW CONNECTION
    connect(&networkManager, &NetworkManager::newTcpPeerConnected, this, &MainWindow::handleNewTcpPeerConnected);
    connect(&networkManager, &NetworkManager::tcpPeerDisconnected, this, &MainWindow::handleTcpPeerDisconnected);
    connect(&networkManager, &NetworkManager::tcpMessageReceived, this, &MainWindow::handleTcpMessageReceived);
    connect(&networkManager, &NetworkManager::tcpConnectionStatusChanged, this, &MainWindow::handleTcpConnectionStatusChanged);
    connect(&networkManager, &NetworkManager::lanPeerDiscoveredOrUpdated, this, &MainWindow::handleLanPeerDiscoveredOrUpdated);
    connect(&networkManager, &NetworkManager::lanPeerLost, this, &MainWindow::handleLanPeerLost);

    updateRepositoryStatus();
    setWindowTitle("P2P Git Client - " + m_myPeerName);
}

// ... (Destructor, setupUi, Git methods: updateRepositoryStatus, loadCommitLogForBranch, loadCommitLog, loadBranchList, on*Git*Clicked - all same as the last full version I gave) ...
MainWindow::~MainWindow() {}
void MainWindow::setupUi() { /* ... exactly as before ... */
    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *mainVLayout = new QVBoxLayout(centralWidget); 
    QHBoxLayout *pathActionLayout = new QHBoxLayout();
    repoPathInput = new QLineEdit(this);
    repoPathInput->setPlaceholderText("Enter path or click Open/Initialize");
    repoPathInput->setText(QDir::toNativeSeparators(QDir::homePath() + "/my_test_repo_p2p"));
    pathActionLayout->addWidget(repoPathInput, 1); 
    initRepoButton = new QPushButton("Initialize Here", this);
    pathActionLayout->addWidget(initRepoButton);
    openRepoButton = new QPushButton("Open Existing", this);
    pathActionLayout->addWidget(openRepoButton);
    mainVLayout->addLayout(pathActionLayout);
    QHBoxLayout *statusLayout = new QHBoxLayout();
    currentRepoLabel = new QLabel("No repository open.", this);
    QFont boldFont = currentRepoLabel->font(); boldFont.setBold(true);
    currentRepoLabel->setFont(boldFont); statusLayout->addWidget(currentRepoLabel, 1); 
    currentBranchLabel = new QLabel("Branch: -", this);
    currentBranchLabel->setFont(boldFont); statusLayout->addWidget(currentBranchLabel);
    mainVLayout->addLayout(statusLayout);
    QSplitter *overallSplitter = new QSplitter(Qt::Horizontal, this); 
    QWidget *gitPaneWidget = new QWidget(overallSplitter);
    QVBoxLayout *gitPaneLayout = new QVBoxLayout(gitPaneWidget);
    QSplitter *gitInfoSplitter = new QSplitter(Qt::Vertical, gitPaneWidget); 
    QWidget *topGitPaneWidget = new QWidget(gitInfoSplitter);
    QVBoxLayout *topGitPaneLayout = new QVBoxLayout(topGitPaneWidget);
    QLabel *commitLogTitleLabel = new QLabel("Commit History:", topGitPaneWidget); 
    topGitPaneLayout->addWidget(commitLogTitleLabel);
    commitLogDisplay = new QTextEdit(topGitPaneWidget);
    commitLogDisplay->setReadOnly(true); commitLogDisplay->setFontFamily("monospace"); commitLogDisplay->setLineWrapMode(QTextEdit::NoWrap);
    topGitPaneLayout->addWidget(commitLogDisplay, 1); 
    refreshLogButton = new QPushButton("Refresh Log", topGitPaneWidget);
    topGitPaneLayout->addWidget(refreshLogButton);
    QHBoxLayout *branchControlLayout = new QHBoxLayout(); 
    QLabel *branchSelectionLabel = new QLabel("Branches:", topGitPaneWidget); 
    branchControlLayout->addWidget(branchSelectionLabel);
    branchComboBox = new QComboBox(topGitPaneWidget);
    branchComboBox->setMinimumWidth(200); branchControlLayout->addWidget(branchComboBox, 1); 
    refreshBranchesButton = new QPushButton("Refresh Branches", topGitPaneWidget);
    branchControlLayout->addWidget(refreshBranchesButton);
    checkoutBranchButton = new QPushButton("Checkout/View Selected", topGitPaneWidget); 
    branchControlLayout->addWidget(checkoutBranchButton);
    topGitPaneLayout->addLayout(branchControlLayout);
    gitInfoSplitter->addWidget(topGitPaneWidget);
    messageLog = new QTextEdit(gitInfoSplitter); 
    messageLog->setReadOnly(true); messageLog->setPlaceholderText("Git operation status messages..."); messageLog->setMaximumHeight(100); 
    gitInfoSplitter->addWidget(messageLog);
    QList<int> gitSplitterSizes; gitSplitterSizes << 350 << 100; gitInfoSplitter->setSizes(gitSplitterSizes);
    gitPaneLayout->addWidget(gitInfoSplitter);
    overallSplitter->addWidget(gitPaneWidget);
    networkFrame = new QFrame(overallSplitter);
    networkFrame->setFrameShape(QFrame::StyledPanel);
    QVBoxLayout* networkVLayout = new QVBoxLayout(networkFrame); 
    networkVLayout->addWidget(new QLabel("<b>P2P Network (UDP Discovery):</b>", networkFrame));
    myPeerNameInput = new QLineEdit(m_myPeerName, networkFrame); 
    myPeerNameInput->setReadOnly(true); 
    QHBoxLayout* myNameLayout = new QHBoxLayout();
    myNameLayout->addWidget(new QLabel("My Peer Name:", networkFrame));
    myNameLayout->addWidget(myPeerNameInput);
    networkVLayout->addLayout(myNameLayout);
    toggleDiscoveryButton = new QPushButton("Start Discovery & TCP Server", networkFrame);
    networkVLayout->addWidget(toggleDiscoveryButton);
    tcpServerStatusLabel = new QLabel("TCP Server: Inactive", networkFrame); 
    networkVLayout->addWidget(tcpServerStatusLabel);
    networkVLayout->addWidget(new QLabel("Discovered Peers on LAN (double-click to connect):", networkFrame));
    discoveredPeersList = new QListWidget(networkFrame);
    discoveredPeersList->setToolTip("Double click a peer to initiate a TCP connection.");
    networkVLayout->addWidget(discoveredPeersList, 1); 
    networkVLayout->addWidget(new QLabel("Established TCP Connections:", networkFrame));
    connectedTcpPeersList = new QListWidget(networkFrame); 
    connectedTcpPeersList->setMaximumHeight(100);
    networkVLayout->addWidget(connectedTcpPeersList);
    QHBoxLayout* messageSendLayout = new QHBoxLayout(); 
    messageInput = new QLineEdit(networkFrame);
    messageInput->setPlaceholderText("Enter message (broadcast to TCP peers)...");
    messageSendLayout->addWidget(messageInput, 1);
    sendMessageButton = new QPushButton("Send Broadcast", networkFrame);
    messageSendLayout->addWidget(sendMessageButton);
    networkVLayout->addLayout(messageSendLayout);
    networkVLayout->addWidget(new QLabel("Network Log/Chat:", networkFrame));
    networkLogDisplay = new QTextEdit(networkFrame);
    networkLogDisplay->setReadOnly(true);
    networkLogDisplay->setFontFamily("monospace");
    networkVLayout->addWidget(networkLogDisplay, 2); 
    overallSplitter->addWidget(networkFrame);
    QList<int> overallSplitterSizes; overallSplitterSizes << 500 << 350; overallSplitter->setSizes(overallSplitterSizes);
    mainVLayout->addWidget(overallSplitter, 1); 
    setCentralWidget(centralWidget);
    resize(950, 700);
}
void MainWindow::updateRepositoryStatus() { bool repoIsOpen = gitBackend.isRepositoryOpen(); refreshLogButton->setEnabled(repoIsOpen); refreshBranchesButton->setEnabled(repoIsOpen); checkoutBranchButton->setEnabled(repoIsOpen); branchComboBox->setEnabled(repoIsOpen); if (repoIsOpen) { QString path = QString::fromStdString(gitBackend.getCurrentRepositoryPath()); currentRepoLabel->setText("Current Repository: " + QDir::toNativeSeparators(path)); loadBranchList(); loadCommitLog(); } else { currentRepoLabel->setText("No repository open."); currentBranchLabel->setText("Branch: -"); commitLogDisplay->clear(); branchComboBox->clear(); messageLog->append("No repository is open. Initialize or open one."); m_currentlyDisplayedLogBranch = ""; }}
void MainWindow::loadCommitLogForBranch(const std::string& branchNameOrSha) { commitLogDisplay->clear(); if (!gitBackend.isRepositoryOpen()) { commitLogDisplay->setHtml("<i>No repository open.</i>"); return; } std::string error_message_log; std::vector<CommitInfo> log = gitBackend.getCommitLog(100, error_message_log, branchNameOrSha); QString titleRefName = QString::fromStdString(branchNameOrSha).toHtmlEscaped(); if (branchNameOrSha.empty()){ std::string currentBranchErr; titleRefName = QString::fromStdString(gitBackend.getCurrentBranch(currentBranchErr)); if (titleRefName.isEmpty() || titleRefName.contains("[")) titleRefName = "Current HEAD"; else titleRefName = "HEAD (" + titleRefName + ")";} if (!error_message_log.empty() && log.empty()) { commitLogDisplay->setHtml("<font color=\"red\">Error loading log for <b>" + titleRefName + "</b>: " + QString::fromStdString(error_message_log).toHtmlEscaped() + "</font>"); } else if (log.empty()) { commitLogDisplay->setHtml("<i>No commits for <b>" + titleRefName + "</b>.</i>"); } else { QString htmlLog; htmlLog += "<h3>History for: <b>" + titleRefName + "</b></h3><hr/>"; for (const auto& entry : log) { htmlLog += QString("<b>%1</b> - %2 <%3> (%4)<br/>    %5<br/><hr/>").arg(QString::fromStdString(entry.sha.substr(0, 7))).arg(QString::fromStdString(entry.author_name).toHtmlEscaped()).arg(QString::fromStdString(entry.author_email).toHtmlEscaped()).arg(QString::fromStdString(entry.date)).arg(QString::fromStdString(entry.summary).toHtmlEscaped());} commitLogDisplay->setHtml(htmlLog); }}
void MainWindow::loadCommitLog() { m_currentlyDisplayedLogBranch = ""; loadCommitLogForBranch(""); }
void MainWindow::loadBranchList() { branchComboBox->clear(); if (!gitBackend.isRepositoryOpen()) return; std::string error_message; std::vector<std::string> branches = gitBackend.listBranches(GitBackend::BranchType::ALL, error_message); if (!error_message.empty()) { messageLog->append("<font color=\"red\">Error listing branches: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>"); } else { if (branches.empty()) { messageLog->append("No local or remote-tracking branches found."); } for (const std::string& bn_str : branches) { QString bq_str = QString::fromStdString(bn_str); if (bq_str.endsWith("/HEAD")) continue; branchComboBox->addItem(bq_str);}} std::string cbn_str = gitBackend.getCurrentBranch(error_message); if (!error_message.empty() && cbn_str.empty()){ messageLog->append("<font color=\"red\">Error fetching current branch: " + QString::fromStdString(error_message).toHtmlEscaped() + "</font>"); currentBranchLabel->setText("Branch: [Error]"); } else if (!cbn_str.empty()) { currentBranchLabel->setText("Branch: <b>" + QString::fromStdString(cbn_str).toHtmlEscaped() + "</b>"); int idx = branchComboBox->findText(QString::fromStdString(cbn_str)); if (idx != -1) branchComboBox->setCurrentIndex(idx);} else { currentBranchLabel->setText("Branch: -"); }}
void MainWindow::onInitRepoClicked() { QString qPath = repoPathInput->text().trimmed(); if(qPath.isEmpty()){ QMessageBox::warning(this, "Input Error", "Please enter a path for the new repository."); messageLog->append("<font color=\"red\">Error: Repository path cannot be empty.</font>"); return; } std::string path = qPath.toStdString(); std::string errorMessage; QDir dir(QDir::toNativeSeparators(qPath)); if(!dir.exists()){ if(!dir.mkpath(".")){ messageLog->append("<font color=\"red\">Error: Could not create directory: " + qPath.toHtmlEscaped() + "</font>"); QMessageBox::critical(this, "Directory Error", "Could not create directory: " + qPath); return; }} if(gitBackend.initializeRepository(path, errorMessage)){ messageLog->append("<font color=\"green\">"+QString::fromStdString(errorMessage).toHtmlEscaped()+"</font>");} else{ messageLog->append("<font color=\"red\">"+QString::fromStdString(errorMessage).toHtmlEscaped()+"</font>");} updateRepositoryStatus(); }
void MainWindow::onOpenRepoClicked() { QString currentPathSugg = repoPathInput->text().trimmed(); if(currentPathSugg.isEmpty() || !QDir(currentPathSugg).exists()){ currentPathSugg = QDir::homePath();} QString dirPath = QFileDialog::getExistingDirectory(this, tr("Open Git Repository"), currentPathSugg, QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks); if(dirPath.isEmpty()){messageLog->append("Open cancelled."); return;} repoPathInput->setText(QDir::toNativeSeparators(dirPath)); std::string path = dirPath.toStdString(); std::string errorMessage; if(gitBackend.openRepository(path, errorMessage)){ messageLog->append("<font color=\"green\">"+QString::fromStdString(errorMessage).toHtmlEscaped()+"</font>");} else{ messageLog->append("<font color=\"red\">"+QString::fromStdString(errorMessage).toHtmlEscaped()+"</font>");} updateRepositoryStatus(); }
void MainWindow::onRefreshLogClicked() { if(gitBackend.isRepositoryOpen()){ if(!m_currentlyDisplayedLogBranch.empty()){ networkLogDisplay->append("Refreshing log for: "+QString::fromStdString(m_currentlyDisplayedLogBranch).toHtmlEscaped()); loadCommitLogForBranch(m_currentlyDisplayedLogBranch);} else { networkLogDisplay->append("Refreshing log for current HEAD."); loadCommitLog();}} else { networkLogDisplay->append("No repo open.");} }
void MainWindow::onRefreshBranchesClicked() { if(gitBackend.isRepositoryOpen()){ loadBranchList(); messageLog->append("Branch list refreshed.");} else { messageLog->append("No repo open.");} }
void MainWindow::onCheckoutBranchClicked() { if(!gitBackend.isRepositoryOpen()){ messageLog->append("<font color=\"red\">No repo open.</font>"); return;} QString selBrQStr = branchComboBox->currentText(); if(selBrQStr.isEmpty()){ messageLog->append("<font color=\"red\">No branch selected.</font>"); QMessageBox::warning(this, "Action Error", "No branch selected from the dropdown."); return;} std::string selBrName = selBrQStr.toStdString(); std::string err_op; std::string err_loc_list; std::vector<std::string> loc_brs = gitBackend.listBranches(GitBackend::BranchType::LOCAL, err_loc_list); bool is_loc = false; if(err_loc_list.empty()){ for(const auto& lb : loc_brs){ if(lb == selBrName){is_loc=true; break;}}} else { messageLog->append("<font color=\"orange\">Warn: Cld not list local branches: "+QString::fromStdString(err_loc_list)+"</font>"); is_loc = (selBrName.find('/') == std::string::npos && selBrName.find('[') == std::string::npos);} if(is_loc){ if(gitBackend.checkoutBranch(selBrName, err_op)){ messageLog->append("<font color=\"green\">"+QString::fromStdString(err_op).toHtmlEscaped()+"</font>"); m_currentlyDisplayedLogBranch=""; updateRepositoryStatus();} else{ messageLog->append("<font color=\"red\">Error checkout '"+selBrQStr.toHtmlEscaped()+"': "+QString::fromStdString(err_op).toHtmlEscaped()+"</font>"); QMessageBox::critical(this, "Checkout Fail", "Could not checkout: "+selBrQStr+"\nErr: "+QString::fromStdString(err_op));}} else { networkLogDisplay->append("Displaying history for: <b>"+selBrQStr.toHtmlEscaped()+"</b> (HEAD unchanged)"); loadCommitLogForBranch(selBrName); m_currentlyDisplayedLogBranch = selBrName;} }


// --- Network SLOTS Implementation (with Connection Approval) ---

void MainWindow::onToggleDiscoveryAndTcpServerClicked() {
    // ... (same as the full version I provided in the last big message)
    if (networkManager.getTcpServerPort() > 0) { 
        networkManager.stopUdpDiscovery(); networkManager.stopTcpServer(); 
    } else { 
        if (m_myPeerName.isEmpty()) { QMessageBox::warning(this, "Peer Name Missing", "Peer name is empty."); return; }
        if (networkManager.startTcpServer(0)) { 
            if (networkManager.startUdpDiscovery(45454, m_myPeerName)) { 
                networkLogDisplay->append("<font color=\"blue\">UDP Discovery and TCP Server initiated.</font>");
            } else { networkLogDisplay->append("<font color=\"red\">Failed to start UDP Discovery. TCP Server also stopped.</font>"); networkManager.stopTcpServer(); }
        }
    }
}

void MainWindow::onDiscoveredPeerDoubleClicked(QListWidgetItem* item) {
    // ... (same as the full version I provided in the last big message)
    if (!item) return;
    QString peerIp = item->data(Qt::UserRole).toString(); bool portOk; quint16 peerTcpPort = item->data(Qt::UserRole + 1).toUInt(&portOk);
    QString peerIdToConnect = item->data(Qt::UserRole + 2).toString(); // Get PeerID
    if (peerIdToConnect == m_myPeerName) { networkLogDisplay->append("<font color=\"orange\">Cannot connect to self.</font>"); return; }
    if (portOk && !peerIp.isEmpty() && peerTcpPort > 0) {
        networkLogDisplay->append("Attempting TCP connection to discovered peer: " + peerIdToConnect.toHtmlEscaped() + " @ " + peerIp + ":" + QString::number(peerTcpPort));
        networkManager.connectToTcpPeer(QHostAddress(peerIp), peerTcpPort, peerIdToConnect);
    } else { networkLogDisplay->append("<font color=\"red\">Could not parse peer info from list item: " + item->text().toHtmlEscaped() + "</font>"); }
}

void MainWindow::onSendMessageClicked() {
    // ... (same as the full version I provided - using networkManager.hasActiveTcpConnections()) ...
    QString message = messageInput->text().trimmed(); if (message.isEmpty()) return;
    if (!networkManager.hasActiveTcpConnections() && networkManager.getTcpServerPort() == 0) { 
        networkLogDisplay->append("<font color=\"red\">Not connected and TCP server not listening. Cannot send.</font>"); return; }
    networkManager.broadcastTcpMessage(message);
    networkLogDisplay->append("<font color=\"blue\"><b>Me (Broadcast):</b> " + message.toHtmlEscaped() + "</font>"); messageInput->clear();
}

void MainWindow::handleTcpServerStatusChanged(bool listening, quint16 port, const QString& error) {
    // ... (same as the full version I provided) ...
    if (listening) { tcpServerStatusLabel->setText("TCP Server: Listening on port <b>" + QString::number(port) + "</b>"); toggleDiscoveryButton->setText("Stop Discovery & TCP Server"); myPeerNameInput->setEnabled(false);
    } else { tcpServerStatusLabel->setText("TCP Server: Inactive"); toggleDiscoveryButton->setText("Start Discovery & TCP Server"); myPeerNameInput->setEnabled(true); 
        if (!error.isEmpty()) { networkLogDisplay->append("<font color=\"red\">TCP Server error/stopped: " + error.toHtmlEscaped() + "</font>");} 
        else { bool wasRunning = (toggleDiscoveryButton->text() == "Stop Discovery & TCP Server"); if(wasRunning) { networkLogDisplay->append("TCP Server stopped.");}}}
}

// **** NEW SLOT IMPLEMENTATION FOR CONNECTION APPROVAL ****
void MainWindow::handleIncomingTcpConnectionRequest(QTcpSocket* pendingSocket, const QHostAddress& address, quint16 port) {
    // Try to find if we know this peer from UDP discovery to get a name
    QString incomingPeerId = "Unknown Peer";
    for (int i = 0; i < discoveredPeersList->count(); ++i) {
        QListWidgetItem* item = discoveredPeersList->item(i);
        if (item->data(Qt::UserRole).toString() == address.toString() /* && item->data(Qt::UserRole+1).toUInt() == some_udp_advertised_tcp_port - harder to match directly */ ) {
            // A simple match by IP. For more robustness, discovery packet should include a unique instance ID.
            // For now, we'll use the DiscoveredPeerInfo ID if IP matches
            QString discoveredId = item->data(Qt::UserRole+2).toString();
            if (!discoveredId.isEmpty()) {
                incomingPeerId = discoveredId;
                break;
            }
        }
    }
    if (incomingPeerId == "Unknown Peer") {
        incomingPeerId = address.toString() + ":" + QString::number(port);
    }


    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, "Incoming Connection",
                                  QString("Accept incoming TCP connection from %1?").arg(incomingPeerId.toHtmlEscaped()),
                                  QMessageBox::Yes | QMessageBox::No);

    if (reply == QMessageBox::Yes) {
        networkLogDisplay->append("<font color=\"blue\">User accepted connection from " + incomingPeerId.toHtmlEscaped() + "</font>");
        networkManager.acceptPendingTcpConnection(pendingSocket);
    } else {
        networkLogDisplay->append("<font color=\"orange\">User rejected connection from " + incomingPeerId.toHtmlEscaped() + "</font>");
        networkManager.rejectPendingTcpConnection(pendingSocket);
    }
}
// **** END OF NEW SLOT IMPLEMENTATION ****


void MainWindow::handleNewTcpPeerConnected(QTcpSocket* peerSocket, const QString& peerId) {
    // ... (same as the full version I provided) ...
    Q_UNUSED(peerSocket); QString fullPeerDisplayId = peerId;
    if(peerSocket){ fullPeerDisplayId += " (" + peerSocket->peerAddress().toString() + ":" + QString::number(peerSocket->peerPort()) + ")";}
    for(int i=0; i < connectedTcpPeersList->count(); ++i){ if(connectedTcpPeersList->item(i)->text().startsWith(peerId + " (")) { connectedTcpPeersList->item(i)->setText(fullPeerDisplayId); return;}}
    QListWidgetItem* newItem = new QListWidgetItem(fullPeerDisplayId, connectedTcpPeersList); newItem->setData(Qt::UserRole, peerId); 
    networkLogDisplay->append("<font color=\"green\">TCP Peer fully connected: " + peerId.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpPeerDisconnected(QTcpSocket* peerSocket, const QString& peerId) {
    // ... (same as the full version I provided) ...
    Q_UNUSED(peerSocket); 
    for (int i = 0; i < connectedTcpPeersList->count(); ++i) { if (connectedTcpPeersList->item(i)->data(Qt::UserRole).toString() == peerId) { delete connectedTcpPeersList->takeItem(i); break; }}
    networkLogDisplay->append("<font color=\"orange\">TCP Peer disconnected: " + peerId.toHtmlEscaped() + "</font>");
}

void MainWindow::handleTcpMessageReceived(QTcpSocket* peerSocket, const QString& peerId, const QString& message) {
    // ... (same as the full version I provided) ...
    Q_UNUSED(peerSocket); networkLogDisplay->append("<b>" + peerId.toHtmlEscaped() + ":</b> " + message.toHtmlEscaped());
}

void MainWindow::handleTcpConnectionStatusChanged(const QString& peerId, bool connected, const QString& error) {
    // ... (same as the full version I provided) ...
    if (connected) { /* newTcpPeerConnected handles list addition */ } 
    else { networkLogDisplay->append("<font color=\"red\">Failed TCP connection to " + peerId.toHtmlEscaped() + ": " + error.toHtmlEscaped() + "</font>");}
}

void MainWindow::handleLanPeerDiscoveredOrUpdated(const DiscoveredPeerInfo& peerInfo) {
    // ... (same as the full version I provided) ...
    QString itemText = peerInfo.id + " (" + peerInfo.address.toString() + ":" + QString::number(peerInfo.tcpPort) + ")";
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerInfo.id, Qt::MatchStartsWith); 
    if (!items.isEmpty()) { items.first()->setText(itemText); items.first()->setData(Qt::UserRole, peerInfo.address.toString()); items.first()->setData(Qt::UserRole + 1, peerInfo.tcpPort); items.first()->setData(Qt::UserRole + 2, peerInfo.id); } 
    else { QListWidgetItem* newItem = new QListWidgetItem(itemText, discoveredPeersList); newItem->setData(Qt::UserRole, peerInfo.address.toString()); newItem->setData(Qt::UserRole + 1, peerInfo.tcpPort); newItem->setData(Qt::UserRole + 2, peerInfo.id); }
    // networkLogDisplay->append("<font color=\"purple\">LAN Peer: " + itemText.toHtmlEscaped() + " active.</font>"); // Can be a bit noisy
}

void MainWindow::handleLanPeerLost(const QString& peerId) {
    // ... (same as the full version I provided) ...
    QList<QListWidgetItem*> items = discoveredPeersList->findItems(peerId, Qt::MatchStartsWith); 
    if (!items.isEmpty()) { delete discoveredPeersList->takeItem(discoveredPeersList->row(items.first())); }
    networkLogDisplay->append("<font color=\"gray\">LAN Peer lost: " + peerId.toHtmlEscaped() + "</font>");
}