#include "welcome_window.h"
#include "auth_manager.h"
#include "custom_dialogs.h"
#include <QApplication>
#include <QScreen>
#include <QKeyEvent>
#include <QGroupBox>
#include <QDesktopServices>
#include <QTimer>

WelcomeWindow::WelcomeWindow(const QString &defaultName, QWidget *parent)
    : QDialog(parent),
      m_peerName(defaultName)
{
    setupUi();
    applyStyles();

    // Prefill username fields
    if (!defaultName.isEmpty())
    {
        if (m_logUserEdit)
            m_logUserEdit->setText(defaultName);
        if (m_regUserEdit)
            m_regUserEdit->setText(defaultName);
    }

    // Make the window full screen
    setWindowState(Qt::WindowMaximized);

    // Focus on login username
    if (m_logUserEdit)
        m_logUserEdit->setFocus();

    // Position close button properly after window is shown
    QTimer::singleShot(0, this, [this]()
                       {
        if (auto closeBtn = findChild<QPushButton*>("closeButton")) {
            closeBtn->move(width() - 50, 10);
        } });
}

QString WelcomeWindow::getPeerName() const
{
    return m_peerName;
}

void WelcomeWindow::setupUi()
{
    setWindowTitle("SyncIt - Setup");
    setWindowFlags(Qt::Window | Qt::WindowMaximizeButtonHint | Qt::WindowMinimizeButtonHint);

    // Add close button in top-right corner
    QPushButton *closeButton = new QPushButton("×", this);
    closeButton->setObjectName("closeButton");
    closeButton->setFixedSize(40, 40);
    closeButton->move(width() - 50, 10);
    closeButton->setStyleSheet(
        "QPushButton { "
        "background-color: #DC2626; "
        "color: white; "
        "border: none; "
        "border-radius: 20px; "
        "font-size: 20px; "
        "font-weight: bold; "
        "} "
        "QPushButton:hover { "
        "background-color: #EF4444; "
        "} "
        "QPushButton:pressed { "
        "background-color: #B91C1C; "
        "}");
    connect(closeButton, &QPushButton::clicked, this, &WelcomeWindow::reject);

    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(40, 80, 40, 80);
    mainLayout->setSpacing(0);

    // Title section
    m_titleLabel = new QLabel("SyncIt", this);
    m_titleLabel->setObjectName("welcomeTitle");
    m_titleLabel->setAlignment(Qt::AlignCenter);
    // Make title use system font, bold, larger size and apply heading property for theme
    QFont titleFont = QApplication::font();
    titleFont.setBold(true);
    titleFont.setPointSize(48);
    m_titleLabel->setFont(titleFont);
    m_titleLabel->setProperty("heading", "1");

    m_subtitleLabel = new QLabel("Your Code, Your Network : True P2P", this);
    m_subtitleLabel->setObjectName("welcomeSubtitle");
    m_subtitleLabel->setAlignment(Qt::AlignCenter);
    QFont subtitleFont = QApplication::font();
    subtitleFont.setPointSize(18);
    subtitleFont.setWeight(QFont::Light);
    m_subtitleLabel->setFont(subtitleFont);

    mainLayout->addWidget(m_titleLabel);
    mainLayout->addSpacing(16);
    mainLayout->addWidget(m_subtitleLabel);
    mainLayout->addSpacing(60);

    // Center the card
    QHBoxLayout *cardCenterLayout = new QHBoxLayout();
    cardCenterLayout->addStretch();

    // Card frame
    m_cardFrame = new QFrame(this);
    m_cardFrame->setObjectName("welcomeCard");
    m_cardFrame->setFixedWidth(1100);
    m_cardFrame->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);

    QVBoxLayout *cardLayout = new QVBoxLayout(m_cardFrame);
    cardLayout->setContentsMargins(50, 50, 50, 50);
    cardLayout->setSpacing(20);

    // Build Login section
    QGroupBox *loginBox = new QGroupBox("Login", m_cardFrame);
    loginBox->setObjectName("loginBox");
    QVBoxLayout *loginLayout = new QVBoxLayout(loginBox);
    loginLayout->setContentsMargins(20, 20, 20, 20);
    loginLayout->setSpacing(12);

    QLabel *loginInfo = new QLabel("Enter your username and password:", loginBox);
    loginInfo->setProperty("heading", "2");
    m_logUserEdit = new QLineEdit(loginBox);
    m_logUserEdit->setPlaceholderText("Username");
    m_logPassEdit = new QLineEdit(loginBox);
    m_logPassEdit->setPlaceholderText("Password");
    m_logPassEdit->setEchoMode(QLineEdit::Password);
    m_logButton = new QPushButton("Login", loginBox);
    m_logButton->setObjectName("primaryButton");
    connect(m_logButton, &QPushButton::clicked, this, &WelcomeWindow::onLoginClicked);

    // Forgot password link and recovery row
    m_forgotLink = new QLabel("<a href=\"#\">Forgot password?</a>", loginBox);
    m_forgotLink->setObjectName("forgotLink");
    m_forgotLink->setTextFormat(Qt::RichText);
    m_forgotLink->setTextInteractionFlags(Qt::TextBrowserInteraction);
    m_forgotLink->setOpenExternalLinks(false);
    connect(m_forgotLink, &QLabel::linkActivated, this, [this](const QString &)
            { onForgotPasswordClicked(); });

    m_recoveryRow = new QWidget(loginBox);
    QHBoxLayout *recLay = new QHBoxLayout(m_recoveryRow);
    recLay->setContentsMargins(0, 0, 0, 0);
    m_recoveryEdit = new QLineEdit(m_recoveryRow);
    m_recoveryEdit->setPlaceholderText("Enter recovery key (<= 30 chars)");
    m_recoveryEdit->setMaxLength(30);
    m_showPwButton = new QPushButton("Show Password", m_recoveryRow);
    connect(m_showPwButton, &QPushButton::clicked, this, &WelcomeWindow::onShowRecoveredPassword);
    recLay->addWidget(m_recoveryEdit, 1);
    recLay->addWidget(m_showPwButton);
    m_recoveryRow->setVisible(false);

    loginLayout->addWidget(loginInfo);
    loginLayout->addWidget(m_logUserEdit);
    loginLayout->addWidget(m_logPassEdit);
    loginLayout->addWidget(m_logButton);
    loginLayout->addWidget(m_forgotLink);
    loginLayout->addWidget(m_recoveryRow);

    // Build Register section
    QGroupBox *regBox = new QGroupBox("Register", m_cardFrame);
    regBox->setObjectName("registerBox");
    QVBoxLayout *regLayout = new QVBoxLayout(regBox);
    regLayout->setContentsMargins(20, 20, 20, 20);
    regLayout->setSpacing(12);
    QLabel *regInfo = new QLabel("Create a new profile:", regBox);
    regInfo->setProperty("heading", "2");
    m_regUserEdit = new QLineEdit(regBox);
    m_regUserEdit->setPlaceholderText("Choose a username");
    m_regPassEdit = new QLineEdit(regBox);
    m_regPassEdit->setPlaceholderText("Choose a password");
    m_regPassEdit->setEchoMode(QLineEdit::Password);
    m_regConfirmEdit = new QLineEdit(regBox);
    m_regConfirmEdit->setPlaceholderText("Confirm password");
    m_regConfirmEdit->setEchoMode(QLineEdit::Password);
    m_regButton = new QPushButton("Register", regBox);
    m_regButton->setObjectName("primaryButton");
    connect(m_regButton, &QPushButton::clicked, this, &WelcomeWindow::onRegisterClicked);
    regLayout->addWidget(regInfo);
    regLayout->addWidget(m_regUserEdit);
    regLayout->addWidget(m_regPassEdit);
    regLayout->addWidget(m_regConfirmEdit);
    regLayout->addWidget(m_regButton);

    // Add sections side-by-side with a vertical divider
    QHBoxLayout *row = new QHBoxLayout();
    row->setContentsMargins(0, 0, 0, 0);
    row->setSpacing(40);

    QWidget *divider = new QWidget(m_cardFrame);
    divider->setObjectName("authDivider");
    divider->setFixedWidth(2);
    divider->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);

    row->addWidget(loginBox, 1);
    row->addWidget(divider);
    row->addWidget(regBox, 1);

    cardLayout->addLayout(row);

    // Legacy controls hidden (kept for stylesheet compatibility)
    m_fieldLabel = new QLabel(this);
    m_fieldLabel->setVisible(false);
    m_nameInput = new QLineEdit(this);
    m_nameInput->setVisible(false);
    m_continueButton = new QPushButton(this);
    m_continueButton->setVisible(false);
    m_cancelButton = new QPushButton(this);
    m_cancelButton->setVisible(false);

    cardCenterLayout->addWidget(m_cardFrame);
    cardCenterLayout->addStretch();

    mainLayout->addLayout(cardCenterLayout);
    mainLayout->addStretch();
    // No legacy signal connections
}

void WelcomeWindow::applyStyles()
{
    // Use global styles.qss. Optionally tweak the forgot-password link.
    setStyleSheet("");
}

void WelcomeWindow::onContinueClicked()
{
    // Not used in new UI
}

void WelcomeWindow::onCancelClicked()
{
    reject();
}

void WelcomeWindow::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Escape)
    {
        onCancelClicked();
    }
    else
    {
        QDialog::keyPressEvent(event);
    }
}

// ---- New auth logic ----
void WelcomeWindow::onRegisterClicked()
{
    QString u = m_regUserEdit->text().trimmed();
    QString p = m_regPassEdit->text();
    QString c = m_regConfirmEdit->text();

    if (u.isEmpty() || p.isEmpty() || c.isEmpty())
    {
        CustomMessageBox::warning(this, "Missing Fields", "Please fill username, password, and confirm password.");
        return;
    }
    if (p != c)
    {
        CustomMessageBox::warning(this, "Password Mismatch", "Password and confirmation do not match.");
        return;
    }

    QString err, token, profilePath;
    if (!AuthManager::registerUser(u, p, err, token, profilePath))
    {
        if (err.contains("exists", Qt::CaseInsensitive))
            CustomMessageBox::warning(this, "Profile Exists", "Profile already exists, please login!");
        else
            CustomMessageBox::critical(this, "Registration Failed", err);
        return;
    }

    // Save recovery key file
    QString savedPath = AuthManager::saveRecoveryTokenToFile(u, token, this);
    if (savedPath.isEmpty())
    {
        CustomMessageBox::warning(this, "Recovery Key Not Saved", "Registration succeeded, but the recovery key was not saved. Store this token safely:\n\n" + token);
    }
    else
    {
        CustomMessageBox::information(this, "Registered Successfully",
                                      QString("Your profile has been created.\n\nRecovery key was saved to:\n%1\n\nStore it safely. Please login now.").arg(savedPath));
    }

    // Prefill login and focus
    m_logUserEdit->setText(u);
    m_logPassEdit->clear();
    m_logUserEdit->setFocus();
}

void WelcomeWindow::onLoginClicked()
{
    QString u = m_logUserEdit->text().trimmed();
    QString p = m_logPassEdit->text();

    if (u.isEmpty() || p.isEmpty())
    {
        CustomMessageBox::warning(this, "Missing Fields", "Please enter username and password.");
        return;
    }
    if (!AuthManager::userExists(u))
    {
        CustomMessageBox::warning(this, "Profile Not Found", "No profile found. Please register first, then login.");
        return;
    }

    QString err;
    if (!AuthManager::loginUser(u, p, err))
    {
        CustomMessageBox::critical(this, "Login Failed", err);
        return;
    }

    m_peerName = u;
    accept();
}

void WelcomeWindow::onForgotPasswordClicked()
{
    if (!m_recoveryRow)
        return;
    m_recoveryRow->setVisible(!m_recoveryRow->isVisible());
    if (m_recoveryRow->isVisible())
        m_recoveryEdit->setFocus();
}

void WelcomeWindow::onShowRecoveredPassword()
{
    QString u = m_logUserEdit->text().trimmed();
    QString token = m_recoveryEdit->text().trimmed();

    if (u.isEmpty())
    {
        CustomMessageBox::warning(this, "Enter Username", "Please enter the username whose password you want to recover.");
        return;
    }
    if (token.isEmpty())
    {
        CustomMessageBox::warning(this, "Enter Recovery Key", "Please enter the recovery key.");
        return;
    }

    QString err, pw;
    if (!AuthManager::recoverPassword(u, token, pw, err))
    {
        CustomMessageBox::critical(this, "Recovery Failed", err);
        return;
    }

    CustomMessageBox::information(this, "Recovered Password", QString("Your password is:\n\n%1").arg(pw));
}
