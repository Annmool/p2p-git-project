#include "welcome_window.h"
#include <QApplication>
#include <QScreen>
#include <QKeyEvent>

WelcomeWindow::WelcomeWindow(const QString &defaultName, QWidget *parent)
    : QDialog(parent),
      m_peerName(defaultName)
{
    setupUi();
    applyStyles();

    // Set default name
    if (!defaultName.isEmpty())
    {
        m_nameInput->setText(defaultName);
        m_nameInput->selectAll();
    }

    // Make the window full screen
    setWindowState(Qt::WindowMaximized);

    // Focus on the input field
    m_nameInput->setFocus();
}

QString WelcomeWindow::getPeerName() const
{
    return m_peerName;
}

void WelcomeWindow::setupUi()
{
    setWindowTitle("SyncIt - Setup");
    setWindowFlags(Qt::Window | Qt::WindowMaximizeButtonHint | Qt::WindowMinimizeButtonHint);

    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(40, 60, 40, 60);
    mainLayout->setSpacing(0);

    // Title section
    m_titleLabel = new QLabel("SyncIt", this);
    m_titleLabel->setObjectName("welcomeTitle");
    m_titleLabel->setAlignment(Qt::AlignCenter);

    m_subtitleLabel = new QLabel("Your Code, Your Network : True P2P", this);
    m_subtitleLabel->setObjectName("welcomeSubtitle");
    m_subtitleLabel->setAlignment(Qt::AlignCenter);

    mainLayout->addWidget(m_titleLabel);
    mainLayout->addSpacing(20);
    mainLayout->addWidget(m_subtitleLabel);
    mainLayout->addSpacing(80);

    // Center the card
    QHBoxLayout *cardCenterLayout = new QHBoxLayout();
    cardCenterLayout->addStretch();

    // Card frame
    m_cardFrame = new QFrame(this);
    m_cardFrame->setObjectName("welcomeCard");
    m_cardFrame->setFixedSize(500, 300);

    QVBoxLayout *cardLayout = new QVBoxLayout(m_cardFrame);
    cardLayout->setContentsMargins(40, 40, 40, 40);
    cardLayout->setSpacing(20);

    // Card content
    m_fieldLabel = new QLabel("Peer Username", this);
    m_fieldLabel->setObjectName("welcomeFieldLabel");

    m_nameInput = new QLineEdit(this);
    m_nameInput->setObjectName("welcomeInput");
    m_nameInput->setPlaceholderText("Enter your peer name...");
    m_nameInput->setMinimumHeight(50);

    // Button layout
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    m_cancelButton = new QPushButton("Cancel", this);
    m_cancelButton->setObjectName("welcomeCancelButton");
    m_cancelButton->setMinimumHeight(45);
    m_cancelButton->setMinimumWidth(120);

    m_continueButton = new QPushButton("Continue", this);
    m_continueButton->setObjectName("welcomeContinueButton");
    m_continueButton->setMinimumHeight(45);
    m_continueButton->setMinimumWidth(120);
    m_continueButton->setDefault(true);

    buttonLayout->addWidget(m_cancelButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_continueButton);

    // Add to card
    cardLayout->addWidget(m_fieldLabel);
    cardLayout->addWidget(m_nameInput);
    cardLayout->addStretch();
    cardLayout->addLayout(buttonLayout);

    cardCenterLayout->addWidget(m_cardFrame);
    cardCenterLayout->addStretch();

    mainLayout->addLayout(cardCenterLayout);
    mainLayout->addStretch();

    // Connect signals
    connect(m_continueButton, &QPushButton::clicked, this, &WelcomeWindow::onContinueClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &WelcomeWindow::onCancelClicked);
    connect(m_nameInput, &QLineEdit::returnPressed, this, &WelcomeWindow::onContinueClicked);
}

void WelcomeWindow::applyStyles()
{
    setStyleSheet(R"(
        WelcomeWindow {
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                      stop:0 #0A3A35, stop:1 #0F4C4A);
        }
        
        QLabel#welcomeTitle {
            font-size: 72px;
            font-weight: bold;
            color: #FFFFFF;
            margin: 20px 0;
        }
        
        QLabel#welcomeSubtitle {
            font-size: 24px;
            font-weight: 300;
            color: #B8E6E1;
            margin: 10px 0;
        }
        
        QFrame#welcomeCard {
            background-color: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
        }
        
        QLabel#welcomeFieldLabel {
            font-size: 18px;
            font-weight: 600;
            color: #0F4C4A;
            margin-bottom: 8px;
        }
        
        QLineEdit#welcomeInput {
            font-size: 16px;
            padding: 15px;
            border: 2px solid #0F4C4A;
            border-radius: 10px;
            background-color: #FFFFFF;
            color: #333333;
        }
        
        QLineEdit#welcomeInput:focus {
            border-color: #17C6B6;
            outline: none;
        }
        
        QPushButton#welcomeContinueButton {
            background-color: #0F4C4A;
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            padding: 12px 24px;
        }
        
        QPushButton#welcomeContinueButton:hover {
            background-color: #17C6B6;
        }
        
        QPushButton#welcomeContinueButton:pressed {
            background-color: #0D403D;
        }
        
        QPushButton#welcomeCancelButton {
            background-color: transparent;
            color: #666666;
            border: 2px solid #CCCCCC;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 500;
            padding: 12px 24px;
        }
        
        QPushButton#welcomeCancelButton:hover {
            background-color: #F5F5F5;
            border-color: #999999;
            color: #333333;
        }
        
        QPushButton#welcomeCancelButton:pressed {
            background-color: #E5E5E5;
        }
    )");
}

void WelcomeWindow::onContinueClicked()
{
    QString name = m_nameInput->text().trimmed();
    if (name.isEmpty())
    {
        m_nameInput->setFocus();
        m_nameInput->setStyleSheet(m_nameInput->styleSheet() + "; border-color: #E74C3C;");
        return;
    }

    m_peerName = name;
    emit nameEntered(name);
    accept();
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
