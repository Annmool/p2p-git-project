#ifndef WELCOME_WINDOW_H
#define WELCOME_WINDOW_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QWidget>
#include <QFrame>

class QKeyEvent;
class QResizeEvent;

class WelcomeWindow : public QDialog
{
    Q_OBJECT

public:
    explicit WelcomeWindow(const QString &defaultName = QString(), QWidget *parent = nullptr);

    QString getPeerName() const;

signals:
    void nameEntered(const QString &name);

private slots:
    // Legacy buttons no longer used
    void onContinueClicked();
    void onCancelClicked();
    // New auth actions
    void onRegisterClicked();
    void onLoginClicked();
    void onForgotPasswordClicked();
    void onShowRecoveredPassword();

private:
    void setupUi();
    void applyStyles();
    void keyPressEvent(QKeyEvent *event) override;
    void resizeEvent(QResizeEvent *event) override;

    // Header widgets
    QLabel *m_titleLabel;
    QLabel *m_subtitleLabel;
    QFrame *m_cardFrame;

    // Deprecated single name input (kept to avoid compile churn in applyStyles)
    QLabel *m_fieldLabel;
    QLineEdit *m_nameInput;
    QPushButton *m_continueButton;
    QPushButton *m_cancelButton;
    QPushButton *m_closeButton{nullptr};

    // Register widgets
    QLineEdit *m_regUserEdit{nullptr};
    QLineEdit *m_regPassEdit{nullptr};
    QLineEdit *m_regConfirmEdit{nullptr};
    QPushButton *m_regButton{nullptr};

    // Login widgets
    QLineEdit *m_logUserEdit{nullptr};
    QLineEdit *m_logPassEdit{nullptr};
    QPushButton *m_logButton{nullptr};
    QLabel *m_forgotLink{nullptr};
    QWidget *m_recoveryRow{nullptr};
    QLineEdit *m_recoveryEdit{nullptr};
    QPushButton *m_showPwButton{nullptr};

    QString m_peerName;
};

#endif // WELCOME_WINDOW_H
