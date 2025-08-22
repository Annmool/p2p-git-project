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

class WelcomeWindow : public QDialog
{
    Q_OBJECT

public:
    explicit WelcomeWindow(const QString &defaultName = QString(), QWidget *parent = nullptr);

    QString getPeerName() const;

signals:
    void nameEntered(const QString &name);

private slots:
    void onContinueClicked();
    void onCancelClicked();

private:
    void setupUi();
    void applyStyles();
    void keyPressEvent(QKeyEvent *event) override;

    QLabel *m_titleLabel;
    QLabel *m_subtitleLabel;
    QFrame *m_cardFrame;
    QLabel *m_fieldLabel;
    QLineEdit *m_nameInput;
    QPushButton *m_continueButton;
    QPushButton *m_cancelButton;

    QString m_peerName;
};

#endif // WELCOME_WINDOW_H
