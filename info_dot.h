#ifndef INFO_DOT_H
#define INFO_DOT_H

#include <QLabel>
#include <QEvent>

// Custom info dot with hover textbox
class InfoDot : public QLabel
{
    Q_OBJECT
public:
    InfoDot(const QString &tip, QWidget *parent = nullptr);

protected:
    void enterEvent(QEvent *event) override;
    void leaveEvent(QEvent *event) override;

private:
    void showTooltip();
    void hideTooltip();

    QString m_tipText;
    QLabel *m_tooltip;
};

// Helper function to create info dots
QLabel *makeInfoDot(const QString &tip, QWidget *parent);

#endif // INFO_DOT_H
