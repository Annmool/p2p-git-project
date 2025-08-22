#include "info_dot.h"

InfoDot::InfoDot(const QString &tip, QWidget *parent) : QLabel("i", parent), m_tipText(tip)
{
    setAlignment(Qt::AlignCenter);
    setFixedSize(12, 12);
    setStyleSheet(
        "QLabel {"
        "  border: 1px solid #2D5F5D;"
        "  color: #0F4C4A;"
        "  background: #EAF7F5;"
        "  border-radius: 6px;"
        "  font-weight: 700;"
        "  font-size: 9px;"
        "}");
    setCursor(Qt::WhatsThisCursor);
    setFocusPolicy(Qt::NoFocus);
    setMouseTracking(true);
    
    // Create the hover tooltip
    m_tooltip = new QLabel(parent);
    m_tooltip->setText(tip);
    m_tooltip->setStyleSheet(
        "QLabel {"
        "  background-color: #2D3748;"
        "  color: white;"
        "  border: 1px solid #4A5568;"
        "  border-radius: 6px;"
        "  padding: 8px 12px;"
        "  font-size: 12px;"
        "}");
    m_tooltip->setWordWrap(true);
    m_tooltip->setMaximumWidth(250);
    m_tooltip->adjustSize();
    m_tooltip->hide();
}

void InfoDot::enterEvent(QEvent *event)
{
    QLabel::enterEvent(event);
    showTooltip();
}

void InfoDot::leaveEvent(QEvent *event)
{
    QLabel::leaveEvent(event);
    hideTooltip();
}

void InfoDot::showTooltip()
{
    if (!m_tooltip) return;
    
    // Position tooltip near the info dot
    QPoint globalPos = mapToGlobal(QPoint(width() + 5, -height()/2));
    QPoint parentPos = parentWidget()->mapFromGlobal(globalPos);
    
    // Adjust if tooltip would go off screen
    if (parentPos.x() + m_tooltip->width() > parentWidget()->width()) {
        parentPos.setX(mapToParent(QPoint(-m_tooltip->width() - 5, -height()/2)).x());
    }
    if (parentPos.y() < 0) {
        parentPos.setY(mapToParent(QPoint(0, height() + 5)).y());
    }
    
    m_tooltip->move(parentPos);
    m_tooltip->show();
    m_tooltip->raise();
}

void InfoDot::hideTooltip()
{
    if (m_tooltip) {
        m_tooltip->hide();
    }
}

QLabel *makeInfoDot(const QString &tip, QWidget *parent)
{
    return new InfoDot(tip, parent);
}

