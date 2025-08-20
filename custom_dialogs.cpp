#include "custom_dialogs.h"
#include <QApplication>
#include <QDesktopWidget>
#include <QScreen>
#include <QFontMetrics>
#include <QHeaderView>
#include <QStandardPaths>
#include <QPainter>

// ============================================================================
// CustomMessageBox Implementation
// ============================================================================

CustomMessageBox::CustomMessageBox(QWidget *parent)
    : QDialog(parent), m_icon(NoIcon), m_standardButtons(Ok), m_clickedButton(NoButton)
{
    setupUi();
    applyStyles();
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
}

CustomMessageBox::CustomMessageBox(Icon icon, const QString &title, const QString &text,
                                   StandardButtons buttons, QWidget *parent)
    : QDialog(parent), m_icon(icon), m_text(text), m_standardButtons(buttons), m_clickedButton(NoButton)
{
    setupUi();
    applyStyles();
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setWindowTitle(title);
    setIcon(icon);
    setText(text);
    setStandardButtons(buttons);
}

void CustomMessageBox::setupUi()
{
    setMinimumSize(400, 150);
    setMaximumSize(600, 400);

    m_mainLayout = new QVBoxLayout(this);
    m_contentLayout = new QHBoxLayout();
    m_textLayout = new QVBoxLayout();
    m_buttonLayout = new QHBoxLayout();

    m_iconLabel = new QLabel();
    m_iconLabel->setFixedSize(48, 48);
    m_iconLabel->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

    m_textLabel = new QLabel();
    m_textLabel->setObjectName("textLabel");
    m_textLabel->setWordWrap(true);
    m_textLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);

    m_detailTextEdit = new QTextEdit();
    m_detailTextEdit->setVisible(false);
    m_detailTextEdit->setMaximumHeight(100);
    m_detailTextEdit->setReadOnly(true);

    m_okButton = new QPushButton("OK");
    m_cancelButton = new QPushButton("Cancel");
    m_yesButton = new QPushButton("Yes");
    m_noButton = new QPushButton("No");

    // Connect buttons
    connect(m_okButton, &QPushButton::clicked, this, &CustomMessageBox::onButtonClicked);
    connect(m_cancelButton, &QPushButton::clicked, this, &CustomMessageBox::onButtonClicked);
    connect(m_yesButton, &QPushButton::clicked, this, &CustomMessageBox::onButtonClicked);
    connect(m_noButton, &QPushButton::clicked, this, &CustomMessageBox::onButtonClicked);

    // Layout setup
    m_textLayout->addWidget(m_textLabel);
    m_textLayout->addWidget(m_detailTextEdit);

    m_contentLayout->addWidget(m_iconLabel);
    m_contentLayout->addLayout(m_textLayout);
    m_contentLayout->setStretch(1, 1);

    m_buttonLayout->addStretch();

    m_mainLayout->addLayout(m_contentLayout);
    m_mainLayout->addLayout(m_buttonLayout);
    m_mainLayout->setStretch(0, 1);
}

void CustomMessageBox::applyStyles()
{
    setStyleSheet(R"(
        QDialog {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 8px;
        }
        QLabel {
            color: #334155;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
            font-weight: bold;
        }
        QLabel#textLabel {
            font-size: 16px;
            font-weight: bold;
            color: #1E293B;
            line-height: 1.4;
        }
        QPushButton {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            color: #334155;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #F8FAFC;
            border-color: #94A3B8;
        }
        QPushButton#primaryButton {
            background-color: #0F4C4A;
            color: #FFFFFF;
            border: none;
            font-weight: bold;
        }
        QPushButton#primaryButton:hover {
            background-color: #14625F;
        }
        QTextEdit {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 8px;
            background-color: #F8FAFC;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 12px;
        }
    )");
}

QPixmap CustomMessageBox::getIconPixmap(Icon icon)
{
    QPixmap pixmap(48, 48);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);

    switch (icon)
    {
    case Information:
        // Blue circle with "i"
        painter.setBrush(QColor("#3B82F6"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(4, 4, 40, 40);
        painter.setPen(QPen(Qt::white, 3, Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(24, 32, 24, 24);
        painter.drawPoint(24, 16);
        break;

    case Warning:
        // Orange triangle with "!"
        painter.setBrush(QColor("#F59E0B"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(4, 4, 40, 40);
        painter.setPen(QPen(Qt::white, 3, Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(24, 18, 24, 26);
        painter.drawPoint(24, 34);
        break;

    case Critical:
        // Red circle with "X"
        painter.setBrush(QColor("#EF4444"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(4, 4, 40, 40);
        painter.setPen(QPen(Qt::white, 3, Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(18, 18, 30, 30);
        painter.drawLine(18, 30, 30, 18);
        break;

    case Question:
        // Teal circle with "?"
        painter.setBrush(QColor("#0F4C4A"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(4, 4, 40, 40);
        painter.setPen(QPen(Qt::white, 3, Qt::SolidLine, Qt::RoundCap));
        // Draw question mark shape
        painter.drawArc(18, 16, 12, 8, 0, 180 * 16);
        painter.drawLine(24, 24, 24, 28);
        painter.drawPoint(24, 34);
        break;

    default:
        break;
    }

    painter.end();
    return pixmap;
}

void CustomMessageBox::setIcon(Icon icon)
{
    m_icon = icon;
    if (icon != NoIcon)
    {
        QPixmap iconPixmap = getIconPixmap(icon);
        m_iconLabel->setPixmap(iconPixmap);
        m_iconLabel->setVisible(true);
    }
    else
    {
        m_iconLabel->setVisible(false);
    }
}

void CustomMessageBox::setText(const QString &text)
{
    m_text = text;
    m_textLabel->setText(text);
}

void CustomMessageBox::setDetailedText(const QString &text)
{
    m_detailText = text;
    if (!text.isEmpty())
    {
        m_detailTextEdit->setText(text);
        m_detailTextEdit->setVisible(true);
    }
    else
    {
        m_detailTextEdit->setVisible(false);
    }
}

void CustomMessageBox::setStandardButtons(StandardButtons buttons)
{
    m_standardButtons = buttons;

    // Remove all buttons first
    m_okButton->setVisible(false);
    m_cancelButton->setVisible(false);
    m_yesButton->setVisible(false);
    m_noButton->setVisible(false);

    // Remove from layout
    while (m_buttonLayout->count() > 1)
    { // Keep the stretch
        QLayoutItem *item = m_buttonLayout->takeAt(1);
        if (item && item->widget())
        {
            item->widget()->setParent(nullptr);
        }
        delete item;
    }

    // Add buttons based on flags
    if (buttons & Ok)
    {
        m_okButton->setVisible(true);
        m_okButton->setObjectName("primaryButton");
        m_buttonLayout->addWidget(m_okButton);
    }
    if (buttons & Cancel)
    {
        m_cancelButton->setVisible(true);
        m_buttonLayout->addWidget(m_cancelButton);
    }
    if (buttons & Yes)
    {
        m_yesButton->setVisible(true);
        m_yesButton->setObjectName("primaryButton");
        m_buttonLayout->addWidget(m_yesButton);
    }
    if (buttons & No)
    {
        m_noButton->setVisible(true);
        m_buttonLayout->addWidget(m_noButton);
    }
}

CustomMessageBox::StandardButton CustomMessageBox::execCustom()
{
    m_clickedButton = NoButton;
    QDialog::exec();
    return m_clickedButton;
}

void CustomMessageBox::onButtonClicked()
{
    QPushButton *button = qobject_cast<QPushButton *>(sender());
    if (button == m_okButton)
    {
        m_clickedButton = Ok;
    }
    else if (button == m_cancelButton)
    {
        m_clickedButton = Cancel;
    }
    else if (button == m_yesButton)
    {
        m_clickedButton = Yes;
    }
    else if (button == m_noButton)
    {
        m_clickedButton = No;
    }
    accept();
}

CustomMessageBox::StandardButton CustomMessageBox::information(QWidget *parent, const QString &title,
                                                               const QString &text, StandardButtons buttons)
{
    CustomMessageBox msgBox(Information, title, text, StandardButtons(Ok), parent);
    msgBox.setStandardButtons(buttons);
    return msgBox.execCustom();
}

CustomMessageBox::StandardButton CustomMessageBox::warning(QWidget *parent, const QString &title,
                                                           const QString &text, StandardButtons buttons)
{
    CustomMessageBox msgBox(Warning, title, text, StandardButtons(Ok), parent);
    msgBox.setStandardButtons(buttons);
    return msgBox.execCustom();
}

CustomMessageBox::StandardButton CustomMessageBox::critical(QWidget *parent, const QString &title,
                                                            const QString &text, StandardButtons buttons)
{
    CustomMessageBox msgBox(Critical, title, text, StandardButtons(Ok), parent);
    msgBox.setStandardButtons(buttons);
    return msgBox.execCustom();
}

CustomMessageBox::StandardButton CustomMessageBox::question(QWidget *parent, const QString &title,
                                                            const QString &text, StandardButtons buttons)
{
    CustomMessageBox msgBox(Question, title, text, StandardButtons(Ok), parent);
    msgBox.setStandardButtons(buttons);
    return msgBox.execCustom();
} // ============================================================================
// CustomFileDialog Implementation
// ============================================================================

CustomFileDialog::CustomFileDialog(QWidget *parent, const QString &caption, const QString &directory)
    : QDialog(parent), m_fileMode(ExistingFile), m_currentDir(directory.isEmpty() ? QDir::homePath() : directory)
{
    setWindowTitle(caption);
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setupUi();
    applyStyles();
    updateCurrentPath();
}

void CustomFileDialog::setupUi()
{
    setMinimumSize(600, 400);
    resize(800, 500);

    m_mainLayout = new QVBoxLayout(this);
    m_topLayout = new QHBoxLayout();
    m_bottomLayout = new QHBoxLayout();

    // Top navigation
    m_pathLabel = new QLabel();
    m_pathLabel->setStyleSheet("font-weight: 500; padding: 4px 8px; background-color: #F8FAFC; border-radius: 4px;");

    m_upButton = new QPushButton("↑");
    m_upButton->setFixedSize(32, 32);
    m_upButton->setToolTip("Go up");

    m_homeButton = new QPushButton("🏠");
    m_homeButton->setFixedSize(32, 32);
    m_homeButton->setToolTip("Go home");

    m_topLayout->addWidget(m_pathLabel);
    m_topLayout->addWidget(m_upButton);
    m_topLayout->addWidget(m_homeButton);
    m_topLayout->setStretch(0, 1);

    // File tree view
    m_model = new QFileSystemModel(this);
    m_model->setRootPath(m_currentDir);

    m_treeView = new QTreeView();
    m_treeView->setModel(m_model);
    m_treeView->setRootIndex(m_model->index(m_currentDir));
    m_treeView->hideColumn(1); // Size
    m_treeView->hideColumn(2); // Type
    m_treeView->hideColumn(3); // Date Modified
    m_treeView->header()->hide();
    m_treeView->setSelectionMode(QAbstractItemView::SingleSelection);

    // Bottom section
    m_fileNameEdit = new QLineEdit();

    m_okButton = new QPushButton("OK");
    m_okButton->setObjectName("primaryButton");
    m_cancelButton = new QPushButton("Cancel");

    m_bottomLayout->addWidget(new QLabel("File name:"));
    m_bottomLayout->addWidget(m_fileNameEdit);
    m_bottomLayout->addWidget(m_okButton);
    m_bottomLayout->addWidget(m_cancelButton);
    m_bottomLayout->setStretch(1, 1);

    m_mainLayout->addLayout(m_topLayout);
    m_mainLayout->addWidget(m_treeView);
    m_mainLayout->addLayout(m_bottomLayout);
    m_mainLayout->setStretch(1, 1);

    // Connect signals
    connect(m_treeView, &QTreeView::clicked, this, &CustomFileDialog::onTreeViewClicked);
    connect(m_treeView, &QTreeView::doubleClicked, this, &CustomFileDialog::onTreeViewDoubleClicked);
    connect(m_fileNameEdit, &QLineEdit::textChanged, this, &CustomFileDialog::onFileNameChanged);
    connect(m_upButton, &QPushButton::clicked, this, &CustomFileDialog::onUpButtonClicked);
    connect(m_homeButton, &QPushButton::clicked, this, &CustomFileDialog::onHomeButtonClicked);
    connect(m_okButton, &QPushButton::clicked, this, &CustomFileDialog::accept);
    connect(m_cancelButton, &QPushButton::clicked, this, &CustomFileDialog::reject);
}

void CustomFileDialog::applyStyles()
{
    setStyleSheet(R"(
        QDialog {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 8px;
        }
        QLabel {
            color: #334155;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
            font-weight: bold;
        }
        QPushButton {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: bold;
            color: #334155;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #F8FAFC;
            border-color: #94A3B8;
        }
        QPushButton#primaryButton {
            background-color: #0F4C4A;
            color: #FFFFFF;
            border: none;
            font-weight: bold;
        }
        QPushButton#primaryButton:hover {
            background-color: #14625F;
        }
        QLineEdit {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 8px;
            background-color: #FFFFFF;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
        }
        QLineEdit:focus {
            border: 1px solid #4A90E2;
        }
        QTreeView {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            background-color: #FFFFFF;
            selection-background-color: #E0F2FE;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
        }
        QTreeView::item {
            padding: 4px;
            border: none;
        }
        QTreeView::item:selected {
            background-color: #E0F2FE;
            color: #0F4C4A;
        }
        QTreeView::item:hover {
            background-color: #F0F9FF;
        }
    )");
}

void CustomFileDialog::updateCurrentPath()
{
    m_pathLabel->setText(m_currentDir);
    m_treeView->setRootIndex(m_model->index(m_currentDir));
}

void CustomFileDialog::setFileMode(FileMode mode)
{
    m_fileMode = mode;
    if (mode == Directory)
    {
        m_model->setFilter(QDir::Dirs | QDir::NoDotAndDotDot);
        m_fileNameEdit->setVisible(false);
    }
    else
    {
        m_model->setFilter(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);
        m_fileNameEdit->setVisible(true);
    }
}

void CustomFileDialog::setDirectory(const QString &directory)
{
    m_currentDir = directory;
    updateCurrentPath();
}

void CustomFileDialog::setNameFilter(const QString &filter)
{
    m_nameFilter = filter;
    // For now, just store the filter - could implement actual filtering later
}

QString CustomFileDialog::selectedFile() const
{
    if (m_fileMode == Directory)
    {
        return m_currentDir;
    }
    return QDir(m_currentDir).absoluteFilePath(m_fileNameEdit->text());
}

QStringList CustomFileDialog::selectedFiles() const
{
    return QStringList() << selectedFile();
}

void CustomFileDialog::onTreeViewClicked(const QModelIndex &index)
{
    if (m_model->isDir(index))
    {
        if (m_fileMode == Directory)
        {
            m_fileNameEdit->setText(m_model->fileName(index));
        }
    }
    else
    {
        if (m_fileMode != Directory)
        {
            m_fileNameEdit->setText(m_model->fileName(index));
        }
    }
}

void CustomFileDialog::onTreeViewDoubleClicked(const QModelIndex &index)
{
    if (m_model->isDir(index))
    {
        m_currentDir = m_model->filePath(index);
        updateCurrentPath();
    }
    else if (m_fileMode != Directory)
    {
        m_fileNameEdit->setText(m_model->fileName(index));
        accept();
    }
}

void CustomFileDialog::onFileNameChanged()
{
    m_okButton->setEnabled(!m_fileNameEdit->text().isEmpty() || m_fileMode == Directory);
}

void CustomFileDialog::onUpButtonClicked()
{
    QDir dir(m_currentDir);
    if (dir.cdUp())
    {
        m_currentDir = dir.absolutePath();
        updateCurrentPath();
    }
}

void CustomFileDialog::onHomeButtonClicked()
{
    m_currentDir = QDir::homePath();
    updateCurrentPath();
}

void CustomFileDialog::accept()
{
    if (m_fileMode == Directory)
    {
        // If a directory name is entered/selected, update m_currentDir to point to that directory
        QString selectedDirName = m_fileNameEdit->text();
        if (!selectedDirName.isEmpty())
        {
            QString fullPath = QDir(m_currentDir).absoluteFilePath(selectedDirName);
            QDir selectedDir(fullPath);
            if (selectedDir.exists())
            {
                m_currentDir = selectedDir.absolutePath();
            }
        }
        QDialog::accept();
        return;
    }

    QString fileName = m_fileNameEdit->text();
    if (fileName.isEmpty())
    {
        return;
    }

    QString fullPath = QDir(m_currentDir).absoluteFilePath(fileName);
    QFileInfo fileInfo(fullPath);

    if (m_fileMode == ExistingFile && !fileInfo.exists())
    {
        CustomMessageBox::warning(this, "File Not Found", "The specified file does not exist.");
        return;
    }

    QDialog::accept();
}

QString CustomFileDialog::getOpenFileName(QWidget *parent, const QString &caption,
                                          const QString &dir, const QString &filter)
{
    CustomFileDialog dialog(parent, caption.isEmpty() ? "Open File" : caption, dir);
    dialog.setFileMode(ExistingFile);
    if (!filter.isEmpty())
    {
        dialog.setNameFilter(filter);
    }

    if (dialog.exec() == QDialog::Accepted)
    {
        return dialog.selectedFile();
    }
    return QString();
}

QString CustomFileDialog::getSaveFileName(QWidget *parent, const QString &caption,
                                          const QString &dir, const QString &filter)
{
    CustomFileDialog dialog(parent, caption.isEmpty() ? "Save File" : caption, dir);
    dialog.setFileMode(AnyFile);
    if (!filter.isEmpty())
    {
        dialog.setNameFilter(filter);
    }

    if (dialog.exec() == QDialog::Accepted)
    {
        return dialog.selectedFile();
    }
    return QString();
}

QString CustomFileDialog::getExistingDirectory(QWidget *parent, const QString &caption, const QString &dir)
{
    CustomFileDialog dialog(parent, caption.isEmpty() ? "Select Directory" : caption, dir);
    dialog.setFileMode(Directory);

    if (dialog.exec() == QDialog::Accepted)
    {
        return dialog.selectedFile();
    }
    return QString();
}

// ============================================================================
// CustomInputDialog Implementation
// ============================================================================

CustomInputDialog::CustomInputDialog(QWidget *parent)
    : QDialog(parent)
{
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setupUi();
    applyStyles();
}

void CustomInputDialog::setupUi()
{
    setMinimumSize(300, 150);
    setMaximumSize(500, 200);

    m_mainLayout = new QVBoxLayout(this);
    m_buttonLayout = new QHBoxLayout();

    m_label = new QLabel();
    m_lineEdit = new QLineEdit();

    m_okButton = new QPushButton("OK");
    m_okButton->setObjectName("primaryButton");
    m_cancelButton = new QPushButton("Cancel");

    m_buttonLayout->addStretch();
    m_buttonLayout->addWidget(m_okButton);
    m_buttonLayout->addWidget(m_cancelButton);

    m_mainLayout->addWidget(m_label);
    m_mainLayout->addWidget(m_lineEdit);
    m_mainLayout->addLayout(m_buttonLayout);
    m_mainLayout->setStretch(0, 0);
    m_mainLayout->setStretch(1, 0);
    m_mainLayout->setStretch(2, 1);

    connect(m_okButton, &QPushButton::clicked, this, &CustomInputDialog::accept);
    connect(m_cancelButton, &QPushButton::clicked, this, &CustomInputDialog::reject);
    connect(m_lineEdit, &QLineEdit::returnPressed, this, &CustomInputDialog::accept);
}

void CustomInputDialog::applyStyles()
{
    setStyleSheet(R"(
        QDialog {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 8px;
        }
        QLabel {
            color: #334155;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
            font-weight: bold;
        }
        QPushButton {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: bold;
            color: #334155;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #F8FAFC;
            border-color: #94A3B8;
        }
        QPushButton#primaryButton {
            background-color: #0F4C4A;
            color: #FFFFFF;
            border: none;
            font-weight: bold;
        }
        QPushButton#primaryButton:hover {
            background-color: #14625F;
        }
        QLineEdit {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 8px;
            background-color: #FFFFFF;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
        }
        QLineEdit:focus {
            border: 1px solid #4A90E2;
        }
    )");
}

void CustomInputDialog::setLabelText(const QString &text)
{
    m_label->setText(text);
}

void CustomInputDialog::setTextValue(const QString &text)
{
    m_lineEdit->setText(text);
}

QString CustomInputDialog::textValue() const
{
    return m_lineEdit->text();
}

void CustomInputDialog::accept()
{
    if (m_lineEdit->text().isEmpty())
    {
        return;
    }
    QDialog::accept();
}

QString CustomInputDialog::getText(QWidget *parent, const QString &title, const QString &label,
                                   const QString &text, bool *ok)
{
    CustomInputDialog dialog(parent);
    dialog.setWindowTitle(title);
    dialog.setLabelText(label);
    dialog.setTextValue(text);

    bool accepted = (dialog.exec() == QDialog::Accepted);
    if (ok)
    {
        *ok = accepted;
    }

    return accepted ? dialog.textValue() : QString();
}

// ============================================================================
// CustomProgressDialog Implementation
// ============================================================================

CustomProgressDialog::CustomProgressDialog(QWidget *parent)
    : QDialog(parent), m_wasCanceled(false), m_autoClose(true), m_autoReset(true)
{
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setupUi();
    applyStyles();
}

CustomProgressDialog::CustomProgressDialog(const QString &labelText, const QString &cancelButtonText,
                                           int minimum, int maximum, QWidget *parent)
    : QDialog(parent), m_wasCanceled(false), m_autoClose(true), m_autoReset(true)
{
    setModal(true);
    setWindowFlags(Qt::Dialog | Qt::FramelessWindowHint);
    setupUi();
    applyStyles();

    setLabelText(labelText);
    setCancelButtonText(cancelButtonText);
    setRange(minimum, maximum);
}

void CustomProgressDialog::setupUi()
{
    setMinimumSize(400, 120);
    setMaximumSize(500, 150);

    m_mainLayout = new QVBoxLayout(this);

    m_label = new QLabel();
    m_progressBar = new QProgressBar();
    m_cancelButton = new QPushButton("Cancel");

    m_mainLayout->addWidget(m_label);
    m_mainLayout->addWidget(m_progressBar);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    buttonLayout->addWidget(m_cancelButton);
    m_mainLayout->addLayout(buttonLayout);

    connect(m_cancelButton, &QPushButton::clicked, this, &CustomProgressDialog::onCancelClicked);
}

void CustomProgressDialog::applyStyles()
{
    setStyleSheet(R"(
        QDialog {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            border-radius: 8px;
        }
        QLabel {
            color: #334155;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 14px;
            font-weight: bold;
        }
        QPushButton {
            background-color: #FFFFFF;
            border: 1px solid #CBD5E1;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: bold;
            color: #334155;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: #F8FAFC;
            border-color: #94A3B8;
        }
        QProgressBar {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            background-color: #F8FAFC;
            text-align: center;
            font-family: "Inter", "Segoe UI", "Cantarell", "sans-serif";
            font-size: 12px;
            color: #334155;
        }
        QProgressBar::chunk {
            background-color: #0F4C4A;
            border-radius: 5px;
        }
    )");
}

void CustomProgressDialog::setLabelText(const QString &text)
{
    m_label->setText(text);
}

void CustomProgressDialog::setCancelButtonText(const QString &text)
{
    m_cancelButton->setText(text);
    m_cancelButton->setVisible(!text.isEmpty());
}

void CustomProgressDialog::setRange(int minimum, int maximum)
{
    m_progressBar->setRange(minimum, maximum);
}

void CustomProgressDialog::setValue(int progress)
{
    m_progressBar->setValue(progress);

    if (m_autoClose && progress >= m_progressBar->maximum())
    {
        accept();
    }
}

void CustomProgressDialog::setAutoClose(bool close)
{
    m_autoClose = close;
}

void CustomProgressDialog::setAutoReset(bool reset)
{
    m_autoReset = reset;
}

bool CustomProgressDialog::wasCanceled() const
{
    return m_wasCanceled;
}

void CustomProgressDialog::cancel()
{
    m_wasCanceled = true;
    emit canceled();
    reject();
}

void CustomProgressDialog::reset()
{
    m_wasCanceled = false;
    m_progressBar->reset();
}

void CustomProgressDialog::onCancelClicked()
{
    cancel();
}
