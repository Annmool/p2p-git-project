#ifndef CUSTOM_DIALOGS_H
#define CUSTOM_DIALOGS_H

#include <QDialog>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QTextEdit>
#include <QListWidget>
#include <QTreeView>
#include <QFileSystemModel>
#include <QProgressBar>
#include <QIcon>
#include <QDir>

class CustomMessageBox : public QDialog
{
    Q_OBJECT

public:
    enum Icon
    {
        NoIcon,
        Information,
        Warning,
        Critical,
        Question
    };

    enum StandardButton
    {
        NoButton = 0x00000000,
        Ok = 0x00000400,
        Cancel = 0x00400000,
        Yes = 0x00004000,
        No = 0x00010000
    };
    Q_DECLARE_FLAGS(StandardButtons, StandardButton)

    explicit CustomMessageBox(QWidget *parent = nullptr);
    CustomMessageBox(Icon icon, const QString &title, const QString &text,
                     StandardButtons buttons = StandardButtons(Ok), QWidget *parent = nullptr);
    void setIcon(Icon icon);
    void setText(const QString &text);
    void setDetailedText(const QString &text);
    void setStandardButtons(StandardButtons buttons);
    StandardButton execCustom();

    static StandardButton information(QWidget *parent, const QString &title, const QString &text,
                                      StandardButtons buttons = StandardButtons(Ok));
    static StandardButton warning(QWidget *parent, const QString &title, const QString &text,
                                  StandardButtons buttons = StandardButtons(Ok));
    static StandardButton critical(QWidget *parent, const QString &title, const QString &text,
                                   StandardButtons buttons = StandardButtons(Ok));
    static StandardButton question(QWidget *parent, const QString &title, const QString &text,
                                   StandardButtons buttons = StandardButtons(Yes | No));

private slots:
    void onButtonClicked();

private:
private:
    void setupUi();
    void applyStyles();
    QPixmap getIconPixmap(Icon icon);

    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_contentLayout;
    QVBoxLayout *m_textLayout;
    QHBoxLayout *m_buttonLayout;
    QLabel *m_iconLabel;
    QLabel *m_textLabel;
    QTextEdit *m_detailTextEdit;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
    QPushButton *m_yesButton;
    QPushButton *m_noButton;

    Icon m_icon;
    QString m_text;
    QString m_detailText;
    StandardButtons m_standardButtons;
    StandardButton m_clickedButton;
};

Q_DECLARE_OPERATORS_FOR_FLAGS(CustomMessageBox::StandardButtons)

class CustomFileDialog : public QDialog
{
    Q_OBJECT

public:
    enum FileMode
    {
        AnyFile,
        ExistingFile,
        Directory,
        ExistingFiles
    };

    explicit CustomFileDialog(QWidget *parent = nullptr, const QString &caption = QString(),
                              const QString &directory = QString());

    void setFileMode(FileMode mode);
    void setNameFilter(const QString &filter);
    QString selectedFile() const;
    QStringList selectedFiles() const;
    void setDirectory(const QString &directory);

    static QString getOpenFileName(QWidget *parent = nullptr, const QString &caption = QString(),
                                   const QString &dir = QString(), const QString &filter = QString());
    static QString getSaveFileName(QWidget *parent = nullptr, const QString &caption = QString(),
                                   const QString &dir = QString(), const QString &filter = QString());
    static QString getExistingDirectory(QWidget *parent = nullptr, const QString &caption = QString(),
                                        const QString &dir = QString());

public slots:
    void accept() override;

private slots:
    void onTreeViewClicked(const QModelIndex &index);
    void onTreeViewDoubleClicked(const QModelIndex &index);
    void onFileNameChanged();
    void onUpButtonClicked();
    void onHomeButtonClicked();

private:
    void setupUi();
    void applyStyles();
    void updateCurrentPath();

    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_topLayout;
    QHBoxLayout *m_bottomLayout;
    QLabel *m_pathLabel;
    QPushButton *m_upButton;
    QPushButton *m_homeButton;
    QTreeView *m_treeView;
    QLineEdit *m_fileNameEdit;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;

    QFileSystemModel *m_model;
    FileMode m_fileMode;
    QString m_nameFilter;
    QString m_currentDir;
};

class CustomInputDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CustomInputDialog(QWidget *parent = nullptr);

    void setLabelText(const QString &text);
    void setTextValue(const QString &text);
    QString textValue() const;

    static QString getText(QWidget *parent, const QString &title, const QString &label,
                           const QString &text = QString(), bool *ok = nullptr);

public slots:
    void accept() override;

private:
    void setupUi();
    void applyStyles();

    QVBoxLayout *m_mainLayout;
    QLabel *m_label;
    QLineEdit *m_lineEdit;
    QHBoxLayout *m_buttonLayout;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
};

class CustomProgressDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CustomProgressDialog(QWidget *parent = nullptr);
    CustomProgressDialog(const QString &labelText, const QString &cancelButtonText,
                         int minimum, int maximum, QWidget *parent = nullptr);

    void setLabelText(const QString &text);
    void setCancelButtonText(const QString &text);
    void setRange(int minimum, int maximum);
    void setValue(int progress);
    void setAutoClose(bool close);
    void setAutoReset(bool reset);

    bool wasCanceled() const;

signals:
    void canceled();

public slots:
    void cancel();
    void reset();

private slots:
    void onCancelClicked();

private:
    void setupUi();
    void applyStyles();

    QVBoxLayout *m_mainLayout;
    QLabel *m_label;
    QProgressBar *m_progressBar;
    QPushButton *m_cancelButton;

    bool m_wasCanceled;
    bool m_autoClose;
    bool m_autoReset;
};

#endif // CUSTOM_DIALOGS_H
