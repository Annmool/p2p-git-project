#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLineEdit>
#include <QTextEdit> // To display messages
#include <QVBoxLayout>
#include "git_backend.h" // Include our backend

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; } // Forward declaration for UI file if using .ui
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onInitRepoClicked(); // Slot for button click

private:
    // Ui::MainWindow *ui; // If using a .ui file from Qt Designer

    // Manual UI elements
    QLineEdit *repoPathInput;
    QPushButton *initRepoButton;
    QTextEdit *messageLog; // To display success/error messages

    GitBackend gitBackend; // Instance of our Git backend logic
};

#endif // MAINWINDOW_H