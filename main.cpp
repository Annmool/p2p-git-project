#include "mainwindow.h"
#include <QApplication>
#include <QFile> // Add this include

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Load the stylesheet
    QFile styleFile(":/styles.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        a.setStyleSheet(styleSheet);
        styleFile.close();
    } else {
        qWarning("Could not open stylesheet file");
    }

    MainWindow w;
    w.show();
    return a.exec();
}