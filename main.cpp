#include "mainwindow.h"
#include <QApplication>
#include <QFile>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Load the global stylesheet
    QFile styleFile(":/styles.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        QString styleSheet = QLatin1String(styleFile.readAll());
        a.setStyleSheet(styleSheet);
        styleFile.close();
    } else {
        qWarning("Could not open stylesheet file ':/styles.qss'. Make sure it's in your res.qrc file.");
    }

    MainWindow w;
    w.show();
    return a.exec();
}