// tools/env_smoke/qt_smoke.cpp
// Qt 6 Widgets probe: headers, linking, runtime libraries and platform plugin.
// Run with QT_QPA_PLATFORM=offscreen for a headless, scriptable check.

#include <QApplication>
#include <QDebug>
#include <QGuiApplication>
#include <QLabel>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    qInfo().noquote() << "Qt runtime version:" << qVersion();
    qInfo().noquote() << "Compiled against   :" << QT_VERSION_STR;
    qInfo().noquote() << "Platform plugin    :" << QGuiApplication::platformName();

    QLabel label(QStringLiteral("Qt Widgets OK"));
    label.resize(320, 120);
    label.show();
    qInfo().noquote() << "QLabel size        :" << label.size();

    qInfo().noquote() << "RESULT: PASS (Qt Widgets is usable)";
    return 0;
}
