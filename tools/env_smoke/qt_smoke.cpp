// tools/env_smoke/qt_smoke.cpp
// Qt 6 Widgets 验收程序：验证头文件、链接、运行库、平台插件都正常。
// 建议以 QT_QPA_PLATFORM=offscreen 运行，不弹窗、可脚本化。

#include <QApplication>
#include <QDebug>
#include <QLabel>
#include <QGuiApplication>

int main(int argc, char **argv)
{
    QApplication app(argc, argv);

    qInfo().noquote() << "Qt 运行库版本 :" << qVersion();
    qInfo().noquote() << "编译时版本    :" << QT_VERSION_STR;
    qInfo().noquote() << "平台插件      :" << QGuiApplication::platformName();

    QLabel label(QStringLiteral("Qt Widgets OK"));
    label.resize(320, 120);
    label.show();
    qInfo().noquote() << "QLabel 尺寸   :" << label.size();

    qInfo().noquote() << "RESULT: PASS (Qt Widgets 可用)";
    return 0;
}
