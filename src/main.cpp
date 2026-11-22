// SSS Sniffer - experiment 1A entry point.
//
//   sss_sniffer                      start the GUI
//   sss_sniffer --selftest           headless check: fill the panes, print a
//                                    one-line result and exit with 0/1
//   sss_sniffer --screenshot <path>  render the window to a PNG and exit
//                                    (used for report figures)

#include <QApplication>
#include <QPixmap>
#include <QTimer>

#include <cstdio>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include "app/MainWindow.h"

namespace {

// The executable is linked as a GUI subsystem binary, so there is no console by
// default. When launched from a terminal, borrow the parent's console so the
// self-test line is still visible.
void attachParentConsole()
{
#ifdef _WIN32
    if (::AttachConsole(ATTACH_PARENT_PROCESS) != 0) {
        FILE *stream = nullptr;
        freopen_s(&stream, "CONOUT$", "w", stdout);
        freopen_s(&stream, "CONOUT$", "w", stderr);
    }
#endif
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("SSS Sniffer"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    QCoreApplication::setOrganizationName(QStringLiteral("UCAS SSS Lab"));

    sss::app::MainWindow window;
    window.show();

    const QStringList arguments = QApplication::arguments();

    if (arguments.contains(QStringLiteral("--selftest"))) {
        attachParentConsole();
        QTimer::singleShot(300, &app, [&window]() {
            const bool ok = window.runSelfTest();
            std::printf("SELFTEST: %s (rows=%d, details=%d)\n",
                        ok ? "PASS" : "FAIL",
                        window.visiblePacketCount(),
                        window.detailTopLevelCount());
            std::fflush(stdout);
            QCoreApplication::exit(ok ? 0 : 1);
        });
    } else {
        const int screenshotIndex = arguments.indexOf(QStringLiteral("--screenshot"));
        if (screenshotIndex > 0 && screenshotIndex + 1 < arguments.size()) {
            const QString path = arguments.at(screenshotIndex + 1);
            QTimer::singleShot(600, &app, [&window, path]() {
                const bool ok = window.grab().save(path, "PNG");
                QCoreApplication::exit(ok ? 0 : 1);
            });
        }
    }

    return app.exec();
}
