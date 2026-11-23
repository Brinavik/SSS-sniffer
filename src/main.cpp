// SSS Sniffer - experiment 1A entry point.
//
//   sss_sniffer                      start the GUI
//   sss_sniffer --selftest           headless UI check, exit code 0/1
//   sss_sniffer --capture-test PATH  capture 7 s on the loopback device, write a
//                                    report to PATH plus PATH.png, exit 0 when
//                                    packets arrived
//   sss_sniffer --screenshot PATH    render the window to a PNG and exit

#include <QApplication>
#include <QFile>
#include <QProcess>
#include <QPixmap>
#include <QTextStream>
#include <QTimer>

#include <cstdio>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#endif

#include "app/MainWindow.h"
#include "capture/CaptureThread.h"
#include "capture/DeviceEnumerator.h"

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

bool writeReport(const QString &path, const QStringList &lines)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    QTextStream stream(&file);
    for (const QString &line : lines) {
        stream << line << '\n';
    }
    stream.flush();
    return true;
}

QString pickLoopbackDevice(QString *error)
{
    const QVector<sss::capture::DeviceInfo> devices = sss::capture::DeviceEnumerator::list(error);
    for (const sss::capture::DeviceInfo &device : devices) {
        if (device.loopback) {
            return device.name;
        }
    }
    return devices.isEmpty() ? QString() : devices.first().name;
}

} // namespace

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("SSS Sniffer"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.2.0"));
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
                        window.packetCount(),
                        window.detailTopLevelCount());
            std::fflush(stdout);
            QCoreApplication::exit(ok ? 0 : 1);
        });
    } else if (arguments.contains(QStringLiteral("--capture-test"))) {
        window.setHeadless(true);

        const int index = arguments.indexOf(QStringLiteral("--capture-test"));
        const QString reportPath = (index + 1 < arguments.size())
                                       ? arguments.at(index + 1)
                                       : QStringLiteral("capture-test.txt");

        // Optional second argument: the BPF filter (defaults to "ip").
        // An IPv6 filter also switches the traffic generator to ping ::1.
        const QString filter = (index + 2 < arguments.size())
                                   ? arguments.at(index + 2)
                                   : QStringLiteral("ip");
        const bool ipv6 = filter.contains(QLatin1Char('6'));
        // Optional third argument: a display filter applied before the capture
        // screenshot, so the filtered view can be verified automatically.
        const QString displayFilter = (index + 3 < arguments.size())
                                          ? arguments.at(index + 3)
                                          : QString();

        QString enumerationError;
        const QString device = pickLoopbackDevice(&enumerationError);

        QString startError;
        const bool started = window.startCapture(device, filter, &startError);

        // Ping the loopback interface so there is guaranteed traffic to capture.
        QTimer::singleShot(200, &app, [ipv6]() {
            QStringList pingArguments;
            if (ipv6) {
                pingArguments << QStringLiteral("-6") << QStringLiteral("-n")
                              << QStringLiteral("8") << QStringLiteral("::1");
            } else {
                pingArguments << QStringLiteral("-n") << QStringLiteral("8")
                              << QStringLiteral("127.0.0.1");
            }
            QProcess::startDetached(QStringLiteral("ping.exe"), pingArguments);
        });

        QTimer::singleShot(7000, &app, [&app, &window, reportPath, device, filter, displayFilter, started, startError, enumerationError]() {
            window.stopCapture();
            window.pollCapture();

            const bool filterApplied =
                displayFilter.isEmpty() ? true : window.setDisplayFilter(displayFilter);

            // Follow the busiest TCP conversation so the screenshot shows the
            // flow restriction working, not just the filter.
            const bool followed = window.followLargestFlow();
            const int flows = window.flowCount();

            // Snapshot the capture numbers before demo data replaces them.
            const int capturedRows = window.packetCount();
            const int capturedVisible = window.visiblePacketCount();
            const QString protocols = window.protocolSummary();

            const QString pngPath = reportPath + QStringLiteral(".png");
            if (!window.selectFirstPacketWithProtocol(QStringLiteral("HTTP"))) {
                window.selectFirstPacketWithProtocol(QStringLiteral("TCP"));
            }
            window.grab().save(pngPath, "PNG");

            // Regression check: after following a flow, switching to demo data
            // must clear the flow filter and show every demo packet.
            window.loadDemoPackets();
            const int demoRows = window.packetCount();
            const int demoVisible = window.visiblePacketCount();

            const sss::capture::CaptureStats stats = window.captureStats();
            const bool ok = (capturedRows > 0);

            writeReport(reportPath,
                        QStringList()
                            << QString("device=%1").arg(device)
                            << QString("filter=%1").arg(filter)
                            << QString("started=%1").arg(started ? "yes" : "no")
                            << QString("start_error=%1").arg(startError)
                            << QString("enumeration_error=%1").arg(enumerationError)
                            << QString("elevated=%1").arg(sss::capture::CaptureThread::isElevated() ? "yes" : "no")
                            << QString("rows=%1").arg(capturedRows)
                            << QString("protocols=%1").arg(protocols)
                            << QString("tcp_flows=%1").arg(flows)
                            << QString("followed_largest_flow=%1").arg(followed ? "yes" : "no")
                            << QString("display_filter=%1").arg(displayFilter)
                            << QString("filter_applied=%1").arg(filterApplied ? "yes" : "no")
                            << QString("visible=%1").arg(capturedVisible)
                            << QString("demo_rows=%1").arg(demoRows)
                            << QString("demo_visible=%1").arg(demoVisible)
                            << QString("received=%1").arg(stats.received)
                            << QString("dropped=%1").arg(stats.dropped)
                            << QString("queue_dropped=%1").arg(stats.queueDropped)
                            << QString("png=%1").arg(pngPath)
                            << QString("result=%1").arg(ok ? "PASS" : "FAIL"));

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
