#pragma once

#include <QMainWindow>
#include <QModelIndex>

#include "capture/CaptureThread.h"
#include "model/PacketRecord.h"

class QAction;
class QCloseEvent;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QTableView;
class QTimer;
class QTreeWidget;

namespace sss::ui {
class PacketFilterProxyModel;
class PacketTableModel;
}

namespace sss::app {

// Main window: packet list on top, protocol tree and hex dump below.
// Packets come either from the live capture thread or from the demo generator.
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

    // Same code path the toolbar uses; also driven by the CLI self tests.
    bool startCapture(const QString &deviceName, const QString &bpfFilter, QString *error);
    void stopCapture();
    void pollCapture();
    void setHeadless(bool headless);

    // Parses and applies a display filter. Returns false and keeps the previous
    // filter when the expression is invalid (error text goes to the status bar).
    bool applyDisplayFilter(const QString &text);
    bool setDisplayFilter(const QString &text);
    int visiblePacketCount() const;

    int packetCount() const;
    int detailTopLevelCount() const;
    QString protocolSummary() const;
    bool selectFirstPacketWithProtocol(const QString &protocol);
    sss::capture::CaptureStats captureStats() const;

    bool runSelfTest();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous);
    void onStartTriggered();
    void onStopTriggered();
    void onClearTriggered();
    void onDemoTriggered();
    void onElevateTriggered();
    void onAboutTriggered();
    void onRefreshDevices();
    void onCaptureFailed(const QString &message);
    void onCaptureStopped();
    void onDisplayFilterEdited(const QString &text);
    void onDisplayFilterCommitted();
    void onDisplayFilterCleared();

private:
    void createCentralWidget();
    void createToolBar();
    void createStatusBar();
    void loadDevices();
    void loadDemoPackets();
    void showPacketDetail(const sss::model::PacketRecord &record);
    void showPacketHex(const sss::model::PacketRecord &record);
    void updateCounters();

    sss::ui::PacketTableModel *m_model = nullptr;
    sss::ui::PacketFilterProxyModel *m_proxy = nullptr;
    QTableView *m_table = nullptr;
    QTreeWidget *m_details = nullptr;
    QPlainTextEdit *m_hex = nullptr;
    QLineEdit *m_filterEdit = nullptr;
    QLineEdit *m_displayFilterEdit = nullptr;
    QComboBox *m_deviceSelector = nullptr;
    QLabel *m_countLabel = nullptr;
    QLabel *m_privilegeLabel = nullptr;
    QAction *m_startAction = nullptr;
    QAction *m_stopAction = nullptr;
    sss::capture::CaptureThread *m_capture = nullptr;
    QTimer *m_drainTimer = nullptr;
    QTimer *m_filterDebounce = nullptr;
    bool m_headless = false;
};

} // namespace sss::app
