#pragma once

#include <QElapsedTimer>
#include <QHash>
#include <QMainWindow>
#include <QModelIndex>

#include "capture/CaptureThread.h"
#include "capture/DeviceEnumerator.h"
#include "flow/ProcessResolver.h"
#include "flow/TcpFlowTracker.h"
#include "model/PacketRecord.h"

class QAction;
class QCloseEvent;
class QComboBox;
class QDockWidget;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QTableView;
class QThread;
class QTimer;
class QTreeWidget;

namespace sss::ui {
class FlowTableModel;
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
    ~MainWindow() override;

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

    // Also used by the CLI regression check: load demo data after a capture.
    void loadDemoPackets();

    int packetCount() const;
    int detailTopLevelCount() const;
    int flowCount() const;
    int attributedFlowCount() const;
    QString protocolSummary() const;
    bool selectFirstPacketWithProtocol(const QString &protocol);
    bool followFlow(int flowIndex);
    bool followLargestFlow();
    QString followedFlowProcess() const;
    void clearFlowFilter();
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
    void onFlowActivated(const QModelIndex &index);
    void onStopFollowing();

private:
    void createCentralWidget();
    void createToolBar();
    void createStatusBar();
    void createFlowDock();
    void refreshFlows();
    void resetDataset();
    void resolveProcessForPacket(const sss::model::PacketRecord &packet);
    void applyProcess(const sss::flow::TcpFlowKey &key, quint32 pid);
    void retryPendingProcesses();
    void loadDevices();
    void loadDevicesAsync();
    void applyDevices(const QVector<sss::capture::DeviceInfo> &devices, const QString &error);
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
    QThread *m_deviceThread = nullptr;
    bool m_deviceLoading = false;

    sss::flow::TcpFlowTracker *m_flows = nullptr;
    sss::flow::ProcessResolver m_processResolver;
    QHash<sss::flow::TcpFlowKey, int> m_unresolvedProcesses;
    QElapsedTimer m_processClock;
    sss::ui::FlowTableModel *m_flowModel = nullptr;
    QTableView *m_flowTable = nullptr;
    QDockWidget *m_flowDock = nullptr;
    int m_flowRefreshTick = 0;
    int m_followedFlowIndex = -1;

    bool m_headless = false;
};

} // namespace sss::app
