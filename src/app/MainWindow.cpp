#include "app/MainWindow.h"

#include <QAction>
#include <QCloseEvent>
#include <QComboBox>
#include <QCoreApplication>
#include <QFont>
#include <QFontDatabase>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QSizePolicy>
#include <QSplitter>
#include <QStatusBar>
#include <QStringList>
#include <QTableView>
#include <QTextCursor>
#include <QTimer>
#include <QToolBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <utility>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <shellapi.h>
#endif

#include "capture/DeviceEnumerator.h"
#include "filter/FilterExpression.h"
#include "model/SamplePackets.h"
#include "ui/PacketFilterProxyModel.h"
#include "ui/PacketTableModel.h"

namespace sss::app {
namespace {

// Classic 16-bytes-per-line dump with an ASCII gutter.
QString hexDump(const QByteArray &data)
{
    QString text;
    text.reserve(data.size() * 4);

    for (int offset = 0; offset < data.size(); offset += 16) {
        const QByteArray chunk = data.mid(offset, 16);
        QString hex;
        QString ascii;

        for (int i = 0; i < 16; ++i) {
            if (i < chunk.size()) {
                const uchar byte = static_cast<uchar>(chunk.at(i));
                hex += QString("%1").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
                hex += QLatin1Char(' ');
                ascii += (byte >= 0x20 && byte < 0x7F) ? QChar(byte) : QLatin1Char('.');
            } else {
                hex += QStringLiteral("   ");
                ascii += QLatin1Char(' ');
            }
            if (i == 7) {
                hex += QLatin1Char(' ');
            }
        }

        text += QString("%1  %2 |%3|\n")
                    .arg(offset, 8, 16, QLatin1Char('0'))
                    .arg(hex)
                    .arg(ascii);
    }
    return text;
}

void addDetailNodes(QTreeWidgetItem *parent, const QVector<sss::model::DetailNode> &nodes)
{
    for (const sss::model::DetailNode &node : nodes) {
        auto *item = new QTreeWidgetItem(parent);
        item->setText(0, node.name);
        item->setText(1, node.value);
        addDetailNodes(item, node.children);
    }
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("SSS Sniffer - Experiment 1A"));
    resize(1280, 820);

    m_model = new sss::ui::PacketTableModel(this);
    m_proxy = new sss::ui::PacketFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_capture = new sss::capture::CaptureThread(this);
    m_drainTimer = new QTimer(this);
    m_drainTimer->setInterval(100);
    m_filterDebounce = new QTimer(this);
    m_filterDebounce->setSingleShot(true);
    m_filterDebounce->setInterval(300);
    connect(m_filterDebounce, &QTimer::timeout, this, &MainWindow::onDisplayFilterCommitted);

    createCentralWidget();
    createToolBar();
    createStatusBar();

    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onCurrentRowChanged);
    connect(m_capture, &sss::capture::CaptureThread::captureFailed,
            this, &MainWindow::onCaptureFailed);
    connect(m_capture, &sss::capture::CaptureThread::captureStopped,
            this, &MainWindow::onCaptureStopped);
    connect(m_drainTimer, &QTimer::timeout, this, &MainWindow::pollCapture);

    loadDevices();
    updateCounters();

    if (sss::capture::CaptureThread::isElevated()) {
        statusBar()->showMessage(QStringLiteral("Ready"));
    } else {
        statusBar()->showMessage(
            QStringLiteral("Not elevated: press Elevate before starting a capture"));
    }
}

void MainWindow::createCentralWidget()
{
    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setShowGrid(false);
    m_table->verticalHeader()->setVisible(false);
    m_table->verticalHeader()->setDefaultSectionSize(22);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setHighlightSections(false);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnNo, 60);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnTime, 110);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnSource, 150);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnDestination, 150);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnProtocol, 70);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnLength, 70);

    m_details = new QTreeWidget(this);
    m_details->setColumnCount(2);
    m_details->setHeaderLabels({QStringLiteral("Field"), QStringLiteral("Value")});
    m_details->setAlternatingRowColors(true);
    m_details->setRootIsDecorated(true);
    m_details->header()->setStretchLastSection(true);

    m_hex = new QPlainTextEdit(this);
    m_hex->setReadOnly(true);
    m_hex->setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont monospace = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    monospace.setPointSize(10);
    m_hex->setFont(monospace);
    m_hex->setPlaceholderText(QStringLiteral("Select a packet to inspect its bytes"));

    auto *bottom = new QSplitter(Qt::Horizontal, this);
    bottom->addWidget(m_details);
    bottom->addWidget(m_hex);
    bottom->setStretchFactor(0, 3);
    bottom->setStretchFactor(1, 4);

    auto *root = new QSplitter(Qt::Vertical, this);
    root->addWidget(m_table);
    root->addWidget(bottom);
    root->setStretchFactor(0, 3);
    root->setStretchFactor(1, 2);

    setCentralWidget(root);
}

void MainWindow::createToolBar()
{
    QToolBar *toolBar = addToolBar(QStringLiteral("Main"));
    toolBar->setMovable(false);
    toolBar->setFloatable(false);

    m_startAction = toolBar->addAction(QStringLiteral("Start"));
    connect(m_startAction, &QAction::triggered, this, &MainWindow::onStartTriggered);

    m_stopAction = toolBar->addAction(QStringLiteral("Stop"));
    m_stopAction->setEnabled(false);
    connect(m_stopAction, &QAction::triggered, this, &MainWindow::onStopTriggered);

    QAction *clearAction = toolBar->addAction(QStringLiteral("Clear"));
    connect(clearAction, &QAction::triggered, this, &MainWindow::onClearTriggered);

    QAction *demoAction = toolBar->addAction(QStringLiteral("Demo"));
    connect(demoAction, &QAction::triggered, this, &MainWindow::onDemoTriggered);

    QAction *elevateAction = toolBar->addAction(QStringLiteral("Elevate"));
    elevateAction->setEnabled(!sss::capture::CaptureThread::isElevated());
    elevateAction->setToolTip(QStringLiteral("Restart the application with administrator rights"));
    connect(elevateAction, &QAction::triggered, this, &MainWindow::onElevateTriggered);

    QAction *aboutAction = toolBar->addAction(QStringLiteral("About"));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::onAboutTriggered);

    toolBar->addSeparator();
    toolBar->addWidget(new QLabel(QStringLiteral(" Device: "), this));
    m_deviceSelector = new QComboBox(this);
    m_deviceSelector->setMinimumWidth(380);
    toolBar->addWidget(m_deviceSelector);

    QAction *refreshAction = toolBar->addAction(QStringLiteral("Refresh"));
    refreshAction->setToolTip(QStringLiteral("Re-enumerate capture devices"));
    connect(refreshAction, &QAction::triggered, this, &MainWindow::onRefreshDevices);

    toolBar->addSeparator();
    toolBar->addWidget(new QLabel(QStringLiteral(" Filter: "), this));
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setPlaceholderText(QStringLiteral("BPF capture filter, e.g. tcp port 80 (empty = all)"));
    m_filterEdit->setMinimumWidth(320);
    m_filterEdit->setClearButtonEnabled(true);
    toolBar->addWidget(m_filterEdit);

    // Second row: display filter, evaluated over captured packets by the proxy.
    addToolBarBreak();
    QToolBar *filterBar = addToolBar(QStringLiteral("Display filter"));
    filterBar->setMovable(false);
    filterBar->setFloatable(false);

    filterBar->addWidget(new QLabel(QStringLiteral(" Display filter: "), this));
    m_displayFilterEdit = new QLineEdit(this);
    m_displayFilterEdit->setPlaceholderText(
        QStringLiteral("e.g. http and ip.src == 127.0.0.1 | tcp or udp | not icmp | len > 100"));
    m_displayFilterEdit->setClearButtonEnabled(true);
    m_displayFilterEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    filterBar->addWidget(m_displayFilterEdit);
    connect(m_displayFilterEdit, &QLineEdit::textEdited, this, &MainWindow::onDisplayFilterEdited);
    connect(m_displayFilterEdit, &QLineEdit::returnPressed, this, &MainWindow::onDisplayFilterCommitted);

    QAction *applyAction = filterBar->addAction(QStringLiteral("Apply"));
    connect(applyAction, &QAction::triggered, this, &MainWindow::onDisplayFilterCommitted);

    QAction *resetAction = filterBar->addAction(QStringLiteral("Reset"));
    connect(resetAction, &QAction::triggered, this, &MainWindow::onDisplayFilterCleared);
}

void MainWindow::createStatusBar()
{
    m_countLabel = new QLabel(QStringLiteral("0 packets"), this);
    statusBar()->addPermanentWidget(m_countLabel);

    m_privilegeLabel = new QLabel(this);
    if (sss::capture::CaptureThread::isElevated()) {
        m_privilegeLabel->setText(QStringLiteral(" ADMIN "));
        m_privilegeLabel->setStyleSheet(
            QStringLiteral("QLabel { background: #2E7D32; color: white; "
                           "border-radius: 3px; padding: 1px 6px; }"));
    } else {
        m_privilegeLabel->setText(QStringLiteral(" NOT ELEVATED "));
        m_privilegeLabel->setStyleSheet(
            QStringLiteral("QLabel { background: #C62828; color: white; "
                           "border-radius: 3px; padding: 1px 6px; }"));
    }
    statusBar()->addPermanentWidget(m_privilegeLabel);
}

void MainWindow::loadDevices()
{
    m_deviceSelector->clear();

    QString error;
    const QVector<sss::capture::DeviceInfo> devices = sss::capture::DeviceEnumerator::list(&error);

    for (const sss::capture::DeviceInfo &device : devices) {
        QString label = device.description.isEmpty() ? device.name : device.description;
        if (!device.addresses.isEmpty()) {
            label += QString(" - %1").arg(device.addresses.first());
        }
        if (device.loopback) {
            label = QStringLiteral("[loopback] ") + label;
        }
        m_deviceSelector->addItem(label, device.name);
    }

    if (devices.isEmpty()) {
        statusBar()->showMessage(error.isEmpty()
                                     ? QStringLiteral("No capture devices found")
                                     : QString("Device enumeration failed: %1").arg(error));
    }
}

void MainWindow::onRefreshDevices()
{
    loadDevices();
    statusBar()->showMessage(QString("Devices refreshed: %1 found").arg(m_deviceSelector->count()));
}

bool MainWindow::startCapture(const QString &deviceName, const QString &bpfFilter, QString *error)
{
    if (m_capture->isRunning()) {
        if (error != nullptr) {
            *error = QStringLiteral("capture is already running");
        }
        return false;
    }

    m_model->clear();
    m_details->clear();
    m_hex->clear();
    updateCounters();

    // Keep the device selector in sync when the caller (CLI test) picked a
    // device that is not the one currently shown in the combo box.
    const int comboIndex = m_deviceSelector->findData(deviceName);
    if (comboIndex >= 0) {
        m_deviceSelector->setCurrentIndex(comboIndex);
    }

    const bool started = m_capture->startCapture(deviceName, bpfFilter, error);
    if (!started) {
        return false;
    }

    m_drainTimer->start();
    m_startAction->setEnabled(false);
    m_stopAction->setEnabled(true);
    statusBar()->showMessage(bpfFilter.isEmpty()
                                 ? QString("Capturing on %1 ...").arg(deviceName)
                                 : QString("Capturing on %1 with filter \"%2\" ...").arg(deviceName, bpfFilter));
    return true;
}

void MainWindow::stopCapture()
{
    if (!m_capture->isRunning()) {
        return;
    }

    m_capture->stopCapture();
    m_drainTimer->stop();
    pollCapture();

    m_startAction->setEnabled(true);
    m_stopAction->setEnabled(false);
    updateCounters();
    statusBar()->showMessage(QString("Capture stopped: %1 packets").arg(m_model->rowCount()));
}

void MainWindow::pollCapture()
{
    const QVector<sss::model::PacketRecord> packets = m_capture->takePending(2000);
    if (packets.isEmpty()) {
        return;
    }

    QScrollBar *scrollBar = m_table->verticalScrollBar();
    const bool followTail = scrollBar->value() >= scrollBar->maximum() - 4;

    m_model->appendPackets(packets);
    if (followTail) {
        m_table->scrollToBottom();
    }
    // Show details for the first packet instead of an empty lower half.
    if (!m_table->currentIndex().isValid()) {
        m_table->selectRow(0);
    }
    updateCounters();
}

void MainWindow::onStartTriggered()
{
    if (m_capture->isRunning()) {
        return;
    }

    const QString device = m_deviceSelector->currentData().toString();
    if (device.isEmpty()) {
        statusBar()->showMessage(QStringLiteral("Select a capture device first"));
        return;
    }

    QString error;
    if (!startCapture(device, m_filterEdit->text().trimmed(), &error)) {
        statusBar()->showMessage(QString("Cannot start capture: %1").arg(error));
        if (!m_headless) {
            QMessageBox::warning(this, QStringLiteral("Capture"), error);
        }
    }
}

void MainWindow::onStopTriggered()
{
    stopCapture();
}

void MainWindow::onClearTriggered()
{
    if (m_capture->isRunning()) {
        stopCapture();
    }
    m_model->clear();
    m_details->clear();
    m_hex->clear();
    updateCounters();
    statusBar()->showMessage(QStringLiteral("Cleared"));
}

void MainWindow::onDemoTriggered()
{
    if (m_capture->isRunning()) {
        statusBar()->showMessage(QStringLiteral("Stop the capture before loading demo data"));
        return;
    }
    loadDemoPackets();
}

void MainWindow::loadDemoPackets()
{
    m_model->setPackets(sss::model::makeSamplePackets());
    m_details->clear();
    m_hex->clear();

    if (m_proxy->rowCount() > 0) {
        m_table->selectRow(0);
    }
    updateCounters();
    statusBar()->showMessage(QString("Demo data loaded: %1 synthetic packets").arg(m_model->rowCount()));
}

void MainWindow::onElevateTriggered()
{
#ifdef _WIN32
    const QString executable = QCoreApplication::applicationFilePath();
    const std::wstring path = executable.toStdWString();
    const HINSTANCE result = ::ShellExecuteW(nullptr, L"runas", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    if (reinterpret_cast<qintptr>(result) > 32) {
        QCoreApplication::quit();
    } else {
        statusBar()->showMessage(QStringLiteral("Elevation was cancelled"));
    }
#endif
}

void MainWindow::onAboutTriggered()
{
    QMessageBox::about(this,
                       QStringLiteral("About SSS Sniffer"),
                       QStringLiteral("<b>SSS Sniffer 0.1</b><br/>"
                                      "Software and System Security - Experiment 1A<br/>"
                                      "A Qt based packet sniffer built on the Npcap API."));
}

void MainWindow::onCaptureFailed(const QString &message)
{
    m_drainTimer->stop();
    m_startAction->setEnabled(true);
    m_stopAction->setEnabled(false);
    updateCounters();
    statusBar()->showMessage(QString("Capture failed: %1").arg(message));

    if (m_headless) {
        return;
    }

    QString text = message;
    if (!sss::capture::CaptureThread::isElevated()) {
        text += QStringLiteral("\n\nNpcap requires administrator privileges. "
                               "Use the Elevate button to restart the application elevated.");
    }
    QMessageBox::warning(this, QStringLiteral("Capture failed"), text);
}

void MainWindow::onCaptureStopped()
{
    if (!m_capture->isRunning()) {
        m_drainTimer->stop();
        pollCapture();
        m_startAction->setEnabled(true);
        m_stopAction->setEnabled(false);
        updateCounters();
    }
}

void MainWindow::onCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous)
{
    Q_UNUSED(previous);
    if (!current.isValid()) {
        return;
    }

    const QModelIndex sourceIndex = m_proxy->mapToSource(current);
    const sss::model::PacketRecord *record = m_model->packetAt(sourceIndex.row());
    if (record == nullptr) {
        return;
    }

    showPacketDetail(*record);
    showPacketHex(*record);
}

void MainWindow::showPacketDetail(const sss::model::PacketRecord &record)
{
    m_details->clear();
    addDetailNodes(m_details->invisibleRootItem(), record.details);
    m_details->expandAll();
    m_details->resizeColumnToContents(0);
}

void MainWindow::showPacketHex(const sss::model::PacketRecord &record)
{
    m_hex->setPlainText(hexDump(record.raw));
    m_hex->moveCursor(QTextCursor::Start);
}

void MainWindow::updateCounters()
{
    const sss::capture::CaptureStats stats = m_capture->stats();

    QString text = QString("%1 packets").arg(m_model->rowCount());
    if (m_proxy->hasExpression()) {
        text += QString(" | showing %1").arg(m_proxy->rowCount());
    }
    if (stats.dropped > 0 || stats.interfaceDropped > 0) {
        text += QString(" | dropped %1").arg(stats.dropped + stats.interfaceDropped);
    }
    if (stats.queueDropped > 0) {
        text += QString(" | queue drops %1").arg(stats.queueDropped);
    }
    m_countLabel->setText(text);
}

void MainWindow::setHeadless(bool headless)
{
    m_headless = headless;
}

int MainWindow::packetCount() const
{
    return m_model->rowCount();
}

bool MainWindow::applyDisplayFilter(const QString &text)
{
    QString error;
    sss::filter::FilterExpression expression = sss::filter::FilterExpression::parse(text, &error);
    if (!error.isEmpty()) {
        m_displayFilterEdit->setStyleSheet(QStringLiteral("QLineEdit { border: 1px solid #C62828; }"));
        statusBar()->showMessage(QString("Invalid filter: %1").arg(error));
        return false;
    }

    m_displayFilterEdit->setStyleSheet(QString());
    const bool empty = expression.isEmpty();
    m_proxy->setExpression(std::move(expression));
    updateCounters();

    if (empty) {
        statusBar()->showMessage(QStringLiteral("Display filter cleared"));
    } else {
        statusBar()->showMessage(QString("Filter \"%1\": %2 of %3 packets")
                                     .arg(text.trimmed())
                                     .arg(m_proxy->rowCount())
                                     .arg(m_model->rowCount()));
    }
    return true;
}

void MainWindow::onDisplayFilterEdited(const QString &text)
{
    Q_UNUSED(text);
    m_filterDebounce->start();
}

bool MainWindow::setDisplayFilter(const QString &text)
{
    m_displayFilterEdit->setText(text);
    return applyDisplayFilter(text);
}

int MainWindow::visiblePacketCount() const
{
    return m_proxy->rowCount();
}

void MainWindow::onDisplayFilterCommitted()
{
    m_filterDebounce->stop();
    applyDisplayFilter(m_displayFilterEdit->text());
}

void MainWindow::onDisplayFilterCleared()
{
    m_filterDebounce->stop();
    m_displayFilterEdit->clear();
    applyDisplayFilter(QString());
}

int MainWindow::detailTopLevelCount() const
{
    return m_details->topLevelItemCount();
}

// "HTTP=4,TCP=20,ICMP=29" - lets the CLI report prove what was recognized
// without a human looking at the table.
QString MainWindow::protocolSummary() const
{
    QMap<QString, int> counts;
    for (int row = 0; row < m_model->rowCount(); ++row) {
        const sss::model::PacketRecord *record = m_model->packetAt(row);
        if (record != nullptr) {
            counts[record->protocol] += 1;
        }
    }

    QStringList parts;
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it) {
        parts << QString("%1=%2").arg(it.key()).arg(it.value());
    }
    return parts.join(QLatin1Char(','));
}

// Used by the CLI report to bring a representative packet into view.
bool MainWindow::selectFirstPacketWithProtocol(const QString &protocol)
{
    for (int row = 0; row < m_model->rowCount(); ++row) {
        const sss::model::PacketRecord *record = m_model->packetAt(row);
        if (record != nullptr && record->protocol == protocol) {
            const QModelIndex proxyIndex = m_proxy->mapFromSource(m_model->index(row, 0));
            if (proxyIndex.isValid()) {
                m_table->selectRow(proxyIndex.row());
                m_table->scrollTo(proxyIndex);
                return true;
            }
            return false;
        }
    }
    return false;
}

sss::capture::CaptureStats MainWindow::captureStats() const
{
    return m_capture->stats();
}

bool MainWindow::runSelfTest()
{
    setHeadless(true);

    loadDemoPackets();
    QCoreApplication::processEvents();

    if (m_model->rowCount() == 0) {
        return false;
    }

    m_table->selectRow(0);
    QCoreApplication::processEvents();

    if (m_details->topLevelItemCount() == 0) {
        return false;
    }
    if (m_hex->toPlainText().isEmpty()) {
        return false;
    }

    // Device enumeration must work without elevation.
    return m_deviceSelector->count() > 0;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    stopCapture();
    QMainWindow::closeEvent(event);
}

} // namespace sss::app
