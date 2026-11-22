#include "app/MainWindow.h"

#include <QAction>
#include <QComboBox>
#include <QCoreApplication>
#include <QFont>
#include <QFontDatabase>
#include <QItemSelectionModel>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStatusBar>
#include <QTableView>
#include <QTextCursor>
#include <QToolBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "model/SamplePackets.h"
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
    setWindowTitle(QStringLiteral("SSS Sniffer \u2014 实验 1A  [示例数据]"));
    resize(1280, 820);

    m_model = new sss::ui::PacketTableModel(this);
    m_proxy = new QSortFilterProxyModel(this);
    m_proxy->setSourceModel(m_model);
    m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_proxy->setFilterKeyColumn(-1); // match any visible column

    createCentralWidget();
    createToolBar();
    createStatusBar();

    connect(m_table->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onCurrentRowChanged);

    loadDemoPackets();
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
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnNo, 64);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnTime, 120);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnSource, 140);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnDestination, 140);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnProtocol, 80);
    m_table->setColumnWidth(sss::ui::PacketTableModel::ColumnLength, 70);

    m_details = new QTreeWidget(this);
    m_details->setColumnCount(2);
    m_details->setHeaderLabels({QStringLiteral("字段"), QStringLiteral("值")});
    m_details->setAlternatingRowColors(true);
    m_details->setRootIsDecorated(true);
    m_details->header()->setStretchLastSection(true);

    m_hex = new QPlainTextEdit(this);
    m_hex->setReadOnly(true);
    m_hex->setLineWrapMode(QPlainTextEdit::NoWrap);
    QFont monospace = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    monospace.setPointSize(10);
    m_hex->setFont(monospace);
    m_hex->setPlaceholderText(QStringLiteral("选中一个数据包后显示原始字节"));

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
    QToolBar *toolBar = addToolBar(QStringLiteral("工具栏"));
    toolBar->setMovable(false);
    toolBar->setFloatable(false);

    QAction *startAction = toolBar->addAction(QStringLiteral("开始"));
    connect(startAction, &QAction::triggered, this, &MainWindow::onStartTriggered);

    QAction *stopAction = toolBar->addAction(QStringLiteral("停止"));
    stopAction->setEnabled(false);

    QAction *clearAction = toolBar->addAction(QStringLiteral("清空"));
    connect(clearAction, &QAction::triggered, this, &MainWindow::onClearTriggered);

    QAction *aboutAction = toolBar->addAction(QStringLiteral("关于"));
    connect(aboutAction, &QAction::triggered, this, &MainWindow::onAboutTriggered);

    toolBar->addSeparator();
    toolBar->addWidget(new QLabel(QStringLiteral(" 网卡: "), this));
    m_deviceSelector = new QComboBox(this);
    m_deviceSelector->addItem(QStringLiteral("（capture 模块待接入）"));
    m_deviceSelector->setMinimumWidth(280);
    m_deviceSelector->setEnabled(false);
    toolBar->addWidget(m_deviceSelector);

    toolBar->addSeparator();
    toolBar->addWidget(new QLabel(QStringLiteral(" 过滤: "), this));
    m_filter = new QLineEdit(this);
    m_filter->setPlaceholderText(QStringLiteral("输入 IP / 端口 / 协议关键字（简易文本过滤）"));
    m_filter->setMinimumWidth(340);
    m_filter->setClearButtonEnabled(true);
    toolBar->addWidget(m_filter);

    connect(m_filter, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);
}

void MainWindow::createStatusBar()
{
    m_demoBadge = new QLabel(QStringLiteral(" DEMO 示例数据 "), this);
    m_demoBadge->setStyleSheet(
        QStringLiteral("QLabel { background: #F5A623; color: #1B1B1B; "
                       "border-radius: 3px; padding: 1px 6px; }"));
    statusBar()->addPermanentWidget(m_demoBadge);
    statusBar()->showMessage(QStringLiteral("就绪"));
}

void MainWindow::loadDemoPackets()
{
    m_model->setPackets(sss::model::makeSamplePackets());
    m_details->clear();
    m_hex->clear();

    if (m_proxy->rowCount() > 0) {
        m_table->selectRow(0);
    }

    statusBar()->showMessage(
        QStringLiteral("已载入 %1 个示例数据包（尚未接入抓包）").arg(m_model->rowCount()));
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

void MainWindow::onFilterChanged(const QString &text)
{
    m_proxy->setFilterFixedString(text);
    statusBar()->showMessage(
        QStringLiteral("过滤 \"%1\" 命中 %2 条（简易文本过滤，协议/BPF 过滤待接入）")
            .arg(text, QString::number(m_proxy->rowCount())));
}

void MainWindow::onClearTriggered()
{
    m_model->clear();
    m_details->clear();
    m_hex->clear();
    statusBar()->showMessage(QStringLiteral("已清空列表"));
}

void MainWindow::onStartTriggered()
{
    statusBar()->showMessage(
        QStringLiteral("抓包尚未接入：下一步接入 Npcap 网卡枚举与抓包线程"));
}

void MainWindow::onAboutTriggered()
{
    QMessageBox::about(this, QStringLiteral("关于 SSS Sniffer"),
                       QStringLiteral("<b>SSS Sniffer 0.1</b><br/>"
                                      "软件与系统安全 实验 1A：带 GUI 的网络嗅探器<br/>"
                                      "当前界面使用示例数据，尚未接入 Npcap。"));
}

int MainWindow::visiblePacketCount() const
{
    return m_proxy->rowCount();
}

int MainWindow::detailTopLevelCount() const
{
    return m_details->topLevelItemCount();
}

bool MainWindow::runSelfTest()
{
    if (m_model->rowCount() == 0) {
        return false;
    }
    if (m_proxy->rowCount() != m_model->rowCount()) {
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

    m_filter->setText(QStringLiteral("ICMP"));
    QCoreApplication::processEvents();
    const int icmpRows = m_proxy->rowCount();
    m_filter->clear();
    QCoreApplication::processEvents();

    return icmpRows > 0 && icmpRows < m_model->rowCount();
}

} // namespace sss::app
