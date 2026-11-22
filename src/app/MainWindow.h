#pragma once

#include <QMainWindow>

#include "model/PacketRecord.h"

class QComboBox;
class QLabel;
class QLineEdit;
class QModelIndex;
class QPlainTextEdit;
class QSortFilterProxyModel;
class QTableView;
class QTreeWidget;

namespace sss::ui {
class PacketTableModel;
}

namespace sss::app {

// Main window: packet list on top, protocol tree and hex dump below.
// This is the shell only; it is currently fed by synthesized demo frames.
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);

    int visiblePacketCount() const;
    int detailTopLevelCount() const;

    // Exercises the UI wiring without a display: fills the table, selects the
    // first row and checks that the detail tree and hex pane got populated.
    bool runSelfTest();

private slots:
    void onCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous);
    void onFilterChanged(const QString &text);
    void onClearTriggered();
    void onStartTriggered();
    void onAboutTriggered();

private:
    void createCentralWidget();
    void createToolBar();
    void createStatusBar();
    void loadDemoPackets();
    void showPacketDetail(const sss::model::PacketRecord &record);
    void showPacketHex(const sss::model::PacketRecord &record);

    sss::ui::PacketTableModel *m_model = nullptr;
    QSortFilterProxyModel *m_proxy = nullptr;
    QTableView *m_table = nullptr;
    QTreeWidget *m_details = nullptr;
    QPlainTextEdit *m_hex = nullptr;
    QLineEdit *m_filter = nullptr;
    QComboBox *m_deviceSelector = nullptr;
    QLabel *m_demoBadge = nullptr;
};

} // namespace sss::app
