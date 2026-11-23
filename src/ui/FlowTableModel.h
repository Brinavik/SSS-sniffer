#pragma once

#include <QAbstractTableModel>
#include <QVector>

#include "flow/TcpFlowTracker.h"

namespace sss::ui {

// Table of TCP conversations shown in the flow dock.
class FlowTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        ColumnIndex = 0,
        ColumnClient,
        ColumnServer,
        ColumnProcess,
        ColumnPid,
        ColumnPackets,
        ColumnBytes,
        ColumnDuration,
        ColumnState,
        ColumnCount
    };

    explicit FlowTableModel(QObject *parent = nullptr);

    // Keeps the selection when only counters changed (same number of flows).
    void setFlows(QVector<sss::flow::TcpFlow> flows);
    void clear();

    const sss::flow::TcpFlow *flowAt(int row) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

private:
    QVector<sss::flow::TcpFlow> m_flows;
};

} // namespace sss::ui
