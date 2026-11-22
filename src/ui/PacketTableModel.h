#pragma once

#include <QAbstractTableModel>
#include <QVector>

#include "model/PacketRecord.h"

namespace sss::ui {

// Read-only table model over PacketRecord. The table view never owns packets;
// it only renders whatever the model was handed.
class PacketTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    enum Column {
        ColumnNo = 0,
        ColumnTime,
        ColumnSource,
        ColumnDestination,
        ColumnProtocol,
        ColumnLength,
        ColumnInfo,
        ColumnCount
    };

    explicit PacketTableModel(QObject *parent = nullptr);

    void setPackets(QVector<sss::model::PacketRecord> packets);
    void clear();

    const sss::model::PacketRecord *packetAt(int row) const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation,
                        int role = Qt::DisplayRole) const override;

private:
    QVector<sss::model::PacketRecord> m_packets;
};

} // namespace sss::ui
