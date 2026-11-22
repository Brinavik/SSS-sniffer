#include "ui/PacketTableModel.h"

#include <utility>

namespace sss::ui {

PacketTableModel::PacketTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void PacketTableModel::setPackets(QVector<sss::model::PacketRecord> packets)
{
    beginResetModel();
    m_packets = std::move(packets);
    endResetModel();
}

void PacketTableModel::clear()
{
    setPackets({});
}

const sss::model::PacketRecord *PacketTableModel::packetAt(int row) const
{
    if (row < 0 || row >= m_packets.size()) {
        return nullptr;
    }
    return &m_packets.at(row);
}

int PacketTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return m_packets.size();
}

int PacketTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return ColumnCount;
}

QVariant PacketTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_packets.size()) {
        return {};
    }

    const sss::model::PacketRecord &packet = m_packets.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ColumnNo:
            return QVariant::fromValue(packet.index);
        case ColumnTime:
            return packet.timestamp.toString(QStringLiteral("HH:mm:ss.zzz"));
        case ColumnSource:
            return packet.source;
        case ColumnDestination:
            return packet.destination;
        case ColumnProtocol:
            return packet.protocol;
        case ColumnLength:
            return packet.length;
        case ColumnInfo:
            return packet.info;
        default:
            break;
        }
    } else if (role == Qt::TextAlignmentRole) {
        if (index.column() == ColumnNo || index.column() == ColumnLength) {
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        }
        return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
    } else if (role == Qt::ToolTipRole) {
        return packet.info;
    }

    return {};
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
        return {};
    }

    switch (section) {
    case ColumnNo:
        return QStringLiteral("序号");
    case ColumnTime:
        return QStringLiteral("时间");
    case ColumnSource:
        return QStringLiteral("源地址");
    case ColumnDestination:
        return QStringLiteral("目的地址");
    case ColumnProtocol:
        return QStringLiteral("协议");
    case ColumnLength:
        return QStringLiteral("长度");
    case ColumnInfo:
        return QStringLiteral("信息");
    default:
        return {};
    }
}

} // namespace sss::ui
