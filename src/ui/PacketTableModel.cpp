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

void PacketTableModel::appendPackets(const QVector<sss::model::PacketRecord> &packets)
{
    if (packets.isEmpty()) {
        return;
    }

    const int first = static_cast<int>(m_packets.size());
    const int last = first + static_cast<int>(packets.size()) - 1;
    beginInsertRows(QModelIndex(), first, last);
    m_packets += packets;
    endInsertRows();
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
    return static_cast<int>(m_packets.size());
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
        return QStringLiteral("No.");
    case ColumnTime:
        return QStringLiteral("Time");
    case ColumnSource:
        return QStringLiteral("Source");
    case ColumnDestination:
        return QStringLiteral("Destination");
    case ColumnProtocol:
        return QStringLiteral("Protocol");
    case ColumnLength:
        return QStringLiteral("Length");
    case ColumnInfo:
        return QStringLiteral("Info");
    default:
        return {};
    }
}

} // namespace sss::ui
