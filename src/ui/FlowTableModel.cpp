#include "ui/FlowTableModel.h"

#include <utility>

namespace sss::ui {
namespace {

QString durationText(qint64 milliseconds)
{
    if (milliseconds < 1000) {
        return QString("%1 ms").arg(milliseconds);
    }
    return QString("%1 s").arg(milliseconds / 1000.0, 0, 'f', 2);
}

} // namespace

FlowTableModel::FlowTableModel(QObject *parent)
    : QAbstractTableModel(parent)
{
}

void FlowTableModel::setFlows(QVector<sss::flow::TcpFlow> flows)
{
    if (flows.size() == m_flows.size()) {
        m_flows = std::move(flows);
        if (!m_flows.isEmpty()) {
            emit dataChanged(index(0, 0), index(static_cast<int>(m_flows.size()) - 1, ColumnCount - 1));
        }
        return;
    }

    beginResetModel();
    m_flows = std::move(flows);
    endResetModel();
}

void FlowTableModel::clear()
{
    beginResetModel();
    m_flows.clear();
    endResetModel();
}

const sss::flow::TcpFlow *FlowTableModel::flowAt(int row) const
{
    if (row < 0 || row >= m_flows.size()) {
        return nullptr;
    }
    return &m_flows.at(row);
}

int FlowTableModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return static_cast<int>(m_flows.size());
}

int FlowTableModel::columnCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return ColumnCount;
}

QVariant FlowTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_flows.size()) {
        return {};
    }

    const sss::flow::TcpFlow &flow = m_flows.at(index.row());

    if (role == Qt::DisplayRole) {
        switch (index.column()) {
        case ColumnIndex:
            return index.row() + 1;
        case ColumnClient:
            return flow.initiatorText();
        case ColumnServer:
            return flow.responderText();
        case ColumnPackets:
            return QVariant::fromValue(flow.packetCount());
        case ColumnBytes:
            return QVariant::fromValue(flow.byteCount());
        case ColumnDuration:
            return durationText(flow.durationMs());
        case ColumnState:
            return flow.stateText();
        default:
            break;
        }
    } else if (role == Qt::TextAlignmentRole) {
        switch (index.column()) {
        case ColumnIndex:
        case ColumnPackets:
        case ColumnBytes:
        case ColumnDuration:
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        default:
            return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
        }
    } else if (role == Qt::ToolTipRole) {
        return QString("Endpoint A: %1\nEndpoint B: %2\n"
                       "Endpoint A is the side that sent the first captured packet "
                       "(the SYN sender when the handshake was captured).\n"
                       "packets: %3\nbytes: %4\nstate: %5")
            .arg(flow.initiatorText(),
                 flow.responderText(),
                 QString::number(flow.packetCount()),
                 QString::number(flow.byteCount()),
                 flow.stateText());
    }

    return {};
}

QVariant FlowTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) {
        return {};
    }

    switch (section) {
    case ColumnIndex:
        return QStringLiteral("#");
    case ColumnClient:
        return QStringLiteral("Endpoint A");
    case ColumnServer:
        return QStringLiteral("Endpoint B");
    case ColumnPackets:
        return QStringLiteral("Packets");
    case ColumnBytes:
        return QStringLiteral("Bytes");
    case ColumnDuration:
        return QStringLiteral("Duration");
    case ColumnState:
        return QStringLiteral("State");
    default:
        return {};
    }
}

} // namespace sss::ui
