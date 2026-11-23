#include "ui/FlowTableModel.h"

#include <algorithm>
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
    // The tracker only ever appends, so an unchanged prefix means the tail is
    // new flows: insert them incrementally. A full reset would clear the dock
    // selection every time a new conversation starts during a capture.
    const bool samePrefix =
        flows.size() >= m_flows.size()
        && std::equal(m_flows.cbegin(), m_flows.cend(), flows.cbegin(),
                      [](const sss::flow::TcpFlow &left, const sss::flow::TcpFlow &right) {
                          return left.key == right.key;
                      });

    if (samePrefix) {
        const int oldSize = static_cast<int>(m_flows.size());
        const int newSize = static_cast<int>(flows.size());

        if (newSize > oldSize) {
            beginInsertRows(QModelIndex(), oldSize, newSize - 1);
            m_flows = std::move(flows);
            endInsertRows();
        } else {
            m_flows = std::move(flows);
        }

        if (oldSize > 0) {
            emit dataChanged(index(0, 0), index(oldSize - 1, ColumnCount - 1));
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
        case ColumnProcess:
            return flow.processName.isEmpty() ? QStringLiteral("-") : flow.processName;
        case ColumnPid:
            return flow.pid == 0 ? QStringLiteral("-") : QString::number(flow.pid);
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
        case ColumnPid:
        case ColumnPackets:
        case ColumnBytes:
        case ColumnDuration:
            return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        default:
            return static_cast<int>(Qt::AlignLeft | Qt::AlignVCenter);
        }
    } else if (role == Qt::ToolTipRole) {
        const QString process = flow.processName.isEmpty()
                                    ? QStringLiteral("not attributed to a local process")
                                    : QString("%1 (PID %2)").arg(flow.processName).arg(flow.pid);
        return QString("Initiator: %1\nResponder: %2\n"
                       "The initiator is the side that sent the first captured packet "
                       "(the SYN sender when the handshake was captured).\n"
                       "process: %3\npackets: %4\nframe bytes: %5\nstate: %6")
            .arg(flow.initiatorText(),
                 flow.responderText(),
                 process,
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
        return QStringLiteral("Initiator");
    case ColumnServer:
        return QStringLiteral("Responder");
    case ColumnProcess:
        return QStringLiteral("Process");
    case ColumnPid:
        return QStringLiteral("PID");
    case ColumnPackets:
        return QStringLiteral("Packets");
    case ColumnBytes:
        return QStringLiteral("Frame bytes");
    case ColumnDuration:
        return QStringLiteral("Duration");
    case ColumnState:
        return QStringLiteral("State");
    default:
        return {};
    }
}

} // namespace sss::ui
