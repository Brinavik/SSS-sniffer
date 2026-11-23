#include "ui/PacketFilterProxyModel.h"

#include <utility>

#include "ui/PacketTableModel.h"

namespace sss::ui {

PacketFilterProxyModel::PacketFilterProxyModel(QObject *parent)
    : QSortFilterProxyModel(parent)
{
}

void PacketFilterProxyModel::setExpression(sss::filter::FilterExpression expression)
{
    m_expression = std::move(expression);
    invalidateFilter();
}

void PacketFilterProxyModel::clearExpression()
{
    m_expression = sss::filter::FilterExpression();
    invalidateFilter();
}

bool PacketFilterProxyModel::hasExpression() const
{
    return !m_expression.isEmpty();
}

void PacketFilterProxyModel::setFlowFilter(const sss::flow::TcpFlowKey &key)
{
    m_flowKey = key;
    m_flowFilterActive = true;
    invalidateFilter();
}

void PacketFilterProxyModel::clearFlowFilter()
{
    m_flowFilterActive = false;
    m_flowKey = sss::flow::TcpFlowKey();
    invalidateFilter();
}

bool PacketFilterProxyModel::hasFlowFilter() const
{
    return m_flowFilterActive;
}

bool PacketFilterProxyModel::isFiltering() const
{
    return m_flowFilterActive || !m_expression.isEmpty();
}

bool PacketFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    Q_UNUSED(sourceParent);

    const auto *model = qobject_cast<const PacketTableModel *>(sourceModel());
    if (model == nullptr) {
        return true;
    }

    const sss::model::PacketRecord *record = model->packetAt(sourceRow);
    if (record == nullptr) {
        return true;
    }

    if (m_flowFilterActive) {
        sss::flow::TcpFlowKey key;
        if (!sss::flow::TcpFlowKey::fromRecord(*record, &key) || !(key == m_flowKey)) {
            return false;
        }
    }

    if (m_expression.isEmpty()) {
        return true;
    }

    return m_expression.matches(*record);
}

} // namespace sss::ui
