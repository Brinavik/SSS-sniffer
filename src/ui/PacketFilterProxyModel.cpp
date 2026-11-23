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

bool PacketFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    if (m_expression.isEmpty()) {
        return true;
    }

    Q_UNUSED(sourceParent);

    const auto *model = qobject_cast<const PacketTableModel *>(sourceModel());
    if (model == nullptr) {
        return true;
    }

    const sss::model::PacketRecord *record = model->packetAt(sourceRow);
    if (record == nullptr) {
        return true;
    }

    return m_expression.matches(*record);
}

} // namespace sss::ui
