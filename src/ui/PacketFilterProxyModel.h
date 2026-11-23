#pragma once

#include <QSortFilterProxyModel>

#include "filter/FilterExpression.h"
#include "flow/TcpFlowTracker.h"

namespace sss::ui {

// Applies a display filter and an optional "follow this TCP flow" restriction
// to the packet table without touching the model.
class PacketFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit PacketFilterProxyModel(QObject *parent = nullptr);

    void setExpression(sss::filter::FilterExpression expression);
    void clearExpression();
    bool hasExpression() const;

    void setFlowFilter(const sss::flow::TcpFlowKey &key);
    void clearFlowFilter();
    bool hasFlowFilter() const;

    // True when any restriction is active.
    bool isFiltering() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    sss::filter::FilterExpression m_expression;
    sss::flow::TcpFlowKey m_flowKey;
    bool m_flowFilterActive = false;
};

} // namespace sss::ui
