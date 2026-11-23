#pragma once

#include <QSortFilterProxyModel>

#include "filter/FilterExpression.h"

namespace sss::ui {

// Applies a display filter to the packet table without touching the model.
class PacketFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit PacketFilterProxyModel(QObject *parent = nullptr);

    void setExpression(sss::filter::FilterExpression expression);
    void clearExpression();
    bool hasExpression() const;

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const override;

private:
    sss::filter::FilterExpression m_expression;
};

} // namespace sss::ui
