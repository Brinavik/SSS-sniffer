#pragma once

#include <QString>

#include <memory>

#include "model/PacketRecord.h"

namespace sss::filter {
namespace detail {
struct Node;
}

// Display filter evaluated per packet, independent of the BPF capture filter.
//
// Grammar (keywords are case insensitive):
//   expr       := or
//   or         := and (("or"  | "||") and)*
//   and        := unary (("and" | "&&") unary)*
//   unary      := ("not" | "!") unary | primary
//   primary    := "(" expr ")" | keyword | comparison
//   comparison := field op value
//   op         := "==" | "!=" | ">" | "<" | ">=" | "<=" | "contains"
//
// Keywords: ip, ipv4, ipv6, tcp, udp, icmp, icmpv6, arp, http, dns, tls
// Fields:   proto, ip, ip.src, ip.dst, port, srcport, dstport,
//           tcp.port, udp.port, len, info
//
// Examples: "http and ip.src == 127.0.0.1", "tcp or udp", "not icmp",
//           "(http or dns) and len > 100", "info contains POST"
class FilterExpression
{
public:
    FilterExpression();
    ~FilterExpression();

    FilterExpression(FilterExpression &&other) noexcept;
    FilterExpression &operator=(FilterExpression &&other) noexcept;

    FilterExpression(const FilterExpression &) = delete;
    FilterExpression &operator=(const FilterExpression &) = delete;

    // On error returns an empty (match everything) expression and fills `error`.
    static FilterExpression parse(const QString &text, QString *error);

    bool isEmpty() const;
    QString text() const;
    bool matches(const sss::model::PacketRecord &record) const;

private:
    std::shared_ptr<const detail::Node> m_root;
    QString m_text;
};

} // namespace sss::filter
