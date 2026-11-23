#include "filter/FilterExpression.h"

#include <QStringList>
#include <QVector>

#include <utility>

namespace sss::filter::detail {

struct Node
{
    virtual ~Node() = default;
    virtual bool evaluate(const sss::model::PacketRecord &record) const = 0;
};

using NodePtr = std::shared_ptr<const Node>;

struct TrueNode : Node
{
    bool evaluate(const sss::model::PacketRecord &) const override { return true; }
};

struct AndNode : Node
{
    NodePtr left;
    NodePtr right;

    bool evaluate(const sss::model::PacketRecord &record) const override
    {
        return left->evaluate(record) && right->evaluate(record);
    }
};

struct OrNode : Node
{
    NodePtr left;
    NodePtr right;

    bool evaluate(const sss::model::PacketRecord &record) const override
    {
        return left->evaluate(record) || right->evaluate(record);
    }
};

struct NotNode : Node
{
    NodePtr operand;

    bool evaluate(const sss::model::PacketRecord &record) const override
    {
        return !operand->evaluate(record);
    }
};

enum class Keyword { Ip, Ipv4, Ipv6, Tcp, Udp, Icmp, Icmpv6, Arp, Http, Dns, Tls };

struct KeywordNode : Node
{
    Keyword keyword = Keyword::Ip;

    bool evaluate(const sss::model::PacketRecord &record) const override
    {
        switch (keyword) {
        case Keyword::Ip:
            return record.ipVersion == 4 || record.ipVersion == 6;
        case Keyword::Ipv4:
            return record.ipVersion == 4;
        case Keyword::Ipv6:
            return record.ipVersion == 6;
        case Keyword::Tcp:
            return record.ipProtocol == 6;
        case Keyword::Udp:
            return record.ipProtocol == 17;
        case Keyword::Icmp:
            return record.ipProtocol == 1;
        case Keyword::Icmpv6:
            return record.ipProtocol == 58;
        case Keyword::Arp:
            return record.protocol == QStringLiteral("ARP");
        case Keyword::Http:
            return record.protocol == QStringLiteral("HTTP");
        case Keyword::Dns:
            return record.protocol == QStringLiteral("DNS");
        case Keyword::Tls:
            return record.protocol == QStringLiteral("TLS");
        }
        return false;
    }
};

enum class Field
{
    Protocol,
    Ip,
    IpSource,
    IpDestination,
    Port,
    SourcePort,
    DestinationPort,
    TcpPort,
    UdpPort,
    Length,
    Info
};

enum class Op { Eq, Ne, Lt, Gt, Le, Ge, Contains };

bool compareNumber(qint64 actual, Op op, qint64 expected)
{
    switch (op) {
    case Op::Eq:
        return actual == expected;
    case Op::Ne:
        return actual != expected;
    case Op::Lt:
        return actual < expected;
    case Op::Gt:
        return actual > expected;
    case Op::Le:
        return actual <= expected;
    case Op::Ge:
        return actual >= expected;
    case Op::Contains:
        return false;
    }
    return false;
}

bool compareText(const QString &actual, Op op, const QString &expected)
{
    switch (op) {
    case Op::Eq:
        return actual.compare(expected, Qt::CaseInsensitive) == 0;
    case Op::Ne:
        return actual.compare(expected, Qt::CaseInsensitive) != 0;
    case Op::Contains:
        return actual.contains(expected, Qt::CaseInsensitive);
    default:
        return false;
    }
}

// Address fields can match either endpoint, so "not equal" must fail only when
// both endpoints differ.
bool comparePair(const QString &first, const QString &second, Op op, const QString &expected)
{
    if (op == Op::Eq) {
        return compareText(first, op, expected) || compareText(second, op, expected);
    }
    if (op == Op::Ne) {
        return compareText(first, op, expected) && compareText(second, op, expected);
    }
    return compareText(first, op, expected) || compareText(second, op, expected);
}

struct CompareNode : Node
{
    Field field = Field::Protocol;
    Op op = Op::Eq;
    QString text;
    qint64 number = 0;
    bool numeric = false;

    bool evaluate(const sss::model::PacketRecord &record) const override
    {
        switch (field) {
        case Field::Length:
            return compareNumber(record.length, op, number);
        case Field::Port:
            return compareNumber(record.sourcePort, op, number)
                   || compareNumber(record.destinationPort, op, number);
        case Field::SourcePort:
            return compareNumber(record.sourcePort, op, number);
        case Field::DestinationPort:
            return compareNumber(record.destinationPort, op, number);
        case Field::TcpPort:
            return record.ipProtocol == 6
                   && (compareNumber(record.sourcePort, op, number)
                       || compareNumber(record.destinationPort, op, number));
        case Field::UdpPort:
            return record.ipProtocol == 17
                   && (compareNumber(record.sourcePort, op, number)
                       || compareNumber(record.destinationPort, op, number));
        case Field::Protocol:
            return compareText(record.protocol, op, text);
        case Field::Ip:
            return comparePair(record.source, record.destination, op, text);
        case Field::IpSource:
            return compareText(record.source, op, text);
        case Field::IpDestination:
            return compareText(record.destination, op, text);
        case Field::Info:
            return compareText(record.info, op, text);
        }
        return false;
    }
};

} // namespace sss::filter::detail

namespace sss::filter {
namespace {

using detail::NodePtr;

enum class TokenType { Identifier, Number, String, LeftParen, RightParen, Operator, End };

struct Token
{
    TokenType type = TokenType::End;
    QString text;
    int position = 0;
};

bool isIdentifierStart(QChar c)
{
    return c.isLetter() || c == QLatin1Char('_');
}

bool isIdentifierPart(QChar c)
{
    return c.isLetterOrNumber() || c == QLatin1Char('_') || c == QLatin1Char('.');
}

QVector<Token> tokenize(const QString &text, QString *error)
{
    QVector<Token> tokens;
    int index = 0;

    while (index < text.size()) {
        const QChar current = text.at(index);

        if (current.isSpace()) {
            ++index;
            continue;
        }
        if (current == QLatin1Char('(')) {
            tokens.append({TokenType::LeftParen, QStringLiteral("("), index});
            ++index;
            continue;
        }
        if (current == QLatin1Char(')')) {
            tokens.append({TokenType::RightParen, QStringLiteral(")"), index});
            ++index;
            continue;
        }
        if (current == QLatin1Char('"')) {
            const int start = index;
            ++index;
            QString value;
            bool closed = false;
            while (index < text.size()) {
                if (text.at(index) == QLatin1Char('"')) {
                    closed = true;
                    ++index;
                    break;
                }
                value += text.at(index);
                ++index;
            }
            if (!closed) {
                if (error != nullptr) {
                    *error = QString("unterminated string starting at %1").arg(start);
                }
                return {};
            }
            tokens.append({TokenType::String, value, start});
            continue;
        }
        if (current.isDigit()) {
            const int start = index;
            // Dots are accepted so dotted IPv4 values stay a single token.
            while (index < text.size()
                   && (text.at(index).isDigit() || text.at(index) == QLatin1Char('.'))) {
                ++index;
            }
            tokens.append({TokenType::Number, text.mid(start, index - start), start});
            continue;
        }
        if (isIdentifierStart(current)) {
            const int start = index;
            while (index < text.size() && isIdentifierPart(text.at(index))) {
                ++index;
            }
            tokens.append({TokenType::Identifier, text.mid(start, index - start).toLower(), start});
            continue;
        }
        if (current == QLatin1Char('=') || current == QLatin1Char('!') || current == QLatin1Char('<')
            || current == QLatin1Char('>') || current == QLatin1Char('&') || current == QLatin1Char('|')) {
            const int start = index;
            QString op = QString(current);
            ++index;
            if (index < text.size()) {
                const QChar next = text.at(index);
                if ((current == QLatin1Char('=') && next == QLatin1Char('='))
                    || (current == QLatin1Char('!') && next == QLatin1Char('='))
                    || (current == QLatin1Char('<') && next == QLatin1Char('='))
                    || (current == QLatin1Char('>') && next == QLatin1Char('='))
                    || (current == QLatin1Char('&') && next == QLatin1Char('&'))
                    || (current == QLatin1Char('|') && next == QLatin1Char('|'))) {
                    op += next;
                    ++index;
                }
            }
            tokens.append({TokenType::Operator, op, start});
            continue;
        }

        if (error != nullptr) {
            *error = QString("unexpected character '%1' at %2").arg(current).arg(index);
        }
        return {};
    }

    tokens.append({TokenType::End, QString(), static_cast<int>(text.size())});
    return tokens;
}

bool keywordFromText(const QString &word, detail::Keyword *keyword)
{
    if (word == QStringLiteral("ip")) {
        *keyword = detail::Keyword::Ip;
    } else if (word == QStringLiteral("ipv4")) {
        *keyword = detail::Keyword::Ipv4;
    } else if (word == QStringLiteral("ipv6")) {
        *keyword = detail::Keyword::Ipv6;
    } else if (word == QStringLiteral("tcp")) {
        *keyword = detail::Keyword::Tcp;
    } else if (word == QStringLiteral("udp")) {
        *keyword = detail::Keyword::Udp;
    } else if (word == QStringLiteral("icmp")) {
        *keyword = detail::Keyword::Icmp;
    } else if (word == QStringLiteral("icmpv6")) {
        *keyword = detail::Keyword::Icmpv6;
    } else if (word == QStringLiteral("arp")) {
        *keyword = detail::Keyword::Arp;
    } else if (word == QStringLiteral("http")) {
        *keyword = detail::Keyword::Http;
    } else if (word == QStringLiteral("dns")) {
        *keyword = detail::Keyword::Dns;
    } else if (word == QStringLiteral("tls")) {
        *keyword = detail::Keyword::Tls;
    } else {
        return false;
    }
    return true;
}

bool fieldFromText(const QString &word, detail::Field *field)
{
    if (word == QStringLiteral("proto") || word == QStringLiteral("protocol")) {
        *field = detail::Field::Protocol;
    } else if (word == QStringLiteral("ip") || word == QStringLiteral("ip.addr")) {
        *field = detail::Field::Ip;
    } else if (word == QStringLiteral("ip.src") || word == QStringLiteral("src")) {
        *field = detail::Field::IpSource;
    } else if (word == QStringLiteral("ip.dst") || word == QStringLiteral("dst")) {
        *field = detail::Field::IpDestination;
    } else if (word == QStringLiteral("port")) {
        *field = detail::Field::Port;
    } else if (word == QStringLiteral("srcport")) {
        *field = detail::Field::SourcePort;
    } else if (word == QStringLiteral("dstport")) {
        *field = detail::Field::DestinationPort;
    } else if (word == QStringLiteral("tcp.port")) {
        *field = detail::Field::TcpPort;
    } else if (word == QStringLiteral("udp.port")) {
        *field = detail::Field::UdpPort;
    } else if (word == QStringLiteral("len") || word == QStringLiteral("length")) {
        *field = detail::Field::Length;
    } else if (word == QStringLiteral("info")) {
        *field = detail::Field::Info;
    } else {
        return false;
    }
    return true;
}

bool numericField(detail::Field field)
{
    switch (field) {
    case detail::Field::Port:
    case detail::Field::SourcePort:
    case detail::Field::DestinationPort:
    case detail::Field::TcpPort:
    case detail::Field::UdpPort:
    case detail::Field::Length:
        return true;
    default:
        return false;
    }
}

class Parser
{
public:
    explicit Parser(const QVector<Token> &tokens)
        : m_tokens(tokens)
    {
    }

    NodePtr parse(QString *error)
    {
        NodePtr root = parseOr();
        if (root == nullptr) {
            if (error != nullptr) {
                *error = m_error;
            }
            return nullptr;
        }
        if (m_tokens.at(m_index).type != TokenType::End) {
            if (error != nullptr) {
                *error = QString("unexpected token '%1' at %2")
                             .arg(m_tokens.at(m_index).text)
                             .arg(m_tokens.at(m_index).position);
            }
            return nullptr;
        }
        return root;
    }

private:
    const Token &current() const { return m_tokens.at(m_index); }

    bool acceptOperator(const QString &op)
    {
        if (current().type == TokenType::Operator && current().text == op) {
            ++m_index;
            return true;
        }
        return false;
    }

    bool acceptKeyword(const QString &word)
    {
        if (current().type == TokenType::Identifier && current().text == word) {
            ++m_index;
            return true;
        }
        return false;
    }

    NodePtr parseOr()
    {
        NodePtr left = parseAnd();
        if (left == nullptr) {
            return nullptr;
        }
        while (acceptKeyword(QStringLiteral("or")) || acceptOperator(QStringLiteral("||"))) {
            NodePtr right = parseAnd();
            if (right == nullptr) {
                return nullptr;
            }
            auto node = std::make_shared<detail::OrNode>();
            node->left = left;
            node->right = right;
            left = node;
        }
        return left;
    }

    NodePtr parseAnd()
    {
        NodePtr left = parseUnary();
        if (left == nullptr) {
            return nullptr;
        }
        while (acceptKeyword(QStringLiteral("and")) || acceptOperator(QStringLiteral("&&"))) {
            NodePtr right = parseUnary();
            if (right == nullptr) {
                return nullptr;
            }
            auto node = std::make_shared<detail::AndNode>();
            node->left = left;
            node->right = right;
            left = node;
        }
        return left;
    }

    NodePtr parseUnary()
    {
        if (acceptKeyword(QStringLiteral("not")) || acceptOperator(QStringLiteral("!"))) {
            NodePtr operand = parseUnary();
            if (operand == nullptr) {
                return nullptr;
            }
            auto node = std::make_shared<detail::NotNode>();
            node->operand = operand;
            return node;
        }
        return parsePrimary();
    }

    NodePtr fail(const QString &message)
    {
        if (m_error.isEmpty()) {
            m_error = message;
        }
        return nullptr;
    }

    NodePtr parsePrimary()
    {
        if (current().type == TokenType::LeftParen) {
            ++m_index;
            NodePtr inner = parseOr();
            if (inner == nullptr) {
                return nullptr;
            }
            if (current().type != TokenType::RightParen) {
                return fail(QString("missing ')' at %1").arg(current().position));
            }
            ++m_index;
            return inner;
        }

        if (current().type != TokenType::Identifier) {
            return fail(QString("expected a keyword or field at %1").arg(current().position));
        }

        const Token word = current();
        detail::Keyword keyword = detail::Keyword::Ip;
        if (keywordFromText(word.text, &keyword) && m_tokens.at(m_index + 1).type != TokenType::Operator) {
            ++m_index;
            auto node = std::make_shared<detail::KeywordNode>();
            node->keyword = keyword;
            return node;
        }

        return parseComparison();
    }

    NodePtr parseComparison()
    {
        const Token word = current();
        ++m_index;

        detail::Field field = detail::Field::Protocol;
        if (!fieldFromText(word.text, &field)) {
            return fail(QString("unknown field '%1' at %2").arg(word.text).arg(word.position));
        }

        detail::Op op = detail::Op::Eq;
        bool hasOperator = false;

        if (current().type == TokenType::Operator) {
            const QString opText = current().text;
            ++m_index;
            hasOperator = true;
            if (opText == QStringLiteral("==")) {
                op = detail::Op::Eq;
            } else if (opText == QStringLiteral("!=")) {
                op = detail::Op::Ne;
            } else if (opText == QStringLiteral("<")) {
                op = detail::Op::Lt;
            } else if (opText == QStringLiteral(">")) {
                op = detail::Op::Gt;
            } else if (opText == QStringLiteral("<=")) {
                op = detail::Op::Le;
            } else if (opText == QStringLiteral(">=")) {
                op = detail::Op::Ge;
            } else {
                return fail(QString("unsupported operator '%1'").arg(opText));
            }
        } else if (current().type == TokenType::Identifier
                   && current().text == QStringLiteral("contains")) {
            op = detail::Op::Contains;
            hasOperator = true;
            ++m_index;
        }

        if (!hasOperator) {
            return fail(QString("expected an operator after '%1'").arg(word.text));
        }

        if (current().type != TokenType::Number && current().type != TokenType::String
            && current().type != TokenType::Identifier) {
            return fail(QString("expected a value at %1").arg(current().position));
        }

        const Token value = current();
        ++m_index;

        auto node = std::make_shared<detail::CompareNode>();
        node->field = field;
        node->op = op;
        node->text = value.text;

        if (numericField(field)) {
            bool ok = false;
            node->number = value.text.toLongLong(&ok);
            if (!ok) {
                return fail(QString("field '%1' needs a numeric value").arg(word.text));
            }
            node->numeric = true;
        }

        return node;
    }

    const QVector<Token> &m_tokens;
    int m_index = 0;
    QString m_error;
};

} // namespace

FilterExpression::FilterExpression() = default;
FilterExpression::~FilterExpression() = default;
FilterExpression::FilterExpression(FilterExpression &&other) noexcept = default;
FilterExpression &FilterExpression::operator=(FilterExpression &&other) noexcept = default;

FilterExpression FilterExpression::parse(const QString &text, QString *error)
{
    FilterExpression expression;
    expression.m_text = text.trimmed();

    if (expression.m_text.isEmpty()) {
        return expression;
    }

    QString tokenError;
    const QVector<Token> tokens = tokenize(expression.m_text, &tokenError);
    if (tokens.isEmpty()) {
        if (error != nullptr) {
            *error = tokenError;
        }
        expression.m_text.clear();
        return expression;
    }

    QString parseError;
    Parser parser(tokens);
    NodePtr root = parser.parse(&parseError);
    if (root == nullptr) {
        if (error != nullptr) {
            *error = parseError;
        }
        expression.m_text.clear();
        return expression;
    }

    expression.m_root = root;
    return expression;
}

bool FilterExpression::isEmpty() const
{
    return m_root == nullptr;
}

QString FilterExpression::text() const
{
    return m_text;
}

bool FilterExpression::matches(const sss::model::PacketRecord &record) const
{
    if (m_root == nullptr) {
        return true;
    }
    return m_root->evaluate(record);
}

} // namespace sss::filter
