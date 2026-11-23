#include "protocol/ApplicationDissector.h"

#include <QByteArray>
#include <QList>
#include <QStringList>

#include <cstring>

#include "protocol/ProtocolHelpers.h"

namespace sss::protocol::detail {
namespace {

using detail::ipv4Text;
using detail::ipv6Text;
using detail::node;
using detail::readU16;
using detail::readU32;

bool startsWith(const uchar *payload, int captured, const char *prefix)
{
    const int length = static_cast<int>(std::strlen(prefix));
    return captured >= length && std::memcmp(payload, prefix, length) == 0;
}

bool looksLikeHttpRequest(const uchar *payload, int captured)
{
    static const char *const methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    };
    for (const char *method : methods) {
        if (startsWith(payload, captured, method)) {
            return true;
        }
    }
    return false;
}

// Only the headers a reader would care about; the rest would just be noise.
bool isInterestingHeader(const QString &name)
{
    static const char *const names[] = {
        "Host", "User-Agent", "Content-Type", "Content-Length", "Server",
        "Location", "Referer", "Accept", "Cookie", "Date",
    };
    for (const char *candidate : names) {
        if (name.compare(QLatin1String(candidate), Qt::CaseInsensitive) == 0) {
            return true;
        }
    }
    return false;
}

bool dissectHttp(const uchar *payload, int captured, Dissection &out)
{
    const bool request = looksLikeHttpRequest(payload, captured);
    const bool response = !request && startsWith(payload, captured, "HTTP/");
    if (!request && !response) {
        return false;
    }

    const int limit = qMin(captured, 2048);
    const QByteArray block(reinterpret_cast<const char *>(payload), limit);
    const int headerEnd = block.indexOf("\r\n\r\n");
    const QByteArray headerBlock = (headerEnd >= 0) ? block.left(headerEnd) : block;
    const QList<QByteArray> lines = headerBlock.split('\n');

    QString firstLine;
    if (!lines.isEmpty()) {
        firstLine = QString::fromLatin1(lines.first()).trimmed();
    }

    sss::model::DetailNode http = node(QStringLiteral("Hypertext Transfer Protocol"));
    if (request) {
        const QStringList parts = firstLine.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        http.children.append(node(QStringLiteral("Request Method"), parts.value(0)));
        http.children.append(node(QStringLiteral("Request URI"), parts.value(1)));
        http.children.append(node(QStringLiteral("Request Version"), parts.value(2)));
    } else {
        const QStringList parts = firstLine.split(QLatin1Char(' '), Qt::SkipEmptyParts);
        http.children.append(node(QStringLiteral("Response Version"), parts.value(0)));
        http.children.append(node(QStringLiteral("Status Code"), parts.value(1)));
        http.children.append(node(QStringLiteral("Response Phrase"), parts.value(2)));
    }

    for (int i = 1; i < lines.size(); ++i) {
        const QByteArray line = lines.at(i).trimmed();
        if (line.isEmpty()) {
            continue;
        }
        const int colon = line.indexOf(':');
        if (colon <= 0) {
            continue;
        }
        const QString name = QString::fromLatin1(line.left(colon)).trimmed();
        if (!isInterestingHeader(name)) {
            continue;
        }
        http.children.append(node(name, QString::fromLatin1(line.mid(colon + 1)).trimmed()));
    }

    out.details.append(http);
    out.protocol = QStringLiteral("HTTP");
    out.info = firstLine;
    return true;
}

QString dnsTypeText(quint16 type)
{
    switch (type) {
    case 1:
        return QStringLiteral("A");
    case 2:
        return QStringLiteral("NS");
    case 5:
        return QStringLiteral("CNAME");
    case 6:
        return QStringLiteral("SOA");
    case 12:
        return QStringLiteral("PTR");
    case 15:
        return QStringLiteral("MX");
    case 16:
        return QStringLiteral("TXT");
    case 28:
        return QStringLiteral("AAAA");
    default:
        return QString("type %1").arg(type);
    }
}

// Decodes a possibly compressed DNS name. Bounded by `captured` and a jump
// limit so a malformed packet cannot loop.
bool decodeDnsName(const uchar *data, int captured, int offset, QString &name, int &nextOffset)
{
    name.clear();
    nextOffset = offset;

    int position = offset;
    bool jumped = false;
    int jumps = 0;

    while (position >= 0 && position < captured) {
        const quint8 length = data[position];
        if (length == 0) {
            ++position;
            if (!jumped) {
                nextOffset = position;
            }
            return !name.isEmpty();
        }
        if ((length & 0xC0) == 0xC0) {
            if (position + 1 >= captured || ++jumps > 8) {
                return false;
            }
            const int pointer = ((length & 0x3F) << 8) | data[position + 1];
            if (pointer >= captured) {
                return false;
            }
            position = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xC0) != 0 || position + 1 + length > captured) {
            return false;
        }
        if (!name.isEmpty()) {
            name += QLatin1Char('.');
        }
        name += QString::fromLatin1(reinterpret_cast<const char *>(data + position + 1), length);
        position += 1 + length;
        if (!jumped) {
            nextOffset = position;
        }
        if (name.size() > 255) {
            return false;
        }
    }

    return false;
}

bool dissectDns(const uchar *payload, int captured, Dissection &out)
{
    if (captured < 12) {
        return false;
    }

    const quint16 id = readU16(payload);
    const quint16 flags = readU16(payload + 2);
    const quint16 questionCount = readU16(payload + 4);
    const quint16 answerCount = readU16(payload + 6);
    const bool response = (flags & 0x8000) != 0;

    QString queryName;
    int cursor = 12;
    quint16 queryType = 0;
    quint16 queryClass = 0;

    if (questionCount > 0) {
        if (!decodeDnsName(payload, captured, 12, queryName, cursor)) {
            return false;
        }
        if (cursor + 4 > captured) {
            return false;
        }
        queryType = readU16(payload + cursor);
        queryClass = readU16(payload + cursor + 2);
        cursor += 4;
    }

    QString answerText;
    if (response && answerCount > 0) {
        int position = cursor;
        for (int i = 0; i < qMin<int>(answerCount, 4); ++i) {
            QString answerName;
            if (!decodeDnsName(payload, captured, position, answerName, position)) {
                break;
            }
            if (position + 10 > captured) {
                break;
            }
            const quint16 type = readU16(payload + position);
            const quint32 ttl = readU32(payload + position + 4);
            const quint16 dataLength = readU16(payload + position + 8);
            position += 10;
            if (position + dataLength > captured) {
                break;
            }
            if (type == 1 && dataLength == 4) {
                answerText = QString("%1 (ttl %2)").arg(ipv4Text(payload + position)).arg(ttl);
            } else if (type == 28 && dataLength == 16) {
                answerText = QString("%1 (ttl %2)").arg(ipv6Text(payload + position)).arg(ttl);
            }
            position += dataLength;
            if (!answerText.isEmpty()) {
                break;
            }
        }
    }

    QStringList flagNames;
    flagNames << (response ? QStringLiteral("Response") : QStringLiteral("Query"));
    if ((flags & 0x0100) != 0) {
        flagNames << QStringLiteral("Recursion desired");
    }
    if ((flags & 0x0080) != 0) {
        flagNames << QStringLiteral("Recursion available");
    }
    const int replyCode = flags & 0x000F;
    if (replyCode != 0) {
        flagNames << QString("Reply code %1").arg(replyCode);
    }

    sss::model::DetailNode dns = node(response ? QStringLiteral("Domain Name System (response)")
                                               : QStringLiteral("Domain Name System (query)"));
    dns.children.append(node(QStringLiteral("Transaction ID"),
                             QString("0x%1").arg(id, 4, 16, QLatin1Char('0'))));
    dns.children.append(node(QStringLiteral("Flags"), flagNames.join(QLatin1Char(','))));
    dns.children.append(node(QStringLiteral("Questions"), QString::number(questionCount)));
    dns.children.append(node(QStringLiteral("Answer RRs"), QString::number(answerCount)));
    if (!queryName.isEmpty()) {
        dns.children.append(node(QStringLiteral("Query Name"), queryName));
        dns.children.append(node(QStringLiteral("Type"), dnsTypeText(queryType)));
        dns.children.append(node(QStringLiteral("Class"),
                                 queryClass == 1 ? QStringLiteral("IN (1)")
                                                 : QString::number(queryClass)));
    }
    if (!answerText.isEmpty()) {
        dns.children.append(node(QStringLiteral("Answer"), answerText));
    }
    out.details.append(dns);

    out.protocol = QStringLiteral("DNS");
    out.info = QString("%1 0x%2 %3 %4")
                   .arg(response ? QStringLiteral("Standard query response")
                                 : QStringLiteral("Standard query"))
                   .arg(id, 4, 16, QLatin1Char('0'))
                   .arg(dnsTypeText(queryType))
                   .arg(queryName);
    return true;
}

QString tlsVersionText(quint16 version)
{
    switch (version) {
    case 0x0300:
        return QStringLiteral("SSL 3.0");
    case 0x0301:
        return QStringLiteral("TLS 1.0");
    case 0x0302:
        return QStringLiteral("TLS 1.1");
    case 0x0303:
        return QStringLiteral("TLS 1.2");
    case 0x0304:
        return QStringLiteral("TLS 1.3");
    default:
        return QString("0x%1").arg(version, 4, 16, QLatin1Char('0'));
    }
}

// Minimal TLS record peek: enough to label the stream, not to decrypt it.
bool dissectTls(const uchar *payload, int captured, Dissection &out)
{
    if (captured < 5) {
        return false;
    }

    const quint8 contentType = payload[0];
    const quint16 version = readU16(payload + 1);
    if ((version & 0xFF00) != 0x0300 || contentType < 20 || contentType > 23) {
        return false;
    }

    QString typeText;
    switch (contentType) {
    case 20:
        typeText = QStringLiteral("Change Cipher Spec");
        break;
    case 21:
        typeText = QStringLiteral("Alert");
        break;
    case 22:
        typeText = QStringLiteral("Handshake");
        break;
    default:
        typeText = QStringLiteral("Application Data");
        break;
    }

    if (contentType == 22 && captured >= 6) {
        const quint8 handshakeType = payload[5];
        if (handshakeType == 1) {
            typeText = QStringLiteral("Handshake: Client Hello");
        } else if (handshakeType == 2) {
            typeText = QStringLiteral("Handshake: Server Hello");
        }
    }

    sss::model::DetailNode tls = node(QStringLiteral("Transport Layer Security"));
    tls.children.append(node(QStringLiteral("Content Type"), typeText));
    tls.children.append(node(QStringLiteral("Record Version"), tlsVersionText(version)));
    tls.children.append(node(QStringLiteral("Record Length"), QString::number(readU16(payload + 3))));
    out.details.append(tls);

    out.protocol = QStringLiteral("TLS");
    out.info = QString("TLS %1, %2").arg(tlsVersionText(version), typeText);
    return true;
}

} // namespace

bool dissectApplication(quint16 sourcePort,
                        quint16 destinationPort,
                        const uchar *payload,
                        int capturedBytes,
                        Dissection &out)
{
    if (payload == nullptr || capturedBytes <= 0) {
        return false;
    }

    // DNS is port bound and binary; test it before the text heuristics.
    if (sourcePort == 53 || destinationPort == 53) {
        if (dissectDns(payload, capturedBytes, out)) {
            return true;
        }
    }
    if (dissectHttp(payload, capturedBytes, out)) {
        return true;
    }
    if (dissectTls(payload, capturedBytes, out)) {
        return true;
    }
    return false;
}

} // namespace sss::protocol::detail
