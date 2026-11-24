#include "flow/ProcessResolver.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <windows.h>
#  include <iphlpapi.h>
#endif

namespace sss::flow {
namespace {

#ifdef _WIN32
QByteArray readTcpTable(ULONG family)
{
    // The table can grow between the size query and the data query, so retry a
    // few times instead of giving up and returning an empty snapshot.
    for (int attempt = 0; attempt < 3; ++attempt) {
        DWORD size = 0;
        DWORD result = ::GetExtendedTcpTable(nullptr, &size, FALSE, family,
                                             TCP_TABLE_OWNER_PID_ALL, 0);
        if (result != ERROR_INSUFFICIENT_BUFFER || size == 0) {
            continue;
        }

        QByteArray buffer(static_cast<int>(size), '\0');
        result = ::GetExtendedTcpTable(buffer.data(), &size, FALSE, family,
                                       TCP_TABLE_OWNER_PID_ALL, 0);
        if (result == NO_ERROR) {
            return buffer;
        }
    }
    return {};
}
#endif

} // namespace

void ProcessResolver::reset()
{
    m_rows.clear();
    m_names.clear();
}

void ProcessResolver::refresh()
{
    QVector<TcpTableRow> fresh;
    bool anyTableRead = false;

#ifdef _WIN32
    // IPv4 and IPv6 live in two separate tables; querying only one of them
    // silently loses half of the connections.
    const QByteArray ipv4Table = readTcpTable(AF_INET);
    if (!ipv4Table.isEmpty()) {
        fresh += parseTcpTableV4(ipv4Table.constData(),
                                 static_cast<quint32>(ipv4Table.size()));
        anyTableRead = true;
    }

    const QByteArray ipv6Table = readTcpTable(AF_INET6);
    if (!ipv6Table.isEmpty()) {
        fresh += parseTcpTableV6(ipv6Table.constData(),
                                 static_cast<quint32>(ipv6Table.size()));
        anyTableRead = true;
    }
#endif

    // Keep the previous snapshot when both reads failed: a stale snapshot is
    // better than wiping every attribution until the next successful refresh.
    if (anyTableRead) {
        m_rows = std::move(fresh);
    }
}

bool ProcessResolver::resolve(const TcpFlowKey &key, quint32 *pid) const
{
    const quint32 found = resolvePid(m_rows, key);
    if (found == 0) {
        return false;
    }
    if (pid != nullptr) {
        *pid = found;
    }
    return true;
}

QString ProcessResolver::processName(quint32 pid)
{
    if (pid == 0) {
        return QStringLiteral("Idle");
    }
    if (pid == 4) {
        return QStringLiteral("System");
    }

    const auto cached = m_names.constFind(pid);
    if (cached != m_names.constEnd()) {
        return cached.value();
    }

    QString name;
#ifdef _WIN32
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process != nullptr) {
        // Long paths exist, so do not use MAX_PATH here.
        wchar_t buffer[32768] = {0};
        DWORD length = 32768;
        if (::QueryFullProcessImageNameW(process, 0, buffer, &length) != 0) {
            const QString fullPath = QString::fromWCharArray(buffer, static_cast<int>(length));
            const int slash = fullPath.lastIndexOf(QLatin1Char('\\'));
            name = (slash >= 0) ? fullPath.mid(slash + 1) : fullPath;
        }
        ::CloseHandle(process);
    }
#endif

    // Cache misses as well: a dead or protected process will not become
    // readable and retrying on every refresh would be pointless.
    m_names.insert(pid, name);
    return name;
}

} // namespace sss::flow
