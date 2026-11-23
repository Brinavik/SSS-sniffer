#include "capture/DeviceEnumerator.h"

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#include <pcap.h>

namespace sss::capture {
namespace {

// Winsock must be up for inet_ntop(). Npcap starts and stops it around its own
// calls, so we keep our own reference for the lifetime of the listing.
class WinsockScope
{
public:
    WinsockScope()
    {
        WSADATA data {};
        m_ok = (WSAStartup(MAKEWORD(2, 2), &data) == 0);
    }

    ~WinsockScope()
    {
        if (m_ok) {
            WSACleanup();
        }
    }

    WinsockScope(const WinsockScope &) = delete;
    WinsockScope &operator=(const WinsockScope &) = delete;

private:
    bool m_ok = false;
};

QString addressText(const sockaddr *address)
{
    if (address == nullptr) {
        return {};
    }

    char host[INET6_ADDRSTRLEN] = {0};
    if (address->sa_family == AF_INET) {
        const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address);
        if (::inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host)) != nullptr) {
            return QString::fromLatin1(host);
        }
    } else if (address->sa_family == AF_INET6) {
        const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(address);
        if (::inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host)) != nullptr) {
            return QString::fromLatin1(host);
        }
    }
    return {};
}

} // namespace

QVector<DeviceInfo> DeviceEnumerator::list(QString *error)
{
    QVector<DeviceInfo> devices;

    const WinsockScope winsock;

    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *all = nullptr;
    if (pcap_findalldevs(&all, errorBuffer) != 0) {
        if (error != nullptr) {
            *error = QString::fromLocal8Bit(errorBuffer);
        }
        return devices;
    }

    for (pcap_if_t *device = all; device != nullptr; device = device->next) {
        DeviceInfo info;
        info.name = QString::fromLocal8Bit(device->name != nullptr ? device->name : "");
        info.description = QString::fromLocal8Bit(device->description != nullptr ? device->description : "");
        info.loopback = ((device->flags & PCAP_IF_LOOPBACK) != 0)
                        || info.name.contains(QStringLiteral("NPF_Loopback"));

        for (pcap_addr_t *address = device->addresses; address != nullptr; address = address->next) {
            const QString text = addressText(address->addr);
            if (!text.isEmpty()) {
                info.addresses.append(text);
            }
        }

        devices.append(info);
    }

    pcap_freealldevs(all);
    return devices;
}

} // namespace sss::capture
