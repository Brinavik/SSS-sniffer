#pragma once

#include <QString>
#include <QStringList>
#include <QVector>

namespace sss::capture {

// One pcap-visible network interface.
struct DeviceInfo
{
    QString name;          // pcap device name, e.g. "\Device\NPF_{GUID}"
    QString description;   // human readable adapter description
    QStringList addresses; // IPv4 / IPv6 addresses, display only
    bool loopback = false;
};

// Thin wrapper around pcap_findalldevs(). Listing works without administrator
// privileges; opening a device does not (Npcap restricts capture to admins).
class DeviceEnumerator
{
public:
    // Returns the device list. On failure returns an empty list and, when
    // `error` is not null, stores the libpcap error text in it.
    static QVector<DeviceInfo> list(QString *error = nullptr);
};

} // namespace sss::capture
