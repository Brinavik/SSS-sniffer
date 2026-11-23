#include "capture/CaptureThread.h"

#include <QMutexLocker>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <windows.h>
#endif

#include <pcap.h>

#include "protocol/Dissector.h"

namespace sss::capture {
namespace {

constexpr int kSnaplen = 65536;
constexpr int kReadTimeoutMs = 200;
constexpr int kStatsInterval = 256;
constexpr std::size_t kMaxPending = 20000;

QString errorText(const char *buffer)
{
    // libpcap error strings are ASCII on Windows; fromLatin1 keeps them intact
    // without depending on the current code page.
    return QString::fromLatin1(buffer == nullptr ? "" : buffer);
}

} // namespace

CaptureThread::CaptureThread(QObject *parent)
    : QThread(parent)
{
}

CaptureThread::~CaptureThread()
{
    stopCapture();
}

bool CaptureThread::isElevated()
{
#ifdef _WIN32
    HANDLE token = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token) == 0) {
        return false;
    }

    TOKEN_ELEVATION elevation {};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (::GetTokenInformation(token, TokenElevation, &elevation, size, &size) != 0) {
        elevated = (elevation.TokenIsElevated != 0);
    }
    ::CloseHandle(token);
    return elevated;
#else
    return false;
#endif
}

bool CaptureThread::startCapture(const QString &device, const QString &bpfFilter, QString *error)
{
    if (isRunning()) {
        if (error != nullptr) {
            *error = QStringLiteral("capture is already running");
        }
        return false;
    }
    if (device.isEmpty()) {
        if (error != nullptr) {
            *error = QStringLiteral("no capture device selected");
        }
        return false;
    }

    {
        QMutexLocker locker(&m_mutex);
        m_device = device;
        m_filter = bpfFilter;
        m_pending.clear();
        m_stats = CaptureStats {};
        m_index = 0;
    }

    m_stopRequested.store(false);
    start();
    return true;
}

void CaptureThread::stopCapture()
{
    m_stopRequested.store(true);

    {
        QMutexLocker locker(&m_mutex);
        if (m_handle != nullptr) {
            pcap_breakloop(m_handle);
        }
    }

    if (isRunning()) {
        // pcap_next_ex() wakes up at least every kReadTimeoutMs, so this is
        // generous; it only fails if the driver itself is stuck.
        wait(3000);
    }
}

QVector<sss::model::PacketRecord> CaptureThread::takePending(int maxCount)
{
    QMutexLocker locker(&m_mutex);

    if (m_pending.empty() || maxCount <= 0) {
        return {};
    }

    const std::size_t count = qMin<std::size_t>(static_cast<std::size_t>(maxCount), m_pending.size());
    QVector<sss::model::PacketRecord> batch;
    batch.reserve(static_cast<int>(count));
    for (std::size_t i = 0; i < count; ++i) {
        batch.append(std::move(m_pending.front()));
        m_pending.pop_front();
    }
    return batch;
}

CaptureStats CaptureThread::stats() const
{
    QMutexLocker locker(&m_mutex);
    return m_stats;
}

QString CaptureThread::deviceName() const
{
    QMutexLocker locker(&m_mutex);
    return m_device;
}

void CaptureThread::run()
{
    QString device;
    QString filter;
    {
        QMutexLocker locker(&m_mutex);
        device = m_device;
        filter = m_filter;
    }

    const QByteArray deviceName = device.toLocal8Bit();
    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};

    pcap_t *handle = pcap_open_live(deviceName.constData(), kSnaplen, 1, kReadTimeoutMs, errorBuffer);
    if (handle == nullptr) {
        emit captureFailed(errorText(errorBuffer));
        return;
    }

    if (!filter.isEmpty()) {
        const QByteArray filterText = filter.toLocal8Bit();
        bpf_program program {};
        if (pcap_compile(handle, &program, filterText.constData(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
            const QString message = QString("invalid capture filter: %1").arg(errorText(pcap_geterr(handle)));
            pcap_close(handle);
            emit captureFailed(message);
            return;
        }
        if (pcap_setfilter(handle, &program) != 0) {
            const QString message = QString("cannot apply capture filter: %1").arg(errorText(pcap_geterr(handle)));
            pcap_freecode(&program);
            pcap_close(handle);
            emit captureFailed(message);
            return;
        }
        pcap_freecode(&program);
    }

    {
        QMutexLocker locker(&m_mutex);
        m_handle = handle;
    }

    const int linkType = pcap_datalink(handle);
    int sinceStats = 0;

    while (!m_stopRequested.load()) {
        pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        const int result = pcap_next_ex(handle, &header, &data);

        if (result == 0) {
            continue; // read timeout, nothing captured in this window
        }
        if (result == -2) {
            break; // pcap_breakloop() from stopCapture()
        }
        if (result < 0) {
            emit captureFailed(errorText(pcap_geterr(handle)));
            break;
        }

        sss::model::PacketRecord record;
        {
            QMutexLocker locker(&m_mutex);
            record.index = ++m_index;
        }

        const qint64 seconds = static_cast<qint64>(header->ts.tv_sec);
        record.timestamp = QDateTime::fromSecsSinceEpoch(seconds).addMSecs(header->ts.tv_usec / 1000);
        record.length = static_cast<int>(header->len);
        record.raw = QByteArray(reinterpret_cast<const char *>(data), static_cast<int>(header->caplen));

        const sss::protocol::Dissection dissection =
            sss::protocol::dissectFrame(data,
                                        static_cast<int>(header->caplen),
                                        static_cast<int>(header->len),
                                        linkType,
                                        record.index,
                                        record.timestamp);
        record.source = dissection.source;
        record.destination = dissection.destination;
        record.protocol = dissection.protocol;
        record.info = dissection.info;
        record.details = dissection.details;
        record.ipVersion = dissection.ipVersion;
        record.ipProtocol = dissection.ipProtocol;
        record.sourcePort = dissection.sourcePort;
        record.destinationPort = dissection.destinationPort;
        record.tcpFlags = dissection.tcpFlags;

        {
            QMutexLocker locker(&m_mutex);
            if (m_pending.size() >= kMaxPending) {
                ++m_stats.queueDropped;
            } else {
                m_pending.push_back(std::move(record));
            }
            ++m_stats.received;
            ++sinceStats;
        }

        if (sinceStats >= kStatsInterval) {
            sinceStats = 0;
            struct pcap_stat counters {};
            if (pcap_stats(handle, &counters) == 0) {
                QMutexLocker locker(&m_mutex);
                m_stats.dropped = counters.ps_drop;
                m_stats.interfaceDropped = counters.ps_ifdrop;
            }
        }
    }

    struct pcap_stat counters {};
    if (pcap_stats(handle, &counters) == 0) {
        QMutexLocker locker(&m_mutex);
        m_stats.dropped = counters.ps_drop;
        m_stats.interfaceDropped = counters.ps_ifdrop;
    }

    {
        QMutexLocker locker(&m_mutex);
        m_handle = nullptr;
    }
    pcap_close(handle);

    emit captureStopped();
}

} // namespace sss::capture
