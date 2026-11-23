#pragma once

#include <QDateTime>
#include <QMutex>
#include <QString>
#include <QThread>
#include <QVector>

#include <atomic>
#include <deque>

#include "model/PacketRecord.h"

// Opaque libpcap handle; keeps <pcap.h> out of this header and out of the UI.
struct pcap;

namespace sss::capture {

struct CaptureStats
{
    quint64 received = 0;          // packets accepted by the capture loop
    quint64 dropped = 0;           // packets dropped by the kernel buffer
    quint64 interfaceDropped = 0;  // packets dropped by the adapter
    quint64 queueDropped = 0;      // packets discarded because the UI fell behind
};

// Runs pcap_next_ex() on its own thread and hands packets to the UI in batches.
//
// Threading contract:
//   - startCapture()/stopCapture() are called from the GUI thread;
//   - packets pile up in a mutex protected deque that the GUI drains with
//     takePending() from a timer, so no per packet signal is ever emitted;
//   - std::deque keeps both ends O(1): the capture thread pushes at the back
//     and the UI pops from the front without shifting the backlog.
class CaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit CaptureThread(QObject *parent = nullptr);
    ~CaptureThread() override;

    bool startCapture(const QString &device, const QString &bpfFilter, QString *error);
    void stopCapture();

    QVector<sss::model::PacketRecord> takePending(int maxCount);
    CaptureStats stats() const;
    QString deviceName() const;

    // True when the current process token is elevated. Npcap refuses capture
    // handles to non elevated processes when AdminOnly is enabled.
    static bool isElevated();

signals:
    void captureFailed(const QString &message);
    void captureStopped();

protected:
    void run() override;

private:
    mutable QMutex m_mutex;
    std::deque<sss::model::PacketRecord> m_pending;
    QString m_device;
    QString m_filter;
    CaptureStats m_stats;
    pcap *m_handle = nullptr;
    quint64 m_index = 0;
    std::atomic<bool> m_stopRequested{false};
};

} // namespace sss::capture
