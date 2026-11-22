// tools/env_smoke/npcap_smoke.cpp
// Npcap 环境验收程序：验证驱动可用、网卡可枚举、能真正抓到包。
//
// 用法：
//   npcap_smoke                    列出所有网卡（不需要管理员）
//   npcap_smoke --selftest         在回环网卡上抓包自测（需要管理员）
//   npcap_smoke -i <序号|设备名> -n <包数>
//
// 退出码：0 成功；1 枚举失败；2 打开网卡失败（多为权限/驱动问题）；3 未抓到包

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#endif

#include <pcap.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

struct Device {
    std::string name;
    std::string desc;
    bool loopback = false;
};

bool isElevated()
{
#ifdef _WIN32
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (::GetTokenInformation(token, TokenElevation, &elevation, size, &size)) {
        elevated = (elevation.TokenIsElevated != 0);
    }
    ::CloseHandle(token);
    return elevated;
#else
    return false;
#endif
}

// 返回网卡数量，失败返回 -1
int listDevices(std::vector<Device> &devices)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *all = nullptr;
    if (pcap_findalldevs(&all, errbuf) != 0) {
        std::printf("[FAIL] pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    int index = 0;
    for (pcap_if_t *d = all; d != nullptr; d = d->next, ++index) {
        Device dev;
        dev.name = (d->name != nullptr) ? d->name : "";
        dev.desc = (d->description != nullptr) ? d->description : "";
        dev.loopback = ((d->flags & PCAP_IF_LOOPBACK) != 0)
                       || (dev.name.find("NPF_Loopback") != std::string::npos);
        devices.push_back(dev);
        std::printf("[%2d] %-40s %s%s\n",
                    index,
                    dev.name.c_str(),
                    dev.desc.c_str(),
                    dev.loopback ? "   <loopback>" : "");
    }
    pcap_freealldevs(all);
    return index;
}

// 在指定网卡上抓包，返回抓到的包数，失败返回负值
int capture(const std::string &device, int want, std::string &error)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(device.c_str(), 65536, 1, 250, errbuf);
    if (handle == nullptr) {
        error = errbuf;
        return -1;
    }

    // 只抓 IPv4，减少无关流量
    struct bpf_program program {};
    if (pcap_compile(handle, &program, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &program);
        pcap_freecode(&program);
    }

    const DWORD deadline = ::GetTickCount() + 12000;
    int got = 0;
    while (got < want && ::GetTickCount() < deadline) {
        struct pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        const int rc = pcap_next_ex(handle, &header, &data);
        if (rc == 0) {
            continue; // 超时，继续等
        }
        if (rc == -1) {
            error = pcap_geterr(handle);
            pcap_close(handle);
            return -2;
        }
        if (rc == -2) {
            break; // 抓包结束
        }
        ++got;
        std::printf("  #%02d  ts=%ld.%06ld  len=%u  caplen=%u\n",
                    got,
                    static_cast<long>(header->ts.tv_sec),
                    static_cast<long>(header->ts.tv_usec),
                    header->len,
                    header->caplen);
    }

    pcap_close(handle);
    return got;
}

void flushLoopbackTraffic()
{
#ifdef _WIN32
    std::system("start /b ping -n 8 127.0.0.1 > nul");
#endif
}

} // namespace

int main(int argc, char **argv)
{
    std::printf("=====================================================\n");
    std::printf(" Npcap 环境验收程序 (npcap_smoke)\n");
    std::printf("=====================================================\n");

    const char *version = pcap_lib_version();
    std::printf("pcap_lib_version : %s\n", version);
    std::printf("实现             : %s\n",
                std::strstr(version, "Npcap") != nullptr ? "Npcap" : "WinPcap / 其他");
    std::printf("管理员权限       : %s\n", isElevated() ? "是" : "否");

    std::printf("\n--- 网卡列表 ---\n");
    std::vector<Device> devices;
    const int count = listDevices(devices);
    if (count < 0) {
        std::printf("\nRESULT: FAIL (网卡枚举失败，检查 npcap 服务是否运行)\n");
        return 1;
    }
    std::printf("共 %d 个网卡接口\n", count);

    if (argc == 1) {
        std::printf("\nRESULT: LIST-OK (枚举正常；抓包验证请运行 npcap_smoke --selftest)\n");
        return 0;
    }

    std::string device;
    int want = 3;
    bool selftest = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--selftest") == 0) {
            selftest = true;
        } else if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            const std::string arg = argv[++i];
            const bool numeric = !arg.empty()
                                 && arg.find_first_not_of("0123456789") == std::string::npos;
            if (numeric) {
                const int index = std::atoi(arg.c_str());
                if (index < 0 || index >= count) {
                    std::printf("[FAIL] 网卡序号越界: %s\n", arg.c_str());
                    return 1;
                }
                device = devices[static_cast<size_t>(index)].name;
            } else {
                device = arg;
            }
        } else if (std::strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            want = std::atoi(argv[++i]);
        }
    }

    if (selftest || device.empty()) {
        for (const Device &dev : devices) {
            if (dev.loopback) {
                device = dev.name;
                break;
            }
        }
        if (device.empty()) {
            std::printf("[FAIL] 未找到回环网卡 (NPF_Loopback)，无法自测\n");
            return 1;
        }
        std::printf("\n--- 自测：在回环网卡 %s 上抓 %d 个包 ---\n", device.c_str(), want);
        flushLoopbackTraffic();
    } else {
        std::printf("\n--- 在 %s 上抓 %d 个包 ---\n", device.c_str(), want);
    }

    if (!isElevated()) {
        std::printf("[WARN] 当前不是管理员权限，Npcap 默认只允许管理员抓包，"
                    "可能返回 Access denied。请右键以管理员身份运行。\n");
    }

    std::string error;
    const int got = capture(device, want, error);
    if (got < 0) {
        std::printf("[FAIL] 抓包失败: %s\n", error.c_str());
        std::printf("\nRESULT: FAIL (打开/读取网卡失败)\n");
        return 2;
    }
    if (got == 0) {
        std::printf("[FAIL] 12 秒内没有抓到任何包\n");
        std::printf("\nRESULT: FAIL (无流量，或网卡选择不当)\n");
        return 3;
    }

    std::printf("\nRESULT: PASS (抓到 %d 个包，Npcap 工作正常)\n", got);
    return 0;
}
