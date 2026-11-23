// tools/env_smoke/npcap_smoke.cpp
// Npcap probe: driver installed, devices enumerable, packets capturable.
//
// Usage:
//   npcap_smoke                    list capture devices
//   npcap_smoke --selftest         capture 3 packets on loopback (needs admin)
//   npcap_smoke -i <index|name> -n <count>
//
// Exit codes: 0 ok, 1 enumeration failed, 2 open/read failed, 3 no packets.

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <windows.h>
#endif

#include <pcap.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct Device
{
    std::string name;
    std::string description;
    bool loopback = false;
};

bool isElevated()
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

// Returns the device count, or -1 on failure.
int listDevices(std::vector<Device> &devices)
{
    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *all = nullptr;
    if (pcap_findalldevs(&all, errorBuffer) != 0) {
        std::printf("[FAIL] pcap_findalldevs: %s\n", errorBuffer);
        return -1;
    }

    int index = 0;
    for (pcap_if_t *entry = all; entry != nullptr; entry = entry->next, ++index) {
        Device device;
        device.name = (entry->name != nullptr) ? entry->name : "";
        device.description = (entry->description != nullptr) ? entry->description : "";
        device.loopback = ((entry->flags & PCAP_IF_LOOPBACK) != 0)
                          || (device.name.find("NPF_Loopback") != std::string::npos);
        devices.push_back(device);
        std::printf("[%2d] %-40s %s%s\n",
                    index,
                    device.name.c_str(),
                    device.description.c_str(),
                    device.loopback ? "   <loopback>" : "");
    }

    pcap_freealldevs(all);
    return index;
}

// Returns the number of captured packets, or a negative value on failure.
int capture(const std::string &device, int want, std::string &error)
{
    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(device.c_str(), 65536, 1, 250, errorBuffer);
    if (handle == nullptr) {
        error = errorBuffer;
        return -1;
    }

    struct bpf_program program {};
    if (pcap_compile(handle, &program, "ip", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &program);
        pcap_freecode(&program);
    }

    const DWORD deadline = ::GetTickCount() + 12000;
    int captured = 0;
    while (captured < want && ::GetTickCount() < deadline) {
        pcap_pkthdr *header = nullptr;
        const u_char *data = nullptr;
        const int result = pcap_next_ex(handle, &header, &data);
        if (result == 0) {
            continue;
        }
        if (result == -1) {
            error = pcap_geterr(handle);
            pcap_close(handle);
            return -2;
        }
        if (result == -2) {
            break;
        }
        ++captured;
        std::printf("  #%02d  ts=%ld.%06ld  len=%u  caplen=%u\n",
                    captured,
                    static_cast<long>(header->ts.tv_sec),
                    static_cast<long>(header->ts.tv_usec),
                    header->len,
                    header->caplen);
    }

    pcap_close(handle);
    return captured;
}

} // namespace

int main(int argc, char **argv)
{
    std::printf("=====================================================\n");
    std::printf(" Npcap environment probe\n");
    std::printf("=====================================================\n");

    const char *version = pcap_lib_version();
    std::printf("pcap_lib_version : %s\n", version);
    std::printf("implementation   : %s\n",
                std::strstr(version, "Npcap") != nullptr ? "Npcap" : "WinPcap or other");
    std::printf("elevated         : %s\n", isElevated() ? "yes" : "no");

    std::printf("\n--- devices ---\n");
    std::vector<Device> devices;
    const int count = listDevices(devices);
    if (count < 0) {
        std::printf("\nRESULT: FAIL (enumeration failed, check the npcap service)\n");
        return 1;
    }
    std::printf("%d device(s)\n", count);

    if (argc == 1) {
        std::printf("\nRESULT: LIST-OK (run with --selftest to verify capture)\n");
        return 0;
    }

    std::string device;
    int want = 3;
    bool selftest = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--selftest") == 0) {
            selftest = true;
        } else if (std::strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            const std::string argument = argv[++i];
            const bool numeric = !argument.empty()
                                 && argument.find_first_not_of("0123456789") == std::string::npos;
            if (numeric) {
                const int index = std::atoi(argument.c_str());
                if (index < 0 || index >= count) {
                    std::printf("[FAIL] device index out of range: %s\n", argument.c_str());
                    return 1;
                }
                device = devices[static_cast<std::size_t>(index)].name;
            } else {
                device = argument;
            }
        } else if (std::strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            want = std::atoi(argv[++i]);
        }
    }

    if (selftest || device.empty()) {
        for (const Device &candidate : devices) {
            if (candidate.loopback) {
                device = candidate.name;
                break;
            }
        }
        if (device.empty()) {
            std::printf("[FAIL] no loopback device found\n");
            return 1;
        }
        std::printf("\n--- selftest: %d packets on %s ---\n", want, device.c_str());
        std::system("start /b ping -n 8 127.0.0.1 > nul");
    } else {
        std::printf("\n--- capturing %d packets on %s ---\n", want, device.c_str());
    }

    if (!isElevated()) {
        std::printf("[WARN] not running as administrator; Npcap may answer Access denied\n");
    }

    std::string error;
    const int captured = capture(device, want, error);
    if (captured < 0) {
        std::printf("[FAIL] capture error: %s\n", error.c_str());
        std::printf("\nRESULT: FAIL (could not open or read the device)\n");
        return 2;
    }
    if (captured == 0) {
        std::printf("[FAIL] no packet captured within 12 seconds\n");
        std::printf("\nRESULT: FAIL (no traffic, or wrong device)\n");
        return 3;
    }

    std::printf("\nRESULT: PASS (%d packets captured, Npcap works)\n", captured);
    return 0;
}
