# SSS Sniffer

A Qt 6 / C++17 packet sniffer built for experiment 1A of the Software and
System Security course: capture, protocol analysis, display filtering and TCP
flow tracking with process attribution.

## Requirements

- Windows 10 or 11 (x64)
- Visual Studio 2022 with the "Desktop development with C++" workload
- Qt 6.8 `msvc2022_64`
- Npcap 1.90 and the Npcap SDK 1.17 (`NPCAP_SDK_DIR` or `-DNPCAP_SDK_DIR=<path>`)

## Build

```powershell
cmake --preset vs2022
cmake --build --preset release
```

## Run

```powershell
.\build\vs2022\Release\sss_sniffer.exe
```

Npcap restricts packet capture to administrators on most installations, so
start the program elevated (the toolbar has an `Elevate` button for that).

## Command line modes

| Mode | Purpose |
|---|---|
| `--selftest` | builds the window headless, checks the panes, exits 0/1 |
| `--capture-test <report> [bpf] [display-filter]` | captures 7 s on loopback, writes the report and a PNG |
| `--process-test <report>` | opens a loopback connection and reports the resolved PID and image |
| `--screenshot <png>` | renders the window to a PNG |

## Layout

See `docs/design/architecture.md` for the module map, the data flow and the
known limitations. Tests live in `tests/protocol_tests.cpp`; they need neither
Npcap nor a network adapter.
