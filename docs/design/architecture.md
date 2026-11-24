# SSS Sniffer - design notes

## Scope

Experiment 1A of the Software and System Security course: a GUI packet sniffer
(NPS) with protocol analysis (NPA), a display filter and TCP flow tracking with
process attribution.

## Module map

| Directory | Responsibility |
|---|---|
| `src/model` | `PacketRecord`, `DetailNode`, synthetic demo frames |
| `src/capture` | `DeviceEnumerator` (pcap device list), `CaptureThread` (pcap loop, packet queue, drop counters) |
| `src/protocol` | `dissectFrame`: link layer, IPv4/IPv6, TCP/UDP/ICMP, HTTP/DNS/TLS summary |
| `src/filter` | `FilterExpression`: tokenizer, parser, AST, per packet evaluation |
| `src/flow` | `TcpFlowTracker` (conversations), `TcpTableParser` (MIB buffers), `ProcessResolver` (PID attribution) |
| `src/ui` | `PacketTableModel`, `PacketFilterProxyModel`, `FlowTableModel` |
| `src/app` | `MainWindow`: three pane layout, toolbars, flow dock |
| `tools/env_smoke` | standalone Npcap / Qt probes used during setup |
| `tests` | `protocol_tests.cpp`, runs without a network adapter |

## Data flow

```
CaptureThread (pcap_next_ex)
      |
      v
  std::deque<PacketRecord>          (mutex protected, capped at 20000)
      |
      |  100 ms QTimer drain
      v
  PacketTableModel -> PacketFilterProxyModel -> QTableView
      |
      +-> TcpFlowTracker -> ProcessResolver (GetExtendedTcpTable)
                          -> FlowTableModel -> flow dock
```

## Key decisions

- **Sources are ASCII only.** The course requires it, and it removes a whole
  class of MSVC code page problems. `/utf-8` stays as a safety net.
- **No per packet signals.** The capture thread never touches the UI; it fills
  a deque and the GUI drains it in batches.
- **Dissection is pure.** `dissectFrame` takes bytes and returns a `Dissection`,
  so the parser is unit tested without Npcap, adapters or privileges.
- **Display filter is compiled, not evaluated as text per packet.** A small
  recursive descent parser builds an AST; a proxy model applies it.
- **Flow keys are canonical.** Both directions of a conversation map to one
  key; addresses are case folded once so `==` and `qHash` stay exact.
- **Process attribution happens per packet batch**, after every socket of the
  batch exists, with two retries for flows that were not in the snapshot yet.

## Known limits

- No IP fragment reassembly: non-first fragments are labelled and skipped.
- No TCP stream reassembly: HTTP is parsed from the segment that carries it.
- TLS is identified (record type, hello) but not decrypted.
- Process attribution only covers local sockets; UDP is not attributed.
- The flow table has no aging; very long captures grow it without bound.

## Verification

- `tests/protocol_tests.cpp`: 92 checks (dissector, filter grammar, flow keys,
  TCP table parsing with byte order and address mapping).
- CLI modes used for reproducible checks:
  - `--selftest` builds the window and verifies the three panes.
  - `--capture-test <report> [bpf] [display-filter]` captures 7 s on loopback,
    writes a report plus a PNG, and checks that demo data is visible after a
    followed flow.
  - `--process-test <report>` opens a loopback connection and reports the
    resolved PID and image name without Npcap.
