# eBPF Firewall
A stateless layer 2 and layer 3-4 access control firewall build with eBPF (XDP for ingress, TC for egress). With Cisco ACL style commnad-line.

## Features
- Layer 2 filtering: source/destination MAC, EtherType
- Layer 3/4 filtering: source/destination IP, protocol, source/destination port
- TCP flag matching (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR). For example `flags syn` matches any packet with SYN set
- First-match-wins rule evaluation, Cisco ACL semantics (`permit`/`deny`, `in`/`out`)
- Denied packets are reported via a BPF ring buffer and logged with kernel-accurate timestamps
- Interactive CLI
-
## Project structure
```
acl/
├── include/    shared headers (common.h, structs, TCP flag masks)
├── src/
│   ├── kernel/
│   │   ├── packet_filter.bpf.c   eBPF program
│   │   └── vmlinux.h
│   └── user/
│       ├── acl.hpp         ACL table read/write/insert/remove/update
│       ├── loader.cpp/hpp  EbpfLoader, attach/detach, ring buffer polling
│       ├── logger.cpp/hpp  Logger, timestamped file logging
│       ├── main.cpp        interactive CLI
│       └── utils.cpp/hpp   parsing and formatting helpers
├── run.sh                run
└── acl.log               runtime deny/info/error log
```
## Build & run
```bash
./run.sh <interface>
```
This compiles the BPF object, builds the userspace loader, and attaches it to the given interface. Requires: `clang` (BPF target support), `g++` with C++23 support, `libbpf-dev`, root privileges to attach XDP/TC.

## CLI usage
![CLI help](docs/images/help.png)
### Show
![Show ACEs](docs/images/show.png)
### Add
![Show ACEs](docs/images/add.png)
![Show ACEs](docs/images/add2.png)
### Update
![Show ACEs](docs/images/update.png)
### delete
![Show ACEs](docs/images/delete.png)
### validation
![Show ACEs](docs/images/validation.png)


## Logs
 
`acl.log` records every denied packet, plus startup and error events, with a millisecond-accurate timestamp — so you can see exactly what was blocked, when, and why.
 
**Format:**
```
[timestamp] [LEVEL] message
```
 
- `INFO` — engine lifecycle (startup, interface attached)
- `DENY` — a packet was dropped by a rule
**Sample:**
```
[2026-09-26 14:03:47.902] [DENY ] access-list ACL-L3L4 denied tcp 192.168.0.66:51422 -> 192.168.0.72:80 flags syn (ACE 0, in, dropped-at 2026-09-26 14:03:47.899)
```
Read it left to right:
- `ACL-L3L4`, matched an IP/port rule (`ACL-L2` = MAC/EtherType rule instead)
- `tcp 192.168.0.66:51422 -> 192.168.0.72:80`, who sent it, and where it was going
- `flags syn`, TCP flags on the packet (TCP only)
- `ACE 0`, the rule index that matched (`implicit-deny` = no rule matched, blocked by default)
- `in` / `out`, inbound or outbound traffic
- `dropped-at`, the exact kernel-side drop time
Watch it live:
```bash
tail -f acl.log
```
