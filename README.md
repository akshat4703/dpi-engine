# DPI Engine

**Deep packet inspection in C++17, with no external dependencies.**

Reads a packet capture, works out which application is behind each connection,
drops the ones you've banned, and writes the survivors to a new capture — the
same job an ISP or corporate firewall does, built from scratch.

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=c%2B%2B&logoColor=white)](https://en.cppreference.com/w/cpp/17)
[![Dependencies](https://img.shields.io/badge/dependencies-none-success)](#requirements)
[![Tests](https://img.shields.io/badge/tests-59%20passing-success)](tests/test_sni.cpp)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)](docs/WINDOWS_SETUP.md)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```
input.pcap  ──►  [ parse → classify → filter ]  ──►  output.pcap
                                │
                                └──►  classification report
```

No libpcap. No Boost. The PCAP reader, the Ethernet/IP/TCP/UDP parsers and the
TLS handshake walker are all hand-written against the wire formats.

---

## The idea

HTTPS is encrypted, so you shouldn't be able to tell `youtube.com` from
`yourbank.com` by looking at the packets. Except you can.

Before encryption starts, the client sends a TLS **Client Hello** — and it
carries the destination hostname in plaintext, in a field called **SNI**
(Server Name Indication). It has to: one server IP hosts many sites, and the
server needs to know which certificate to present before it can negotiate a key.

```
TLS Client Hello
├── Version, Random, Cipher Suites
└── Extensions
    └── server_name: "www.youtube.com"   ◄── readable, unencrypted
```

This engine reads that field. Nothing is decrypted and nothing is broken — the
hostname was simply never hidden.

**The catch:** SNI appears exactly once, in the first packet. Packets 2 through
500 of that connection are opaque. So every connection is tracked by its
**five-tuple** — `(src_ip, dst_ip, src_port, dst_port, protocol)` — and the
verdict reached on packet 1 is applied to every packet that follows.

---

## See it run

```bash
make
./dpi_engine test_dpi.pcap filtered.pcap --block-app YouTube --block-domain "*.tiktok.com"
```

```
╔══════════════════════════════════════════════════════════════╗
║ PACKET STATISTICS                                             ║
║   Total Packets:                77                        ║
║   Total Bytes:                5738                        ║
║   TCP Packets:                  73                        ║
║   UDP Packets:                   4                        ║
╠══════════════════════════════════════════════════════════════╣
║ FILTERING STATISTICS                                          ║
║   Forwarded:                    75                        ║
║   Dropped/Blocked:               2                        ║
║   Drop Rate:                 2.60%                        ║
╠══════════════════════════════════════════════════════════════╣
║ FAST PATH STATISTICS                                          ║
║   FP Processed:                 77                        ║
║   Active Connections:           43                        ║
╚══════════════════════════════════════════════════════════════╝

╔══════════════════════════════════════════════════════════════╗
║                 APPLICATION CLASSIFICATION REPORT             ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:            43                           ║
║ Classified:                   22 (51.2%)                  ║
╠══════════════════════════════════════════════════════════════╣
║ Unknown              21  48.8% #########              ║
║ DNS                   4   9.3% #                      ║
║ HTTPS                 2   4.7%                        ║
║ GitHub                1   2.3%                        ║
║ Google                1   2.3%                        ║
║ Netflix               1   2.3%                        ║
║ YouTube               1   2.3%                        ║
║ ...                                                    ║
╚══════════════════════════════════════════════════════════════╝
```

Every hostname recovered from the sample capture, with no decryption:

```
www.apple.com     -> Apple        twitter.com       -> Twitter/X
open.spotify.com  -> Spotify      www.facebook.com  -> Facebook
www.tiktok.com    -> TikTok       discord.com       -> Discord
www.netflix.com   -> Netflix      github.com        -> GitHub
www.amazon.com    -> Amazon       www.instagram.com -> Instagram
zoom.us           -> Zoom         www.microsoft.com -> Microsoft
web.telegram.org  -> Telegram     www.youtube.com   -> YouTube
www.cloudflare.com-> Cloudflare   www.google.com    -> Google
```

---

## Architecture

The multi-threaded engine is a hash-sharded pipeline — the design real DPI
appliances use.

```
                    ┌──────────────┐
                    │ PCAP Reader  │   one thread
                    └──────┬───────┘
                           │  hash(5-tuple) % num_lbs
              ┌────────────┴────────────┐
              ▼                         ▼
        ┌──────────┐              ┌──────────┐
        │   LB 0   │              │   LB 1   │   load balancers
        └─┬──────┬─┘              └─┬──────┬─┘
          │      │  hash(5-tuple) % num_fps
      ┌───▼──┐ ┌─▼────┐         ┌───▼──┐ ┌─▼────┐
      │ FP 0 │ │ FP 1 │         │ FP 2 │ │ FP 3 │   fast paths
      └───┬──┘ └─┬────┘         └───┬──┘ └─┬────┘
          └──────┴────────┬─────────┴──────┘
                          ▼
                   ┌─────────────┐
                   │ PCAP Writer │
                   └─────────────┘
```

**Why hashing, and not a work queue?** Because every packet of a connection
*must* reach the thread that holds that connection's state. Hashing the
five-tuple guarantees it: same connection → same hash → same fast path, always.

The payoff is that no fast path ever touches another's connection table. No
shared map, no mutex on the hot path, no contention. Threads are configurable:

```bash
./dpi_engine in.pcap out.pcap --lbs 4 --fps 4    # 4 LBs × 4 FPs = 16 workers
```

---

## Quick start

### Requirements

A C++17 compiler. That is the entire list.

### Build

```bash
make
```

Produces `dpi_engine`, `dpi_mt` and `dpi_simple`. Or with CMake:

```bash
cmake -S . -B build && cmake --build build
```

Windows users: see [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md).

### Run

```bash
./dpi_engine test_dpi.pcap filtered.pcap
```

### Test

```bash
make test        # or: cd build && ctest
```

### Generate your own test capture

```bash
python3 generate_test_pcap.py
```

Or capture live traffic with Wireshark or `tcpdump` and feed it the `.pcap`.

---

## The three binaries

Three separate programs, in increasing order of complexity. All three are built
and tested — they are not versions of one another.

| Binary | Entry point | What it is |
|--------|-------------|------------|
| **`dpi_simple`** | `src/main_working.cpp` | Single-threaded. Read, classify, filter, in one loop. **Start reading here.** |
| **`dpi_mt`** | `src/dpi_mt.cpp` | The full LB/FP pipeline in a single translation unit, so the whole design fits in one file. |
| **`dpi_engine`** | `src/main_dpi.cpp` | The pipeline split into modules. Adds rules files, wildcard domains and per-thread statistics. **The complete version.** |

---

## Usage

```
dpi_engine <input.pcap> <output.pcap> [options]

  --block-ip <ip>          Block packets from a source IP
  --block-app <app>        Block an application by name
  --block-domain <domain>  Block a domain (wildcards supported)
  --block-port <port>      Block a destination port (1-65535)
  --rules <file>           Load rules from a file
  --lbs <n>                Load balancer threads (default 2)
  --fps <n>                Fast paths per load balancer (default 2)
  --verbose                Per-packet output
  --help, -h               Usage
```

Each `--block-*` flag may be repeated. All four rule types are also settable
from a [rules file](#rules-file).

### Recognised applications

`Google` · `YouTube` · `Facebook` · `Instagram` · `Twitter/X` · `Netflix` ·
`Amazon` · `Microsoft` · `Apple` · `WhatsApp` · `Telegram` · `TikTok` ·
`Spotify` · `Zoom` · `Discord` · `GitHub` · `Cloudflare`

Plus the protocol-level classes `HTTP`, `HTTPS`, `DNS`, `TLS` and `QUIC`.

### Rules file

```ini
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com

[BLOCKED_PORTS]
8080
```

```bash
./dpi_engine capture.pcap filtered.pcap --rules blocklist.txt
```

---

## Design note: matching hostnames correctly

Mapping a hostname to a vendor looks like a job for substring search. It isn't,
and getting this wrong is the most common bug in hobby DPI code.

A hostname is a **structured identifier** — dot-separated labels, ownership
attached to the suffix. A substring test throws that structure away:

```cpp
"www.microsoft.com".find("t.co")   // matches!  microsof|t.co|m
"linux.com".find("x.com")          // matches!
"contact.medium.com".find("t.me")  // matches!
```

All three are false positives, and the first is not hypothetical — an earlier
revision of this classifier reported `www.microsoft.com` as **Twitter/X** on the
sample capture in this repository.

So the matchers respect label boundaries:

| Matcher | Matches when | Used for |
|---------|--------------|----------|
| `domainIs(host, d)` | `host == d`, or `host` is a subdomain of `d` | Short domains: `t.co`, `x.com`, `t.me`, `fb.com` |
| `labelIs(labels, l)` | some label equals `l` exactly | Short tokens that hide in longer words: `aws`, `bing`, `cf` |
| `labelHas(labels, f)` | some label contains `f` | Fragments distinctive enough to be safe: `microsoft`, `cloudfront` |

Rule **order** matters too, since the chain returns on first match. YouTube is
checked before Google: `yt3.ggpht.com` is Google-owned, so a Google rule
matching `ggpht` first would make the YouTube rule for it permanently
unreachable — dead code that still reads as coverage.

[`tests/test_sni.cpp`](tests/test_sni.cpp) asserts both properties: that each
false positive above stays unclassified, and that every pattern in the table
actually reaches the rule that lists it.

---

## Project layout

```
.
├── include/                  Headers
│   ├── types.h                 FiveTuple, AppType, hashing
│   ├── pcap_reader.h           PCAP file format
│   ├── packet_parser.h         Ethernet / IP / TCP / UDP
│   ├── sni_extractor.h         TLS Client Hello + HTTP Host
│   ├── connection_tracker.h    Per-flow state
│   ├── rule_manager.h          Blocking rules
│   ├── load_balancer.h         LB thread
│   ├── fast_path.h             FP thread
│   ├── thread_safe_queue.h     Bounded MPMC queue
│   └── platform.h              Portable byte-order conversion
│
├── src/                      Implementations + the three entry points
├── tests/test_sni.cpp        Classification test suite
├── docs/
│   ├── DEEP_DIVE.md            Full walkthrough: packet-by-packet, component
│   │                           by component, from networking basics up
│   └── WINDOWS_SETUP.md        Visual Studio / MinGW / WSL instructions
├── generate_test_pcap.py     Test capture generator
├── test_dpi.pcap             Sample capture
├── Makefile
└── CMakeLists.txt
```

---

## How it works, in more depth

[**docs/DEEP_DIVE.md**](docs/DEEP_DIVE.md) traces a single packet through the
whole system — the layered header walk, the TLS handshake parse, the five-tuple
hash, the thread handoff and the filtering decision — starting from networking
fundamentals and assuming no prior knowledge. Read that if you want to
understand the codebase without reading the code.

---

## Limitations

Worth being straight about what this does and doesn't do:

- **Offline only.** Reads capture files; it is not an inline live-traffic filter.
- **SNI-dependent.** Encrypted Client Hello (ECH) hides the hostname by design,
  and this engine cannot classify such connections.
- **IPv4 only.** No IPv6 header parsing yet.
- **No TCP reassembly.** A Client Hello split across segments is missed.
- **Classification is a lookup table**, not a behavioural or statistical model.

---

## License

[MIT](LICENSE).
