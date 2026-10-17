# MAU Protocol — Wireshark Dissectors

Two Lua dissector plugins for [Wireshark](https://www.wireshark.org/) that decode the protocols used by `mautg`:

- **`mau_protocol.lua`** — the data-plane traffic packets (default UDP ports 5001-5008), format version 1 (mautg v1.05+).
- **`mau_owd_sync_protocol.lua`** — the OWD (one-way delay) clock-sync exchange between the receiver and the sender's embedded sync server (default UDP port 5556, `--sync-port`). Binary `struct` format.

## Data Packet Protocol Format

MAU uses UDP to transmit packets with embedded timestamps for one-way delay measurement (format version 1, mautg v1.05+).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number (32)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Timestamp in µs (64)                        |
|                    CLOCK_REALTIME                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic "MAUT" (32)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (8)   |       Sender OWD Sync Port (16)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Padding (variable)                       |
|   "mautg_trafficgen_www.jeitler.cc:" + 0x2A fill             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          CRC32 (32)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Length | Type | Description |
|--------|--------|------|-------------|
| 0 | 4 bytes | uint32 BE | Sequence number (starts at 0) |
| 4 | 8 bytes | uint64 BE | Timestamp in microseconds since Unix epoch |
| 12 | 4 bytes | ASCII | Magic `MAUT` |
| 16 | 1 byte | uint8 | Format version (1) |
| 17 | 2 bytes | uint16 BE | UDP port of the sender's OWD sync server (0 = none) |
| 19 | variable | bytes | Padding: readable preamble `mautg_trafficgen_www.jeitler.cc:` (if it fits), then `0x2A` fill |
| last 4 | 4 bytes | uint32 BE | CRC-32 (zlib) over all preceding bytes |

All multi-byte fields are **big-endian** (network byte order). The minimum UDP payload is 23 bytes (header only, no padding). The user-configured "packet size" refers to the IP wire size; the UDP payload is 28 bytes smaller (20 IP + 8 UDP header).

Packets on the port that do not carry the magic are **not** dissected, so foreign UDP traffic stays untouched. This format is **not compatible** with mautg 1.04 and older (including the earlier mau-send/mau-recv scripts).

## Wireshark Decoded View

```
▼ MAU Protocol
    Sequence Number: 42
    Timestamp (µs): 1775400123456789
    Sender Timestamp (UTC): 2026-04-05 18:42:03.456789 UTC
    Magic: MAUT
    Format Version: 1
    Sender OWD Sync Port (0 = none): 5556
    Padding Preamble: mautg_trafficgen_www.jeitler.cc:
    Padding: 6d61752d74675f...
    CRC32: 0x860d9985
    CRC Status: OK
    Wire Size (bytes): 1500
```

The info column shows a compact summary:

```
Seq=42  Len=1500B  Sync=5556  CRC=OK
```

CRC mismatches are flagged as expert info errors and highlighted in the packet list.

## OWD Sync Protocol Format

Dissected by `mau_owd_sync_protocol.lua`. Fixed-size binary messages exchanged between the receiver and the peer's embedded sync server — this is how the receiver measures its clock offset (the receiver learns the sync port from the data packets; see `--sender` / `--sender-sync-port` / `--resync-interval` in the main README).

| Message | Size | Layout |
|---------|------|--------|
| Request | 9 bytes | `[0]` type = `0x01` · `[1:9]` t1_ns (uint64 BE) |
| Response | 25 bytes | `[0]` type = `0x02` · `[1:9]` t1_ns · `[9:17]` t2_ns · `[17:25]` t3_ns (all uint64 BE) |

All timestamps are `CLOCK_REALTIME` nanoseconds since the Unix epoch. A packet of any other size, or with an unrecognized type byte, is left to other dissectors rather than misparsed.

### Wireshark Decoded View (OWD Sync)

```
▼ MAU OWD Sync Protocol
    Message Type: 0x02 (RSP - sync response)
    T1 - Receiver TX (ns since epoch): 1787941343040081408
    T1 (UTC): 2026-08-28 18:22:23.040081 UTC
    T2 - Sender RX (ns since epoch): 1787941343040231408
    T2 (UTC): 2026-08-28 18:22:23.040231 UTC
    T3 - Sender TX (ns since epoch): 1787941343040239408
    T3 (UTC): 2026-08-28 18:22:23.040239 UTC
    Server Processing Time (T3-T2, ns): 8000
```

Info column:

```
MAU OWD Sync RSP  t1=2026-08-28 18:22:23.040081 UTC  server_proc=8000ns
```

`Server Processing Time` (T3−T2) is the one leg of the exchange kernel RX timestamping doesn't reach (see the main README's Delay Measurement section) — a growing value there under load is a direct sign of scheduling/GC jitter on the sender host.

## Installation

1. Find your Wireshark personal plugins directory:
   **Wireshark → Help → About Wireshark → Folders → Personal Plugins**

   Typical locations:

   | OS | Path |
   |----|------|
   | Linux | `~/.local/lib/wireshark/plugins/` |
   | macOS | `~/.local/lib/wireshark/plugins/` |
   | Windows | `%APPDATA%\Wireshark\plugins\` |

2. Copy both dissector files (install just one if you only need it):

   ```bash
   # Linux / macOS
   mkdir -p ~/.local/lib/wireshark/plugins
   cp mau_protocol.lua mau_owd_sync_protocol.lua ~/.local/lib/wireshark/plugins/
   ```

   ```powershell
   # Windows (PowerShell)
   Copy-Item mau_protocol.lua,mau_owd_sync_protocol.lua "$env:APPDATA\Wireshark\plugins\"
   ```

3. Reload: restart Wireshark or press **Ctrl+Shift+L** to reload Lua plugins.

## Usage

`mau_protocol.lua` registers on **UDP ports 5001-5008** (default data port range; other ports via *Decode As*) and `mau_owd_sync_protocol.lua` on **UDP port 5556** (default `--sync-port`) automatically.

For a different port: right-click any UDP packet → **Decode As…** → set UDP port → select **MAU** or **MAU-OWD**.

### Display Filters

```
mau                          # all MAU data-packet traffic
mau.seq >= 1000              # sequence number filter
mau.crc_status == "MISMATCH" # CRC errors only
mau.sync_port == 5556        # packets of senders advertising sync port 5556

mau_owd                              # all MAU OWD sync traffic
mau_owd.type == 0x02                 # sync responses only
mau_owd.server_processing_ns > 5000  # slow server-side processing (ns)
```

### Capture Filter

```bash
wireshark -i eth0 -f "udp portrange 5001-5008 or udp port 5556"
```

## Related

- [`mautg.py`](../mautg.py) — traffic generator (`send`), receiver (`recv`) and OWD sync server

## License

MIT

## Author

ewald@jeitler.cc — [jeitler.cc](https://www.jeitler.cc)
