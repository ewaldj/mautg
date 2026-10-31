# MAU Protocol — Wireshark Dissectors

Two Lua dissector plugins for [Wireshark](https://www.wireshark.org/) that decode the protocols used by `mautg`:

- **`mau_protocol.lua`** — the data traffic: UDP packets and TCP streams (default ports 5001-5008), data format version 2. TCP segments are reassembled to whole messages; the TCP hello and the statistics connection are decoded too.
- **`mau_owd_sync_protocol.lua`** — the OWD (one-way delay) clock-sync exchange between the receiver and the sender's embedded sync server (default UDP port 5556, `--sync-port`). Binary `struct` format.

Both recognise mautg traffic on **any port** by its content, and the ports can be changed in the Wireshark preferences.

## Data Packet Protocol Format

Every UDP packet and every TCP message carries embedded timestamps for the one-way delay measurement (format version 2).

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
|                      Stream ID (32)                           |
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
| 16 | 1 byte | uint8 | Format version (2) |
| 17 | 2 bytes | uint16 BE | UDP port of the sender's OWD sync server (0 = none) |
| 19 | 4 bytes | uint32 BE | Stream ID (random, new at every start of a stream) |
| 23 | variable | bytes | Padding: readable preamble `mautg_trafficgen_www.jeitler.cc:` (if it fits), then `0x2A` fill |
| last 4 | 4 bytes | uint32 BE | CRC-32 (zlib) over all preceding bytes |

All multi-byte fields are **big-endian** (network byte order). The minimum UDP payload is 27 bytes (header only, no padding). The user-configured "packet size" refers to the IP wire size; the UDP payload is 28 bytes smaller (20 IP + 8 UDP header).

Packets on the port that do not carry the magic are **not** dissected, so foreign traffic stays untouched.

## Wireshark Decoded View

```
▼ MAU Protocol
    Sequence Number: 42
    Timestamp (µs): 1775400123456789
    Sender Timestamp (UTC): 2026-04-05 18:42:03.456789 UTC
    Magic: MAUT
    Format Version: 2
    Sender OWD Sync Port (0 = none): 5556
    Padding Preamble: mautg_trafficgen_www.jeitler.cc:
    Padding: 6d61752d74675f...
    CRC32: 0x860d9985
    CRC Status: OK
    Wire Size (bytes): 1500
```

The Info column shows a compact summary:

```
Seq=42  Len=1500B  Sync=5556  CRC=OK
```

CRC mismatches are flagged as expert info errors and highlighted in the packet list.

## TCP Stream Format

A TCP stream is a connection to the receiver's data port. Dissected by `mau_protocol.lua` (protocol `MAU-TCP`, the messages inside as `MAU`).

| Part | Size | Content |
|------|------|---------|
| Hello (sender → receiver) | 16 bytes | `MTCP` · version `1` (uint8) · DSCP (uint8) · flags (uint16) · message size (uint32 BE) · reserved (uint32) |
| Messages | message size, back to back | normal data message (layout above, 27 … 1048576 bytes) |

A **statistics connection** (the sender asks the receiver for its values) starts with the hello `MSTA`, then one JSON line per request / reply; shown as `MAU TCP stats`.

The Info column shows `hello + Seq=0 ...`, `Seq=42  Len=262144B  TCP` or, when one frame carries several messages, `5 messages  Seq=2..6  Len=300B each  TCP`. The CRC of TCP messages is **not** checked by default (TCP protects the data and the check in Lua is slow for large messages): *Edit → Preferences → Protocols → MAU-TCP → Verify the CRC*.

Needs *Allow subdissector to reassemble TCP streams* (default on). A capture that starts in the middle of a connection (hello missing) cannot be framed and stays plain TCP.

## Ports and automatic detection

| | Default | Change |
|---|---|---|
| Data UDP | 5001-5008 | *Preferences → Protocols → MAU → UDP ports* |
| Data TCP | 5001-5008 | *Preferences → Protocols → MAU-TCP → TCP ports* |
| OWD sync UDP | 5556 | *Preferences → Protocols → MAU-OWD → UDP ports* |

Besides the port lists the dissectors recognise mautg traffic on **any other port** by its content: UDP data packets (magic `MAUT` + format version 2), TCP connections (hello `MTCP` / `MSTA`, then the whole connection), OWD sync messages (size 9 / 25, type byte, plausible timestamp). Switch these off in *Analyze → Enabled Protocols* (`mau`, `mau_tcp`, `mau_owd`) if they get in the way. A port that another dissector already owns (e.g. RTP on an even UDP port) needs *Decode As…*.

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

Both files work without any setting on the default ports and, through the content detection, on any other port (see above). Manual way for one port: right-click a packet → **Decode As…** → select **MAU**, **MAU-TCP** or **MAU-OWD**.

### Display Filters

```
mau                          # all MAU data-packet traffic
mau.seq >= 1000              # sequence number filter
mau.crc_status == "MISMATCH" # CRC errors only
mau.sync_port == 5556        # packets of senders advertising sync port 5556
mau_tcp                      # TCP hello / statistics connections
mau_tcp.msg_size == 262144   # connections with this message size

mau_owd                              # all MAU OWD sync traffic
mau_owd.type == 0x02                 # sync responses only
mau_owd.server_processing_ns > 5000  # slow server-side processing (ns)
```

### Capture Filter

```bash
wireshark -i eth0 -f "portrange 5001-5008 or udp port 5556"
```

## Related

- [`mautg.py`](../mautg.py) — traffic generator (`send`), receiver (`recv`) and OWD sync server

## License

MIT

## Author

ewald@jeitler.cc — [jeitler.cc](https://www.jeitler.cc)
