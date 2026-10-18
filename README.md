# MAU — Multicast/AND/Unicast Traffic Generator & Analyzer

Single-file Python tool (standard library only) to generate and analyze UDP traffic with one-way delay (OWD), loss, DSCP and throughput measurement. `mautg` has two roles: **sender** (`send`) and **receiver** (`recv`), started from a menu or by sub-command.

By Ewald Jeitler - https://www.jeitler.cc

## Features

- Multicast, unicast and broadcast; up to 32 sender streams, up to 36 receiver streams
- OWD via NTP-style 4-timestamp exchange, drift tracking, kernel RX timestamps (Linux)
- Per stream: loss, most packets lost in a row (`Cons`), misorder, restart detection, DSCP, MC/UC/BC, throughput, delay avg/min/max
- Receiver view (TUI and web) ends the stream table with a `SUM` row over all streams: packets, miss, ord and Mbit/s, pkt/s summed; Loss% overall; Cons = maximum; delay avg weighted over all samples, min/max overall
- Burst mode, DSCP marking, TTL, DF bit, source address/port
- Receiver overload detection (RX drops, display limit)
- CSV log, Wireshark dissectors, full-screen text UI (plain ANSI) and line-menu fallback
- Web GUI (`-web`) or web view of a terminal run (`-wv`, `-wvc`), standard library only
- Python 3.6.1+, Linux, macOS, Raspberry Pi OS, Cisco IOS-XE Guest Shell

## Installation / Update

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/mautg/main/e-install.sh)"
```

Installs `mautg.py` to `/usr/local/bin` as command `mautg`; running it again updates. Manual: download `mautg.py` from https://github.com/ewaldj/mautg, `chmod +x mautg.py`.

### Python 3.6 / Cisco Guest Shell

- Python 3.6.1 or newer. Per-packet receiver cost: 2.0 us (3.8), 1.3 us (3.11/3.13).
- Python 3.6 is the Guest Shell interpreter: `python3 mautg.py`. Not yet run on a real 3.6.
- The Guest Shell sees only its own interface (`eth0` or VirtualPortGroup / AppGigabitEthernet). Multicast needs PIM or an IGMP join towards that interface. Use low rates (up to a few thousand pps).

### Character set

- Unicode only if the locale is UTF-8 (`echo $LANG`); otherwise plain ASCII. `--ascii` / `MAUTG_ASCII=1` forces ASCII.
- Garbled output such as `‚úì` = terminal decodes UTF-8 as Mac Roman: set the terminal encoding to UTF-8 (SecureCRT: Session Options > Terminal > Appearance > Character encoding).

## Screenshots

![Sender form](screenshots/form-sender.png)

![Receiver form](screenshots/form-receiver.png)

![Sender live view](screenshots/send-live.png)

![Receiver live view](screenshots/recv-live.png)

![Receiver per-packet view](screenshots/recv-packets.png)

## Quick Start

```bash
./mautg.py send -d 239.1.1.1 -p 5001 --pps 100      # sender (starts the sync server)
./mautg.py recv -g 239.1.1.1 -p 5001 -i 5           # receiver, summary every 5 s
./mautg.py                                          # menu
```

The receiver detects the sender from the first packet; delay values appear after the time sync (a few seconds).

## Menu (full-screen text UI)

One form per role, tabs **Sender** / **Receiver**. Settings are saved with `[ Save settings ]` to `~/.mau/config.json`.

| Key | Action |
|---|---|
| Up / Down | select row |
| Enter | edit row / run button (Esc cancel, Ctrl-U clear) |
| Space, Left / Right | toggle `[x]`, change `< choice >` |
| `s` / `r`, Tab | Sender / Receiver tab |
| Esc / q | leave (unsaved changes: Save & quit / Quit without saving / Cancel; Esc again = quit without saving) |
| Ctrl+C | stop / quit at any time |

- Live views stop only with `q` or Ctrl+C (Esc is ignored).
- Needs a terminal of at least 60x16, otherwise (pipe, `TERM=dumb`, `--no-tui`) numbered line menus are used. The line-menu sender handles one stream.
- Only ANSI/VT100 sequences. `--no-color` / `NO_COLOR`: monochrome; `--color`: force colors.
- Closing the terminal, SIGHUP or SIGTERM stops everything (exit 129 / 143). Use `tmux` / `screen` for persistent sessions.
- Source address pick list: IPv4 addresses of the host; also selects the outgoing multicast interface. DSCP pick list: BE, CS1-7, AF11-43, VA, EF, custom 0-63.
- Receiver form: `OWD sync` auto / sender IP / off; `CSV log` off / auto / file.

## Sub-command `send`

`send` without destination opens the sender menu; with a destination it starts the sender live view (`--no-live` = plain output).

```bash
./mautg.py send -d 239.1.1.1 -p 5001 -s 1500 --pps 1000 --dscp 46   # constant rate
./mautg.py send -d 10.0.0.5 --burst                                  # burst, max speed
./mautg.py send -d 10.0.0.5 -s 1500 --burst --burst-mbps 200         # burst, 200 Mbit/s
./mautg.py send -d 172.17.17.255 -p 5001 --pps 50                    # broadcast
./mautg.py send -d 10.0.0.5 -s 1500 --pps 100 --df                   # DF bit (Linux)
```

### Streams (sender live view)

Up to 32 streams, one thread and one socket each, sharing one sync server. The receiver separates streams by source IP + destination port: each stream needs its own port.

| Key | Action |
|---|---|
| Up / Down | select stream |
| Space | start / stop selected (sequence continues) |
| `s` / `x` | start / stop all |
| `e` / Enter | edit (also while running; Left/Right/Tab = other stream) |
| `n` | new stream (copy, next free port) |
| `d` / Del | delete (y/n) |
| `w` | save streams to config |
| `r` | receiver view (starts the receiver with the saved receiver settings if none runs); streams keep running |
| `q` / Ctrl+C | stop all (also the receiver) |

Per stream: destination, port, size, mode (pps or burst with Mbit/s limit, 0 = unlimited), DSCP, TTL, DF, source address/port. Rate column = measured over the last 0.5 s. Socket error: `ERROR` + reason; send errors are retried every 0.2 s. Form: Left/Right switch streams; streams 2-32 are stored as `extra_streams`.

```bash
./mautg.py send --stream 239.1.1.1:5001,pps=100,dscp=EF \
                --stream 239.1.1.1:5002,size=1500,burst=50 \
                --stream 10.0.0.5:5003,pps=20,dscp=CS1,size=512
```

`--stream DEST:PORT[,pps=N][,size=N][,dscp=N|NAME][,ttl=N][,burst[=MBIT]][,src=IP][,sport=N][,df]`; unset values come from the other `send` options and the saved config. Without terminal or with `--no-live`: one stream prints plain output, several print a status line every 5 s.

### Options (`send`)

| Option | Description |
|---|---|
| `-d`, `--destination` | Destination IP |
| `-p`, `--port` | Destination UDP port (default 5001) |
| `-s`, `--size` | Wire size in bytes (IP packet; payload = size - 28) |
| `--pps` | Packets per second |
| `--dscp` | DSCP 0-63 |
| `--ttl` | TTL 1-255 |
| `--source` | Source IP of this host (also selects the multicast interface) |
| `--source-port` | Source UDP port |
| `--burst` | Burst mode |
| `--burst-mbps` | Burst limit in Mbit/s (0 = unlimited) |
| `--df` | Set DF bit (Linux) |
| `--stream SPEC` | Add stream (repeatable, max 32) |
| `--sync-port` | Local sync server port (default 5556) |
| `--no-sync-server` | No sync server |
| `--no-live` | Plain output |
| `-m`, `--menu` | Sender menu |
| `--no-tui`, `--no-color`, `--color`, `--ascii` | Output options |
| `-web`, `-wv`, `-wvc`, `-port`, `-bind` | Web GUI, see [Web GUI](#web-gui) |

Unset values come from the saved config.

### Pacing and performance

Measured on a 2-core Linux VM, sender and receiver on the same host, 200-byte packets:

| Test | Result |
|---|---|
| One stream, burst max (sender only) | 303k pkt/s |
| Four streams x 50k pps (sender only) | 94k pkt/s |
| Receiver without loss (summary view) | 200k pps |
| Receiver CPU per packet | 1.3 us |

- **One running stream:** each packet is sent at its due time (sleep until 0.5 ms before, then busy-wait on `perf_counter`). One CPU core at 100 % above about 2000 pps. Gaps at 10k pps (100 us): median 100.0 us, 95 % below 103 us, under 1 % back-to-back.
- **Several running streams:** streams with interval below 1 ms sleep until due; late packets are sent back-to-back (max 64 per round). Average rate exact; spacing at 10k+ pps in groups of a few packets (tens of us).
- **Burst mode:** as fast as the limit allows. A stream more than 1 s behind restarts its schedule.
- **Limits:** one Python thread at a time (GIL): all streams of a sender together about 100-300k pps. Per-packet display (`-i 0`) and CSV log (`-l`) cost more than the summary view.

### Receiver overload (loss that is not network loss)

- **Display limit:** per-packet display at most 500 lines/s (`--print-limit N`, 0 = off). All packets are still counted. Status bar: `DISPLAY LIMITED 500/S`; the final statistics show skipped lines.
- **Linux:** kernel drop counter (`SO_RXQ_OVFL`) read per packet. Status bar `RX OVERLOAD: n DROPPED LOCALLY`; summaries and final statistics list the drops. Equals the receiver's reported loss for the same period.
- **Any OS:** receive queue not empty for more than 1 s: status bar `RX AT LIMIT`. (macOS has no per-socket drop counter.)
- Delay values are unreliable while overloaded.
- **Receive buffer:** the receiver requests up to 8 MB; the banner shows the granted size (`Receive buffer: ... KB`). Cap on Linux `net.core.rmem_max` (about 212 KB default on Raspberry Pi OS). Root may exceed it (`SO_RCVBUFFORCE`).

```
sudo sysctl -w net.core.rmem_max=16777216                                   # until reboot
echo 'net.core.rmem_max=16777216' | sudo tee /etc/sysctl.d/99-mautg.conf     # permanent
sudo sysctl -w kern.ipc.maxsockbuf=8388608                                  # macOS
```

100k pps, 1000-byte packets: 416 KB buffer 1.0 % loss, 16 MB buffer 0 %. A bigger buffer only absorbs short stalls; a permanently too slow receiver (about 150-250k pps per process) needs fewer packets or the summary view.

### Raspberry Pi 5 (direct 1 Gbit/s link)

Burst max, 1500-byte packets (about 975 Mbit/s, 81k pps = line rate), receiver in summary view:

- Receiver takes about **65k pps (790 Mbit/s)** with all functions on; loss 17-19 %.
- About 1/4 of the loss is counted by the socket (`DROPPED LOCALLY`), 3/4 is lost before the socket (NIC ring, kernel backlog).
- Delay is constant 85-95 ms in this state (full queues).
- Reliable measurement: **60k pps or less** (about 700 Mbit/s at 1500 bytes). x86 PC: 200k pps and more.
- Checks (not tested): `ip -s link show eth0`, `ethtool -S eth0 | grep -i -E 'drop|discard|over'`, `/proc/net/softnet_stat` (column 3), `sysctl net.core.netdev_max_backlog=10000` (default 1000), `taskset -c 3 ./mautg.py recv ...`.
- `recvmmsg` measured: no gain. Several receiver processes do not help for one stream.

## Sub-command `recv`

`recv` starts with its defaults and the given options; it does not read the saved menu config. `-m` opens the receiver menu. Live view is the default on a terminal of at least 80x16 (`--no-live` = scrolling output).

```bash
./mautg.py recv -g 239.1.1.1 -p 5001                  # summary every 2 s
./mautg.py recv -g 239.1.1.1 -p 5001 -i 0             # per packet
./mautg.py recv -g 239.1.1.1 -c 1                     # compact summary, 1 s
./mautg.py recv -u -p 5001 -i 2                       # unicast
./mautg.py recv -g 239.1.1.1 -i 10 -l                 # CSV log, automatic name
./mautg.py recv -g 239.1.1.1 -i 10 -l capture.csv     # CSV log, own name
./mautg.py recv -g 239.1.1.1 --resync-interval 30
./mautg.py recv -g 239.1.1.1 --sender 192.168.1.10 --sender-sync-port 5600
./mautg.py recv -g 239.1.1.1 --sender none            # no time sync
```

### Live view

- Status bar, stream table (one row per stream: Source, Port, Cast, Packets, Loss%, Miss, Avg, Max, Mbit/s, Sync = `ok`/`wait`/`FAIL`/`none`/`off`), then headline and scrolling log. Columns separated by ` | `.
- Narrow terminals drop columns in this order: `Min`, `Ord`, `SPort`, `DSCP`, `Size`, `Miss`. Full table needs about 110 columns. The table shows 2/4/8 streams depending on height.
- DSCP column = DSCP of the latest packet (`CS1*` = changed during the run).
- Log line widths: per packet 87 columns (+4 several streams, +18 with sender IP), summary 149 (+22), compact 83 (+22).

| Key | Action |
|---|---|
| `s` | sender view (streams and receiver keep running in the background; `r` there returns) |
| `q` | stop the receiver (final statistics follow at the end); with running streams the sender view comes up |
| `e` | edit the receiver settings (same form as the receiver menu), Apply restarts the receiver with them; statistics start from zero |
| `p` | pause log |
| `i` | show/hide sender IP |
| `r` | reset view (streams, counters, clock; sync and CSV keep running) |
| `d` | per-packet / summary |
| `+` / `-` | summary interval 1, 2, 3, 5, 10, 20, 30, 60 s |

### Line formats

Per packet (`-i 0`; a stream label appears once a 2nd stream is detected, `--show-ip` adds the sender IP):

```
18:16:01 | A | Seq:   946 | Size:  256 | DSCP:EF    | Delay:   0.25ms | OK    | Loss:  0.00%
```

Interval summary (`-i N`):

```
20:47:37 |      0–2s |  695.81 Mbps |  1500B | DSCP:BE    | OK     | Pkt:    58023 | Loss: 0.00% Pkt:     0 | Dly(ms): avg:0.42 min:0.33 max:0.55
```

Compact summary (`-c N`):

```
      0–1s |    0.04 Mbps | BE    | OK   | Pkt:       21 | LPkt:      0 | Dly:0.29
```

- Values are per interval; one line per stream. The final summary (Ctrl+C) shows totals per stream.
- `Delay:~` = negative reading floored to 0 for display; CSV keeps the raw value.

### Options (`recv`)

| Option | Description |
|---|---|
| `-I`, `--interface` | Multicast join interface: `all` (default), `auto`, IP or name (`eth0`) |
| `-g`, `--group` | Multicast group(s): list / range / short range (default 239.1.1.1) |
| `-p`, `--port` | Port, range or list, e.g. `5005`, `5001-5008`, `5005,6000-6003` (default 5001-5008) |
| `-u`, `--unicast` | Unicast mode (bind to own IP) |
| `-i`, `--interval` | Summary interval in s (default 2; 0 = per packet) |
| `-c`, `--compact` | Compact summary interval in s (overrides `-i`) |
| `-l`, `--log` | CSV log in the current directory; without name `mautg-log_<date>_<time>.csv` |
| `--sender` | Sender IP for sync (default: auto-detect; `none` = no sync) |
| `--sender-sync-port` | Sync port of the sender (default: from packets; 5556 with `--sender`) |
| `--show-ip` | Sender IP in every line |
| `--verify` | CRC + padding check of every packet (default: magic check per packet, full check at lock-in) |
| `--print-limit N` | Max lines/s in per-packet display (default 500, 0 = unlimited) |
| `--resync-interval` | Resync interval in s (default 3) |
| `--sync-port` | Local sync server port (default 5556) |
| `--no-sync-server` | No sync server |
| `--no-live` | Scrolling output instead of live view |
| `-m`, `--menu` | Receiver menu |
| `--no-tui`, `--no-color`, `--color`, `--ascii` | Output options |
| `-web`, `-wv`, `-wvc`, `-port`, `-bind` | Web GUI, see [Web GUI](#web-gui) |

### Multicast interface

`-I` selects the interface for the IGMP join (form field *Multicast interface*).

- `all` (default): join every group on every IPv4 address of the host except loopback. Interfaces that cannot join are skipped and listed in the banner; the receiver fails only if none works. Linux limit: 20 memberships per socket (`net.ipv4.igmp_max_memberships`); groups x interfaces beyond that are reported as failed joins.
- `auto`: kernel chooses (routing table).
- IP or interface name: that interface only; errors are fatal.
- Multicast arriving on two interfaces is recognised as one stream (duplicate counter).

### Cast: MC / UC / BC

Per stream, taken from the destination address of each datagram (`IP_PKTINFO` Linux, `IP_RECVDSTADDR` macOS/BSD): **MC** 224.0.0.0/4, **BC** 255.255.255.255 or directed `x.y.z.255` not local to the host, **UC** otherwise. Shown as `Cast` (`Ty` on narrow screens) in table, lines and CSV; `--` = unknown (Windows). A stream shows the cast of its latest packet.

### Several multicast groups

`-g 239.1.1.1,239.1.1.10` (list), `-g 239.1.1.1-239.1.1.10` (range), `-g 239.1.1.1-10` (short range), combinable. Maximum 16 groups. Every port socket joins all groups; a stream is not tied to a group.

### Port ranges and lists

Default 5001-5008. One socket per port (max 512). Stream key = **sender IP + advertised sync port + destination port** (labels A-Z, 0-9; max 36). With more than one port the `Port` column appears in table, lines, statistics and CSV. Ports that cannot be opened are reported and skipped.

### Sender detection and foreign packets

- **Auto-detect:** the first valid packet gives source IP and sync port; sync runs in a background thread. Delay shows `n/a` until it succeeds; failed sync is retried every 5 s, throughput and loss keep working.
- **Own-traffic check:** magic `MAUT` + version on every packet; other packets are ignored and counted (`non-mautg`). CRC32 + padding are checked at lock-in, or per packet with `--verify`.
- **Per stream:** key = source IP + destination port + stream id. Own sequence tracker, statistics, DSCP, sync. Tracker: highest sequence number plus a window of the last 2048; a gap counts as lost, a late arrival inside the window takes the loss back and counts as misorder, a repeated sequence number is `DUP` (not counted for loss). A new stream id on the same IP/port after the old one was silent (more than 4x the packet interval, at least 0.3 s) is a restart of the same stream (`Sender restart detected`, tracker starts over, no false loss); a new id while the old one still arrives is a second sender (own stream). Packets of the replaced id are dropped and counted. `Cons` = longest run of consecutive sequence numbers that never arrived (a late packet splits a run, so the value can also go down). An outage of the same running stream (e.g. a 60 s convergence) is not a restart: the id stays the same, the gap counts as loss and `Cons`. The silence rule only decides between restart and second sender when a new id appears. With `--sender IP` only streams of that IP get delay values.
- **Copies:** the same packet (timestamp + sequence) on two streams is reported as `Copies of stream A: N` with arrival-time difference avg/min/max.
- **Firewall / NAT:** UDP from receiver to the sender's sync port (5556) must be allowed. Without return path no delay is measurable (`--sender none`).

### Delay measurement

1. Warmup: 3 requests, discarded; none answered = sync server unreachable.
2. Initial sync: 16 samples, clock filter (median/MAD outlier rejection, then lowest RTT).
3. Resync every 3 s (`--resync-interval`), 8 samples per round, same filter.
4. Between resyncs the offset is extrapolated with a tracked linear drift rate.
5. Linux: sync exchange and data packets use kernel RX timestamps (`SO_TIMESTAMPNS`); elsewhere `time.time_ns()`.

Accuracy is limited by path symmetry: offset error ≈ half the asymmetry. Negative readings are floored to 0 on screen (`~`); CSV keeps the raw value.

## Web GUI

![Web receiver](screenshots/web-receiver.png)

![Web sender](screenshots/web-sender.png)

| Option | Effect |
|---|---|
| `-web` | Web GUI instead of the terminal UI: sender (up to 32 streams) and receiver are started, stopped and edited in the browser. `send ... -web` / `recv ... -web` start the streams / the receiver with the given options at once |
| `-wv` | Terminal run as usual plus a read-only web view of the same run |
| `-wvc` | Like `-wv`, the browser can also control the run (receiver: view, interval, IP, reset, stop; sender live view: start, stop, add, edit, delete, all streams) |
| `-port N`, `--web-port N` | HTTP port (default 8081). `--port` / `-p` of `recv` is the data port |
| `-bind ADDR` | Bind address (default `0.0.0.0`) |

- Receiver tab: stream table, log (download as text; START LOG / STOP LOG writes a CSV file, Enter = default name), settings dialog (same fields as the receiver form); the log jumps to the last line after every change and when a new stream is detected. Sender tab: stream table, add/edit dialog (same fields as the sender form).
- FILE OPERATIONS (both tabs, working directory of mautg.py): download active CSV log (only while logging), log text, config (`~/.mau/config.json`, downloaded as `mautg-config.json`); download selected `.csv`/`.txt`/`.html`/`.json` files (several = ZIP); upload files (max 16 MB); SAVE CONFIG (Enter = default file, or a name -> `NAME.json` in the working directory); delete files (not the active log); load a `.json` of the working directory as config (LOAD CONFIG FROM SERVER, one file, same as the upload); upload a config `.json` - it is validated, saved and activated; LOAD restarts what was running, LOAD & RUN starts all sender streams and the receiver (`-web` and `-wvc` without `send`/`recv`).
- Keys: `Tab` receiver/sender. Receiver: `s` start, `q` stop, `d` summary/per packet, `+`/`-` interval, `i` IP, `r` reset, `l` log. Sender: Up/Down/Home/End select, `Space` start/stop, `e`/Enter edit, `n` new, `d`/Del delete, `s`/`x` all. Dialogs: Enter = first button, Esc = cancel.
- Server gone / stopped: dialog MAUTG.PY STOPPED. The page reloads itself when mautg is back (as long as the dialog is open). RELOAD PAGE reloads only if the server answers (no browser error page). CLOSE ends the checking.
- Only one receiver runs per program: a start from the terminal replaces a receiver started in the browser; a start while another one runs is refused ("a receiver is already running").
- Page polls `/api/status` once per second; commands go to `POST /api/command` and are executed by the thread that owns the receiver / the streams.
- `-wvc` without `send`/`recv`: text menu in the terminal, receiver and streams can also be started and edited in the browser.
- `-wv`/`-wvc`: status bars of the terminal views show `web :PORT` (`ro` = read only).
- Exit in the browser stops the program; `-wvc` exit and `q` in the terminal are equivalent.
- No authentication, no TLS. `-bind 127.0.0.1` restricts the page to the local host (e.g. with an SSH tunnel).

## Protocol

Data packet (format version 1), all fields big-endian:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number (32)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
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

| Field | Offset | Size | Format | Description |
|---|---|---|---|---|
| Sequence | 0 | 4 | uint32 | Counter, starts at 0 |
| Timestamp | 4 | 8 | uint64 | µs since Unix epoch |
| Magic | 12 | 4 | ASCII | `MAUT` |
| Version | 16 | 1 | uint8 | 2 |
| Sync port | 17 | 2 | uint16 | Sync server port of the sender (0 = none) |
| Stream ID | 19 | 4 | uint32 | Random, new at every start of a stream |
| Padding | 23 | variable | bytes | `mautg_trafficgen_www.jeitler.cc:` if it fits, then `0x2A` |
| CRC | last 4 | 4 | uint32 | CRC-32 (zlib) over all preceding bytes |

Minimum UDP payload 27 bytes (55 on the wire). `--size` is the wire size (IP packet); UDP payload = size - 28 (1500 gives 1472). Maximum with DF set = MTU of the way to the destination (Linux: kernel route MTU; macOS: MTU of the interface owning the local address, from `ifconfig`); if it cannot be determined, 65507. With DF off the maximum is 65507 (the packets are fragmented). macOS/BSD: additionally limited by `net.inet.udp.maxdgram` (default 9216 -> 9244 on the wire; `sudo sysctl -w net.inet.udp.maxdgram=65535` raises it), otherwise the send fails with `Errno 40 Message too long`. The sender table shows DF (on/off). Checked in the dialogs and with `-s`; a loaded config is not checked against the MTU.

### OWD time sync protocol

UDP, default port 5556, one server per process.

```
Receiver                          Sender
   |--- REQ {t1_ns} ------------->|  T1: receiver TX
   |                              |  T2: sender RX
   |<-- RSP {t1,t2,t3_ns} --------|  T3: sender TX
   |                              |  T4: receiver RX
```

```
RTT    = (T4 - T1) - (T3 - T2)
Offset = ((T2 - T1) + (T3 - T4)) / 2
OWD    = receiver_now - sender_timestamp + offset
```

| Message | Size | Layout |
|---|---|---|
| Request | 9 | `!B` type 0x01, `!Q` t1_ns |
| Response | 25 | `!B` type 0x02, `!Q` t1_ns, `!Q` t2_ns, `!Q` t3_ns |

Wrong size or unknown type: discarded.

### Several instances on one host

Each instance binds its own sync server. Give each its own `--sync-port` (and data `-p`), or use `--no-sync-server` on all but one. Without that, instances share port 5556 (`SO_REUSEADDR`) and only one answers sync requests. Receivers get the sync port from the packets.

## Configuration and logs

- Menu settings: `~/.mau/config.json`.
- CSV (`recv -l [name]`): current directory; default name `mautg-log_YYYY-MM-DD_HH:MM:SS.csv` (Windows: `-` instead of `:`); absolute paths as given.
- CSV columns: `Timestamp, Seq, Delay_us, DSCP, DSCP_Name, Status, Stream, Source_IP, Sync_Port, Port, Cast, Dest_IP` (Delay_us = one-way delay in whole microseconds, raw, unclamped, no decimal separator; Dest_IP = destination address of the packet: multicast group, broadcast address or the unicast address it was received on; empty on Windows).

## Wireshark

[mau_protocol.lua](wireshark/mau_protocol.lua) (data packets, UDP 5001-5008) and [mau_owd_sync_protocol.lua](wireshark/mau_owd_sync_protocol.lua) (sync, UDP 5556). See the [Wireshark README](wireshark/README.md).

## Examples

```bash
# QoS check: EF marking, delay and loss at the receiver
./mautg.py send -d 239.1.1.1 -s 1500 --pps 1000 --dscp 46
./mautg.py recv -g 239.1.1.1 -i 5

# Link stress: 500 Mbit/s with 1500-byte packets
./mautg.py send -d 10.0.0.5 -s 1500 --burst --burst-mbps 500

# Asymmetry: measure both directions
hostA$ ./mautg.py send -d 10.0.0.2 --pps 10 ; hostB$ ./mautg.py recv -u -i 10
hostB$ ./mautg.py send -d 10.0.0.1 --pps 10 ; hostA$ ./mautg.py recv -u -i 10

# Subnet broadcast
./mautg.py send -d 172.17.17.255 -p 5001 -s 256 --pps 10
```

## Project structure

```
├── mautg.py              # sender + receiver + OWD sync server
├── e-install.sh          # installer / updater
├── screenshots/          # images for this README
├── wireshark/            # Lua dissectors + README
├── LICENSE
└── README.md
```
