# MAU — Multicast/AND/Unicast Traffic Generator & Analyzer

A lightweight, dependency-free Python tool for generating and analyzing network traffic with accurate one-way delay (OWD) measurement. Designed for network engineers who need to verify QoS policies, measure path latency, detect packet loss, and stress-test links.

`mautg` is a single script with two roles — **sender** (`send`) and **receiver** (`recv`) — selectable from an interactive menu or via sub-commands.

By Ewald Jeitler - https://www.jeitler.cc (also shown in the menus, the status bars of the live views and `--version`).

## Features

- **One Script, Two Roles** — `mautg.py send` / `mautg.py recv`, or start without arguments for a menu
- **Multicast, Unicast & Broadcast** — send to any destination type
- **One-Way Delay Measurement** — NTP-style 4-timestamp protocol, no third-party time server required
- **Kernel-Level RX Timestamping** — uses `SO_TIMESTAMPNS` on Linux to keep Python/GIL scheduling jitter out of the delay measurement
- **Drift-Aware Clock Tracking** — periodic resync (default 3s, configurable) with a clock-filter (outlier rejection) and linear drift extrapolation between syncs
- **Multi-Stream Sender** — up to 32 streams (`SEND_MAX_STREAMS` in the script), each with its own destination, port, size, rate/burst, DSCP, TTL, DF and source address; start, stop, edit, add and delete them while others keep running (sender live view)
- **Multiple Streams** — every sender (source IP + sync port) is tracked as its own stream **A, B, …** with separate sequence numbers, loss, misorder, statistics and time sync; a multicast stream arriving over two interfaces (Ethernet + WLAN) is shown twice instead of being mixed up
- **Clean Shutdown** — closing the terminal (SIGHUP), `kill` (SIGTERM) or a lost TTY stops sender and receiver; nothing keeps running in the background (use tmux/screen for persistent sessions)
- **Auto-Detected Sender** — without `--sender` the receiver learns the sender's IP and sync port from the first valid packet and syncs in the background; delay values appear as soon as the sync is done
- **Own-Traffic Check** — packets carry a magic value + CRC32; foreign UDP traffic on the port is ignored and counted
- **Sync Server in Every Mode** — the embedded OWD sync server also runs while receiving, so the peer can measure the reverse direction
- **Per-Interval Statistics** — throughput, delay (avg/min/max), loss, DSCP tracking
- **Burst Mode** — saturate links at max speed or with a configurable bandwidth limit
- **DSCP/QoS Marking** — set and track DiffServ code points end-to-end
- **Don't Fragment (DF) Bit** — optionally set DF on all packets (Linux)
- **Sender Restart Detection** — receiver automatically resets sequence tracking
- **CSV Export** — log every packet for post-analysis (raw, unclamped delay values)
- **Wireshark Dissectors** — included Lua plugins for the data-packet and the OWD sync protocol
- **Zero Dependencies** — Python 3.6.1+ standard library only (on Python 3.7 and newer nothing is slower or missing; see *Python versions*)
- **Cross-Platform** — tested on Linux (x86/ARM), macOS, Raspberry Pi OS (kernel RX timestamping is Linux-only; falls back cleanly elsewhere)

## Installation / Update

```
/bin/bash -c "$(curl -fsSL https://www.jeitler.cc/mautg/e-install.sh)"
```

The installer puts `mautg.py` into `/usr/local/bin` and creates the command `mautg`. Running it again updates.

or

```bash
# download mautg.py from https://www.jeitler.cc/mautg/
chmod +x mautg.py
```

### Python versions

mautg runs on **Python 3.6.1 or newer** (standard library only). Newer Python versions are faster per packet (receiver processing measured on one x86 machine: 2.0 us with 3.8, 1.3 us with 3.11, 1.3-1.7 us with 3.13) but have no other advantage; no feature depends on the version. Python 3.6 is the interpreter inside the **Cisco IOS-XE Guest Shell** (CentOS 8), so the tool can be copied there and started with `python3 mautg.py` (check with `guestshell run python3 --version`). Differences on 3.6: the clock is read through `time.time()` (microsecond precision is kept), and the output encoding follows the locale (see below). Tested with Python 3.8 and 3.13; the 3.6 compatibility itself (syntax, standard-library calls) was checked statically and **not yet run on a real 3.6 interpreter**.

**Special characters (check marks, dashes, box frames, `us`)**: mautg writes Unicode only if the locale says UTF-8 (`echo $LANG` shows e.g. `en_US.UTF-8`); otherwise (e.g. `LANG` unset or `C`, as in the Guest Shell) it automatically falls back to plain ASCII (`OK`, `-`, `+===+`). `--ascii` or `MAUTG_ASCII=1` forces ASCII. If instead you see strange sequences such as `‚úì` or `‚Äî`, the *terminal program* is decoding UTF-8 with the wrong character set (typical: Mac Roman in SecureCRT): set the session's character encoding to UTF-8 (SecureCRT: Session Options > Terminal > Appearance > Character encoding), and `export LANG=en_US.UTF-8` on the router side, or just use `--ascii`.

Guest Shell notes: the container has its own network namespace and sees only its own interface (management port `eth0`, or the VirtualPortGroup / AppGigabitEthernet interface of the application); traffic on the router's front ports is not visible there. Unicast works with an address on that interface. Multicast needs the router to forward the group to that interface (PIM, or `ip igmp join-group` / static join on the VirtualPortGroup). The packets run through the router CPU and the Guest Shell resource profile, so use low rates (hundreds to a few thousand pps) and no performance tests there.

## Quick Start

```bash
# Terminal 1: Start sender (includes embedded time sync server)
./mautg.py send -d 239.1.1.1 -p 5005 --pps 100

# Terminal 2: Start receiver with OWD delay measurement
./mautg.py recv -g 239.1.1.1 -p 5005 -i 5
```

No sender IP needed: the receiver detects it from the first packet and shows delay values once the time sync is done (a few seconds).

## Menu (full-screen text UI)

```bash
./mautg.py
```

```
+- mautg v1.46 --  Sender -- Receiver ----------------------------------------+
| Destination            239.1.1.1                                           |
| Destination port       5001                                                |
| Packet size (bytes)    1500                                                |
| Mode                   < Normal >                                          |
| Rate (pps)             100                                                 |
| Burst limit (Mbit/s)   (unlimited)                                         |
| DSCP                   46 (EF)                                             |
| TTL                    32                                                  |
| Don't fragment (DF)    [ ]                                                 |
| Source address         any                                                 |
| Source port            any                                                 |
| Local OWD sync port    5556                                                |
|                                                                            |
|  [ Start sender ]                                                          |
|  [ Save settings ]                                                         |
+----------------------------------------------------------------------------+
 [UP/DOWN]=SELECT  [ENTER]=EDIT  [S/R]=SENDER/RECEIVER  [ESC/Q]=QUIT
```

The key line at the bottom of every screen shows the keys as `[KEY]=ACTION` (the key highlighted, everything in capitals - the keys themselves are not case sensitive).

One form per role (tabs **Sender** and **Receiver**, switch with `s` and `r`, or `Tab`). Only a few keys are needed everywhere:

| Key | Action |
|---|---|
| Up / Down | select a row (rows that do not apply, e.g. *Sender IP* while *OWD sync* is `auto`, are shown in `( )` and skipped) |
| Enter | edit a text/number row (Enter = accept, Esc = cancel, Ctrl-U = clear); run a button |
| Space, Left / Right | toggle `[x]` rows, change `< choice >` rows |
| `s` / `r` (or Tab / Shift-Tab) | switch to the Sender / Receiver tab |
| Esc / q | quit (asks *Save & quit / Quit without saving / Cancel* if there are unsaved changes, marked `*` in the title) |

`[ Start ... ]` runs the sender/receiver, `[ Save settings ]` writes `~/.mau/config.json`. Invalid values are rejected with a message in the footer. Ctrl+C while sending stops the run and returns to the form; the receiver is stopped with `q`.

The UI uses only plain ANSI/VT100 sequences (cursor addressing, reverse video, scroll region) and the Python standard library, so it also works on a VT100 and over plain SSH. Frames are ASCII unless the locale is UTF-8. Colors are decoration only (`--no-color` or `NO_COLOR` switches them off). It needs a real terminal of at least 60x16; with a pipe, `TERM=dumb`, a smaller terminal or `--no-tui` the simple line menus (numbers/letters) are used instead.

### Leaving: one rule everywhere

`q` or `Esc` leaves the current screen / goes one level back: cancels the stream editor and pick lists and quits the form (with the *unsaved changes* question; `Esc` there quits without saving, *Cancel* goes back). While a text field is being edited `Esc` cancels the edit (a typed `q` is just a character). In the **live views** (receiver, sender) only `q` stops - `Esc` is deliberately ignored there, so a running measurement is not ended by accident. **Ctrl+C** stops whatever is running at any time (the live view returns to the menu if it was started from there, otherwise the program ends) and quits the form immediately.

### Pick lists (sender form)

Rows marked "choose from list" open a sub menu (Up/Down/PgUp/PgDn, Enter = choose, Esc = cancel):

- **Source address** lists the IPv4 addresses of this host (with the interface name where it can be determined: from `ip`, `ifconfig` or `ipconfig`), `any` and `Other address...` for manual entry. A manually typed address is accepted only if it exists on this host, so a wrong address is rejected; if a saved address has disappeared (other network) the form refuses to start and jumps to the row. The source address also selects the outgoing interface for **multicast** destinations - so you can choose Ethernet or Wi-Fi.
- **DSCP** lists the standard classes with value, name and meaning (BE, CS1-CS7, AF11-AF43, VA, EF) plus `Custom value (0-63)...`.

### Receiver form

```
+- mautg v1.46 --  Sender -- Receiver ----------------------------------------+
| Receive mode           < Multicast >                                       |
| Multicast group(s)     239.1.1.1                                           |
| Multicast interface    all                                                 |
| Data port(s)           5001-5008                                           |
| OWD sync               < auto >                                            |
| Sender IP              ()                                                  |
| Sender sync port       from packet                                         |
| Resync interval (s)    3                                                   |
| Summary (s)            every 2 s                                           |
| Compact summary        ([ ])                                               |
| Show sender IP         [ ]                                                 |
| Verify every packet    [ ]                                                 |
| CSV log                < off >                                             |
| Log file name          (-)                                                 |
| Live view              [x]                                                 |
| Local OWD sync port    5556                                                |
|                                                                            |
|  [ Start receiver ]                                                        |
|  [ Save settings ]                                                         |
+----------------------------------------------------------------------------+
```

`OWD sync`: `auto` = detect every sender from its packets, `sender IP` = fixed sender (enter the IP in the next row), `off` = no delay values. `CSV log`: `auto` = timestamp name (the row shows the real file name that the run will use), `file` = your own name.

### Live view (receiver)

With *Live view* on (default in the form; default of `recv` too; `--no-live` switches it off, terminal at least 80x16) the receiver uses the whole screen:

```
 mautg v1.46  239.1.1.1:5001-5008  sync auto  streams 2  00:01:23  summary 2s
--------------------------------------------------------------------------------
 St | Source          |  Port | Cast |  Packets |  Loss% |  Miss |    Avg |    Max |  Mbit/s | Sync
------------------------------------------------------------------------------------------------
 A  | 192.168.1.10    |  5001 | MC   |    12345 |   0.00 |     0 |   0.25 |   1.30 |    0.04 | ok
 B  | 192.168.1.10    |  5002 | UC   |    12301 |   0.35 |    43 |   0.31 |   2.01 |    0.04 | ok
------------------------------------------------------------------------------------------------
 S |  Port | Cast |   Interval |   Throughput | DSCP  | Stat | Packets       | Lost         | Dly
------------------------------------------------------------------------------------------------
 A |  5001 | MC   |       0–2s |    0.04 Mbps | EF    | OK   | Pkt:      101 | LPkt:      0 | Dly:0.25
 ...
 [Q]=STOP  [P]=PAUSE  [R]=RESET  [I]=IP  [D]=PACKETS/SUMMARY  [+/-]=INTERVAL
```


- **Status bar** (top), rules (`----`) and ` | ` between **all** columns (always a blank on both sides of the bar). Terminals that are too narrow for that get the columns grouped instead (`Min`, `Ord`, `SPort`, `DSCP`, `Size` and finally `Miss` are left out first); the full, fully separated table needs about 110 columns (with the `Port` column), then **one table row per stream** (delay in ms, `Sync` = `ok`/`wait`/`FAIL`/`none`/`off`). Wide terminals add `Min` and the columns the columns `SPort` (sync port of the sender), `DSCP` (the *current* DSCP of the stream, i.e. of the latest packet; `CS1*` = it changed during the run) and `Size`. With several ports a `Port` column is added (and `Min` is dropped on narrow terminals).
- **Headline** above the log names every field of the line format in use (per packet or summary, with/without stream label and sender IP).
- **Log** in its own scroll region. It uses the *original* line formats (the same as without live view, including the sender IP) whenever the terminal is wide enough; only on a small terminal it falls back to a compact and finally to a narrow format. The widest per-packet line needs 87 columns (+4 with several streams, +18 with *Show sender IP*); a full summary line 149 (+22); the compact summary 83 (+22).
- **Keys:** `q` stop (final statistics follow), `p` pause the log, `i` show/hide the sender IP, `r` reset the live view (forget all streams and counters, clear the screen, restart the clock; OWD sync and the CSV log keep running, streams show up again with their next packet), `d` switch between per-packet lines and summary (the last interval is restored), `+` / `-` change the summary interval (1, 2, 3, 5, 10, 20, 30, 60 s; shown as `summary Ns` in the status bar; the running interval starts over).

The table shows up to 2/4/8 streams depending on the terminal height.

**Colors:** the scheme follows `eping.py`: black background, bold white titles and rules, bright green = good/active, coral red = error, bright cyan = values and info, grey = hints and inactive, selected row in reverse video (no blue bars or frames). Used where the terminal supports colors (title, tabs, selected row, values, loss/sync state). On a VT100 or with `--no-color` / `NO_COLOR` they fall back to plain reverse video and bold - nothing depends on color. `--color` forces colors on if the terminal type does not advertise them.

Ctrl+C while sending or receiving also works everywhere. The OWD sync server runs for the whole session.

Closing the terminal window, `kill <pid>` or a dropped SSH connection ends the whole process (exit code 129 for SIGHUP, 143 for SIGTERM) — sender and receiver never keep running headless; the terminal is restored. For sessions that must survive a closed terminal run `mautg` inside `tmux` or `screen`.

### Simple line menus (fallback)

Used without a terminal, with `--no-tui` or on terminals smaller than 60x16: numbered/lettered menus for sender and receiver with the same settings. The line-menu sender handles a single stream only; multiple streams need the full-screen UI, the sender live view (at least 80x16) or `send --stream`.

## Sub-command `send`

Traffic generator. `./mautg.py send` without a destination (and without `--burst` / `--stream`) opens the sender menu; with a destination it starts the **sender live view** (use `--no-live` for plain output).

```bash
# Constant rate
./mautg.py send -d 239.1.1.1 -p 5005 -s 1500 --pps 1000 --dscp 46

# Burst: maximum speed
./mautg.py send -d 10.0.0.5 --burst

# Burst: limited to 200 Mbit/s
./mautg.py send -d 10.0.0.5 -s 1500 --burst --burst-mbps 200

# Broadcast
./mautg.py send -d 172.17.17.255 -p 5005 --pps 50

# Set the Don't Fragment bit (Linux only)
./mautg.py send -d 10.0.0.5 -s 1500 --pps 100 --df
```

### Sender live view and multiple streams

```
 mautg v1.46  send  sync port 5556  streams 3/32 (2 running)  00:02:10
--------------------------------------------------------------------------------
  # State   | Destination     |  Port | Size | Rate     | DSCP    |  Sent Mbit/s
--------------------------------------------------------------------------------
  1 running | 239.1.1.1       |  5001 |  256 | 100 pps  | 46 EF   | 13020   0.20
  2 running | 239.1.1.1       |  5002 | 1500 | 50 Mb/s  | 0 BE    | 421k   50.01
  3 stopped | 10.0.0.5        |  5003 |  512 | 20 pps   | 8 CS1   |   840   0.00
--------------------------------------------------------------------------------
 Stream 2:  source any:any   TTL 32   DF off   seq 421337   4166.7 pps now

 Stream 2 updated
 [Q]=QUIT  [SPACE]=TOGGLE  [E]=EDIT  [N]=NEW  [D]=DEL  [S/X]=ALL  [W]=SAVE
```

Up to 32 streams run side by side, each in its own thread with its own sequence numbers and socket; all share the one OWD sync server, so a receiver in auto mode syncs once per sender. The receiver tells the streams apart by source IP and **destination port**, so every stream needs its own port (the editor refuses a port that another stream already uses with the same source address).

| Key | Action |
|-----|--------|
| Up / Down | select a stream |
| Space | start / stop the selected stream (the sequence continues, so the receiver sees no loss) |
| `s` / `x` (also `S` / `X`) | start / stop **all** streams |
| `e` / Enter | edit the selected stream — **also while it is running**, changes take effect immediately (sequence numbers continue) |
| Left / Right in the editor | switch to the previous / next stream (also Tab / Shift-Tab, PgUp / PgDn; wraps around). Changes of the current stream are applied first. On the *Mode* and *DF* rows Space / Enter change the value |
| `n` | new stream (a copy of the selected one with the next free port); it starts right away |
| `d` / Del | delete the selected stream (asks `y/n`) |
| `w` | save the streams to the config |
| `q` / Ctrl+C | stop everything (totals per stream follow) |

Per stream: destination, port, packet size (wire size), mode (Normal with pps, or Burst with a Mbit/s limit, 0 = unlimited), DSCP, TTL, DF bit, source address and source port. The measured rate in the table is the actual rate over the last half second. A stream whose socket cannot be set up (e.g. a source address that does not exist) shows `ERROR` and the reason below the table; fix it with `e`, it then starts again. Send errors during operation (link down, ...) are counted and retried every 0.2 s.

In the form menu (`./mautg.py send`, tab *Sender*) **Left/Right switch between the streams** (title: `Sender 2/3`); the form always shows the selected stream. *New stream* adds a copy of the current one with the next free port, *Delete this stream* removes it, *Start sender* checks all streams (settings, duplicate ports) and starts them. On the form, Mode and DF are changed with Space/Enter. Stream 1 is also what `send` without a saved stream list starts; streams 2–32 are saved as *extra_streams*. The stream editor of the sender view (`e`) has the same rows as this form. On the command line only the streams given there are started:

```bash
# Three streams at once: EF voice, a 50 Mbit/s load stream, a slow CS1 stream
./mautg.py send --stream 239.1.1.1:5001,pps=100,dscp=EF \
                --stream 239.1.1.1:5002,size=1500,burst=50 \
                --stream 10.0.0.5:5003,pps=20,dscp=CS1,size=512

# Same, but without the live view (status line every 5 s)
./mautg.py send --no-live --stream ... --stream ...
```

`--stream` takes `DEST:PORT` followed by optional `pps=`, `size=`, `dscp=` (number or name), `ttl=`, `burst` / `burst=MBIT` (burst mode), `src=`, `sport=` and `df`; whatever is not given comes from the other `send` options and the saved settings. Without a terminal (or with `--no-live`) one stream prints plain output, several streams print a status line every 5 s.

### Options (`send`)

| Option | Description |
|--------|-------------|
| `-d`, `--destination` | Destination IP address |
| `-p`, `--port` | Destination UDP port |
| `-s`, `--size` | Packet size in bytes (wire size, including IP/UDP headers) |
| `--pps` | Packets per second |
| `--dscp` | DSCP value (0–63) |
| `--ttl` | TTL (1–255) |
| `--source` | Source IP of this host (must exist; also selects the multicast interface) |
| `--source-port` | Source UDP port |
| `--burst` | Burst mode (send as fast as possible, or paced with `--burst-mbps`) |
| `--burst-mbps` | Bandwidth limit for burst mode in Mbit/s (0 = unlimited) |
| `--df` | Set the Don't Fragment (DF) bit on all packets (Linux only) |
| `--sync-port` | Local OWD sync server port (default: 5556) |
| `--no-sync-server` | Do not start the OWD sync server |
| `--stream SPEC` | Add a stream (repeatable, up to 32), see above |
| `--no-live` | Plain output instead of the sender live view |
| `-m`, `--menu` | Force the sender menu |

Unspecified values come from the saved config (`s` in the menu).

### Performance

Measured on a small 2-core Linux VM with sender and receiver on the same machine (so both compete for the CPU; real hosts do better), 200-byte packets:

| Test | Result |
|---|---|
| One stream, burst `max` (sender only) | 303k pkt/s |
| Four streams x 50k pps (sender only) | 94k pkt/s |
| Receiver without loss (summary view, sender on the same host) | 200k pps |
| Receiver CPU per packet (processing only) | 1.3 us |

How it is done: per-packet work in the sender loop is done with local variables and packets that are due are sent as a batch; the receiver parses known streams inline, uses non-blocking sockets (no extra `poll()` per packet) and asks for a larger receive buffer (up to 8 MB, the kernel reduces it to its limit). Limits: Python runs one thread at a time (the GIL), so the total of all streams of a sender stays around 100-300k pps; the receiver buffer is capped by the OS (Linux: `sysctl net.core.rmem_max`, macOS: `kern.ipc.maxsockbuf`) - raise it for very high rates, e.g. `sudo sysctl -w net.core.rmem_max=16777216`. The per-packet display (`-i 0`) and a CSV log (`-l`) cost more per packet than the summary view.

#### Pacing and burstiness

- **One running stream:** each packet is sent on its own at its due time. The thread sleeps until about 0.5 ms before the packet is due and then waits actively (`perf_counter`), so the OS timer jitter (typically 50-100 us) does not show up in the spacing. Cost: one CPU core at 100 % for rates above about 2000 pps. Measured inter-packet gaps (2-core VM, 10k pps = 100 us): median 100.0 us, 95 % below 103 us, under 1 % of the gaps back-to-back.
- **Several running streams:** spinning threads would fight for the GIL and slow each other down, so streams with an interval below 1 ms sleep until the packet is due. After a late wake-up the packets that have become due are sent back-to-back (at most 64 per round). The average rate stays exact; the spacing at 10k+ pps is coarser (groups of a few packets, some tens of us).
- **Burst mode** (`max` or a Mbit/s limit) is meant to be bursty and sends as fast as the limit allows. A stream that falls more than 1 s behind (suspend, overload) does not catch up with a burst; it restarts its schedule.

#### Receiver overload (loss that is not network loss)

If the receiver cannot keep up, the local kernel drops packets from the socket queue, and they show up as loss. The usual cause is the display itself: a terminal cannot draw 40,000 lines per second (per-packet mode, `-i 0` or key `d`). Therefore:

- **Prevention:** the per-packet display is limited to 500 lines/s (`--print-limit N`, 0 = off). Counting, loss detection, delay statistics and the CSV log still see every packet; only the screen is thinned out. The live status bar shows `DISPLAY LIMITED 500/S` while that happens, the plain output prints a one-time notice, and the final statistics tell how many lines were skipped.
- **Detection (Linux):** the kernel's own drop counter (`SO_RXQ_OVFL`) is read with every packet. The live status bar shows `RX OVERLOAD: n DROPPED LOCALLY`, every summary prints `receiver overloaded: the local kernel dropped n packets in this interval - this is NOT network loss`, and the final statistics list the total. The number is exact: it equals the loss that the receiver reports for the same period.
- **Detection (any OS):** if the receive queue was not empty for more than a second the receiver is at its processing limit; the status bar shows `RX AT LIMIT` and the summary adds a note. (macOS has no drop counter per socket, so only this indication is available there.)

**The receive buffer is the cheapest remedy.** It absorbs short stalls (a scheduler hiccup, a screen redraw). The kernel caps what a normal user may request (Linux: `net.core.rmem_max`, only about 212 KB on Raspberry Pi OS and many distributions - roughly 100 packets of 1500 bytes, i.e. 1-2 ms at 80k pps). The receiver asks for up to 8 MB; what it really got is shown in the banner (`Receive buffer: ... KB`), and after the first local drops a hint with the exact command is printed. Two ways to fix it:

```
sudo sysctl -w net.core.rmem_max=16777216                                   # until reboot
echo 'net.core.rmem_max=16777216' | sudo tee /etc/sysctl.d/99-mautg.conf     # permanent
```

or run the receiver as root, which may exceed the cap (`SO_RCVBUFFORCE`, no sysctl needed). Measured with 100k pps of 1000-byte packets: 416 KB buffer 1.0 % loss, 16 MB buffer 0 %. macOS: `sudo sysctl -w kern.ipc.maxsockbuf=8388608`. A bigger buffer only helps against short stalls; against a receiver that is permanently too slow (about 150-250k pps per Python process, less on a Raspberry Pi) only fewer packets or a lighter display help.

While a receiver is overloaded the delay values are not reliable either (packets wait in the queues of the host). Fix the cause: summary view instead of per-packet, a quieter terminal (no `tmux` scrollback over a slow link), or a faster host.

#### Experience on Raspberry Pi 5 (direct 1 Gbit/s link, no switch)

Test: sender in burst mode `max`, 1500-byte packets, receiver in summary view. The sender offers about 975 Mbit/s of IP traffic (about 81k pps), which is the line rate of Gigabit Ethernet, so this test also exercises the limit of the link itself.

- The receiver (one Python process) takes about **65k pps (about 790 Mbit/s)** with all functions on (CRC check, sync, delay, DSCP, cast); the rest is lost, about 17-19 %.
- Only about a quarter of that loss is counted by the socket (`RX OVERLOAD: ... DROPPED LOCALLY`); about three quarters is lost before the socket (NIC ring, kernel backlog). A larger `net.core.rmem_max` alone therefore does not remove it.
- Delay values are meaningless in this state (a constant 85-95 ms: full queues, not path delay).
- Rule of thumb for measurements on a Pi 5: stay at **60k pps or less** (about 700 Mbit/s with 1500-byte packets, more with smaller packets only up to that packet rate) if loss and delay must be trustworthy. At that rate the receiver stays clean; an x86 PC handles 200k pps and more.

Things that can be checked or adjusted on the Pi (not tested here, no code change needed): where packets are lost (`ip -s link show eth0`, `ethtool -S eth0 | grep -i -E 'drop|discard|over'`, third column of `/proc/net/softnet_stat`); the backlog (`sudo sysctl -w net.core.netdev_max_backlog=10000`, default 1000); the receive buffer (see above); per-core load with `top` and key `1` - if one core is at 100 % with `ksoftirqd` next to Python, pinning the receiver to another core helps (`taskset -c 3 ./mautg.py recv ...`). Batched reception (`recvmmsg`) was measured and brings nothing, because reading timestamps and destination address per packet costs more than the system call; several receiver processes do not help for one stream either, because the kernel always assigns a stream to the same socket.

### Packet Size

The `--size` / menu option specifies the **wire size** (Layer 3 IP packet). The tool automatically subtracts the 28-byte IP/UDP header overhead. For example, entering 1500 produces a 1472-byte UDP payload, resulting in exactly 1500 bytes on the wire — compatible with standard 1500-byte MTU without fragmentation.

## Sub-command `recv`

Traffic receiver with real-time statistics, OWD measurement, and CSV logging. `recv` starts immediately with its defaults and the options given; it does **not** use the saved menu config, so a command line behaves the same every time. Use `-m` to open the receiver menu.

### Usage

```bash
# Multicast, default: summary every 2 seconds
./mautg.py recv -g 239.1.1.1 -p 5005

# Per-packet display
./mautg.py recv -g 239.1.1.1 -p 5005 -i 0

# Summary every 5 seconds
./mautg.py recv -g 239.1.1.1 -p 5005 -i 5

# Compact summary every 1 second (no timestamp/size columns)
./mautg.py recv -g 239.1.1.1 -p 5005 -c 1

# Unicast mode
./mautg.py recv -u -p 5005 -i 2

# CSV log with automatic name, e.g. ./mautg-log_2026-10-07_14:02:04.csv
./mautg.py recv -g 239.1.1.1 -i 10 -l

# CSV log with your own name (written to ./capture.csv)
./mautg.py recv -g 239.1.1.1 -i 10 -l capture.csv

# Custom resync interval (default: 3s)
./mautg.py recv -g 239.1.1.1 -i 5 --resync-interval 30

# Fixed sender (e.g. several IPs, NAT, special sync port)
./mautg.py recv -g 239.1.1.1 --sender 192.168.1.10 --sender-sync-port 5600

# No time sync at all (throughput / loss only)
./mautg.py recv -g 239.1.1.1 --sender none
```

### Per-Packet Display (`-i 0`)

```
18:15:59 | Seq:    21 | Size:  256 | DSCP:EF    | Delay:   0.25ms | OK    | Loss:  0.00%
18:15:59 | Seq:    22 | Size:  256 | DSCP:EF    | Delay:   0.30ms | OK    | Loss:  0.00%
```

As soon as a second stream is detected, every line gets a stream label and a legend is printed once:

```
ⓘ Several streams detected — lines now carry a stream label. Stream A = 192.168.1.10 (sync port 5556)
✓ New stream B = 192.168.1.10 (sync port 5557) — synchronizing, delay values follow after sync
18:16:01 | A | Seq:   946 | Size:  256 | DSCP:EF    | Delay:   0.25ms | OK    | Loss:  0.00%
18:16:01 | B | Seq:   122 | Size:  256 | DSCP:EF    | Delay:   0.31ms | OK    | Loss:  0.00%
```

With `--show-ip` (menu item `i`) the sender IP follows the label (and appears in single-stream runs too):

```
18:16:01 | A | 192.168.1.10   | Seq:   946 | Size:  256 | DSCP:EF    | Delay:   0.25ms | OK    | Loss:  0.00%
```

A `~` in place of the leading space before the delay value (e.g. `Delay:~  0.00ms`) marks a reading that measured negative and was floored to 0 for display — see [Delay Measurement](#delay-measurement) below. The CSV log (`-l`) always keeps the raw, unclamped value.

### Interval Summary (`-i`)

```
20:47:37 |      0–2s |  695.81 Mbps |  1500B | DSCP:BE    | OK     | Pkt:    58023 | Loss: 0.00% Pkt:     0 | Dly(ms): avg:0.42 min:0.33 max:0.55
20:47:39 |      2–4s |  697.24 Mbps |  1500B | DSCP:BE    | OK     | Pkt:    58104 | Loss: 0.00% Pkt:     0 | Dly(ms): avg:0.28 min:0.19 max:0.96
20:47:41 |      4–6s |    0.00 Mbps |  1500B | DSCP:BE    | no traffic received
```

### Compact Interval Summary (`-c`)

A narrower one-line form (no timestamp, size or full DSCP columns) meant for tmux panes / multi-stream layouts:

```
      0–1s |    0.04 Mbps | BE    | OK   | Pkt:       21 | LPkt:      0 | Dly:0.29
      1–2s |    0.04 Mbps | BE    | OK   | Pkt:       20 | LPkt:      0 | Dly:0.34
```

All values are calculated **per interval** and reset after each line. With several streams every interval prints one line per stream, prefixed with the stream label. The final summary on Ctrl+C shows lifetime totals (one block per stream).

### Options (`recv`)

| Option | Description |
|--------|-------------|
| `-I`, `--interface` | Interface(s) for the multicast join: `all` (default), `auto`, an IP address of this host or an interface name (`eth0`), see *Multicast interface* |
| `-g`, `--group` | Multicast group(s), list / range / short range (default: 239.1.1.1), see *Several multicast groups* |
| `-p`, `--port` | Listen port, range or list, e.g. `5005`, `5005-5010`, `5005,5007,6000-6003` (default: 5001-5008) |
| `-u`, `--unicast` | Unicast mode (bind to own IP) |
| `-i`, `--interval` | Summary interval in seconds (default: 2; `0` = per-packet display) |
| `-c`, `--compact` | Compact summary interval in seconds (overrides `-i`) |
| `-l`, `--log` | CSV log in the current directory; without a name: `mautg-log_<date>_<time>.csv` (e.g. `mautg-log_2026-10-07_14:02:04.csv`) |
| `--sender` | Sender IP for OWD time sync (default: auto-detect from the first valid packet; `none` = no sync, no delay values) |
| `--sender-sync-port` | OWD sync port on the sender (default: taken from the packets; 5556 with an explicit `--sender`) |
| `--no-live` | Plain scrolling output instead of the full-screen live view (the default view when stdout is a terminal of at least 80x16; keys `q`/`p`/`i`/`d`) |
| `--no-tui`, `--no-color`, `--color` | Simple line menus / no color codes / force colors (also for `send`) |
| `--ascii` | ASCII-only output (automatic if the locale is not UTF-8; also `MAUTG_ASCII=1`) |
| `--show-ip` | Show the sender IP in every line, right after the stream label (default: off) |
| `--verify` | Check CRC + padding pattern of every packet (default: magic check per packet, full check on sender lock-in) |
| `--print-limit N` | Per-packet display (`-i 0`): at most N lines per second (default 500, 0 = unlimited); every packet is still counted, only the display is thinned out |
| `--resync-interval` | OWD resync interval in seconds (default: 3) |
| `--sync-port` | Local OWD sync server port (default: 5556) |
| `--no-sync-server` | Do not start the OWD sync server |
| `-m`, `--menu` | Open the receiver menu |

### Multicast interface

A multicast receiver has to tell the kernel on which interface it wants a group (IGMP join); packets that arrive on an interface without a membership are dropped by the IP stack, even though `tcpdump` (which looks at the wire) still shows them. With only `INADDR_ANY` the kernel picks the interface from its routing table, which is the wrong one on hosts with several interfaces (e.g. Ethernet + WLAN, Docker, VPN). Therefore `-I` / the form field *Multicast interface* (pick list of the interfaces of this host) controls it:

- `all` (default): join every group on **every** IPv4 address of the host except loopback. An interface that cannot join (down, no multicast) is skipped and reported in the banner; the receiver fails only if none works. Linux allows 20 memberships per socket (`net.ipv4.igmp_max_memberships`): groups x interfaces beyond that are reported as failed joins - choose one interface or fewer groups then.
- `auto`: the kernel chooses.
- an address (`-I 192.168.1.7`) or an interface name (`-I eth0`): join on that interface only; errors are fatal.

The banner (`--no-live`) shows `Multicast join on: all (eth0 192.168.1.7, wlan0 ...)`. Multicast arriving on two interfaces at once is recognised as the same stream (duplicate counter).

### Cast: MC / UC / BC

Every stream shows how its packets reached the receiver: **MC** multicast (destination 224.0.0.0/4), **UC** unicast, **BC** broadcast (255.255.255.255 or a directed broadcast `x.y.z.255` that is not an address of this host). The receiver reads the destination address of each datagram from the kernel (`IP_PKTINFO` on Linux, `IP_RECVDSTADDR` on macOS/BSD), so it is the real destination, not a guess from the settings. It appears as column `Cast` in the live table, in the per-packet and in the summary lines (`Ty` on narrow screens) and in the CSV log; `--` means unknown (Windows does not report the destination address). A stream shows the cast of its most recent packet.

### Several multicast groups

`-g` (form field *Multicast group(s)*) takes more than one group: a list `-g 239.1.1.1,239.1.1.10`, a range `-g 239.1.1.1-239.1.1.10`, the short form `-g 239.1.1.1-10` (only the last octet of the end address; same result as the full range) and any combination, e.g. `-g 239.1.1.1-3,239.1.1.9,239.2.0.1-239.2.0.30`. The status bar and banner show the compressed form (`239.1.1.1-10`). At most **16 groups** (more is refused with `too many groups (max 16)`): that stays below the Linux default of 20 memberships per socket (`net.ipv4.igmp_max_memberships`), so every port socket joins all groups and nothing depends on sysctl settings. A stream is not tied to a group - the receiver shows streams by sender IP, sync port and destination port, whatever group they arrive on. For a wider range start a second receiver (e.g. one with `-g 239.1.1.1-16`, one with `-g 239.1.1.17-32`).

### Port Ranges and Lists

The default is the range **5001-5008**. `-p` takes a single port, a range or a list: `recv -p 5005-5010`, `recv -p 5005,5007,6000-6003` (form field *Data port(s)*, same syntax). The receiver opens one socket per port (max. 512 ports) and handles them together. A stream is identified by **sender IP + advertised sync port + destination port**, so the same sender talking to several ports shows up as several streams (A-Z, 0-9; max. 36). As soon as more than one port is listened on, the port appears in the live table, in the log lines (`Port` column, with headline), in the final statistics and in the CSV (`Port`). Ports that cannot be opened (in use, <1024 without root) are reported and skipped; the rest keeps working. With a single port one socket is used.

### Sender Detection and Foreign Packets

- **Auto-detect (default):** the first valid packet decides. Its source IP and the sync port advertised in the packet header are used for the time sync, which runs in a background thread. Until it succeeds, delay values show `n/a`; after that they appear and are tracked as described below. If the sync cannot be established (firewall, NAT, no sync server on the sender), the receiver says so and retries every 5 s while throughput and loss keep working.
- **Own-traffic check:** every packet must carry the magic `MAUT` and format version; everything else on the port is ignored and counted ("non-mautg" in the final statistics). Full validation (CRC32 and padding pattern) happens when a new sender is locked in; `--verify` does it for every packet. The per-packet magic check is a few-byte slice compare and negligible next to the rest of the per-packet work.
- **One stream per sender:** a stream is identified by source IP + advertised sync port. Each stream (up to 32) has its own sequence tracker (loss, misorder, sender-restart detection), statistics, DSCP and its own OWD sync (auto mode). Two senders — or the same multicast stream arriving over two interfaces — are therefore never mixed up. With `--sender IP` only the streams of that IP get delay values (a stream from another IP only if no stream matched yet, e.g. NAT); the others show `n/a`.
- **Copies of the same packets:** if the same packet (same sender timestamp and sequence) arrives on two streams, the final statistics of the later stream show `Copies of stream A: N` with the arrival-time difference (avg/min/max) — the path difference of e.g. Ethernet vs. WLAN.
- **Special cases:** several IPs on the sender, NAT or an unusual sync port → use `--sender` / `--sender-sync-port`. A firewall must allow UDP from the receiver to the sender's sync port (default 5556) — the data flows the other way. In one-way networks without a return path no delay can be measured; use `--sender none`.

### Delay Measurement

Without a working sync, delay values are shown as `n/a`. The receiver performs an NTP-style 4-timestamp handshake with the sender's embedded sync server:

1. Warmup phase (3 packets, discarded; if none is answered the sync server is considered unreachable)
2. Initial sync: 16 samples, filtered by an NTP-style clock filter (median/MAD outlier rejection, then lowest-RTT sample selected)
3. Background resync every 3 seconds by default (`--resync-interval`), 8 samples per round, same clock filter
4. Between resyncs, the offset is **extrapolated** using a tracked linear drift rate rather than held flat as a step function
5. On Linux, both the sync exchange and data-packet reception use kernel-level RX timestamps (`SO_TIMESTAMPNS`) instead of a Python-level `time.time_ns()` call, removing scheduler/GIL jitter from the measurement

The accuracy depends on path symmetry — this is a fundamental limit of any two-way exchange without a shared external clock (GPS/PTP), not something software can fully correct. On an asymmetric path the offset error is roughly half the asymmetry, which can occasionally make a true near-zero delay measure very slightly negative; these readings are floored to 0 for on-screen display (marked with `~`) while the CSV log keeps the raw value for analysis.

## Protocol

MAU uses a custom UDP protocol with embedded timestamps for the data plane (format version 1).

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

| Field | Offset | Size | Format | Description |
|-------|--------|------|--------|-------------|
| Sequence | 0 | 4 bytes | uint32 BE | Packet counter, starts at 0 |
| Timestamp | 4 | 8 bytes | uint64 BE | Microseconds since Unix epoch |
| Magic | 12 | 4 bytes | ASCII | `MAUT` |
| Version | 16 | 1 byte | uint8 | Format version (1) |
| Sync port | 17 | 2 bytes | uint16 BE | UDP port of the sender's OWD sync server (0 = none) |
| Padding | 19 | variable | bytes | Readable preamble `mautg_trafficgen_www.jeitler.cc:` if it fits, then `0x2A` (42) fill |
| CRC | last 4 | 4 bytes | uint32 BE | CRC-32 (zlib) over all preceding bytes |

Minimum UDP payload: 23 bytes (51 bytes on the wire). All fields are big-endian.

### OWD Time Sync Protocol

Every `mautg` process runs an embedded UDP time sync server (default port 5556, one instance per process — see [Running Multiple Instances](#running-multiple-instances-on-one-host) below). Receivers measure their clock offset using a 4-timestamp exchange:

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

**Wire format: fixed-size binary (`struct`).**

| Message | Size | Layout |
|---------|------|--------|
| Request | 9 bytes | `!B` type (`0x01`) + `!Q` t1_ns |
| Response | 25 bytes | `!B` type (`0x02`) + `!Q` t1_ns + `!Q` t2_ns + `!Q` t3_ns |

All integers big-endian. A packet of the wrong size or with an unrecognized type byte is silently discarded — this also means the sync port safely ignores stray/foreign UDP traffic instead of raising a decode error.

### Running Multiple Instances on One Host

Every `mautg` process embeds its own OWD sync server (also the receivers) and every data packet advertises the sync port of its sender, so receivers need no configuration. If you run several instances **on the same host** (e.g. several parallel DSCP test streams) without giving each one a distinct `--sync-port`, they will all bind the same UDP port without raising an error (the socket uses `SO_REUSEADDR`) — but only one of them will actually receive sync requests; the kernel decides which, and it's implementation-defined. On a single host this typically doesn't corrupt the measured offset (all instances share the same system clock), but it does make the "✓ OWD sync server running" messages from the other instances misleading. Use `--no-sync-server` on all but one instance, or give each concurrently-running instance its own `--sync-port` — the same way you give each its own data `-p` port. Receivers pick the right port up from the packets; a receiver tracks every sender (source IP + sync port) as its own stream.

## Configuration and Logs

Saved menu settings (sender, receiver, sync port) live in `~/.mau/config.json` — written with `s` in a menu.

CSV columns: `Timestamp, Seq, Delay_ms, DSCP, DSCP_Name, Status, Stream, Source_IP, Sync_Port, Port, Cast` (`Stream` = label A, B, … as shown on screen; `Cast` = MC / UC / BC, see below).

CSV logs (`recv -l [name]`; default name `mautg-log_YYYY-MM-DD_HH:MM:SS.csv`, on Windows with `-` instead of `:` in the time) are written to the **current directory**, i.e. the folder you start `mautg.py` from; an absolute path is used as given.

## Wireshark Integration

Two Lua dissectors are included: [mau_protocol.lua](wireshark/mau_protocol.lua) for the data-packet protocol (UDP ports 5001-5008) and [mau_owd_sync_protocol.lua](wireshark/mau_owd_sync_protocol.lua) for the OWD clock-sync exchange (UDP port 5556). See the [Wireshark README](wireshark/README.md) for installation and usage of both.

## Examples

### QoS Verification

Verify that DSCP EF (46) traffic receives priority treatment:

```bash
# Sender: mark traffic as EF
./mautg.py send -d 239.1.1.1 -s 1500 --pps 1000 --dscp 46

# Receiver: check delay and loss
./mautg.py recv -g 239.1.1.1 -i 5
```

### Link Stress Test

Saturate a link at a specific bandwidth:

```bash
# 500 Mbit/s burst with 1500-byte packets
./mautg.py send -d 10.0.0.5 -s 1500 --burst --burst-mbps 500
```

### Multipath / Asymmetry Detection

Compare OWD in both directions by running sender+receiver on each end:

```bash
# Host A → Host B
hostA$ ./mautg.py send -d 10.0.0.2 --pps 10
hostB$ ./mautg.py recv -u -i 10

# Host B → Host A
hostB$ ./mautg.py send -d 10.0.0.1 --pps 10
hostA$ ./mautg.py recv -u -i 10
```

### Broadcast Testing

```bash
# Subnet broadcast /24
./mautg.py send -d 172.17.17.255 -p 5005 -s 256 --pps 10
```

## Project Structure

```
├── mautg.py             # Traffic generator + receiver + OWD sync server (single script)
├── e-install.sh          # One-line installer/updater (fetches from www.jeitler.cc)
├── wireshark/
│   ├── mau_protocol.lua           # Wireshark Lua dissector (data-packet protocol)
│   ├── mau_owd_sync_protocol.lua  # Wireshark Lua dissector (OWD sync protocol)
│   └── README.md                  # Dissector documentation
├── LICENSE
└── README.md              # This file
```
