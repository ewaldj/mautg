-- mau_protocol.lua — Wireshark dissector for the mautg data traffic (UDP and TCP)
-- by ewald@jeitler.cc 2026 https://www.jeitler.cc
--
-- Install:
--   Copy this file to your Wireshark plugins directory:
--     Linux:   ~/.local/lib/wireshark/plugins/
--     macOS:   ~/.local/lib/wireshark/plugins/
--     Windows: %APPDATA%\Wireshark\plugins\
--   Or: Wireshark → Help → About → Folders → Personal Plugins
--   Then restart Wireshark or Ctrl+Shift+L to reload Lua plugins.
--
-- Two protocols are defined here:
--   MAU      one data packet / message (same layout on UDP and TCP)
--   MAU-TCP  TCP stream of mautg: hello block, then messages back to back
--            (TCP segments are reassembled to whole messages), statistics
--            connection (JSON lines)
--
-- Ports: by default UDP and TCP 5001-5008. Another port range:
--   Edit → Preferences → Protocols → MAU / MAU-TCP, or right-click a packet →
--   Decode As.
-- In addition mautg traffic is recognised on ANY port by its content
-- (heuristic: magic "MAUT" + format version, TCP: the hello "MTCP"). This can be
-- switched off in Analyze → Enabled Protocols (mau, mau_tcp). A port that is
-- already taken by another dissector (e.g. RTP) needs Decode As.
--
-- Data packet / message (mautg format version 2):
--   [0:4]    Sequence Number   uint32 big-endian
--   [4:12]   Timestamp (µs)    uint64 big-endian (CLOCK_REALTIME since epoch)
--   [12:16]  Magic             "MAUT"
--   [16]     Format version    2
--   [17:19]  Sync port         uint16 big-endian (sender's OWD sync server, 0 = none)
--   [19:23]  Stream ID         uint32 big-endian (random, new at every start of a stream)
--   [23:N-4] Padding           "mautg_trafficgen_www.jeitler.cc:" (if it fits), then 0x2A
--   [N-4:N]  CRC32             uint32 big-endian over bytes[0:N-4] (zlib CRC-32)
--
-- TCP stream (sender -> receiver):
--   hello, 16 bytes: "MTCP" | version 1 (uint8) | DSCP (uint8) | flags (uint16) |
--                    message size (uint32) | reserved (uint32)
--   then messages of exactly "message size" bytes (layout above).
--   Statistics connection: hello "MSTA", then one JSON line per request / reply.
--
-- Packets without the magic are NOT dissected (returns 0), so foreign traffic on
-- the same port is left to other dissectors.

local mau_proto = Proto("mau", "MAU Traffic Generator Protocol")
local mau_tcp   = Proto("mau_tcp", "MAU TCP Stream")

-- ---------------------------------------------------------------- preferences
local DEF_PORTS = "5001-5008"
mau_proto.prefs.udp_ports = Pref.range("UDP ports", DEF_PORTS,
    "UDP ports of the mautg data packets (mautg default 5001-5008)", 65535)
mau_tcp.prefs.tcp_ports = Pref.range("TCP ports", DEF_PORTS,
    "TCP ports of the mautg data connections (same numbers as the UDP ports)", 65535)
mau_tcp.prefs.crc = Pref.bool("Verify the CRC of TCP messages", false,
    "TCP already protects the data; checking the CRC of large messages in Lua is slow")

-- --------------------------------------------------------------------- fields
local dscp_names = {
    [0] = "BE", [8] = "CS1", [10] = "AF11", [12] = "AF12", [14] = "AF13",
    [16] = "CS2", [18] = "AF21", [20] = "AF22", [22] = "AF23",
    [24] = "CS3", [26] = "AF31", [28] = "AF32", [30] = "AF33",
    [32] = "CS4", [34] = "AF41", [36] = "AF42", [38] = "AF43",
    [40] = "CS5", [44] = "VA", [46] = "EF", [48] = "CS6", [56] = "CS7",
}

local f_seq       = ProtoField.uint32("mau.seq",        "Sequence Number", base.DEC)
local f_ts        = ProtoField.uint64("mau.timestamp",  "Timestamp (µs)",  base.DEC)
local f_delay     = ProtoField.string("mau.delay",      "Sender Timestamp (UTC)")
local f_magic     = ProtoField.string("mau.magic",      "Magic")
local f_version   = ProtoField.uint8 ("mau.version",    "Format Version",  base.DEC)
local f_syncport  = ProtoField.uint16("mau.sync_port",  "Sender OWD Sync Port (0 = none)", base.DEC)
local f_streamid  = ProtoField.uint32("mau.stream_id",  "Stream ID (random, new at every start)", base.HEX)
local f_preamble  = ProtoField.string("mau.preamble",   "Padding Preamble")
local f_payload   = ProtoField.bytes ("mau.payload",    "Padding")
local f_crc       = ProtoField.uint32("mau.crc",        "CRC32",           base.HEX)
local f_crc_valid = ProtoField.string("mau.crc_status", "CRC Status")
local f_wire_size = ProtoField.uint32("mau.wire_size",  "Wire Size (bytes)", base.DEC)
local f_msg_size  = ProtoField.uint32("mau.msg_size",   "Message Size (bytes)", base.DEC)

mau_proto.fields = { f_seq, f_ts, f_delay, f_magic, f_version, f_syncport, f_streamid,
                     f_preamble, f_payload, f_crc, f_crc_valid, f_wire_size, f_msg_size }

local t_magic   = ProtoField.string("mau_tcp.magic",    "Hello Magic")
local t_version = ProtoField.uint8 ("mau_tcp.version",  "Hello Version", base.DEC)
local t_dscp    = ProtoField.uint8 ("mau_tcp.dscp",     "DSCP announced by the sender", base.DEC, dscp_names)
local t_flags   = ProtoField.uint16("mau_tcp.flags",    "Flags", base.HEX)
local t_size    = ProtoField.uint32("mau_tcp.msg_size", "Message Size (bytes)", base.DEC)
local t_reserved = ProtoField.uint32("mau_tcp.reserved", "Reserved", base.HEX)
local t_kind    = ProtoField.string("mau_tcp.kind",     "Connection Type")
local t_stat    = ProtoField.string("mau_tcp.stat",     "Statistics message (JSON)")

mau_tcp.fields = { t_magic, t_version, t_dscp, t_flags, t_size, t_reserved, t_kind, t_stat }

local ef_crc_bad = ProtoExpert.new("mau.crc_bad", "MAU CRC mismatch",
                                    expert.group.CHECKSUM, expert.severity.ERROR)
mau_proto.experts = { ef_crc_bad }
local ef_hello_bad = ProtoExpert.new("mau_tcp.hello_bad", "MAU-TCP: invalid hello (message size)",
                                      expert.group.MALFORMED, expert.severity.WARN)
mau_tcp.experts = { ef_hello_bad }

-- ----------------------------------------------------------------------- CRC32
-- Wireshark ships bit32 (Lua 5.2) or the older bit library
local B = bit32 or bit
local band, bxor, rshift = B.band, B.bxor, B.rshift

local function u32(x) return x % 4294967296 end

-- zlib-compatible CRC-32 (poly 0xEDB88320), table driven
local crc_table = {}
for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
        if band(c, 1) == 1 then c = bxor(rshift(c, 1), 0xEDB88320)
        else c = rshift(c, 1) end
    end
    crc_table[i] = u32(c)
end

local function crc32(raw, len)
    local c = 0xFFFFFFFF
    for i = 1, len do
        c = bxor(crc_table[band(bxor(c, raw:byte(i)), 0xFF)], rshift(c, 8))
    end
    return u32(bxor(c, 0xFFFFFFFF))
end

local MAGIC      = "MAUT"
local FORMAT_VER = 2
local PREAMBLE   = "mautg_trafficgen_www.jeitler.cc:"
-- Minimum packet size: 4(seq) + 8(ts) + 4(magic) + 1(ver) + 2(port) + 4(stream id) + 4(crc) = 27
local MIN_LEN    = 27
local MAX_MSG    = 1048576
local PAD_OFFSET = 23

-- ----------------------------------------------------- one data packet / message
-- buffer: exactly one UDP payload or one TCP message. Returns seq, crc state, sync port.
local function dissect_data(buffer, pinfo, tree, over_tcp)
    local buf_len = buffer:len()
    pinfo.cols.protocol:set("MAU")

    local subtree = tree:add(mau_proto, buffer(), over_tcp and "MAU Message (TCP)" or "MAU Protocol")

    local seq = buffer(0, 4):uint()
    subtree:add(f_seq, buffer(0, 4))

    local ts_raw = buffer(4, 8):uint64()
    subtree:add(f_ts, buffer(4, 8))

    local ts_sec = tonumber(tostring(ts_raw)) / 1000000.0
    if ts_sec > 0 then
        local time_str = os.date("!%Y-%m-%d %H:%M:%S", math.floor(ts_sec))
        local frac = ts_sec - math.floor(ts_sec)
        local full_str = string.format("%s.%06d UTC", time_str, math.floor(frac * 1000000))
        subtree:add(f_delay, buffer(4, 8), full_str)
    end

    subtree:add(f_magic, buffer(12, 4))
    subtree:add(f_version, buffer(16, 1))
    local sync_port = buffer(17, 2):uint()
    subtree:add(f_syncport, buffer(17, 2))
    subtree:add(f_streamid, buffer(19, 4))

    local pad_len = buf_len - MIN_LEN
    if pad_len > 0 then
        if pad_len >= #PREAMBLE and buffer(PAD_OFFSET, #PREAMBLE):string() == PREAMBLE then
            subtree:add(f_preamble, buffer(PAD_OFFSET, #PREAMBLE))
        end
        subtree:add(f_payload, buffer(PAD_OFFSET, pad_len))
    end

    local crc_offset = buf_len - 4
    local crc_received = buffer(crc_offset, 4):uint()
    subtree:add(f_crc, buffer(crc_offset, 4))

    local crc_state
    if over_tcp and not mau_tcp.prefs.crc then
        subtree:add(f_crc_valid, buffer(crc_offset, 4),
                    "not checked (TCP; Preferences → MAU-TCP → verify)"):set_generated(true)
        crc_state = "-"
    else
        local crc_calc = crc32(buffer:raw(), crc_offset)
        if crc_calc == crc_received then
            subtree:add(f_crc_valid, buffer(crc_offset, 4), "OK"):set_generated(true)
            crc_state = "OK"
        else
            local bad = subtree:add(f_crc_valid, buffer(crc_offset, 4),
                                    string.format("MISMATCH (expected 0x%08x)", crc_calc))
            bad:set_generated(true)
            bad:add_tvb_expert_info(ef_crc_bad, buffer(crc_offset, 4))
            crc_state = "BAD"
        end
    end

    if over_tcp then
        subtree:add(f_msg_size, buffer(), buf_len):set_generated(true)
    else
        -- UDP payload + 28 bytes IP/UDP overhead
        subtree:add(f_wire_size, buffer(), buf_len + 28):set_generated(true)
    end
    return seq, crc_state, sync_port
end

-- ------------------------------------------------------------------------- UDP
local function looks_like_udp(buffer)
    return buffer:len() >= MIN_LEN and buffer(12, 4):string() == MAGIC
end

function mau_proto.dissector(buffer, pinfo, tree)
    if not looks_like_udp(buffer) then return 0 end
    local seq, crc, sync_port = dissect_data(buffer, pinfo, tree, false)
    pinfo.cols.info:set(string.format("Seq=%d  Len=%dB  Sync=%s  CRC=%s",
        seq, buffer:len() + 28, sync_port > 0 and tostring(sync_port) or "-", crc == "BAD" and "BAD" or "OK"))
    return buffer:len()
end

-- Any UDP port: magic + format version
local function heur_udp(buffer, pinfo, tree)
    if buffer:len() < MIN_LEN or buffer(12, 4):string() ~= MAGIC
       or buffer(16, 1):uint() ~= FORMAT_VER then
        return false
    end
    mau_proto.dissector(buffer, pinfo, tree)
    return true
end
mau_proto:register_heuristic("udp", heur_udp)

-- ------------------------------------------------------------------------- TCP
local DESEG_MORE = DESEGMENT_ONE_MORE_SEGMENT or 0x0fffffff
local HELLO_LEN  = 16
local streams = {}     -- tcp.stream -> {size = message size} or {stat = true}

local tcp_stream_f = Field.new("tcp.stream")
local function stream_key(pinfo)
    local f = tcp_stream_f()
    if f then return tostring(f.value) end
    local a = tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port)
    local b = tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
    if a > b then a, b = b, a end
    return a .. "|" .. b
end

function mau_tcp.init()
    streams = {}
end

-- hello at tvb offset off? (magic + version 1; a message has 0x00 there: top byte of the timestamp)
local function hello_kind(buffer, off)
    if buffer:len() - off < 5 then return nil end
    local m = buffer(off, 4):string()
    if (m == "MTCP" or m == "MSTA") and buffer(off + 4, 1):uint() == 1 then return m end
    return nil
end

local function hello_prefix(buffer, off)
    local n = buffer:len() - off
    if n > 4 then n = 4 end
    if n <= 0 then return false end
    local s = buffer(off, n):string()
    return s == ("MTCP"):sub(1, n) or s == ("MSTA"):sub(1, n)
end

local function need_more(pinfo, off, n)
    pinfo.desegment_offset = off
    pinfo.desegment_len = n
end

function mau_tcp.dissector(buffer, pinfo, tree)
    local len = buffer:len()
    local key = stream_key(pinfo)
    local st = streams[key]
    local off, nmsg, first_seq, last_seq, msg_size, crc_bad = 0, 0, nil, nil, 0, false
    local info, hello_info = nil, nil

    while off < len do
        local rem = len - off

        -- hello (only at the start of a stream)
        local kind = hello_kind(buffer, off)
        if kind or (st == nil and hello_prefix(buffer, off)) then
            if rem < HELLO_LEN then
                need_more(pinfo, off, HELLO_LEN - rem)
                break
            end
            pinfo.cols.protocol:set("MAU-TCP")
            local sub = tree:add(mau_tcp, buffer(off, HELLO_LEN), "MAU TCP Stream - hello")
            sub:add(t_magic, buffer(off, 4))
            sub:add(t_version, buffer(off + 4, 1))
            if kind == "MTCP" then
                local size = buffer(off + 8, 4):uint()
                sub:add(t_kind, buffer(off, 4), "data connection (messages follow)"):set_generated(true)
                sub:add(t_dscp, buffer(off + 5, 1))
                sub:add(t_flags, buffer(off + 6, 2))
                local it = sub:add(t_size, buffer(off + 8, 4))
                sub:add(t_reserved, buffer(off + 12, 4))
                if size >= MIN_LEN and size <= MAX_MSG then
                    st = { size = size }
                else
                    st = nil
                    it:add_tvb_expert_info(ef_hello_bad, buffer(off + 8, 4))
                end
                info = string.format("MAU TCP hello: message size %d bytes, DSCP %s", size,
                    tostring(dscp_names[buffer(off + 5, 1):uint()] or buffer(off + 5, 1):uint()))
            else
                sub:add(t_kind, buffer(off, 4), "statistics connection (JSON lines)"):set_generated(true)
                sub:add(t_dscp, buffer(off + 5, 1))
                sub:add(t_flags, buffer(off + 6, 2))
                sub:add(t_size, buffer(off + 8, 4))
                sub:add(t_reserved, buffer(off + 12, 4))
                st = { stat = true }
                info = "MAU TCP hello: statistics connection"
            end
            streams[key] = st
            hello_info = info
            off = off + HELLO_LEN

        elseif st == nil then
            -- mid-stream capture or not mautg: nothing we can frame
            if nmsg == 0 and info == nil then return 0 end
            break

        elseif st.stat then
            -- JSON lines
            local s = buffer(off, rem):string()
            local nl = s:find("\n", 1, true)
            if not nl then
                if rem > 8192 then nl = rem else need_more(pinfo, off, DESEG_MORE); break end
            end
            pinfo.cols.protocol:set("MAU-TCP")
            local line = s:sub(1, nl):gsub("[\r\n]+$", "")
            local sub = tree:add(mau_tcp, buffer(off, nl), "MAU TCP Stream - statistics")
            sub:add(t_stat, buffer(off, nl), line)
            info = "MAU TCP stats: " .. (#line > 70 and (line:sub(1, 70) .. "...") or line)
            off = off + nl

        else
            -- one message of the announced size
            local size = st.size
            if rem < size then
                need_more(pinfo, off, size - rem)
                break
            end
            local seq, crc = dissect_data(buffer(off, size):tvb(), pinfo, tree, true)
            nmsg = nmsg + 1
            first_seq = first_seq or seq
            last_seq = seq
            msg_size = size
            if crc == "BAD" then crc_bad = true end
            off = off + size
        end
    end

    if nmsg > 0 then
        if nmsg == 1 then
            info = string.format("Seq=%d  Len=%dB  TCP%s", first_seq, msg_size, crc_bad and "  CRC=BAD" or "")
        else
            info = string.format("%d messages  Seq=%d..%d  Len=%dB each  TCP%s",
                nmsg, first_seq, last_seq, msg_size, crc_bad and "  CRC=BAD" or "")
        end
        if hello_info then info = "hello + " .. info end
        pinfo.cols.protocol:set("MAU")
    end
    if info then pinfo.cols.info:set(info) end
    if off == 0 and info == nil and pinfo.desegment_len == 0 then return 0 end
    return off > 0 and off or len
end

-- Any TCP port: a connection is recognised by its hello, then all of it is ours
local function heur_tcp(buffer, pinfo, tree)
    if streams[stream_key(pinfo)] == nil and not hello_kind(buffer, 0) then return false end
    return mau_tcp.dissector(buffer, pinfo, tree) > 0
end
mau_tcp:register_heuristic("tcp", heur_tcp)

-- ----------------------------------------------------------------------- ports
local udp_table = DissectorTable.get("udp.port")
local tcp_table = DissectorTable.get("tcp.port")
local cur_udp, cur_tcp = DEF_PORTS, DEF_PORTS
udp_table:add(cur_udp, mau_proto)
tcp_table:add(cur_tcp, mau_tcp)

function mau_proto.prefs_changed()
    local want = tostring(mau_proto.prefs.udp_ports)
    if want ~= cur_udp then
        if cur_udp ~= "" then udp_table:remove(cur_udp, mau_proto) end
        if want ~= "" then udp_table:add(want, mau_proto) end
        cur_udp = want
    end
end

function mau_tcp.prefs_changed()
    local want = tostring(mau_tcp.prefs.tcp_ports)
    if want ~= cur_tcp then
        if cur_tcp ~= "" then tcp_table:remove(cur_tcp, mau_tcp) end
        if want ~= "" then tcp_table:add(want, mau_tcp) end
        cur_tcp = want
    end
end
