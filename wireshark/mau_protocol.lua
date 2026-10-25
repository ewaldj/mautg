-- mau_protocol.lua — Wireshark dissector for the mautg data-packet protocol
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
-- The dissector registers on UDP ports 5001-5008 by default (mautg's default
-- receive range).
-- To use a different port: right-click a packet → Decode As → UDP port → MAU
--
-- Packet format (UDP payload, mautg v1.83+, format version 2):
--   [0:4]    Sequence Number   uint32 big-endian
--   [4:12]   Timestamp (µs)    uint64 big-endian (CLOCK_REALTIME since epoch)
--   [12:16]  Magic             "MAUT"
--   [16]     Format version    2
--   [17:19]  Sync port         uint16 big-endian (sender's OWD sync server, 0 = none)
--   [19:23]  Stream ID         uint32 big-endian (random, new at every start of a stream)
--   [23:N-4] Padding           "mautg_trafficgen_www.jeitler.cc:" (if it fits), then 0x2A
--   [N-4:N]  CRC32             uint32 big-endian over bytes[0:N-4] (zlib CRC-32)
--
-- Packets without the magic are NOT dissected (returns 0), so foreign UDP
-- traffic on the same port is left to other dissectors.

local mau_proto = Proto("mau", "MAU Traffic Generator Protocol")

-- Field definitions
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

mau_proto.fields = { f_seq, f_ts, f_delay, f_magic, f_version, f_syncport, f_streamid,
                     f_preamble, f_payload, f_crc, f_crc_valid, f_wire_size }

-- Expert info for CRC errors
local ef_crc_bad = ProtoExpert.new("mau.crc_bad", "MAU CRC mismatch",
                                    expert.group.CHECKSUM, expert.severity.ERROR)
mau_proto.experts = { ef_crc_bad }

-- Bit operations: Wireshark ships bit32 (Lua 5.2) or the older bit library
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
local PREAMBLE   = "mautg_trafficgen_www.jeitler.cc:"
-- Minimum packet size: 4(seq) + 8(ts) + 4(magic) + 1(ver) + 2(port) + 4(stream id) + 4(crc) = 27
local MIN_LEN    = 27
local PAD_OFFSET = 23

function mau_proto.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len < MIN_LEN then return 0 end
    if buffer(12, 4):string() ~= MAGIC then return 0 end

    pinfo.cols.protocol:set("MAU")

    local subtree = tree:add(mau_proto, buffer(), "MAU Protocol")

    -- Sequence number (bytes 0-3)
    local seq = buffer(0, 4):uint()
    subtree:add(f_seq, buffer(0, 4))

    -- Timestamp (bytes 4-11) — uint64 microseconds since epoch
    local ts_raw = buffer(4, 8):uint64()
    subtree:add(f_ts, buffer(4, 8))

    -- Convert timestamp to human-readable UTC
    local ts_sec = tonumber(tostring(ts_raw)) / 1000000.0
    if ts_sec > 0 then
        local time_str = os.date("!%Y-%m-%d %H:%M:%S", math.floor(ts_sec))
        local frac = ts_sec - math.floor(ts_sec)
        local full_str = string.format("%s.%06d UTC", time_str, math.floor(frac * 1000000))
        subtree:add(f_delay, buffer(4, 8), full_str)
    end

    -- Magic, format version, sync port, stream id (bytes 12-22)
    subtree:add(f_magic, buffer(12, 4))
    subtree:add(f_version, buffer(16, 1))
    local sync_port = buffer(17, 2):uint()
    subtree:add(f_syncport, buffer(17, 2))
    subtree:add(f_streamid, buffer(19, 4))

    -- Padding (bytes 23 to N-4): readable preamble first, if present
    local pad_len = buf_len - MIN_LEN
    if pad_len > 0 then
        if pad_len >= #PREAMBLE and buffer(PAD_OFFSET, #PREAMBLE):string() == PREAMBLE then
            subtree:add(f_preamble, buffer(PAD_OFFSET, #PREAMBLE))
        end
        subtree:add(f_payload, buffer(PAD_OFFSET, pad_len))
    end

    -- CRC (last 4 bytes)
    local crc_offset = buf_len - 4
    local crc_received = buffer(crc_offset, 4):uint()
    subtree:add(f_crc, buffer(crc_offset, 4))

    -- Verify CRC32 over everything before the CRC field
    local crc_calc = crc32(buffer:raw(), crc_offset)

    if crc_calc == crc_received then
        subtree:add(f_crc_valid, buffer(crc_offset, 4), "OK"):set_generated(true)
    else
        local bad = subtree:add(f_crc_valid, buffer(crc_offset, 4),
                                string.format("MISMATCH (expected 0x%08x)", crc_calc))
        bad:set_generated(true)
        bad:add_tvb_expert_info(ef_crc_bad, buffer(crc_offset, 4))
    end

    -- Wire size (UDP payload + 28 bytes IP/UDP overhead)
    local wire = buf_len + 28
    subtree:add(f_wire_size, buffer(), wire):set_generated(true)

    -- Info column
    pinfo.cols.info:set(string.format("Seq=%d  Len=%dB  Sync=%s  CRC=%s",
        seq, wire, sync_port > 0 and tostring(sync_port) or "-",
        crc_calc == crc_received and "OK" or "BAD"))

    return buf_len
end

-- Register on the default UDP port range 5001-5008
local udp_table = DissectorTable.get("udp.port")
udp_table:add("5001-5008", mau_proto)
