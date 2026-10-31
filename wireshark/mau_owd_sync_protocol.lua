-- mau_owd_sync_protocol.lua — Wireshark dissector for the mautg
-- OWD (one-way delay) clock-sync protocol.
-- by ewald@jeitler.cc 2026 https://www.jeitler.cc
--
-- Install: same steps as mau_protocol.lua, see ../README.md in this folder.
--   Linux/macOS: cp mau_owd_sync_protocol.lua ~/.local/lib/wireshark/plugins/
--   Windows:     Copy-Item mau_owd_sync_protocol.lua "$env:APPDATA\Wireshark\plugins\"
--   Then restart Wireshark or Ctrl+Shift+L to reload Lua plugins.
--
-- This is a SEPARATE dissector from mau_protocol.lua. mau_protocol.lua
-- decodes the data traffic (UDP / TCP, default ports 5001-5008). This file decodes the 4-timestamp
-- clock-sync exchange the receiver performs against the sender's embedded sync
-- server (default UDP port 5556, --sync-port).
--
-- Wire format (mautg, fixed-size binary).
--
--   Request  (9 bytes):  [0]     type = 0x01
--                        [1:9]   t1_ns   uint64 big-endian (ns since epoch)
--
--   Response (25 bytes): [0]     type = 0x02
--                        [1:9]   t1_ns   uint64 big-endian (echoed from request)
--                        [9:17]  t2_ns   uint64 big-endian (sender RX time)
--                        [17:25] t3_ns   uint64 big-endian (sender TX time)
--
-- All multi-byte fields are big-endian, all timestamps are CLOCK_REALTIME
-- nanoseconds since the Unix epoch. A packet of any other size, or with
-- an unrecognized type byte, is not a valid mau OWD sync message and is
-- left for other dissectors (return 0) rather than misparsed.

local mau_owd_proto = Proto("mau_owd", "MAU OWD Sync Protocol")

-- Field definitions
local f_type     = ProtoField.uint8 ("mau_owd.type",     "Message Type", base.HEX)
local f_t1       = ProtoField.uint64("mau_owd.t1_ns",    "T1 - Receiver TX (ns since epoch)", base.DEC)
local f_t1_human = ProtoField.string("mau_owd.t1_time",  "T1 (UTC)")
local f_t2       = ProtoField.uint64("mau_owd.t2_ns",    "T2 - Sender RX (ns since epoch)", base.DEC)
local f_t2_human = ProtoField.string("mau_owd.t2_time",  "T2 (UTC)")
local f_t3       = ProtoField.uint64("mau_owd.t3_ns",    "T3 - Sender TX (ns since epoch)", base.DEC)
local f_t3_human = ProtoField.string("mau_owd.t3_time",  "T3 (UTC)")
local f_proc_ns  = ProtoField.int64 ("mau_owd.server_processing_ns",
                                      "Server Processing Time (T3-T2, ns)", base.DEC)

mau_owd_proto.fields = {
    f_type, f_t1, f_t1_human, f_t2, f_t2_human, f_t3, f_t3_human, f_proc_ns
}

-- Expert info for malformed messages (right type byte, wrong length - e.g.
-- a truncated capture)
local ef_bad_size = ProtoExpert.new("mau_owd.bad_size", "MAU OWD: size doesn't match message type",
                                     expert.group.MALFORMED, expert.severity.WARN)
mau_owd_proto.experts = { ef_bad_size }

local MSG_REQ = 0x01
local MSG_RSP = 0x02

local REQ_LEN = 9   -- type(1) + t1_ns(8)
local RSP_LEN = 25  -- type(1) + t1_ns(8) + t2_ns(8) + t3_ns(8)

-- 8-byte big-endian TvbRange (nanoseconds since epoch) -> human-readable
-- "YYYY-MM-DD HH:MM:SS.ffffff UTC", or nil if it doesn't look like a
-- plausible timestamp.
local function ns_to_human(ts_buf)
    local ts_sec = tonumber(tostring(ts_buf:uint64())) / 1e9
    if ts_sec <= 0 then return nil end
    local time_str = os.date("!%Y-%m-%d %H:%M:%S", math.floor(ts_sec))
    local frac = ts_sec - math.floor(ts_sec)
    return string.format("%s.%06d UTC", time_str, math.floor(frac * 1000000 + 0.5))
end

function mau_owd_proto.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len ~= REQ_LEN and buf_len ~= RSP_LEN then
        return 0  -- wrong size for either message - not ours
    end

    local msg_type = buffer(0, 1):uint()
    if msg_type ~= MSG_REQ and msg_type ~= MSG_RSP then
        return 0  -- unrecognized type byte - not ours
    end

    pinfo.cols.protocol:set("MAU-OWD")

    local subtree = tree:add(mau_owd_proto, buffer(), "MAU OWD Sync Protocol")
    local type_item = subtree:add(f_type, buffer(0, 1))

    if msg_type == MSG_REQ and buf_len == REQ_LEN then
        type_item:append_text(" (REQ - sync request)")

        local t1_buf = buffer(1, 8)
        subtree:add(f_t1, t1_buf)
        local t1_str = ns_to_human(t1_buf)
        if t1_str then
            subtree:add(f_t1_human, t1_buf, t1_str):set_generated(true)
        end

        pinfo.cols.info:set(string.format("MAU OWD Sync REQ  t1=%s", t1_str or "?"))

    elseif msg_type == MSG_RSP and buf_len == RSP_LEN then
        type_item:append_text(" (RSP - sync response)")

        local t1_buf = buffer(1, 8)
        local t2_buf = buffer(9, 8)
        local t3_buf = buffer(17, 8)

        subtree:add(f_t1, t1_buf)
        local t1_str = ns_to_human(t1_buf)
        if t1_str then subtree:add(f_t1_human, t1_buf, t1_str):set_generated(true) end

        subtree:add(f_t2, t2_buf)
        local t2_str = ns_to_human(t2_buf)
        if t2_str then subtree:add(f_t2_human, t2_buf, t2_str):set_generated(true) end

        subtree:add(f_t3, t3_buf)
        local t3_str = ns_to_human(t3_buf)
        if t3_str then subtree:add(f_t3_human, t3_buf, t3_str):set_generated(true) end

        -- server-side processing time between RX (T2) and TX (T3) - the
        -- one part of the exchange NOT covered by kernel RX timestamping
        -- on the receiver side; a growing value here under load is a
        -- direct signal of scheduling/GC jitter on the sender host
        local proc_ns = tonumber(tostring(t3_buf:uint64())) - tonumber(tostring(t2_buf:uint64()))
        subtree:add(f_proc_ns, t2_buf, proc_ns):set_generated(true)

        pinfo.cols.info:set(string.format("MAU OWD Sync RSP  t1=%s  server_proc=%dns",
            t1_str or "?", proc_ns))

    else
        -- type byte recognized but length matches the OTHER message type
        -- (e.g. a REQ-typed byte on a 25-byte capture) - flag, don't guess
        type_item:add_tvb_expert_info(ef_bad_size, buffer(0, 1))
        pinfo.cols.info:set("MAU OWD Sync: malformed (type/size mismatch)")
    end

    return buf_len
end

-- Ports: default UDP 5556 (--sync-port). Another port: Edit -> Preferences ->
-- Protocols -> MAU-OWD, or Decode As. In addition the messages are recognised on
-- ANY UDP port (heuristic: size 9 / 25, type byte, plausible timestamp); switch
-- it off in Analyze -> Enabled Protocols (mau_owd).
local DEF_PORTS = "5556"
mau_owd_proto.prefs.udp_ports = Pref.range("UDP ports", DEF_PORTS,
    "UDP port of the OWD sync server (mautg --sync-port, default 5556)", 65535)

local function plausible_time(buffer)
    local ns = tonumber(tostring(buffer(1, 8):uint64()))
    return ns ~= nil and ns > 1.5e18 and ns < 4.2e18      -- 2017 .. 2103
end

local function heur_owd(buffer, pinfo, tree)
    local n = buffer:len()
    if n ~= REQ_LEN and n ~= RSP_LEN then return false end
    local t = buffer(0, 1):uint()
    if not ((t == MSG_REQ and n == REQ_LEN) or (t == MSG_RSP and n == RSP_LEN)) then return false end
    if not plausible_time(buffer) then return false end
    mau_owd_proto.dissector(buffer, pinfo, tree)
    return true
end
mau_owd_proto:register_heuristic("udp", heur_owd)

local udp_table = DissectorTable.get("udp.port")
local cur_ports = DEF_PORTS
udp_table:add(cur_ports, mau_owd_proto)

function mau_owd_proto.prefs_changed()
    local want = tostring(mau_owd_proto.prefs.udp_ports)
    if want ~= cur_ports then
        if cur_ports ~= "" then udp_table:remove(cur_ports, mau_owd_proto) end
        if want ~= "" then udp_table:add(want, mau_owd_proto) end
        cur_ports = want
    end
end
