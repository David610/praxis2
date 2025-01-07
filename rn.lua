rn_protocol = Proto("RN", "Computer Networks Chord Protocol")

-- Header fields
flags_f = ProtoField.uint8("rn_protocol.flags", "flags", base.HEX)
hash_f = ProtoField.uint16("rn_protocol.hash", "hash", base.HEX)
id_f = ProtoField.uint16("rn_protocol.id", "id", base.HEX)
ip_f = ProtoField.ipv4("rn_protocol.ip", "ip")
port_f = ProtoField.uint16("rn_protocol.port", "port", base.DEC)

rn_protocol.fields = {flags_f, hash_f, id_f, ip_f, port_f}

op_names = {
    [0] = "Lookup",
    [1] = "Reply",
    [2] = "Stabilize",
    [3] = "Notify",
    [4] = "Join",
}

function info_text(buffer, pinfo)
    local name = op_names[buffer(0, 1):uint()]
    local desc = ""
    if name == "Lookup" then
        desc = string.format(" %x for %x@%s:%u", buffer(1, 2):uint(), buffer(3, 2):uint(), buffer(5, 4):uint(), buffer(9, 2):uint())
    elseif name == "Reply" then
    elseif name == "Stabilize" then
        desc = string.format(" from 0x%02x@%s:%u", buffer(3, 2):uint(), buffer(5, 4):ipv4(), buffer(9, 2):uint())
    elseif name == "Notify" then
        desc = string.format(" of 0x%02x@%s:%u", buffer(3, 2):uint(), buffer(5, 4):ipv4(), buffer(9, 2):uint())
    elseif name == "Join" then
        desc = string.format(" from 0x%02x@%s:%u", buffer(3, 2):uint(), buffer(5, 4):ipv4(), buffer(9, 2):uint())
    end
    local suffix = string.format(" (%s:%u → %s:%u)", pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)
    return name .. desc .. suffix
end

function rn_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()

    if length ~= 11 then
        return 0
    end

    local subtree = tree:add(rn_protocol, buffer(), rn_protocol.description)
    pinfo.cols.protocol = rn_protocol.name
    pinfo.cols.info = info_text(buffer, pinfo) -- string.format("%s: (%s:%u → %s:%u)", op_names[buffer(0, 1):uint()],  pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port)

    subtree:add(flags_f, buffer(0, 1)):append_text(" (" .. op_names[buffer(0, 1):uint()] .. ")")
    subtree:add(hash_f, buffer(1, 2))
    subtree:add(id_f, buffer(3, 2))
    subtree:add(ip_f, buffer(5, 4))
    subtree:add(port_f, buffer(9, 2))

    return 11
end

rn_protocol:register_heuristic("udp", rn_protocol.dissector)
