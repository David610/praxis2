import collections
import contextlib
import enum
# import hashlib
import socket
import struct
from ipaddress import IPv4Address

import util


Peer = collections.namedtuple('Peer', ['id', 'ip', 'port'])
Message = collections.namedtuple('Message', ['flags', 'id', 'peer'])
Flags = enum.Enum('Flags', ['lookup', 'reply', 'stabilize', 'notify', 'join'], start=0)
message_format = "!BHH4sH"


def deserialize(data):
    flags, hash_, id_, ip, port = struct.unpack(message_format, data)
    return Message(Flags(flags), hash_, Peer(id_, IPv4Address(ip).exploded, port))


def serialize(msg):
    return struct.pack(message_format, msg.flags.value, msg.id, msg.peer.id, IPv4Address(msg.peer.ip).packed, msg.peer.port)


def hash(data):
    # return int.from_bytes(hashlib.sha256(data).digest()[:2], 'big')
    hash_val = 0
    if len(data) % 2:
        data += bytes([0])
    for i in range(0, len(data), 2):
        hash_val += data[i] << 8 | data[i + 1]
    hash_val = (hash_val & 0xffff) + (hash_val >> 16)
    hash_val = ~hash_val & 0xffff # make unsigned int
    return hash_val


def expect_msg(sock, expectation):
    assert util.bytes_available(sock) > 0, "No data received on socket"
    data = sock.recv(1024)
    assert len(data) == struct.calcsize(message_format), "Received message has invalid length for DHT message"
    received = deserialize(data)

    assert received.flags == expectation.flags, "Received message is of wrong type"
    assert expectation.id is None or received.id == expectation.id, "ID of message doesn't match"
    assert received.peer == expectation.peer, "Messaged peer is not correct"


def peer_socket(peer: Peer):
    """Create and open a socket corresponding to the given peer
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((peer.ip, peer.port))
    return contextlib.closing(sock)
