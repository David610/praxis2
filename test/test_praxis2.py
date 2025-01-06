"""
Tests for RN Praxis 2
"""

import contextlib
import errno
import struct
import time
import urllib.request as req
from urllib.parse import urlparse
from http.client import HTTPConnection

import pytest

import util
import dht

# We assume that all tests from the previous sheet(s) are working!

# -i dumps header
# -L follows redirects
# curl -iL localhost:12345/static/baz


def _iter_with_neighbors(xs):
    """Return iterator to list that includes each elements neighbors

    For each element in the original list a triple of its neighbors
    is generated: `(xs[i - 1], xs[i], xs[i + 1])`
    """
    return zip(xs[-1:] + xs[:-1], xs, xs[1:] + xs[:1])


@pytest.fixture
def static_peer(request):
    """Return a function for spawning DHT peers
    """
    def runner(peer, predecessor=None, successor=None):
        """Spawn a static DHT peer

        The peer is passed its local neighborhood via environment variables.
        """
        return util.KillOnExit(
            [request.config.getoption('executable'), peer.ip, f'{peer.port}'] + ([f'{peer.id}'] if peer.id is not None else []),
            env={
                **({'PRED_ID': f'{predecessor.id}', 'PRED_IP': predecessor.ip, 'PRED_PORT': f'{predecessor.port}'} if predecessor is not None else {}),
                **({'SUCC_ID': f'{successor.id}', 'SUCC_IP': successor.ip, 'SUCC_PORT': f'{successor.port}'} if successor is not None else {}),
                'NO_STABILIZE': '1',  # Forward compatibility with P3.
            },
        )

    @contextlib.contextmanager
    def empty_context(*args, **kwargs):
        yield  # No peer initialization here, just an empty context that never fails

    if request.config.getoption('debug_own'):
        return empty_context

    return runner


@pytest.mark.timeout(1)
def test_listen(static_peer):
    """
    Tests chord part of the system (1.1).
    Listens on UDP port.
    """

    self = dht.Peer(None, '127.0.0.1', 4711)
    with static_peer(self), pytest.raises(OSError) as exception_info:
        time.sleep(.1)

        # Attempt to open the port that the implementation should have opened
        with dht.peer_socket(self):
            pass

    assert exception_info.value.errno == errno.EADDRINUSE, "UDP port not open"


@pytest.mark.timeout(1)
@pytest.mark.parametrize("uri", ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'])
def test_immediate_dht(static_peer, uri):
    """Test hashing of request (1.2)
    Run peer in minimal (non-trivial) DHT
    - two nodes, equal split of namespace
    - first node real, second mock sockets

    1. make request - internally requires hashing of location part in URL
    2. check that request yields either 404 (if peer is responsible) or 303 (if it isn't)
    3. no packet should be received by the second peer
    """

    predecessor = dht.Peer(0xc000, '127.0.0.1', 4712)
    self = dht.Peer(0x4000, '127.0.0.1', 4711)
    successor = predecessor

    with dht.peer_socket(
        successor
    ) as mock, static_peer(
        self, predecessor, successor,
    ), contextlib.closing(
        HTTPConnection(self.ip, self.port)  # Use `http.client` instead of `urllib` to avoid redirection
    ) as conn:
        conn.connect()

        conn.request('GET', f'/{uri}')
        time.sleep(.1)
        reply = conn.getresponse()
        _ = reply.read()

        uri_hash = dht.hash(f'/{uri}'.encode('latin1'))
        implementation_responsible = not self.id < uri_hash <= successor.id

        if implementation_responsible:
            assert reply.status == 404, "Server should've indicated missing data"
        else:
            assert reply.status == 303, "Server should've delegated response"
            assert reply.headers['Location'] == f'http://{successor.ip}:{successor.port}/{uri}', "Server should've delegated to its successor"

        assert util.bytes_available(mock) == 0, "Data received on successor socket"


@pytest.mark.timeout(1)
@pytest.mark.parametrize("uri", ['a', 'b'])
def test_lookup_sent(static_peer, uri):
    """Test for lookup to correct peer (1.3)

    Node is running with minimal assigned address space, should send lookup messages
    for the correct hash to its successors and reply with 503 & Retry-After header.
    """

    predecessor = dht.Peer(0xffff, '127.0.0.1', 4710)
    self = dht.Peer(0x0000, '127.0.0.1', 4711)
    successor = dht.Peer(0x0001, '127.0.0.1', 4712)

    with dht.peer_socket(successor) as mock:  # Can't differentiate predecessor & successor, reusing ports.
        with static_peer(
            self, predecessor, successor
        ), pytest.raises(req.HTTPError) as exception_info:

            url = f'http://{self.ip}:{self.port}/{uri}'
            req.urlopen(url)

        assert exception_info.value.status == 503, "Server should reply with 503"
        assert exception_info.value.headers.get("Retry-After", None) == "1", "Server should set 'Retry-After' header to 1s"

        time.sleep(.1)
        assert util.bytes_available(mock) > 0, "No data received on successor socket"
        data = mock.recv(1024)
        assert len(data) == struct.calcsize(dht.message_format), "Received message has invalid length for DHT message"
        msg = dht.deserialize(data)

        assert dht.Flags(msg.flags) == dht.Flags.lookup, "Received message should be a lookup"

        uri_hash = dht.hash(urlparse(url).path.encode('latin1'))
        assert msg.id == uri_hash, "Received lookup should query the requested datum's hash"

        assert msg.peer == self, "Received lookup should indicate its originator"


@pytest.mark.timeout(1)
def test_lookup_reply(static_peer):
    """Test whether peer replies to lookup correctly (1.4)"""

    predecessor = dht.Peer(0x0000, '127.0.0.1', 4710)
    self = dht.Peer(0x1000, '127.0.0.1', 4711)
    successor = dht.Peer(0x2000, '127.0.0.1', 4712)

    with dht.peer_socket(
            predecessor
    ) as pred_mock, static_peer(
        self, predecessor, successor
    ), dht.peer_socket(
            successor
    ) as succ_mock:
        lookup = dht.Message(dht.Flags.lookup, 0x1800, predecessor)
        pred_mock.sendto(dht.serialize(lookup), (self.ip, self.port))

        time.sleep(.1)

        assert util.bytes_available(succ_mock) == 0, "Data received on successor socket"
        assert util.bytes_available(pred_mock) > 0, "No data received on predecessor socket"
        data = pred_mock.recv(1024)
        assert len(data) == struct.calcsize(dht.message_format), "Received message has invalid length for DHT message"
        reply = dht.deserialize(data)

        assert dht.Flags(reply.flags) == dht.Flags.reply, "Received message should be a reply"
        assert reply.peer == successor, "Reply does not indicate successor as responsible"
        assert reply.id == self.id, "Reply does not indicate implementation as previous ID"


@pytest.mark.timeout(1)
def test_lookup_forward(static_peer):
    """Test whether peer forwards lookup correctly (1.5)"""

    predecessor = dht.Peer(0x0000, '127.0.0.1', 4710)
    self = dht.Peer(0x1000, '127.0.0.1', 4711)
    successor = dht.Peer(0x2000, '127.0.0.1', 4712)

    with dht.peer_socket(
        predecessor
    ) as pred_mock, static_peer(
        self, predecessor, successor
    ), dht.peer_socket(
        successor
    ) as succ_mock:
        lookup = dht.Message(dht.Flags.lookup, 0x2800, predecessor)
        pred_mock.sendto(dht.serialize(lookup), (self.ip, self.port))

        time.sleep(.1)

        assert util.bytes_available(pred_mock) == 0, "Data received on predecessor socket"
        assert util.bytes_available(succ_mock) > 0, "No data received on successor socket"
        data = succ_mock.recv(1024)
        assert len(data) == struct.calcsize(dht.message_format), "Received message has invalid length for DHT message"
        received = dht.deserialize(data)

        assert received == lookup, "Received message should be equal to original lookup"


@pytest.mark.timeout(1)
@pytest.mark.parametrize("uri", ['a', 'b'])
def test_lookup_complete(static_peer, uri):
    """Test for correct lookup use (1.6)

    Node is running with minimal assigned address space, should send lookup messages
    for the correct hash to its successors and reply with 503 & Retry-After header.
    """

    predecessor = dht.Peer(0xffff, '127.0.0.1', 4710)
    self = dht.Peer(0x0000, '127.0.0.1', 4711)
    successor = dht.Peer(0x0001, '127.0.0.1', 4712)

    with dht.peer_socket(
        predecessor
    ) as pred_mock, static_peer(
        self, predecessor, successor
    ), dht.peer_socket(
        successor
    ) as succ_mock, contextlib.closing(
        HTTPConnection(self.ip, self.port)  # We have to use the more low-level `http.client` instead of `urllib` to avoid it interpreting the `Retry-After` header
    ) as conn:
        conn.connect()
        time.sleep(.1)

        # Check HTTP reply
        conn.request('GET', f'/{uri}')
        time.sleep(.1)
        response = conn.getresponse()
        _ = response.read()
        assert response.status == 503, "Server should reply with 503"
        assert response.headers.get("Retry-After", None) == "1", "Server should set 'Retry-After' header to 1s"
        time.sleep(.1)

        # Check lookup message
        time.sleep(.1)
        assert util.bytes_available(pred_mock) == 0, "Data received on predecessor socket"
        assert util.bytes_available(succ_mock) > 0, "No data received on successor socket"
        data = succ_mock.recv(1024)
        assert len(data) == struct.calcsize(dht.message_format), "Received message has invalid length for DHT message"
        msg = dht.deserialize(data)

        time.sleep(.1)
        assert dht.Flags(msg.flags) == dht.Flags.lookup, "Received message should be a lookup"

        uri_hash = dht.hash(f'/{uri}'.encode('latin1'))
        assert msg.id == uri_hash, "Received lookup should query the requested datum's hash"

        assert msg.peer == self, "Received lookup should indicate its originator"

        time.sleep(.1)

        # Send reply
        reply = dht.Message(dht.Flags.reply, successor.id, predecessor)
        pred_mock.sendto(dht.serialize(reply), (self.ip, self.port))

        time.sleep(.1)

        # Check HTTP reply again
        conn.request('GET', f'/{uri}')
        response = conn.getresponse()
        _ = response.read()
        assert response.status == 303, "Server should've delegated response"
        assert response.headers['Location'] == f'http://{predecessor.ip}:{predecessor.port}/{uri}', "Server should've delegated to its predecessor"


@pytest.mark.timeout(10)  # five requests, two seconds each
def test_dht(static_peer):
    """Test a complete DHT (1.7)

    At this point, a DHT consisting only of the implementation should work as expected.
    We will repeat the dynamic content test, but will contact a different peer for each request.
    """

    # chosen by fair dice roll.
    # guaranteed to be random.
    dht_ids = [10927, 18804, 40809, 54536, 63901]
    contact_order = [1, 0, 3, 2, 4]
    datum = '191b023eb6e0090d'
    content = b'8392cb0f8991fb706b8d80b898fd7bdc888e8fc4b40858e9eb136743ba1ac290'

    peers = [
        dht.Peer(id_, '127.0.0.1', 4710 + i)
        for i, id_
        in enumerate(dht_ids)
    ]

    with contextlib.ExitStack() as contexts:
        for predecessor, peer, successor in _iter_with_neighbors(peers):
            contexts.enter_context(static_peer(
                peer, predecessor, successor
            ))

        # Ensure datum is missing
        contact = peers[contact_order[0]]
        with pytest.raises(req.HTTPError) as exception_info:
            util.urlopen(f'http://{contact.ip}:{contact.port}/dynamic/{datum}')

        assert exception_info.value.status == 404, f"'/dynamic/{datum}' should be missing, but GET was not answered with '404'"

        # Create datum
        contact = peers[contact_order[1]]
        reply = util.urlopen(req.Request(f'http://{contact.ip}:{contact.port}/dynamic/{datum}', data=content, method='PUT'))
        assert reply.status == 201, f"Creation of '/dynamic/{datum}' did not yield '201'"

        # Ensure datum exists
        contact = peers[contact_order[2]]
        reply = util.urlopen(f'http://{contact.ip}:{contact.port}/dynamic/{datum}')
        assert reply.status == 200
        assert reply.read() == content, f"Content of '/dynamic/{datum}' does not match what was passed"

        # Delete datum
        contact = peers[contact_order[3]]
        real_url = util.urlopen(f'http://{contact.ip}:{contact.port}/dynamic/{datum}').geturl()  # Determine correct URL
        reply = util.urlopen(req.Request(real_url, method='DELETE'))
        assert reply.status in {200, 202, 204}, f"Deletion of '/dynamic/{datum}' did not succeed"

        # Ensure datum is missing
        contact = peers[contact_order[4]]
        with pytest.raises(req.HTTPError) as exception_info:
            util.urlopen(f'http://{contact.ip}:{contact.port}/dynamic/{datum}')

        assert exception_info.value.status == 404, f"'/dynamic/{datum}' should be missing, but GET was not answered with '404'"
