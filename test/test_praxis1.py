"""
Tests for RN Praxis 1
"""

import contextlib
import re
import socket
import time
from http.client import HTTPConnection

import pytest

from util import KillOnExit, randbytes


@pytest.fixture
def webserver(request):
    """
    Return a callable function that spawns a webserver with the given arguments.
    """
    def runner(*args, **kwargs):
        """Spawn a webserver with the given arguments."""
        return KillOnExit([request.config.getoption('executable'), *args], **kwargs)

    @contextlib.contextmanager
    def empty_context(*args, **kwargs):
        yield  # No server initialization here, just an empty context that never fails

    if request.config.getoption('debug_own'):
        return empty_context

    return runner


def test_execute(webserver, port):
    """
    Test server is executable
    """

    with webserver('127.0.0.1', f'{port}'):
        pass


@pytest.mark.timeout(1)
def test_listen(webserver, port):
    """
    Test server is listening on port (2.1)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), socket.create_connection(
        ('localhost', port)
    ):
        pass


@pytest.mark.timeout(1)
def test_reply(webserver, port):
    """
    Test the server is sending a reply (2.2)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), socket.create_connection(
        ('localhost', port)
    ) as conn:
        conn.send('Request\r\n\r\n'.encode())
        reply = conn.recv(1024)
        assert len(reply) > 0


@pytest.mark.timeout(2)
def test_packets(webserver, port):
    """
    Test HTTP delimiter for packet end (2.3)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), socket.create_connection(
        ('localhost', port)
    ) as conn:
        conn.send('GET / HTTP/1.1\r\n\r\n'.encode())
        time.sleep(.5)
        conn.send('GET / HTTP/1.1\r\na: b\r\n'.encode())
        time.sleep(.5)
        conn.send('\r\n'.encode())
        time.sleep(.5)  # Attempt to gracefully handle all kinds of multi-packet replies...
        replies = conn.recv(1024).split(b'\r\n\r\n')
        assert replies[0] and replies[1] and not replies[2]


@pytest.mark.timeout(1)
def test_httpreply(webserver, port):
    """
    Test reply is syntactically correct HTTP packet (2.4)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), socket.create_connection(
        ('localhost', port)
    ) as conn:
        conn.send('Request\r\n\r\n'.encode())
        time.sleep(.5)  # Attempt to gracefully handle all kinds of multi-packet replies...
        reply = conn.recv(1024)
        assert re.search(br'HTTP/1.[01] 400.*\r\n(.*\r\n)*\r\n', reply)


@pytest.mark.timeout(1)
def test_httpreplies(webserver, port):
    """
    Test reply is semantically correct HTTP packet (2.5)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), contextlib.closing(
        HTTPConnection('localhost', port)
    ) as conn:
        conn.connect()

        # there is no HEAD command in HTTP :-)
        conn.request('HEAD', '/index.html')
        reply = conn.getresponse()
        reply.read()
        assert reply.status == 501, "HEAD did not reply with '501'"

        conn.request('GET', '/index.html')
        reply = conn.getresponse()
        assert reply.status == 404


@pytest.mark.timeout(1)
def test_static_content(webserver, port):
    """
    Test static content can be accessed (2.6)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), contextlib.closing(
        HTTPConnection('localhost', port)
    ) as conn:
        conn.connect()

        for path, content in {
            '/static/foo': b'Foo',
            '/static/bar': b'Bar',
            '/static/baz': b'Baz',
        }.items():
            conn.request('GET', path)
            reply = conn.getresponse()
            payload = reply.read()
            assert reply.status == 200
            assert payload == content

        for path in [
            '/static/other',
            '/static/anything',
            '/static/else'
        ]:
            conn.request('GET', path)
            reply = conn.getresponse()
            reply.length = 0  # Convince `http.client` to handle no-content 404s properly
            reply.read()
            assert reply.status == 404


@pytest.mark.timeout(1)
def test_dynamic_content(webserver, port):
    """
    Test dynamic storage of data (key,value) works (2.7)
    """

    with webserver(
        '127.0.0.1', f'{port}'
    ), contextlib.closing(
        HTTPConnection('localhost', port)
    ) as conn:
        conn.connect()

        path = f'/dynamic/{randbytes(8).hex()}'
        content = randbytes(32).hex().encode()

        conn.request('GET', path)
        response = conn.getresponse()
        payload = response.read()
        assert response.status == 404, f"'{path}' should be missing, but GET was not answered with '404'"

        conn.request('PUT', path, content)
        response = conn.getresponse()
        payload = response.read()
        assert response.status in {200, 201, 202, 204}, f"Creation of '{path}' did not yield '201'"

        conn.request('GET', path)
        response = conn.getresponse()
        payload = response.read()
        assert response.status == 200
        assert payload == content, f"Content of '{path}' does not match what was passed"

        conn.request('DELETE', path)
        response = conn.getresponse()
        response.read()
        assert response.status in {200, 202, 204}, f"Deletion of '{path}' did not succeed"

        conn.request('GET', path)
        response = conn.getresponse()
        response.read()
        assert response.status == 404, f"'{path}' should be missing"
