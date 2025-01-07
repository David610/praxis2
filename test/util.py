import array
import fcntl
import random
import subprocess
import sys
import termios
import time
import urllib.request


def bytes_available(socket):
    """Return number of bytes available to read on socket

    This requires some magic, but can be via an ioctl.
    """

    sock_size = array.array('i', [0])
    fcntl.ioctl(socket, termios.FIONREAD, sock_size)
    return sock_size[0]


class KillOnExit(subprocess.Popen):
    """A Popen subclass that kills the subprocess when its context exits"""

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, **kwargs,
            #stdout=subprocess.PIPE,
        )
        time.sleep(.1)

    def __exit__(self, exc_type, value, traceback):
        self.kill()

        super().__exit__(exc_type, value, traceback)
        time.sleep(.1)


def urlopen(url):
    """Delegate to `urllib.request.urlopen`, but interpret a 503 with 'Retry-After' header correctly.
    """
    try:
        return urllib.request.urlopen(url)
    except urllib.request.HTTPError as e:
        if e.status == 503 and 'Retry-After' in e.headers:
            seconds = int(e.headers['Retry-After'])
            time.sleep(seconds)
            return urllib.request.urlopen(url)
        else:
            raise e


if sys.version_info[:3] >= (3, 9):
    randbytes = random.randbytes
else:
    def randbytes(n):
        return bytes(random.randint(0, 255) for _ in range(n))
