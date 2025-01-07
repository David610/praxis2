import pytest


def pytest_addoption(parser):
    parser.addoption('--executable', action='store', default='build/webserver')
    parser.addoption('--port', action='store', default=4711)
    parser.addoption('--debug_own', action='store_true', default=False)


@pytest.fixture
def port(request):
    return request.config.getoption('port')
