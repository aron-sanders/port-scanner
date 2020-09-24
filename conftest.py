import pytest
import json

DEFAULT_PORT_RANGE = '0-1023'
DEFAULT_HOSTS_PATH = 'hosts.json'


def pytest_addoption(parser):
    parser.addoption("--port_range", action="store", default=DEFAULT_PORT_RANGE,
                     help=f"Please enter the port range you would like to scan. EX:  {DEFAULT_PORT_RANGE}")
    parser.addoption("--config_file", action="store", default=DEFAULT_HOSTS_PATH, help="Please enter the path of your "
                     "configuration file.")


def pytest_generate_tests(metafunc):
    config_file = open_json_file(metafunc.config.option.config_file)
    metafunc.parametrize("ip", get_ip_list(config_file))


@pytest.fixture
def port_range(request):
    return request.config.getoption("--port_range")


@pytest.fixture
def get_config_file(request):
    return open_json_file(request.config.getoption("--config_file"))


def open_json_file(path):
    with open(path) as file:
        return json.load(file)


def get_ip_list(get_config_file):
    return [key["ip"] for key in get_config_file]
