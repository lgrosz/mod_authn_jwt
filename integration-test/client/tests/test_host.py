# Tests to reach the host

import pytest
from ping3 import ping
from hosts import LIGHTTPD

def test_host_reachability():
    response_time = ping(LIGHTTPD)

    # Assert that the response time is not None (i.e., host is reachable)
    assert response_time is not False, f"Host {LIGHTTPD} is unreachable"
