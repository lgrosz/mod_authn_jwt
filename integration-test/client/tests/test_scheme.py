"""
This module contains tests for the scheme handler
"""

import pytest
import requests
from hosts import LIGHTTPD

def test_noauthheader():
    """
    No authorization header

    According to [section 3 of RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3)

    > If the [...] request does not include authentication credentials [...]
    > server MUST include the HTTP "WWW-Authenticate" response header field
    > [...].

    It also gives an example

    > For example, in response to a protected resource request without
    > authentication:
    >
    >   HTTP/1.1 401 Unauthorized
    >   WWW-Authenticate: Bearer realm="example"
    """
    response = requests.get(f"http://{LIGHTTPD}")

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_bearernotoken():
    """
    Request contains a bearer authorization header, but no token

    According to [section 3.1 of RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1)

    > invalid_request
    >   The request is missing a required parameter, includes an
    >   unsupported parameter or parameter value, repeats the
    >   same parameter, uses more than one method for including
    >   an access token, or is otherwise malformed.  The resource
    >   server SHOULD respond with the HTTP 400 (Bad Request)
    >   status code.
    """
    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': 'Bearer'
        }
    )

    assert response.status_code == 400

def test_bearernotoken1():
    """
    Request contains a bearer authorization header, with subsequent space, but no token
    """
    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': 'Bearer '
        }
    )

    assert response.status_code == 400
