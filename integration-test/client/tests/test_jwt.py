"""
This module contains tests for the jwt backend handler
"""

import pytest
import requests
from hosts import LIGHTTPD

def test_invalidjwt():
    """
    Tests for invalid jwt, like not a jwt at all.
    """
    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': 'Bearer token'
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_invalidsignature():
    """
    Tests a valid jwt but with the incorrect signature
    """
    import jwt

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, "secret", algorithm="HS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_badalgjwt():
    """
    Tests a valid, correctly signed, and correct algorithm jwt
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, PKEY, algorithm="RS512")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_validjwt():
    """
    Tests a valid, correctly signed, and correct algorithm jwt
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_expired():
    """
    Test an expired jwt
    """
    import jwt
    from keys import PKEY
    from datetime import datetime, timedelta, timezone

    payload = {
        "exp": datetime.now(tz=timezone.utc) - timedelta(hours=1)
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_nonexpired():
    """
    Test a non-expired jwt
    """
    import jwt
    from keys import PKEY
    from datetime import datetime, timedelta, timezone

    payload = {
        "exp": datetime.now(tz=timezone.utc) + timedelta(minutes=1)
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_nbfbad():
    """
    Tests nbf claim failure
    """
    import jwt
    from keys import PKEY
    from datetime import datetime, timedelta, timezone

    payload = {
        "nbf": datetime.now(tz=timezone.utc) + timedelta(hours=1)
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_nbfgood():
    """
    Tests nbf claim success
    """
    import jwt
    from keys import PKEY
    from datetime import datetime, timedelta, timezone

    payload = {
        "nbf": datetime.now(tz=timezone.utc) - timedelta(hours=1)
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_aud():
    """
    Tests aud claim success
    """
    import jwt
    from keys import PKEY

    payload = {
        "aud": "the-audience"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/audience",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_badaud():
    """
    Tests aud claim mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "aud": "the-wrong-audience"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/audience",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_missingaud():
    """
    Tests aud claim mismatch
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/audience",
        headers = {
            'Authorization': f"Bearer {jwt.encode({ }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_iss():
    """
    Tests iss claim success
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "the-issuer"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/issuer",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_badiss():
    """
    Tests iss claim mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "the-wrong-issuer"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/issuer",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_missingiss():
    """
    Tests iss claim mismatch
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/issuer",
        headers = {
            'Authorization': f"Bearer {jwt.encode({ }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_sub():
    """
    Tests sub claim success
    """
    import jwt
    from keys import PKEY

    payload = {
        "sub": "the-subject"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/subject",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_badsub():
    """
    Tests sub claim mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "sub": "the-wrong-subject"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/subject",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_missingsub():
    """
    Tests sub claim mismatch
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/subject",
        headers = {
            'Authorization': f"Bearer {jwt.encode({ }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401

def test_no_remote_user():
    """
    Tests if REMOTE_USER is correctly when no subject or issuer present
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/remote-user/env.sh",
        headers = {
            'Authorization': f"Bearer {jwt.encode({ }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
    assert f"REMOTE_USER=" not in response.text

def test_subject_only_remote_user():
    """
    Tests if REMOTE_USER is correctly when subject is present
    """
    import jwt
    from keys import PKEY

    subject = "username"
    payload = {
        "sub": subject
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/remote-user/env.sh",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
    assert f"REMOTE_USER={subject}" in response.text

def test_issuer_only_remote_user():
    """
    Tests if REMOTE_USER is absent when only issuer is present
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "issuer"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/remote-user/env.sh",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
    assert "REMOTE_USER=" not in response.text

def test_subject_and_issuer_remote_user():
    """
    Tests if REMOTE_USER is correctly when subject and issuer are present
    """
    import jwt
    from keys import PKEY

    subject = "username"
    issuer = "place"
    payload = {
        "sub": subject,
        "iss": issuer
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/remote-user/env.sh",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
    assert f"REMOTE_USER={subject}@{issuer}" in response.text

def test__remote_user_scheme_removal():
    """
    Tests url-schemes are removed from REMOTE_USER
    """
    import jwt
    from keys import PKEY

    subject = "https://my-subject.com"
    issuer = "my-issuer.com"
    payload = {
        "sub": f'{subject}',
        "iss": f'https://{issuer}'
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/remote-user/env.sh",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
    assert f"REMOTE_USER={subject}@{issuer}" in response.text
