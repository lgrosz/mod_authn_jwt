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

def test_issuermismatch():
    """
    Tests issuer mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "incorrect-issuer"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/issuer",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_issuermatch():
    """
    Tests issuer match
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "correct-issuer"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/issuer",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_subjectmismatch():
    """
    Tests subject mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "incorrect-subject"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/subject",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_subjectmatch():
    """
    Tests subject match
    """
    import jwt
    from keys import PKEY
    from datetime import datetime, timedelta, timezone

    payload = {
        "iss": "correct-subject"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/subject",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_audiencemismatch():
    """
    Tests audience mismatch
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "incorrect-audience"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/audience",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_audiencematch():
    """
    Tests audience match
    """
    import jwt
    from keys import PKEY

    payload = {
        "iss": "correct-audience"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/audience",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_missingstringclaim():
    """
    Tests missing string claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/string-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_incorrectsingstringclaim():
    """
    Tests incorrect string claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/string-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"string-claim": "incorrect"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_correctsingstringclaim():
    """
    Tests incorrect string claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/string-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"string-claim": "correct"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_missingintegerclaim():
    """
    Tests missing integer claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/integer-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_incorrectsingintegerclaim():
    """
    Tests incorrect integer claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/integer-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"integer-claim": 1 }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_correctsingintegerclaim():
    """
    Tests incorrect integer claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/integer-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"integer-claim": 2 }, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_missingjsonclaim():
    """
    Tests missing json claim
    """
    import jwt
    from keys import PKEY

    response = requests.get(
        url = f"http://{LIGHTTPD}/json-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode({"some": "payload"}, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_partialjsonclaim():
    """
    Tests partial match json claim
    """
    import jwt
    from keys import PKEY

    payload = {
        "integer": 1
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/json-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 401
    assert 'WWW-Authenticate' in response.headers

def test_correctjsonclaim():
    """
    Tests correct json claim
    """
    import jwt
    from keys import PKEY

    payload = {
        "integer": 1,
        "string": "str"
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/json-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_nestedjsonclaim():
    """
    Tests correct json claim
    """
    import jwt
    from keys import PKEY

    payload = {
        "outer": {
            "claim": "valid"
        }
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/nested-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200

def test_booleanworkaround():
    """
    Tests boolean claim workaround
    """
    import jwt
    from keys import PKEY

    payload = {
        "bool": True
    }

    response = requests.get(
        url = f"http://{LIGHTTPD}/boolean-claim",
        headers = {
            'Authorization': f"Bearer {jwt.encode(payload, PKEY, algorithm="RS256")}"
        }
    )

    assert response.status_code == 200
