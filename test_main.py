#Karan Kumar Sah
#11777126
#ks1466
#Project 1: JWKS server
#test_main.py
import json
import time
import pytest
import jwt
from jwt.algorithms import RSAAlgorithm
from main import app, keys_db, generate_key_pair, int_to_base64url


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_int_to_base64url():
    # Test known integer to base64url conversions
    assert int_to_base64url(65537) == "AQAB"
    assert int_to_base64url(0) == "AA"


def test_generate_key_pair():
    # Verify a valid key generates with a future expiry timestamp
    kid = generate_key_pair(expired=False)
    assert kid in keys_db
    assert keys_db[kid]["expiry"] > time.time()

    # Verify an expired key generates with a past expiry timestamp
    expired_kid = generate_key_pair(expired=True)
    assert expired_kid in keys_db
    assert keys_db[expired_kid]["expiry"] < time.time()


def test_jwks_endpoint_excludes_expired(client):
    # Clear the database and bootstrap one valid and one expired key
    keys_db.clear()
    valid_kid = generate_key_pair(expired=False)
    expired_kid = generate_key_pair(expired=True)

    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200

    data = json.loads(response.data)
    assert "keys" in data

    # Ensure the JWKS endpoint only serves the unexpired public key
    returned_kids = [jwk["kid"] for jwk in data["keys"]]
    assert valid_kid in returned_kids
    assert expired_kid not in returned_kids

    # Verify standard JWK properties
    for jwk in data["keys"]:
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert "n" in jwk
        assert "e" in jwk


def test_auth_endpoint_valid(client):
    response = client.post('/auth')
    assert response.status_code == 200

    token = response.data.decode('utf-8')
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers

    # Verify the JWT was signed using a key that is currently valid
    kid = headers["kid"]
    assert keys_db[kid]["expiry"] > time.time()

    # Verify JWT signature against JWKS public key
    jwks_response = client.get('/.well-known/jwks.json')
    jwks_data = json.loads(jwks_response.data)
    matching_jwk = next(k for k in jwks_data["keys"] if k["kid"] == kid)
    public_key = RSAAlgorithm.from_jwk(json.dumps(matching_jwk))

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["user"] == "mock_user"
    assert decoded["exp"] == keys_db[kid]["expiry"]


def test_auth_endpoint_expired_param(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200

    token = response.data.decode('utf-8')
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers

    # Verify the JWT was explicitly signed using an expired key
    kid = headers["kid"]
    assert keys_db[kid]["expiry"] < time.time()

    # Verify that decoding with exp verification fails as expected
    pem_pub = keys_db[kid]["private_key"].public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, pem_pub, algorithms=["RS256"])


def test_auth_endpoint_expired_flag_only(client):
    # Query param ?expired without explicit '=true' should also trigger expired key
    response = client.post('/auth?expired')
    assert response.status_code == 200

    token = response.data.decode('utf-8')
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    kid = headers["kid"]
    assert keys_db[kid]["expiry"] < time.time()


def test_auth_endpoint_fallback_valid(client):
    # Clear the database to force fallback key generation for valid key
    keys_db.clear()
    response = client.post('/auth')
    assert response.status_code == 200

    token = response.data.decode('utf-8')
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    kid = headers["kid"]
    assert keys_db[kid]["expiry"] > time.time()


def test_auth_endpoint_fallback_expired(client):
    # Clear the database to force fallback key generation for expired key
    keys_db.clear()
    response = client.post('/auth?expired=true')
    assert response.status_code == 200

    token = response.data.decode('utf-8')
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers
    kid = headers["kid"]
    assert keys_db[kid]["expiry"] < time.time()


def test_http_methods(client):
    # Ensure /auth only allows POST
    assert client.get('/auth').status_code == 405
    assert client.put('/auth').status_code == 405
    assert client.delete('/auth').status_code == 405

    # Ensure /.well-known/jwks.json only allows GET
    assert client.post('/.well-known/jwks.json').status_code == 405
    assert client.put('/.well-known/jwks.json').status_code == 405
    assert client.delete('/.well-known/jwks.json').status_code == 405
