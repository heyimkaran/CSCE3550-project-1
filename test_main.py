"""
Unit and Integration Test Suite for the SQLite-backed JWKS Server (Project 2).

Tests cover SQLite database creation, PKCS#1 PEM key serialization/deserialization,
parameterized queries for valid and expired keys, JWT issuance (Basic Auth, JSON body,
and default payload), JWKS public key serving, fallback key generation, and HTTP method
restrictions.
"""

import base64
import json
import os
import sqlite3
import time

import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

from main import (
    app,
    deserialize_private_key,
    generate_and_store_key,
    get_db_connection,
    get_key_from_db,
    get_valid_keys_from_db,
    init_db,
    int_to_base64url,
    serialize_private_key,
)


@pytest.fixture
def test_db(tmp_path):
    """Creates an isolated temporary SQLite database for each test."""
    db_file = str(tmp_path / "test_privateKeys.db")
    init_db(db_file)
    return db_file


@pytest.fixture
def client(test_db):
    """Configures the Flask test client to use the temporary SQLite database."""
    app.config["TESTING"] = True
    app.config["DB_FILE"] = test_db
    with app.test_client() as test_client:
        yield test_client


def test_int_to_base64url():
    """Verifies RFC 7518 Base64URL integer encoding without padding."""
    assert int_to_base64url(65537) == "AQAB"
    assert int_to_base64url(0) == "AA"


def test_sqlite_schema_and_initial_seed(test_db):
    """Verifies that init_db creates the `keys` table and seeds valid and expired keys."""
    assert os.path.exists(test_db)

    with get_db_connection(test_db) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(keys)")
        columns = {row["name"]: row["type"].upper() for row in cursor.fetchall()}

    assert "kid" in columns and "INTEGER" in columns["kid"]
    assert "key" in columns and "BLOB" in columns["key"]
    assert "exp" in columns and "INTEGER" in columns["exp"]

    valid_key = get_key_from_db(expired=False, db_path=test_db)
    expired_key = get_key_from_db(expired=True, db_path=test_db)

    assert valid_key is not None
    assert expired_key is not None
    assert valid_key[2] > int(time.time())
    assert expired_key[2] <= int(time.time())


def test_serialize_and_deserialize_key(test_db):
    """Verifies PKCS#1 PEM serialization and deserialization from both bytes and str."""
    kid = generate_and_store_key(expired=False, db_path=test_db)
    assert isinstance(kid, int) and kid > 0

    record = get_key_from_db(expired=False, db_path=test_db)
    assert record is not None
    _, priv_key, _ = record

    pem_bytes = serialize_private_key(priv_key)
    assert pem_bytes.startswith(b"-----BEGIN RSA PRIVATE KEY-----")

    # Test deserializing from bytes and from UTF-8 string
    key_from_bytes = deserialize_private_key(pem_bytes)
    key_from_str = deserialize_private_key(pem_bytes.decode("utf-8"))

    assert (
        key_from_bytes.private_numbers().d
        == key_from_str.private_numbers().d
    )


def test_jwks_endpoint_excludes_expired(client, test_db):
    """Verifies that GET /.well-known/jwks.json only returns unexpired public keys."""
    with get_db_connection(test_db) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    valid_kid = generate_and_store_key(expired=False, db_path=test_db)
    expired_kid = generate_and_store_key(expired=True, db_path=test_db)

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = json.loads(response.data)
    assert "keys" in data

    returned_kids = [jwk["kid"] for jwk in data["keys"]]
    assert str(valid_kid) in returned_kids
    assert str(expired_kid) not in returned_kids

    for jwk in data["keys"]:
        assert jwk["kty"] == "RSA"
        assert jwk["alg"] == "RS256"
        assert jwk["use"] == "sig"
        assert "n" in jwk
        assert "e" in jwk


def test_auth_endpoint_valid_default(client, test_db):
    """Verifies POST /auth issues a valid JWT verifiable by JWKS."""
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers

    jwks_response = client.get("/.well-known/jwks.json")
    jwks_data = json.loads(jwks_response.data)
    matching_jwk = next(k for k in jwks_data["keys"] if k["kid"] == headers["kid"])
    public_key = RSAAlgorithm.from_jwk(json.dumps(matching_jwk))

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["user"] == "userABC"
    assert decoded["exp"] > time.time()


def test_auth_endpoint_json_payload(client):
    """Verifies POST /auth with JSON payload {'username': 'userABC', 'password': 'password123'}."""
    response = client.post(
        "/auth",
        json={"username": "userABC", "password": "password123"},
    )
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["user"] == "userABC"


def test_auth_endpoint_basic_auth(client):
    """Verifies POST /auth with HTTP Basic Authentication header."""
    credentials = base64.b64encode(b"userABC:password123").decode("utf-8")
    response = client.post(
        "/auth",
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded["user"] == "userABC"


def test_auth_endpoint_expired_param(client, test_db):
    """Verifies POST /auth?expired=true signs the JWT with an expired key from SQLite."""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    headers = jwt.get_unverified_header(token)
    assert "kid" in headers

    kid = int(headers["kid"])
    with get_db_connection(test_db) as conn:
        row = conn.execute("SELECT key, exp FROM keys WHERE kid = ?", (kid,)).fetchone()

    assert row is not None
    assert row["exp"] <= int(time.time())

    priv_key = deserialize_private_key(row["key"])
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, priv_key.public_key(), algorithms=["RS256"])


def test_auth_endpoint_expired_flag_only(client, test_db):
    """Verifies POST /auth?expired without explicit '=true' also selects an expired key."""
    response = client.post("/auth?expired")
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    headers = jwt.get_unverified_header(token)
    kid = int(headers["kid"])

    with get_db_connection(test_db) as conn:
        row = conn.execute("SELECT exp FROM keys WHERE kid = ?", (kid,)).fetchone()
    assert row["exp"] <= int(time.time())


def test_auth_endpoint_fallback_generation(client, test_db):
    """Verifies that /auth generates and stores a key if the database table is empty."""
    with get_db_connection(test_db) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    assert get_valid_keys_from_db(test_db) == []

    # Fallback generation for valid key
    res_valid = client.post("/auth")
    assert res_valid.status_code == 200
    assert len(get_valid_keys_from_db(test_db)) == 1

    # Fallback generation for expired key
    res_expired = client.post("/auth?expired=true")
    assert res_expired.status_code == 200
    assert get_key_from_db(expired=True, db_path=test_db) is not None


def test_http_methods(client):
    """Verifies that unsupported HTTP methods return 405 Method Not Allowed."""
    assert client.get("/auth").status_code == 405
    assert client.put("/auth").status_code == 405
    assert client.delete("/auth").status_code == 405

    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.put("/.well-known/jwks.json").status_code == 405
    assert client.delete("/.well-known/jwks.json").status_code == 405
