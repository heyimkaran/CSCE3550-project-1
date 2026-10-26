# test_main.py
import base64
import json
import os
import time
import pytest
import jwt
from jwt.algorithms import RSAAlgorithm
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
    db_file = str(tmp_path / "test_privateKeys.db")
    init_db(db_file)
    return db_file


@pytest.fixture
def client(test_db):
    app.config["TESTING"] = True
    app.config["DB_FILE"] = test_db
    with app.test_client() as client:
        yield client


def test_int_to_base64url():
    assert int_to_base64url(65537) == "AQAB"
    assert int_to_base64url(0) == "AA"


def test_sqlite_schema_and_seed(test_db):
    assert os.path.exists(test_db)

    valid_key = get_key_from_db(expired=False, db_path=test_db)
    expired_key = get_key_from_db(expired=True, db_path=test_db)

    assert valid_key is not None
    assert expired_key is not None
    assert valid_key[2] > time.time()
    assert expired_key[2] <= time.time()


def test_serialize_and_deserialize_key(test_db):
    kid = generate_and_store_key(expired=False, db_path=test_db)
    assert kid > 0

    _, priv_key, _ = get_key_from_db(expired=False, db_path=test_db)
    pem_bytes = serialize_private_key(priv_key)

    key_from_bytes = deserialize_private_key(pem_bytes)
    key_from_str = deserialize_private_key(pem_bytes.decode("utf-8"))

    assert key_from_bytes.private_numbers().d == key_from_str.private_numbers().d


def test_jwks_endpoint_excludes_expired(client, test_db):
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


def test_auth_endpoint_valid(client, test_db):
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


def test_auth_endpoint_json_and_basic_auth(client):
    res_json = client.post(
        "/auth",
        json={"username": "userABC", "password": "password123"},
    )
    assert res_json.status_code == 200
    decoded_json = jwt.decode(
        res_json.data.decode("utf-8"), options={"verify_signature": False}
    )
    assert decoded_json["user"] == "userABC"

    creds = base64.b64encode(b"userABC:password123").decode("utf-8")
    res_basic = client.post("/auth", headers={"Authorization": f"Basic {creds}"})
    assert res_basic.status_code == 200
    decoded_basic = jwt.decode(
        res_basic.data.decode("utf-8"), options={"verify_signature": False}
    )
    assert decoded_basic["user"] == "userABC"


def test_auth_endpoint_expired_param(client, test_db):
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    headers = jwt.get_unverified_header(token)
    kid = int(headers["kid"])

    with get_db_connection(test_db) as conn:
        row = conn.execute("SELECT key, exp FROM keys WHERE kid = ?", (kid,)).fetchone()

    assert row["exp"] <= time.time()
    priv_key = deserialize_private_key(row["key"])
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, priv_key.public_key(), algorithms=["RS256"])


def test_auth_endpoint_expired_flag_only(client, test_db):
    response = client.post("/auth?expired")
    assert response.status_code == 200

    token = response.data.decode("utf-8")
    headers = jwt.get_unverified_header(token)
    kid = int(headers["kid"])

    with get_db_connection(test_db) as conn:
        row = conn.execute("SELECT exp FROM keys WHERE kid = ?", (kid,)).fetchone()
    assert row["exp"] <= time.time()


def test_auth_endpoint_fallback(client, test_db):
    with get_db_connection(test_db) as conn:
        conn.execute("DELETE FROM keys")
        conn.commit()

    assert get_valid_keys_from_db(test_db) == []
    assert client.post("/auth").status_code == 200
    assert client.post("/auth?expired=true").status_code == 200


def test_http_methods(client):
    assert client.get("/auth").status_code == 405
    assert client.put("/auth").status_code == 405
    assert client.delete("/auth").status_code == 405

    assert client.post("/.well-known/jwks.json").status_code == 405
    assert client.put("/.well-known/jwks.json").status_code == 405
    assert client.delete("/.well-known/jwks.json").status_code == 405
