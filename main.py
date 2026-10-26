#Karan Kumar Sah
#11777126
#ks1466
#Project 1: JWKS server
#main.py
import base64
import sqlite3
import time
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

DB_FILE = "totally_not_my_privateKeys.db"


def get_db_connection(db_path=DB_FILE):
    """Opens and returns a connection to the SQLite database."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path=DB_FILE):
    """Creates the keys table if it does not exist and seeds initial keys."""
    with get_db_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        conn.commit()

    current_time = int(time.time())
    if get_key_from_db(expired=True, db_path=db_path) is None:
        generate_and_store_key(exp_timestamp=current_time - 3600, db_path=db_path)
    if get_key_from_db(expired=False, db_path=db_path) is None:
        generate_and_store_key(exp_timestamp=current_time + 3600, db_path=db_path)


def int_to_base64url(value):
    """Converts an integer to a Base64URL-encoded string with no padding."""
    byte_length = (value.bit_length() + 7) // 8 or 1
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")


def serialize_private_key(private_key):
    """Serializes an RSA private key to PKCS1 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_data):
    """Deserializes PKCS1 PEM bytes or string back into an RSA private key."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("utf-8")
    return serialization.load_pem_private_key(bytes(pem_data), password=None)


def generate_and_store_key(exp_timestamp=None, expired=False, db_path=DB_FILE):
    """Generates a 2048-bit RSA private key and saves it to the SQLite database."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem_bytes = serialize_private_key(private_key)

    if exp_timestamp is None:
        current_time = int(time.time())
        exp_timestamp = current_time - 3600 if expired else current_time + 3600

    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_bytes, exp_timestamp),
        )
        conn.commit()
        return cursor.lastrowid


def get_key_from_db(expired=False, db_path=DB_FILE):
    """Reads a valid or expired private key from the database using query parameters."""
    current_time = int(time.time())
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1",
                (current_time,),
            )
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1",
                (current_time,),
            )
        row = cursor.fetchone()

    if row is None:
        return None

    return row["kid"], deserialize_private_key(row["key"]), row["exp"]


def get_valid_keys_from_db(db_path=DB_FILE):
    """Reads all non-expired private keys from the database."""
    current_time = int(time.time())
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?",
            (current_time,),
        )
        rows = cursor.fetchall()

    return [
        (row["kid"], deserialize_private_key(row["key"]), row["exp"])
        for row in rows
    ]


@app.route("/auth", methods=["POST"])
def auth():
    """Issues a signed JWT using a valid or expired key from the SQLite database."""
    is_expired = (
        "expired" in request.args
        and request.args.get("expired", "").lower() != "false"
    )
    db_path = app.config.get("DB_FILE", DB_FILE)

    key_record = get_key_from_db(expired=is_expired, db_path=db_path)
    if key_record is None:
        generate_and_store_key(expired=is_expired, db_path=db_path)
        key_record = get_key_from_db(expired=is_expired, db_path=db_path)

    kid, private_key, exp_timestamp = key_record
    pem_private_key = serialize_private_key(private_key)

    username = "userABC"
    if request.authorization and request.authorization.username:
        username = request.authorization.username
    elif request.is_json:
        body = request.get_json(silent=True) or {}
        username = body.get("username", "userABC")

    headers = {"kid": str(kid)}
    payload = {
        "user": username,
        "exp": exp_timestamp,
    }

    token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=headers)
    return token, 200


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serves all valid public keys in JWKS format."""
    db_path = app.config.get("DB_FILE", DB_FILE)
    valid_keys = get_valid_keys_from_db(db_path=db_path)

    keys = []
    for kid, private_key, _ in valid_keys:
        public_numbers = private_key.public_key().public_numbers()
        jwk = {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(kid),
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e),
        }
        keys.append(jwk)

    return jsonify({"keys": keys}), 200


init_db(DB_FILE)


if __name__ == "__main__":
    app.run(port=8080)
