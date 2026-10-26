"""
JWKS Server with SQLite-backed Persistent Key Storage (Project 2).

This module implements a RESTful JSON Web Key Set (JWKS) and authentication server
using Flask and SQLite. RSA private keys are serialized in PKCS#1 PEM format and
persisted in a local SQLite database (`totally_not_my_privateKeys.db`). All SQL
interactions strictly use parameterized queries (`?` placeholders) to prevent
SQL injection vulnerabilities.
"""

from __future__ import annotations

import base64
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, Response, jsonify, request
import jwt

app = Flask(__name__)

# Default SQLite database filename as required by the project specification
DB_FILE = "totally_not_my_privateKeys.db"


def get_db_connection(db_path: str = DB_FILE) -> sqlite3.Connection:
    """
    Establishes and returns a connection to the SQLite database.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        sqlite3.Connection: Active SQLite connection object.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_FILE) -> None:
    """
    Initializes the SQLite database and creates the `keys` table if it does not exist.
    Also seeds the database with at least one expired key and one valid key (expiring
    in 1 hour) so that POST /auth and GET /.well-known/jwks.json can be tested immediately.

    Args:
        db_path: Path to the SQLite database file.
    """
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        conn.commit()

    # Ensure at least one expired key and one valid key exist on startup
    current_time = int(time.time())
    if get_key_from_db(expired=True, db_path=db_path) is None:
        generate_and_store_key(exp_timestamp=current_time - 3600, db_path=db_path)
    if get_key_from_db(expired=False, db_path=db_path) is None:
        generate_and_store_key(exp_timestamp=current_time + 3600, db_path=db_path)


def int_to_base64url(value: int) -> str:
    """
    Converts an integer to a Base64URL-encoded string without padding (RFC 7518).

    Args:
        value: The positive integer to encode (such as RSA modulus `n` or exponent `e`).

    Returns:
        str: Base64URL-encoded string representation.
    """
    byte_length = (value.bit_length() + 7) // 8 or 1
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).decode("utf-8").rstrip("=")


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Serializes an RSA private key to PKCS#1 (TraditionalOpenSSL) PEM bytes for storage
    in the SQLite `BLOB` column.

    Args:
        private_key: The RSA private key instance to serialize.

    Returns:
        bytes: PEM-encoded PKCS#1 private key bytes.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(pem_data: Union[bytes, str]) -> rsa.RSAPrivateKey:
    """
    Deserializes PKCS#1 PEM data stored in the database back into an RSA private key object.

    Args:
        pem_data: PEM-encoded private key as bytes or string from SQLite.

    Returns:
        rsa.RSAPrivateKey: Deserialized RSA private key object.
    """
    if isinstance(pem_data, str):
        pem_bytes = pem_data.encode("utf-8")
    else:
        pem_bytes = bytes(pem_data)
    private_key = serialization.load_pem_private_key(pem_bytes, password=None)
    return private_key


def generate_and_store_key(
    exp_timestamp: Optional[int] = None,
    expired: bool = False,
    db_path: str = DB_FILE,
) -> int:
    """
    Generates a 2048-bit RSA private key, serializes it to PKCS#1 PEM format,
    and saves it to the SQLite database using a parameterized INSERT statement.

    Args:
        exp_timestamp: Optional explicit UNIX expiration timestamp.
        expired: If True and `exp_timestamp` is not provided, sets expiry to 1 hour ago;
                 otherwise sets expiry to 1 hour in the future.
        db_path: Path to the SQLite database file.

    Returns:
        int: The auto-incremented `kid` assigned by SQLite.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem_bytes = serialize_private_key(private_key)

    if exp_timestamp is None:
        current_time = int(time.time())
        exp_timestamp = current_time - 3600 if expired else current_time + 3600

    # Use parameterized query (?) to prevent SQL injection attacks
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (pem_bytes, exp_timestamp),
        )
        conn.commit()
        kid = int(cursor.lastrowid)

    return kid


def get_key_from_db(
    expired: bool = False,
    db_path: str = DB_FILE,
) -> Optional[Tuple[int, rsa.RSAPrivateKey, int]]:
    """
    Retrieves a single private key from the SQLite database matching the expiration state.
    Uses parameterized SQL queries to prevent SQL injection vulnerabilities.

    Args:
        expired: When True, selects a key with `exp <= current_time`.
                 When False, selects a key with `exp > current_time`.
        db_path: Path to the SQLite database file.

    Returns:
        Optional[Tuple[int, rsa.RSAPrivateKey, int]]: Tuple of (kid, private_key, exp)
        if found, or None if no matching key exists.
    """
    current_time = int(time.time())
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        if expired:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1",
                (current_time,),
            )
        else:
            cursor.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid ASC LIMIT 1",
                (current_time,),
            )
        row = cursor.fetchone()

    if row is None:
        return None

    private_key = deserialize_private_key(row["key"])
    return int(row["kid"]), private_key, int(row["exp"])


def get_valid_keys_from_db(
    db_path: str = DB_FILE,
) -> List[Tuple[int, rsa.RSAPrivateKey, int]]:
    """
    Retrieves all valid (unexpired) private keys from the SQLite database using
    a parameterized SELECT query.

    Args:
        db_path: Path to the SQLite database file.

    Returns:
        List[Tuple[int, rsa.RSAPrivateKey, int]]: List of (kid, private_key, exp) tuples.
    """
    current_time = int(time.time())
    with get_db_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ?",
            (current_time,),
        )
        rows = cursor.fetchall()

    valid_keys: List[Tuple[int, rsa.RSAPrivateKey, int]] = []
    for row in rows:
        private_key = deserialize_private_key(row["key"])
        valid_keys.append((int(row["kid"]), private_key, int(row["exp"])))

    return valid_keys


def extract_username_from_request() -> str:
    """
    Extracts the username from either HTTP Basic Auth or a JSON request payload,
    falling back to 'userABC' for mock authentication.

    Returns:
        str: Authenticated (mocked) username string.
    """
    if request.authorization and request.authorization.username:
        return str(request.authorization.username)

    if request.is_json:
        data = request.get_json(silent=True)
        if isinstance(data, dict) and "username" in data:
            return str(data["username"])

    return "userABC"


@app.route("/auth", methods=["POST"])
def auth() -> Tuple[Union[str, Response], int]:
    """
    Authenticates a mock user request (supporting both HTTP Basic Auth and JSON payloads)
    and returns a signed JWT using a private key fetched from the SQLite database.
    If the `expired` query parameter is present, signs the JWT using an expired key.
    """
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
    username = extract_username_from_request()

    headers = {"kid": str(kid)}
    payload: Dict[str, Any] = {
        "user": username,
        "sub": username,
        "iat": int(time.time()),
        "exp": exp_timestamp,
    }

    token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=headers)
    return token, 200


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks() -> Tuple[Response, int]:
    """
    Reads all non-expired private keys from the SQLite database and returns
    their corresponding public keys in standard RFC 7517 JWKS format.
    """
    db_path = app.config.get("DB_FILE", DB_FILE)
    valid_keys = get_valid_keys_from_db(db_path=db_path)

    keys_list: List[Dict[str, str]] = []
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
        keys_list.append(jwk)

    return jsonify({"keys": keys_list}), 200


# Initialize database and seed keys when module is loaded
init_db(DB_FILE)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
