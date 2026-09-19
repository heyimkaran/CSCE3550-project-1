# main.py
import base64
import time
import uuid
from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)

# In-memory database to store keys and their metadata
keys_db = {}


def int_to_base64url(value):
    """Converts an integer to a Base64URL-encoded string with no padding."""
    byte_length = (value.bit_length() + 7) // 8 or 1
    value_bytes = value.to_bytes(byte_length, byteorder='big')
    return base64.urlsafe_b64encode(value_bytes).decode('utf-8').rstrip('=')


def generate_key_pair(expired=False):
    """
    Generates a 2048-bit RSA private key, assigns a UUID kid,
    and sets an expiration timestamp.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    kid = str(uuid.uuid4())
    expiry_timestamp = int(time.time()) - 3600 if expired else int(time.time()) + 3600

    keys_db[kid] = {
        "private_key": private_key,
        "expiry": expiry_timestamp
    }

    return kid


# Bootstrap the server with one valid and one expired key
generate_key_pair(expired=False)
generate_key_pair(expired=True)


@app.route('/auth', methods=['POST'])
def auth():
    """
    Returns an unexpired, signed JWT on POST.
    If the 'expired' query parameter is present, issues a JWT signed with an expired key.
    """
    is_expired = 'expired' in request.args and request.args.get('expired', '').lower() != 'false'
    current_time = int(time.time())
    selected_kid = None

    # Find an appropriate key based on the query parameter
    for kid, key_data in keys_db.items():
        if is_expired and key_data["expiry"] < current_time:
            selected_kid = kid
            break
        elif not is_expired and key_data["expiry"] > current_time:
            selected_kid = kid
            break

    # Fallback: if no matching key exists, generate one on the fly
    if not selected_kid:
        selected_kid = generate_key_pair(expired=is_expired)

    key_data = keys_db[selected_kid]
    private_key = key_data["private_key"]

    # PyJWT requires the private key in PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # The JWT header must include the 'kid' to identify which key signed it
    headers = {"kid": selected_kid}
    payload = {
        "user": "mock_user",  # Authentication is mocked per requirements
        "exp": key_data["expiry"]
    }

    token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=headers)

    return token, 200


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """
    Serves the public keys in JWKS format.
    Filters out any expired keys.
    """
    keys = []
    current_time = int(time.time())

    for kid, key_data in keys_db.items():
        if key_data["expiry"] > current_time:
            private_key = key_data["private_key"]
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()

            # Construct the JSON Web Key
            jwk = {
                "alg": "RS256",
                "kty": "RSA",
                "use": "sig",
                "kid": kid,
                "n": int_to_base64url(public_numbers.n),
                "e": int_to_base64url(public_numbers.e),
            }
            keys.append(jwk)

    return jsonify({"keys": keys}), 200


if __name__ == "__main__":
    # Serve HTTP on port 8080 per requirements
    app.run(port=8080)
