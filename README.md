# JWKS Server (Project 1)

A RESTful JSON Web Key Set (JWKS) server that generates and serves RSA public keys with unique identifiers (`kid`) for verifying JSON Web Tokens (JWTs), implements key expiration, and provides an authentication endpoint supporting the issuance of both valid and expired JWTs for verification and testing purposes.

---
## Project Manager
Karan Kumar Sah (ks1466)

## Features

1. **RSA Key Generation & Metadata**:
   - Generates 2048-bit RSA key pairs with public exponent 65537.
   - Associates each key with a unique Key ID (`kid`, UUIDv4) and an expiration timestamp (UNIX epoch).
   - Manages key lifecycles, distinguishing between active (unexpired) and expired keys.

2. **RESTful Handlers (Port 8080)**:
   - **`GET /.well-known/jwks.json`**:
     - Serves public keys in standard JWKS (RFC 7517) format.
     - Strictly filters and excludes expired keys.
     - Public numbers (`n`, `e`) are Base64URL-encoded without padding (RFC 7518).
     - Returns HTTP 405 Method Not Allowed for non-GET requests.
   - **`POST /auth`**:
     - Returns a signed JWT (RS256) containing `kid` in the header and mock user authentication payload.
     - Returns an unexpired token signed by a valid key by default.
     - If the `expired` query parameter is present (e.g., `/auth?expired=true`), issues a JWT signed with an expired key and sets the token expiry to the past.
     - Returns HTTP 405 Method Not Allowed for non-POST requests.

3. **Automated Testing & High Coverage**:
   - Comprehensive test suite built with `pytest` and `pytest-cov`.
   - Verifies key generation, JWKS filtering, token issuance, cryptographic signature validation against JWKS public keys, error states, fallback generation, and HTTP method enforcement.
   - Test coverage exceeds 95% (well above the 80% requirement).

---

## Project Structure

```text
jwks_server/
├── .gitignore          # Excludes venv, test caches, coverage, and binaries
├── LICENSE             # Project license
├── README.md           # Project documentation and instructions
├── main.py             # JWKS Flask server implementation
├── requirements.txt    # Python dependencies
└── test_main.py        # Automated test suite and validation
```

---

## Setup & Installation

### Prerequisites
- Python 3.9+
- `pip`

### Virtual Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Running the Server

Start the server on port 8080:
```bash
python3 main.py
```

The server will be available at:
- JWKS Endpoint: `http://localhost:8080/.well-known/jwks.json`
- Auth Endpoint: `http://localhost:8080/auth`

---

## Running Tests and Coverage

Execute the test suite with coverage reporting:
```bash
pytest -v --cov=main test_main.py
```

To generate a detailed terminal report with line numbers:
```bash
pytest --cov=main --cov-report=term-missing test_main.py
```

---

## Blackbox Testing with Gradebot

Run the provided grading client against the server:
```bash
./gradebot project-1 --dir="." --run="python3 main.py"
```

---

## Deliverables & Screenshots

Please include the required screenshots in the repository before final submission:
1. **Test Suite Coverage**: Screenshot of `pytest -v --cov=main test_main.py` demonstrating >80% coverage with identifying information visible.
2. **Gradebot Execution**: Screenshot of `./gradebot project-1 --dir="." --run="python3 main.py"` showing passing results with identifying information visible.
