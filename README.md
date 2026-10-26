# JWKS Server with SQLite Storage (Project 2)

A RESTful JSON Web Key Set (JWKS) server backed by a SQLite database (`totally_not_my_privateKeys.db`). It generates and persists RSA private keys in PKCS#1 PEM format, serves unexpired public keys with unique identifiers (`kid`) for verifying JSON Web Tokens (JWTs), and provides an authentication endpoint (`POST /auth`) that issues signed JWTs while preventing SQL injection via parameterized SQL queries.

## Features

1. **SQLite-Backed Key Persistence**:
   - Creates and opens `totally_not_my_privateKeys.db` on startup with the schema:
     ```sql
     CREATE TABLE IF NOT EXISTS keys(
         kid INTEGER PRIMARY KEY AUTOINCREMENT,
         key BLOB NOT NULL,
         exp INTEGER NOT NULL
     )
     ```
   - Generates 2048-bit RSA private keys (`public_exponent=65537`), serializes them in PKCS#1 PEM (`TraditionalOpenSSL`) format, and persists both valid (expiring in >= 1 hour) and expired keys.
   - Uses parameterized SQL queries (`?` placeholders) for all `INSERT` and `SELECT` operations to prevent SQL injection attacks.

2. **RESTful Endpoints (Port 8080)**:
   - **`POST /auth`**:
     - Accepts mock authentication via HTTP Basic Auth, JSON payload (`{"username": "userABC", "password": "password123"}`), or empty POST body.
     - Queries `totally_not_my_privateKeys.db` for a valid (unexpired) private key by default, or an expired private key when the `expired` query parameter is present (e.g., `/auth?expired=true`).
     - Signs and returns an RS256 JWT containing the key's `kid` in the header and `exp` timestamp in the payload.
     - Returns HTTP `405 Method Not Allowed` for non-POST requests.
   - **`GET /.well-known/jwks.json`**:
     - Queries `totally_not_my_privateKeys.db` for all non-expired private keys (`exp > current_time`).
     - Deserializes each PEM key, extracts its RSA public parameters (`n`, `e`), and returns a standard RFC 7517 JWKS JSON response.
     - Returns HTTP `405 Method Not Allowed` for non-GET requests.

3. **Automated Testing & Coverage**:
   - Comprehensive unit and integration test suite in `test_main.py` built with `pytest` and `pytest-cov`.
   - Achieves **99% test coverage** (exceeding the 80% requirement).

## Project Structure

```text
jwks_server/
├── .gitignore                        # Excludes venv, caches, coverage, and binaries
├── LICENSE                           # Project license
├── README.md                         # Project documentation
├── main.py                           # Flask JWKS server with SQLite storage
├── requirements.txt                  # Python dependencies
├── test_main.py                      # Automated pytest suite
└── totally_not_my_privateKeys.db     # SQLite database file (generated on start)
```

## Setup & Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Running the Server

```bash
python3 main.py
```

The server listens on `http://localhost:8080`:
- JWKS Endpoint: `http://localhost:8080/.well-known/jwks.json`
- Auth Endpoint: `http://localhost:8080/auth`

## Running Tests & Coverage

```bash
pytest -v --cov=main --cov-report=term-missing test_main.py
```

## Blackbox Testing with Gradebot

```bash
./gradebot project-2 --dir="." --run="python3 main.py"
```
