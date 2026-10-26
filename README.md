# JWKS Server (Project 2)

A RESTful JSON Web Key Set (JWKS) server extended with SQLite storage (`totally_not_my_privateKeys.db`). It generates and persists RSA private keys in PKCS#1 PEM format, serves unexpired public keys with unique identifiers (`kid`) for verifying JSON Web Tokens (JWTs), and provides an authentication endpoint (`POST /auth`) using parameterized SQL queries.

## Features

1. **SQLite Key Storage**:
   - Opens `totally_not_my_privateKeys.db` on startup and initializes the `keys` table:
     ```sql
     CREATE TABLE IF NOT EXISTS keys(
         kid INTEGER PRIMARY KEY AUTOINCREMENT,
         key BLOB NOT NULL,
         exp INTEGER NOT NULL
     )
     ```
   - Serializes 2048-bit RSA private keys in PKCS#1 PEM format and stores both valid and expired keys.
   - Uses parameterized SQL queries (`?`) for all database reads and writes to prevent SQL injection.

2. **RESTful Endpoints (Port 8080)**:
   - **`GET /.well-known/jwks.json`**: Reads all non-expired keys from SQLite and returns their public keys in JWKS format.
   - **`POST /auth`**: Reads a valid key (or an expired key if `?expired` is passed) from SQLite and returns a signed RS256 JWT. Supports HTTP Basic Auth and JSON request bodies (`{"username": "userABC", "password": "password123"}`).

3. **Testing**:
   - Automated `pytest` suite in `test_main.py` with >95% coverage.

## Setup & Running

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

## Running Tests & Gradebot

```bash
pytest -v --cov=main --cov-report=term-missing test_main.py
./gradebot project-2 --dir="." --run="python3 main.py"
```
