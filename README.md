# SecureAuth Backend API

A production-grade, reusable backend API built with **Python**, **FastAPI**, **SQLAlchemy (Async)**, **PyJWT**, and **PyOTP**. Designed strictly according to **Security+** principles and **OWASP Top 10** mitigations.

---

## Key Security Features

- **Password Security**: Password complexity enforcement (NIST guidelines) and bcrypt hashing with work factor 12.
- **Multi-Factor Authentication (MFA)**:
  - RFC 6238 TOTP authenticator app integration (Google Authenticator, Microsoft Authenticator, 1Password, Authy).
  - Scalable vector SVG and base64 PNG QR code generation.
  - 10 single-use emergency recovery backup codes (stored hashed in database).
  - Two-step authentication handshake with restricted `mfa_pending` challenge token.
- **Role-Based Access Control (RBAC)**:
  - Granular permissions mapped to roles (`USER`, `MODERATOR`, `ADMIN`, `SUPERADMIN`) following the Principle of Least Privilege.
  - Declarative route guards (`RequirePermission`, `RequireRole`).
  - Hierarchical role escalation protection (Admins cannot grant roles equal to or higher than their own).
- **Cryptographic Tokens & Session Security**:
  - Short-lived signed PyJWT Access Tokens (15 mins).
  - Single-use Refresh Token Rotation with SHA-256 database hashing.
  - Automatic **Family Revocation** upon refresh token reuse detection (replay attack defense).
- **Rate-Limiting**: Per-IP and per-endpoint sliding rate limiting via SlowAPI to prevent brute-force attacks.
- **OWASP Top 10 Protections**:
  - **A01: Broken Access Control**: Strict contextual authorization dependencies, ownership checks, token claim validation.
  - **A03: Injection**: 100% Parameterized queries via SQLAlchemy ORM; strict Pydantic v2 schemas.
  - **A05: Security Misconfiguration**: Automated response headers (HSTS, CSP, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Cache-Control).
  - **A09: Security Logging**: Immutable database audit log capturing authentication events, role changes, and anomalies.

---

## Tech Stack

- **Language**: Python 3.10+ / 3.14
- **Framework**: FastAPI (Pydantic v2, Starlette)
- **Database**: PostgreSQL (via `asyncpg`) for production; automatic SQLite Async (`aiosqlite`) fallback for local dev & testing
- **ORM**: SQLAlchemy 2.0 (Async Engine)
- **Tokens & Crypto**: PyJWT, bcrypt, hashlib
- **MFA**: PyOTP, qrcode
- **Rate Limiting**: SlowAPI / Limits
- **Testing**: Pytest, Pytest-Asyncio, HTTPX

---

## Directory Structure

```text
secure_auth_api/
├── .env.example                         # Environment configuration template
├── README.md                            # Documentation & security specs
├── requirements.txt                     # Project dependencies
├── app/
│   ├── main.py                          # FastAPI app entry point & middleware
│   ├── config.py                        # Pydantic BaseSettings
│   ├── core/
│   │   ├── security.py                  # Cryptography, bcrypt, PyJWT token handlers
│   │   ├── mfa.py                       # PyOTP TOTP, QR codes & backup codes
│   │   ├── rbac.py                      # Roles, permissions & policy matrix
│   │   └── rate_limit.py                # SlowAPI limiter setup
│   ├── db/
│   │   ├── session.py                   # Async engine & session dependency
│   │   └── base.py                      # SQLAlchemy Base & timestamp mixins
│   ├── models/
│   │   ├── user.py                      # User model with MFA & role attributes
│   │   ├── token.py                     # Refresh token rotation entity
│   │   └── audit_log.py                 # Security audit trail model
│   ├── schemas/
│   │   ├── auth.py                      # Login, Register, Token & MFA challenge DTOs
│   │   ├── user.py                      # Profile & role DTOs
│   │   ├── mfa.py                       # MFA setup, enable, disable DTOs
│   │   └── audit.py                     # Audit log query DTOs
│   ├── services/
│   │   ├── auth_service.py              # Auth business logic, token rotation, replay defense
│   │   ├── mfa_service.py               # MFA orchestration & backup recovery
│   │   ├── user_service.py              # User management & role hierarchy
│   │   └── audit_service.py             # Event recording service
│   └── api/
│       ├── deps.py                      # FastAPI security dependencies & RBAC guards
│       └── v1/
│           ├── api.py                   # Router aggregator
│           └── endpoints/
│               ├── auth.py              # Authentication endpoints
│               ├── mfa.py               # MFA management endpoints
│               ├── users.py             # User profile endpoints
│               └── admin.py             # Security & audit log endpoints
└── tests/
    ├── conftest.py                      # Async test database fixtures
    ├── test_auth.py                     # Auth & token rotation tests
    ├── test_mfa.py                      # 2FA & recovery code tests
    ├── test_rbac.py                     # RBAC authorization tests
    └── test_security.py                 # Security hardening tests
```

---

## Quick Start

### 1. Installation

```bash
# Clone or navigate to the directory
cd secure_auth_api

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

### 3. Run Development Server

```bash
uvicorn app.main:app --reload --port 8000
```

Interactive API documentation will be available at:
- **Swagger UI**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
- **ReDoc**: [http://localhost:8000/api/v1/redoc](http://localhost:8000/api/v1/redoc)

---

## Running Automated Tests

Run the full pytest suite:

```bash
python -m pytest tests/ -v
```

---

## API Endpoint Reference

### Authentication (`/api/v1/auth`)

| Method | Endpoint | Description | Rate Limit |
|---|---|---|---|
| `POST` | `/register` | Register new user account | 5/min |
| `POST` | `/login` | Authenticate credentials (returns tokens or MFA challenge) | 5/min |
| `POST` | `/login/mfa` | Complete MFA login challenge using TOTP or backup code | 5/min |
| `POST` | `/refresh` | Rotate single-use refresh token | 100/min |
| `POST` | `/logout` | Revoke active refresh token session | 100/min |

### Multi-Factor Authentication (`/api/v1/mfa`)

| Method | Endpoint | Description | Permission |
|---|---|---|---|
| `POST` | `/setup` | Generate TOTP secret & QR codes | `mfa:manage_self` |
| `POST` | `/enable` | Confirm initial TOTP & receive 10 emergency backup codes | `mfa:manage_self` |
| `POST` | `/disable` | Deactivate MFA with valid code | `mfa:manage_self` |
| `POST` | `/backup-codes/regenerate` | Regenerate new set of 10 recovery codes | `mfa:manage_self` |

### User Management (`/api/v1/users`)

| Method | Endpoint | Description | Permission |
|---|---|---|---|
| `GET` | `/me` | Get current user profile | Authenticated |
| `PATCH` | `/me` | Update current user profile | Authenticated |
| `POST` | `/me/change-password` | Change password & invalidate existing sessions | Authenticated |
| `GET` | `/` | List all users (Paginated) | `user:read_all` |
| `GET` | `/{user_id}` | Get user by ID | Own profile OR `user:read_all` |
| `PATCH` | `/{user_id}/role` | Modify user role (Least Privilege enforced) | `user:change_role` |

### Administration & Audit (`/api/v1/admin`)

| Method | Endpoint | Description | Permission |
|---|---|---|---|
| `GET` | `/audit-logs` | Query security audit log trail | `audit:read` |
| `GET` | `/roles-permissions` | Inspect RBAC matrix | `audit:read` |
| `GET` | `/system-status` | Overview of security parameters | `system:admin` |
