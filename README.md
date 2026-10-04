<div align="center">

# ðŸ” SecureAuth Backend API

### Enterprise-Grade Authentication & Authorization Engine with MFA, RBAC & OWASP Top 10 Hardening

[![CI Status](https://github.com/Drizzy-ul/secure-auth-api/actions/workflows/ci.yml/badge.svg)](https://github.com/Drizzy-ul/secure-auth-api/actions)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)](https://github.com/Drizzy-ul/secure-auth-api)](https://opensource.org/licenses/MIT)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%20Compliant-orange.svg)](https://owasp.org/www-project-top-ten/)
[![Security: RBAC + MFA](https://img.shields.io/badge/Security-RBAC%20%7C%20TOTP%20MFA-red.svg)](#key-security-features)

<p align="center">
  A production-grade, reusable backend API built with <b>Python</b>, <b>FastAPI</b>, <b>SQLAlchemy (Async)</b>, <b>PyJWT</b>, and <b>PyOTP</b>. Designed strictly according to <b>Security+</b> principles and <b>OWASP Top 10</b> mitigations.
</p>

</div>

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
â”œâ”€â”€ .env.example                         # Environment configuration template
â”œâ”€â”€ README.md                            # Documentation & security specs
â”œâ”€â”€ requirements.txt                     # Project dependencies
â”œâ”€â”€ app/
â”‚   â”œâ”€â”€ main.py                          # FastAPI app entry point & middleware
â”‚   â”œâ”€â”€ config.py                        # Pydantic BaseSettings
â”‚   â”œâ”€â”€ core/
â”‚   â”‚   â”œâ”€â”€ security.py                  # Cryptography, bcrypt, PyJWT token handlers
â”‚   â”‚   â”œâ”€â”€ mfa.py                       # PyOTP TOTP, QR codes & backup codes
â”‚   â”‚   â”œâ”€â”€ rbac.py                      # Roles, permissions & policy matrix
â”‚   â”‚   â””â”€â”€ rate_limit.py                # SlowAPI limiter setup
â”‚   â”œâ”€â”€ db/
â”‚   â”‚   â”œâ”€â”€ session.py                   # Async engine & session dependency
â”‚   â”‚   â””â”€â”€ base.py                      # SQLAlchemy Base & timestamp mixins
â”‚   â”œâ”€â”€ models/
â”‚   â”‚   â”œâ”€â”€ user.py                      # User model with MFA & role attributes
â”‚   â”‚   â”œâ”€â”€ token.py                     # Refresh token rotation entity
â”‚   â”‚   â””â”€â”€ audit_log.py                 # Security audit trail model
â”‚   â”œâ”€â”€ schemas/
â”‚   â”‚   â”œâ”€â”€ auth.py                      # Login, Register, Token & MFA challenge DTOs
â”‚   â”‚   â”œâ”€â”€ user.py                      # Profile & role DTOs
â”‚   â”‚   â”œâ”€â”€ mfa.py                       # MFA setup, enable, disable DTOs
â”‚   â”‚   â””â”€â”€ audit.py                     # Audit log query DTOs
â”‚   â”œâ”€â”€ services/
â”‚   â”‚   â”œâ”€â”€ auth_service.py              # Auth business logic, token rotation, replay defense
â”‚   â”‚   â”œâ”€â”€ mfa_service.py               # MFA orchestration & backup recovery
â”‚   â”‚   â”œâ”€â”€ user_service.py              # User management & role hierarchy
â”‚   â”‚   â””â”€â”€ audit_service.py             # Event recording service
â”‚   â””â”€â”€ api/
â”‚       â”œâ”€â”€ deps.py                      # FastAPI security dependencies & RBAC guards
â”‚       â””â”€â”€ v1/
â”‚           â”œâ”€â”€ api.py                   # Router aggregator
â”‚           â””â”€â”€ endpoints/
â”‚               â”œâ”€â”€ auth.py              # Authentication endpoints
â”‚               â”œâ”€â”€ mfa.py               # MFA management endpoints
â”‚               â”œâ”€â”€ users.py             # User profile endpoints
â”‚               â””â”€â”€ admin.py             # Security & audit log endpoints
â””â”€â”€ tests/
    â”œâ”€â”€ conftest.py                      # Async test database fixtures
    â”œâ”€â”€ test_auth.py                     # Auth & token rotation tests
    â”œâ”€â”€ test_mfa.py                      # 2FA & recovery code tests
    â”œâ”€â”€ test_rbac.py                     # RBAC authorization tests
    â””â”€â”€ test_security.py                 # Security hardening tests
```

---

## Quick Start


### 🐳 Run with Docker & Docker Compose

Run the entire API with a containerized PostgreSQL database:

```bash
# Start FastAPI and PostgreSQL in detached mode
docker compose up -d --build

# View container logs
docker compose logs -f app

# Run healthcheck
curl http://localhost:8000/health
```

API docs will be available immediately at `http://localhost:8000/api/v1/docs`.

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
