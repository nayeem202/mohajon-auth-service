# Mohajon Auth Service

The authentication and authorization service for **Mohajon**, a smart
shop-management platform for Bangladeshi small businesses. It is deliberately
domain-agnostic, so the mobile app, admin portal, and future clients can share
a single secure identity layer.

## Responsibilities

- Email/password registration and email verification
- JWT access tokens with refresh-token rotation and session management
- Password recovery, password changes, OTP, and login tracking
- Google and Facebook sign-in token verification
- OAuth 2.1 / OpenID Connect authorization-server support with PKCE
- Role- and permission-based access control

## Technology

| Area | Choice |
|---|---|
| Language & build | Java 25, Gradle |
| Framework | Spring Boot 4.1, Spring Security 7, Spring Authorization Server |
| Data | PostgreSQL 18, JPA, Flyway |
| OTP cache | Redis 8, with an in-memory development fallback |
| Operations | Spring Boot Actuator, Docker Compose |

## How it fits into Mohajon

```text
Mohajon Mobile App ─┐
                    ├──> Mohajon Auth Service :8080 ──> signed JWT
Mohajon Admin Portal ┘                                  │
                                                       └──> Mohajon Core Service :8081
```

The core service validates trusted JWTs issued here; clients should never
store or expose the signing secret.

## Run locally

### Prerequisites

- Java 25
- Docker and Docker Compose

### Start the service

```bash
cp .env.example .env
docker compose up -d postgres redis
bash ./gradlew bootRun
```

The API starts at `http://localhost:8080`. To run the full Compose stack,
including this service, use `docker compose up --build`.

## Configuration

Copy `.env.example` before changing values. Production secrets belong in the
deployment environment, never in Git.

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Strong 32+ character signing secret |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | PostgreSQL connection credentials |
| `GOOGLE_CLIENT_ID` | Enables Google ID-token audience validation |
| `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` | Enables Facebook token verification |
| `CORS_ALLOWED_ORIGINS` | Comma-separated allowed web origins |

## API overview

Base path: `/api/v1/auth`

| Area | Endpoints |
|---|---|
| Registration | `POST /register`, `/verify-email`, `/resend-verification` |
| Sessions | `POST /login`, `/refresh`, `/logout`, `/logout-all` |
| Account recovery | `POST /forgot-password`, `/reset-password`, `/change-password` |
| OTP | `POST /send-otp`, `/verify-otp` |
| Social sign-in | `POST /google`, `/facebook` |
| Current user | `GET /api/v1/users/me` |

Protected routes receive `Authorization: Bearer <access-token>`. The OAuth
authorization-code flow with PKCE is available through the configured Spring
Authorization Server endpoints.

## Database and migrations

Flyway creates users, roles, permissions, refresh tokens, and login-session
records. Migrations are versioned in `src/main/resources/db/migration`; add a
new migration rather than editing one that has already been applied.

## Quality checks

```bash
bash ./gradlew test --no-daemon
```

Integration tests cover registration, verification, login, authenticated user
lookup, refresh-token rotation, password changes, and authorization rules.

## Related repositories

- `mohajon-mobile-app` — Flutter application for shop owners and staff
- `mohajon-core-service` — business APIs for POS, inventory, and reporting
- `mohajon-admin-portal` — Angular operations portal
