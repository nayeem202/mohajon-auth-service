# Auth Service

Generic, self-hosted authentication service built with Spring Boot 4 + Spring
Authorization Server. Provides email/password registration, email-verification
codes, JWT access + refresh tokens (rotation), OTP, Google sign-in
(ID-token verification), and role/permission-based authorization.

Fully plug-and-play: no domain-specific data lives here. Any client app
(mobile, web, desktop) can integrate with it via the REST API or OAuth 2.1.

## Tech stack

- Java 25 (Temurin), Gradle (Kotlin DSL), Spring Boot 4.1.0
- Spring Security 7 + Spring Authorization Server 7.1.0
- PostgreSQL 18 (via Docker Compose), Flyway migrations
- Redis 8 (OTP store; falls back to in-memory store when unavailable)
- Jackson 3 (`tools.jackson.databind`)

## Run locally

```bash
docker compose up -d          # postgres + redis
cp .env.example .env          # adjust secrets if needed

export JAVA_HOME=~/devtools/jdk-25.0.4+7        # JDK 25
export PATH=$JAVA_HOME/bin:$HOME/devtools/gradle-9.6.1/bin:$PATH
./gradlew bootRun
```

Server starts on `http://localhost:8080`.

Default OTP/notification mode logs codes to the console (`DevLogNotificationService`).
Set `app.otp.store=redis` to use Redis, and implement `NotificationService` for
real email/SMS delivery.

## API overview

Base path: `/api/v1/auth`

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create account (requires email verification) |
| POST | `/verify-email` | Verify email with 6-digit code |
| POST | `/resend-verification` | Re-send verification code |
| POST | `/login` | Email + password → `{accessToken, refreshToken, user}` |
| POST | `/refresh` | Rotate refresh token → new token pair |
| POST | `/logout` | Revoke current refresh token |
| POST | `/logout-all` | Revoke all sessions for the user |
| POST | `/forgot-password` | Send reset code |
| POST | `/reset-password` | Set new password with code |
| POST | `/change-password` | Authenticated password change |
| POST | `/send-otp` | Send OTP to verified email |
| POST | `/verify-otp` | Verify OTP |
| POST | `/google` | `{idToken}` from Google → token pair (auto-registers) |
| GET | `/users/me` | Current user + permissions |

OIDC login UI: `http://localhost:8080/oauth2/authorization/web-client`
(authorization-code flow with PKCE, supports 3rd-party apps).

Login response:

```json
{
  "accessToken": "eyJ...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "refreshToken": "eyJ...",
  "user": { "id": "...", "email": "...", "emailVerified": true, "name": "..." }
}
```

Protected endpoints: `Authorization: Bearer <accessToken>`.

## Configuration (`application.yml`)

- `app.base-url` – base URL used in emails/links
- `app.otp.store` – `inmemory` (default) or `redis`
- `app.google.client-id` – Google OAuth client ID verified against token audience
- `spring.datasource.*` / `spring.data.redis.*` – connection settings

## Database

Flyway migration `V1__init.sql` creates: `users`, `roles`, `permissions`,
`user_roles`, `role_permissions`, `refresh_tokens`, `login_sessions` (with
device fingerprinting) and seeds base roles.

## Tests

```bash
./gradlew build --no-daemon
```

`AuthFlowIntegrationTest` covers the full happy path: register → verify →
login → `/users/me` → refresh rotation → change password.
