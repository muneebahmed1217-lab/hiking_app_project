# Hiking App Backend

Local backend for the Expo Hiking App.

## What you get

- JWT auth (`/auth/signup`, `/auth/login`)
- OAuth sign-in (Google/Facebook/Apple) (`/auth/oauth/google`, `/auth/oauth/facebook`, `/auth/oauth/apple`)
- SQLite database (auto-initialized on first run)
- REST endpoints for posts, profile, safety settings, SOS
- Optional media upload (`/media`) with static serving

## Setup

```bash
cd backend
npm install
copy .env.example .env
npm run dev
```

Requires Node 18+ (built-in `fetch()` is used for Facebook token validation).

Health check:

- `http://localhost:4000/health`

## Auth

Send `Authorization: Bearer <token>` for protected routes.

## OAuth sign-in

These endpoints return the same `{ token, user }` shape as email/password auth.

- `POST /auth/oauth/google` body `{ "idToken": "..." }`
  - Requires `GOOGLE_CLIENT_ID` in `.env`
- `POST /auth/oauth/facebook` body `{ "accessToken": "..." }`
  - Uses Facebook Graph API `me` endpoint to validate the token.
- `POST /auth/oauth/apple` body `{ "identityToken": "..." }`
  - Requires `APPLE_CLIENT_ID` in `.env`

