# HireLoop Server

Backend server for HireLoop, backed by MongoDB (via the official `mongodb` driver) and Better Auth.

## User roles & onboarding backfill

Users created before the `role` / `onboardingComplete` fields existed are missing them, which can break
role-based redirects and route protection.

- Dry run (default): `npm run users:backfill` — prints how many documents would change, no changes applied.
- Apply: `npm run users:backfill:apply` — runs the backfill updates (after taking a backup: `mongodump` or an Atlas snapshot).

## Make an existing user an admin

    npm run users:make-admin -- <owner@example.com>

This script runs only on the server/local machine with database access, there is no public endpoint for it,
and the user must sign out and sign in again for the session to pick up the new role.

## Environment

Copy `.env` and fill in the values. Required variables:

- `MONGODB_URI` — MongoDB connection string.
- `DB_NAME` — database name (defaults to the value used by the app).
- `CORS_ORIGIN` — comma-separated list of frontend origins allowed to call the API, for example `http://localhost:3000,http://localhost:5173`.
- `IMGBB_API_KEY` — ImgBB API key used by `POST /api/profile/avatar` to upload user avatars (server-side only). Leave unset in local dev to receive a 503 from that route.

Frontend example:

- React/Vite default dev server: `http://localhost:5173`
- Next.js/CRA default: `http://localhost:3000`

## Stripe checkout

The frontend checkout page (`/checkout` in the Next.js app) uses Stripe Payment Intents.
Amounts are always decided on the server; the client only sends the currency code.

Environment variables:

- `STRIP_PUBLISH_KEY` — Stripe publishable key (also accepts `STRIPE_PUBLISHABLE_KEY`).
- `STRI_SECRET_KEY` — Stripe secret key (also accepts `STRIPE_SECRET_KEY`). Server only, never expose it.
- `STRIPE_WEBHOOK_SECRET` — optional; required to enable the webhook endpoint in production.
- `PAYMENTS_COLLECTION` — optional, defaults to `payments`.

Endpoints:

- `GET /api/plans` — pricing plans (monthly / yearly with 25% yearly discount).
- `GET /api/checkout/config?plan=<id>&billing=<monthly|yearly>` — publishable key, plan and server-side prices for a checkout.
- `POST /api/checkout/payment-intent` — body `{ "planId": "growth", "billing": "monthly", "currency": "BDT", "email": "..." }`.
- `POST /api/checkout/confirm` — body `{ "paymentIntentId": "pi_..." }`; re-fetches the intent
  from Stripe so a success response cannot be faked, then stores it in `payments`.
- `POST /api/checkout/webhook` — Stripe webhook endpoint; point the Stripe dashboard here in production.

The checkout page needs the API URL, for example `NEXT_PUBLIC_API_URL=http://localhost:5000`.

## Publishing jobs

Authenticated recruiter accounts can publish a job with `POST /api/jobs`. Send the Better Auth session cookie or a bearer session token. The JSON body
requires `title`, `companyName`, `description`, and `location`; responsibilities, requirements,
skills, benefits, salary, deadline, and work-mode fields are optional.

Recruiters can update an application with `PATCH /api/applications/:id/status` and a JSON body
such as `{ "status": "shortlisted" }`. The signed-in recruiter must own the job; admins can
update any application.
