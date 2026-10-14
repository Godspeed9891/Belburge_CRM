# Belburge CRM backend

A real server + database for the Belburge CRM container tracker: hashed
passwords checked server-side, every device reading and writing the same
shared data, and live updates pushed to every open screen within about a
second over WebSocket.

It's a small Node.js (Express) app backed by PostgreSQL. It does not serve
the frontend — `belburge-crm.html` and `belburge-crm-mobile.html` stay exactly
what they are (files you can open directly, or host anywhere); they just now
talk to this server over the internet instead of to the browser's own storage.

## What's real here, and what isn't yet

- **Real**: password hashing (bcrypt), signed session tokens (JWT), every
  request other than login/registration requires a valid session, the `users`
  collection is protected by real server-side rules (a non-admin can only ever
  change their own profile; an Admin-department account can manage the whole
  roster), and `containers` writes are checked field-by-field against the same
  department/stage rules the UI uses to hide buttons — who may register a new
  job, advance which stage, set the transfer letter / invoice / exit numbers,
  record a transporter, or touch invoices. A modified client or a direct API
  call can't bypass these; they're enforced here, not just in the browser.
- **Not yet re-implemented server-side**: `activity-log`, `referrals`, and
  `messages` still accept any write from a signed-in account, same as the
  original static file — nobody is impersonable (that requires a valid
  session), but role-based restrictions on those three collections, if you
  want them, would need the same kind of field-diff check `containers` now
  has.

## 1. Create a Postgres database

Any Postgres works. Two easy free options:

- **Neon** (neon.tech) — free serverless Postgres, no time limit on the free tier at time of writing.
- **Render Postgres** — create it from the Render dashboard alongside the web service below.

Either way, copy the connection string — it looks like:
`postgresql://user:password@host/dbname?sslmode=require`

## 2. Deploy the server (Render, free tier)

1. Put this folder in its own GitHub repo (or a folder in one).
2. On [render.com](https://render.com), **New → Web Service**, connect the repo.
3. Build command: `npm install` — Start command: `npm start`.
4. Add environment variables:
   - `DATABASE_URL` — the connection string from step 1.
   - `JWT_SECRET` — any long random string (e.g. generate one with
     `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`).
5. Deploy. Render gives you a public URL like `https://belburge-backend.onrender.com`.

(Railway, Fly.io, or any other Node host works the same way — set the same
two environment variables and run `npm start`.)

Render's free web services sleep after inactivity and take a few seconds to
wake back up on the next request — the frontend will just show a brief delay
on the first request after it's been idle, nothing breaks.

## 3. Point the frontend at it

Open `belburge-crm.html` (or the mobile version) in a browser. The very first
time, it asks for your backend's URL — paste the Render URL from step 2 and
continue. It's saved in that browser going forward (every device needs to be
told the URL once).

The very first time *any* device talks to a freshly deployed backend, the
frontend automatically sends it the familiar demo dataset (the same seed
accounts and demo containers the static file used to start with), so sign-in
with the demo accounts and password `demo123` works immediately. This only
happens once — the server refuses to be "seeded" again once it has real data.

## Local development

```
npm install
createdb belburge           # or any Postgres database
export DATABASE_URL=postgresql://localhost/belburge
export JWT_SECRET=dev-secret-change-me
npm start
```

Then set the frontend's backend URL to `http://localhost:4000`.

## API shape (for reference)

- `POST /api/auth/register` `{id, email, password}` — public.
- `POST /api/auth/login` `{email, password}` → `{token, userId}` — public.
- `POST /api/auth/set-password` `{email, newPassword}` — requires a session; only
  Admin (or the account owner) may reset another account's password.
- `POST /api/bootstrap-demo-data` — public, but only works once, on a
  completely empty database.
- `GET /api/storage/:key` — requires a session, except `org-settings` which is
  public (the login screen needs branding before anyone's signed in).
- `PUT /api/storage/:key` `{value: "<json string>"}` — requires a session
  except for the one-time self-registration case; `users` and `org-settings`
  writes are further restricted (see above).
- The collection keys the frontend uses are: `containers`, `users`,
  `activity-log`, `referrals`, `messages`, `org-settings`.
- `GET /ws?token=<jwt>` (WebSocket) — pushes `{type:"changed", key}` to every
  connected device whenever any collection is written, so open screens update
  live instead of waiting for the next poll.
