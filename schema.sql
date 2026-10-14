-- Belburge CRM backend schema.
-- Run automatically by server.js on startup (safe to run repeatedly).

CREATE TABLE IF NOT EXISTS credentials (
  email         TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  user_id       TEXT NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every shared collection the app used to keep in the browser's localStorage
-- (containers, users, activity-log, referrals, messages, settings) now lives
-- here as one row per collection. The frontend's existing load/save functions
-- already treat each collection as one JSON blob, so this keeps that model
-- but backs it with a real, durable, shared database instead of a browser.
CREATE TABLE IF NOT EXISTS kv_store (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
