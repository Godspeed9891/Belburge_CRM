// Belburge CRM backend — real auth, real shared database, real-time multi-device sync.
//
// What this is: a small Express API + WebSocket server backed by PostgreSQL.
// It replaces the old "pretend window.storage" that the static HTML file used
// (which really only lived in one browser's localStorage) with a real server
// every device talks to, so every importer, agent, and BILBT staff member sees
// the same data, updated live, from any device.
//
// Design note: the frontend already treats most of its data as a handful of
// named JSON blobs (containers, users, activity-log, referrals, messages,
// settings) that it loads whole and saves whole. Rather than rewrite the
// frontend into dozens of fine-grained REST resources, this server keeps that
// same shape (a `kv_store` table, one row per collection) and layers real
// authentication and real, meaningful authorization checks on top of it:
//   - Passwords are hashed (bcrypt) and verified server-side, never trusted
//     from the browser, and never stored inside the JSON blobs.
//   - Every request (except registration and login) requires a valid signed
//     session token (JWT).
//   - Writes to the most sensitive collections are diff-checked against who's
//     asking, not just trusted from the browser:
//       - `users`: a non-admin can only ever change their own record; only an
//         Admin-department BILBT account can rewrite the whole roster.
//       - `containers`: the same department/stage rules the UI uses to hide
//         buttons (who can register a new job, advance which stage, set the
//         transfer letter / invoice / exit numbers, record a transporter, or
//         touch invoices) are re-checked here field-by-field, so a modified
//         client or a direct API call can't bypass them.
//   - Every successful write broadcasts a tiny "this changed" message over
//     WebSocket to every connected device, so other screens update within a
//     second — not just on the next 4-second poll.

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const http = require('http');
const { WebSocketServer } = require('ws');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  console.error('JWT_SECRET is not set. Set it to a long random string before starting the server.');
  process.exit(1);
}
if (!DATABASE_URL) {
  console.error('DATABASE_URL is not set. Point it at your Postgres database before starting the server.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false }
});

async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(sql);
  console.log('Schema ready.');
}

const app = express();
app.use(helmet());
app.use(cors({ origin: true })); // the frontend is a static file that can be opened from anywhere; restrict this later if you host it at a fixed domain
app.use(express.json({ limit: '25mb' })); // user ID photos / profile pictures are embedded as base64 data URLs

// ---------- auth helpers ----------
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}
function authOptional(req) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}
function authRequired(req, res, next) {
  const user = authOptional(req);
  if (!user) return res.status(401).json({ error: 'Sign in required.' });
  req.user = user;
  next();
}
function isElevated(user) {
  // "BILBT Admin" — the one department that can manage every account and platform settings.
  return !!user && user.role === 'admin' && user.department === 'Admin';
}

// ---------- kv_store helpers ----------
async function kvGet(key) {
  const r = await pool.query('SELECT value FROM kv_store WHERE key=$1', [key]);
  return r.rows.length ? r.rows[0].value : null;
}
async function kvSet(key, value) {
  await pool.query(
    `INSERT INTO kv_store (key, value, updated_at) VALUES ($1, $2, now())
     ON CONFLICT (key) DO UPDATE SET value=$2, updated_at=now()`,
    [key, JSON.stringify(value)]
  );
}

// Order-independent deep-equal for plain JSON values (objects/arrays/primitives).
// A naive JSON.stringify comparison would falsely flag two objects as
// "different" just because their keys were inserted in a different order —
// which would incorrectly block a legitimate self-edit. This walks both
// values structurally instead.
function deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (!deepEqual(a[i], b[i])) return false;
    return true;
  }
  const aKeys = Object.keys(a), bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (!deepEqual(a[k], b[k])) return false;
  }
  return true;
}

// ---------- container department/stage permission rules ----------
// These mirror the frontend's own permission constants exactly (FEN_BOL_DEPTS,
// FINANCE_DEPTS, DEFAULT_DEPT_STAGE_ACCESS, and the canEditTransferLetter /
// canEditInvoiceNumber / canEditTransporter / canEditExitNumber functions in
// belburge-crm.html) so a modified client, or a direct API call, can't bypass
// department rules the UI only enforced by hiding buttons.
const FEN_BOL_DEPTS = ['Admin', 'Documentation', 'DTI'];
const FINANCE_DEPTS = ['Admin', 'Accountant'];
const DEFAULT_DEPT_STAGE_ACCESS = {
  Documentation: [], DTI: [], 'Field Staff': [0, 1, 2, 3, 4, 5, 6, 7, 8],
  Operations: [9, 10, 11, 12], Transport: [13, 14], Accountant: []
};
// Container fields that only specific departments may change. Any field not
// listed here may be changed by any signed-in admin-role (BILBT staff)
// account, matching the original app's UI (e.g. progress notes, documents,
// seal numbers, and placement fields are open to any department there too).
const RESTRICTED_CONTAINER_FIELDS = {
  transferLetterNumber: ['Documentation', 'Operations'],
  invoiceNumber: ['Accountant', 'DTI', 'Operations'],
  transporter: ['Documentation', 'DTI', 'Transport'],
  transportHistory: ['Documentation', 'DTI', 'Transport'],
  exitNumber: ['Operations'],
  invoices: FINANCE_DEPTS,
  bolComplete: FEN_BOL_DEPTS,
  aNumber: FEN_BOL_DEPTS,
  cNumber: FEN_BOL_DEPTS
};

// Checks a proposed write to the `containers` collection against who's
// asking. Returns null if allowed, or an error string if not. BILBT Admin
// (isElevated) bypasses this entirely, same as for `users`.
async function checkContainersWrite(oldArr, newArr, authUser) {
  oldArr = Array.isArray(oldArr) ? oldArr : [];
  if (!Array.isArray(newArr)) return 'Malformed container list.';
  if (!authUser) return 'Sign in required.';
  if (isElevated(authUser)) return null;
  if (authUser.role !== 'admin') return 'Only BILBT staff accounts can modify job records.';

  const dept = authUser.department;
  const oldById = new Map(oldArr.map(c => [c.id, c]));
  const newById = new Map(newArr.map(c => [c.id, c]));

  for (const c of newArr) {
    if (!oldById.has(c.id) && !FEN_BOL_DEPTS.includes(dept)) {
      return 'Only Admin, Documentation, or DTI can register a new job (First Entry Note).';
    }
  }
  for (const c of oldArr) {
    if (!newById.has(c.id)) return 'Containers cannot be deleted.';
  }

  let stageAccessCache = null;
  for (const c of newArr) {
    const prev = oldById.get(c.id);
    if (!prev || deepEqual(prev, c)) continue;
    const keys = new Set([...Object.keys(prev), ...Object.keys(c)]);
    for (const k of keys) {
      if (deepEqual(prev[k], c[k])) continue;
      if (k === 'stageIdx') {
        if (stageAccessCache === null) {
          const settings = await kvGet('org-settings');
          stageAccessCache = (settings && settings.deptStageAccess) || {};
        }
        const access = stageAccessCache[dept] || DEFAULT_DEPT_STAGE_ACCESS[dept] || [];
        if (!access.includes(c[k]) && !access.includes(prev[k])) {
          return `Your department (${dept}) is not authorized to set that stage.`;
        }
        continue;
      }
      const allowedDepts = RESTRICTED_CONTAINER_FIELDS[k];
      if (allowedDepts && !allowedDepts.includes(dept)) {
        return `Your department (${dept}) is not authorized to change "${k}".`;
      }
    }
  }
  return null;
}

// Checks a proposed write to the `users` collection against who's asking.
// Returns null if allowed, or an error string if not.
function checkUsersWrite(oldArr, newArr, authUser) {
  oldArr = Array.isArray(oldArr) ? oldArr : [];
  if (!Array.isArray(newArr)) return 'Malformed user list.';

  if (!authUser) {
    // Only path allowed with no session at all: self-registration appending
    // exactly one new pending account, with every existing account untouched.
    if (newArr.length !== oldArr.length + 1) return 'Sign in required.';
    const oldById = new Map(oldArr.map(u => [u.id, u]));
    for (const u of newArr) {
      if (oldById.has(u.id) && !deepEqual(oldById.get(u.id), u)) return 'Sign in required.';
    }
    const added = newArr.find(u => !oldById.has(u.id));
    if (!added || added.status !== 'pending_verification') return 'Sign in required.';
    return null;
  }

  if (isElevated(authUser)) return null; // BILBT Admin can do anything to the roster

  // Anyone else may only ever change their own record, and may not add or remove accounts.
  if (newArr.length !== oldArr.length) return 'Only BILBT Admin can add or remove accounts.';
  const oldById = new Map(oldArr.map(u => [u.id, u]));
  for (const u of newArr) {
    const prev = oldById.get(u.id);
    if (!prev) return 'Only BILBT Admin can add or remove accounts.';
    if (!deepEqual(prev, u) && u.id !== authUser.id) {
      return 'You can only update your own profile.';
    }
  }
  return null;
}

// ---------- WebSocket: live push so every open screen updates within ~1s ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const sockets = new Set();

wss.on('connection', (ws, req) => {
  try {
    const url = new URL(req.url, 'http://x');
    const token = url.searchParams.get('token');
    jwt.verify(token, JWT_SECRET); // throws if missing/invalid/expired
  } catch (e) {
    ws.close(4001, 'Unauthorized');
    return;
  }
  sockets.add(ws);
  ws.on('close', () => sockets.delete(ws));
});

function broadcastChanged(key) {
  const msg = JSON.stringify({ type: 'changed', key });
  for (const ws of sockets) {
    if (ws.readyState === 1) ws.send(msg);
  }
}

// ---------- routes ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

// Public: called once at the end of the registration flow, after the new
// (pending) account object has been built client-side.
app.post('/api/auth/register', async (req, res) => {
  const { id, email, password } = req.body || {};
  if (!id || !email || !password) return res.status(400).json({ error: 'id, email and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const existing = await pool.query('SELECT 1 FROM credentials WHERE email=$1', [email.toLowerCase()]);
  if (existing.rows.length) return res.status(409).json({ error: 'That email is already registered. Try signing in.' });
  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO credentials (email, password_hash, user_id) VALUES ($1,$2,$3)', [email.toLowerCase(), hash, id]);
  res.json({ ok: true });
});

// Public: real sign-in. Verifies the password against the hash, then looks up
// the matching profile (name/role/department/etc.) from the `users` blob so
// the session token can carry role/department for later authorization checks.
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required.' });
  const r = await pool.query('SELECT password_hash, user_id FROM credentials WHERE email=$1', [email.toLowerCase()]);
  if (!r.rows.length) return res.status(401).json({ error: 'No matching account. Check the email and password.' });
  const ok = await bcrypt.compare(password, r.rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'No matching account. Check the email and password.' });
  const userId = r.rows[0].user_id;
  const users = (await kvGet('users')) || [];
  const profile = users.find(u => u.id === userId);
  if (!profile) return res.status(401).json({ error: 'Account record not found. Contact BILBT Admin.' });
  const token = signToken({ id: profile.id, email: email.toLowerCase(), role: profile.role, department: profile.department || null });
  res.json({ token, userId: profile.id });
});

// Requires a session. Used both for BILBT Admin's "reset this person's
// password" action and could be used later for self-service password change.
// Only BILBT Admin, or the account owner themself, may set a password.
app.post('/api/auth/set-password', authRequired, async (req, res) => {
  const { email, newPassword } = req.body || {};
  if (!email || !newPassword) return res.status(400).json({ error: 'email and newPassword are required.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const existing = await pool.query('SELECT user_id FROM credentials WHERE email=$1', [email.toLowerCase()]);
  if (!existing.rows.length) return res.status(404).json({ error: 'No account with that email.' });
  if (!isElevated(req.user) && req.user.email !== email.toLowerCase()) {
    return res.status(403).json({ error: 'Only BILBT Admin can reset another account’s password.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE credentials SET password_hash=$1, updated_at=now() WHERE email=$2', [hash, email.toLowerCase()]);
  res.json({ ok: true });
});

// BILBT Admin only: re-seed demo credentials after "reset demo data" rebuilds
// the seeded account list client-side. Takes the fresh {id,email,password}
// triples so the server never needs its own hardcoded copy of the seed data.
app.post('/api/auth/reset-seed-credentials', authRequired, async (req, res) => {
  if (!isElevated(req.user)) return res.status(403).json({ error: 'Only BILBT Admin can reset demo data.' });
  const { accounts } = req.body || {};
  if (!Array.isArray(accounts)) return res.status(400).json({ error: 'accounts[] is required.' });
  await pool.query('DELETE FROM credentials');
  for (const a of accounts) {
    const hash = await bcrypt.hash(a.password, 10);
    await pool.query('INSERT INTO credentials (email, password_hash, user_id) VALUES ($1,$2,$3)', [a.email.toLowerCase(), hash, a.id]);
  }
  res.json({ ok: true });
});

// One-time bootstrap for a brand-new, empty database: the frontend calls this
// automatically on first load if the `users` collection doesn't exist yet,
// sending its built-in demo dataset (the same seed data the old static file
// used). It's intentionally self-disabling — it refuses once any users exist
// — so it can't be used to overwrite a live deployment, and needs no auth
// (there's no admin account to authenticate as yet on a brand-new database).
app.post('/api/bootstrap-demo-data', async (req, res) => {
  const existingUsers = await kvGet('users');
  if (existingUsers !== null) return res.status(409).json({ error: 'Already initialized.' });
  const { collections, accounts } = req.body || {};
  if (!collections || typeof collections !== 'object') return res.status(400).json({ error: 'collections is required.' });
  if (!Array.isArray(accounts)) return res.status(400).json({ error: 'accounts[] is required.' });
  for (const [key, value] of Object.entries(collections)) {
    await kvSet(key, value);
  }
  for (const a of accounts) {
    const hash = await bcrypt.hash(a.password, 10);
    await pool.query(
      'INSERT INTO credentials (email, password_hash, user_id) VALUES ($1,$2,$3) ON CONFLICT (email) DO NOTHING',
      [a.email.toLowerCase(), hash, a.id]
    );
  }
  res.json({ ok: true });
});

// Generic shared-collection storage, standing in for the old window.storage.
// 'settings' is readable without signing in (the login screen itself needs
// the brand color before anyone has a session). Everything else requires auth.
app.get('/api/storage/:key', async (req, res) => {
  if (req.params.key !== 'org-settings' && !authOptional(req)) {
    return res.status(401).json({ error: 'Sign in required.' });
  }
  const value = await kvGet(req.params.key);
  res.json({ value: value === null ? null : JSON.stringify(value) });
});

app.put('/api/storage/:key', async (req, res) => {
  const key = req.params.key;
  const raw = req.body && req.body.value;
  if (typeof raw !== 'string') return res.status(400).json({ error: 'Body must be { value: "<json string>" }.' });
  let parsed;
  try { parsed = JSON.parse(raw); } catch (e) { return res.status(400).json({ error: 'value must be valid JSON.' }); }

  // Try to authenticate, but don't require it yet — 'users' has one
  // legitimate unauthenticated case (self-registration) checked below.
  let user = null;
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (token) { try { user = jwt.verify(token, JWT_SECRET); } catch (e) { /* treated as anonymous */ } }

  if (key === 'users') {
    const old = (await kvGet('users')) || [];
    const err = checkUsersWrite(old, parsed, user);
    if (err) return res.status(user ? 403 : 401).json({ error: err });
  } else if (key === 'org-settings') {
    if (!user) return res.status(401).json({ error: 'Sign in required.' });
    if (!isElevated(user)) return res.status(403).json({ error: 'Only BILBT Admin can change platform settings.' });
  } else if (key === 'containers') {
    const old = (await kvGet('containers')) || [];
    const err = await checkContainersWrite(old, parsed, user);
    if (err) return res.status(user ? 403 : 401).json({ error: err });
  } else {
    if (!user) return res.status(401).json({ error: 'Sign in required.' });
    // activity-log, referrals, messages: any signed-in account may write.
  }

  await kvSet(key, parsed);
  broadcastChanged(key);
  res.json({ ok: true });
});

initSchema()
  .then(() => {
    server.listen(PORT, () => console.log(`Belburge backend listening on :${PORT}`));
  })
  .catch(err => {
    console.error('Failed to initialize database schema:', err);
    process.exit(1);
  });
