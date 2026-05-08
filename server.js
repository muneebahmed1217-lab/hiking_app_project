require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('node:path');
const fs = require('node:fs');
const multer = require('multer');
const { OAuth2Client } = require('google-auth-library');
const jwksClient = require('jwks-rsa');

const { getDbPath, createDb, initSchema, seedIfEmpty } = require('./db');
const { authOptional, authRequired, signToken, hashPassword, verifyPassword, createUserId } = require('./auth');

const PORT = Number(process.env.PORT || 4000);
const UPLOAD_DIR = process.env.UPLOAD_DIR ? path.resolve(process.cwd(), process.env.UPLOAD_DIR) : path.join(process.cwd(), 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const safeName = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}-${file.originalname}`.replace(
        /[^a-zA-Z0-9._-]/g,
        '_'
      );
      cb(null, safeName);
    },
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
});

const dbPath = getDbPath(process.env.DB_PATH);
const db = createDb(dbPath);
initSchema(db);
seedIfEmpty(db);

const PUBLIC_USER_ID = 'public';
function ensurePublicUser() {
  const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(PUBLIC_USER_ID);
  if (existing) return;
  db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
    PUBLIC_USER_ID,
    'public@local',
    'disabled',
    nowIso()
  );
  db.prepare('INSERT OR IGNORE INTO profiles (user_id, name) VALUES (?, ?)').run(PUBLIC_USER_ID, 'Public');
  db.prepare('INSERT OR IGNORE INTO safety_settings (user_id) VALUES (?)').run(PUBLIC_USER_ID);
}
ensurePublicUser();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

const googleClientId = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = new OAuth2Client(googleClientId || undefined);
const appleAudience = process.env.APPLE_CLIENT_ID || '';
const appleTeamId = process.env.APPLE_TEAM_ID || '';

app.get('/health', (_req, res) => {
  res.json({ ok: true, dbPath });
});

function nowIso() {
  return new Date().toISOString();
}

function normalizeEmail(value) {
  if (typeof value !== 'string') return '';
  return value.trim().toLowerCase();
}

function ensureUserRows(userId, email) {
  const baseName = email ? String(email).split('@')[0] : 'Hiker';
  db.prepare('INSERT OR IGNORE INTO profiles (user_id, name) VALUES (?, ?)').run(userId, baseName);
  db.prepare('INSERT OR IGNORE INTO safety_settings (user_id) VALUES (?)').run(userId);
}

function upsertOAuthAccount({ provider, providerUserId, userId, email }) {
  db.prepare(
    `INSERT INTO oauth_accounts (provider, provider_user_id, user_id, email, created_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(provider, provider_user_id) DO UPDATE SET
       user_id = excluded.user_id,
       email = excluded.email`
  ).run(provider, providerUserId, userId, email ?? null, nowIso());
}

function issueTokenResponse(userId, email) {
  const token = signToken({ sub: userId, email: email ?? undefined });
  return { token, user: { id: userId, email: email ?? undefined } };
}

function requireEmailPassword(req, res) {
  const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!email || !password || password.length < 6) {
    res.status(400).json({ message: 'Email and password (min 6 chars) are required.' });
    return null;
  }
  return { email, password };
}

app.post('/auth/signup', async (req, res) => {
  const payload = requireEmailPassword(req, res);
  if (!payload) return;

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(payload.email);
  if (existing) return res.status(409).json({ message: 'Email already registered.' });

  const id = createUserId();
  const passwordHash = await hashPassword(payload.password);
  db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
    id,
    payload.email,
    passwordHash,
    nowIso()
  );
  db.prepare('INSERT OR IGNORE INTO profiles (user_id, name) VALUES (?, ?)').run(id, payload.email.split('@')[0]);
  db.prepare('INSERT OR IGNORE INTO safety_settings (user_id) VALUES (?)').run(id);

  const token = signToken({ sub: id, email: payload.email });
  return res.json({ token, user: { id, email: payload.email } });
});

app.post('/auth/login', async (req, res) => {
  const payload = requireEmailPassword(req, res);
  if (!payload) return;

  const row = db.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').get(payload.email);
  if (!row) return res.status(401).json({ message: 'Invalid email or password.' });

  const ok = await verifyPassword(payload.password, row.password_hash);
  if (!ok) return res.status(401).json({ message: 'Invalid email or password.' });

  return res.json(issueTokenResponse(row.id, row.email));
});

app.post('/auth/oauth/google', async (req, res) => {
  const idToken = typeof req.body.idToken === 'string' ? req.body.idToken : '';
  if (!idToken) return res.status(400).json({ message: 'idToken is required.' });
  if (!googleClientId) return res.status(500).json({ message: 'Server missing GOOGLE_CLIENT_ID.' });

  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: googleClientId });
    const payload = ticket.getPayload();
    const providerUserId = payload?.sub ? String(payload.sub) : '';
    const email = normalizeEmail(payload?.email);
    if (!providerUserId) return res.status(401).json({ message: 'Invalid Google token.' });

    const existingLink = db
      .prepare('SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?')
      .get('google', providerUserId);

    let userId = existingLink?.user_id ?? null;
    if (!userId && email) {
      const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      userId = existingUser?.id ?? null;
    }
    if (!userId) {
      userId = createUserId();
      db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
        userId,
        email || `google_${providerUserId}@local`,
        'oauth',
        nowIso()
      );
    }

    upsertOAuthAccount({ provider: 'google', providerUserId, userId, email });
    ensureUserRows(userId, email);
    return res.json(issueTokenResponse(userId, email));
  } catch {
    return res.status(401).json({ message: 'Invalid Google token.' });
  }
});

app.post('/auth/oauth/facebook', async (req, res) => {
  const accessToken = typeof req.body.accessToken === 'string' ? req.body.accessToken : '';
  if (!accessToken) return res.status(400).json({ message: 'accessToken is required.' });

  try {
    const fbRes = await fetch(`https://graph.facebook.com/me?fields=id,email&access_token=${encodeURIComponent(accessToken)}`);
    if (!fbRes.ok) return res.status(401).json({ message: 'Invalid Facebook token.' });
    const data = await fbRes.json();
    const providerUserId = data?.id ? String(data.id) : '';
    const email = normalizeEmail(data?.email);
    if (!providerUserId) return res.status(401).json({ message: 'Invalid Facebook token.' });

    const existingLink = db
      .prepare('SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?')
      .get('facebook', providerUserId);

    let userId = existingLink?.user_id ?? null;
    if (!userId && email) {
      const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      userId = existingUser?.id ?? null;
    }
    if (!userId) {
      userId = createUserId();
      db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
        userId,
        email || `facebook_${providerUserId}@local`,
        'oauth',
        nowIso()
      );
    }

    upsertOAuthAccount({ provider: 'facebook', providerUserId, userId, email });
    ensureUserRows(userId, email);
    return res.json(issueTokenResponse(userId, email));
  } catch {
    return res.status(401).json({ message: 'Invalid Facebook token.' });
  }
});

app.post('/auth/oauth/apple', async (req, res) => {
  const identityToken = typeof req.body.identityToken === 'string' ? req.body.identityToken : '';
  if (!identityToken) return res.status(400).json({ message: 'identityToken is required.' });
  if (!appleAudience) return res.status(500).json({ message: 'Server missing APPLE_CLIENT_ID.' });

  const client = jwksClient({ jwksUri: 'https://appleid.apple.com/auth/keys', cache: true, rateLimit: true });
  const getKey = (header, cb) => {
    client.getSigningKey(header.kid, (err, key) => {
      if (err) return cb(err);
      const signingKey = key.getPublicKey();
      cb(null, signingKey);
    });
  };

  try {
    const decoded = require('jsonwebtoken').verify(identityToken, getKey, {
      algorithms: ['RS256'],
      audience: appleAudience,
      issuer: 'https://appleid.apple.com',
    });

    const providerUserId = decoded?.sub ? String(decoded.sub) : '';
    const email = normalizeEmail(decoded?.email);
    // team id isn't always directly present for all flows; only enforce if configured.
    if (appleTeamId && decoded?.iss && decoded.iss !== 'https://appleid.apple.com') {
      return res.status(401).json({ message: 'Invalid Apple token.' });
    }
    if (!providerUserId) return res.status(401).json({ message: 'Invalid Apple token.' });

    const existingLink = db
      .prepare('SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?')
      .get('apple', providerUserId);

    let userId = existingLink?.user_id ?? null;
    if (!userId && email) {
      const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      userId = existingUser?.id ?? null;
    }
    if (!userId) {
      userId = createUserId();
      db.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)').run(
        userId,
        email || `apple_${providerUserId}@local`,
        'oauth',
        nowIso()
      );
    }

    upsertOAuthAccount({ provider: 'apple', providerUserId, userId, email });
    ensureUserRows(userId, email);
    return res.json(issueTokenResponse(userId, email));
  } catch {
    return res.status(401).json({ message: 'Invalid Apple token.' });
  }
});

app.get('/me', authRequired, (req, res) => {
  return res.json({ user: { id: req.user.sub, email: req.user.email } });
});

app.delete('/me/data', authRequired, (req, res) => {
  const uid = req.user.sub;
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM sos_events WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM posts WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM safety_settings WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM profiles WHERE user_id = ?').run(uid);
    db.prepare('DELETE FROM users WHERE id = ?').run(uid);
  });
  tx();
  res.json({ ok: true });
});

app.get('/posts', (req, res) => {
  const rows = db
    .prepare('SELECT id, author, location, caption, likes, media_type, media_path FROM posts ORDER BY id DESC LIMIT 100')
    .all();
  res.json({ data: rows });
});

app.post('/posts', authRequired, (req, res) => {
  const location = typeof req.body.location === 'string' ? req.body.location.trim() : '';
  const caption = typeof req.body.caption === 'string' ? req.body.caption.trim() : '';
  const mediaType = req.body.mediaType === 'video' ? 'video' : 'photo';
  const mediaPath = typeof req.body.mediaPath === 'string' ? req.body.mediaPath : null;
  if (!location) return res.status(400).json({ message: 'location is required.' });

  const profile = db.prepare('SELECT name FROM profiles WHERE user_id = ?').get(req.user.sub);
  const author = profile?.name || (req.user.email ? String(req.user.email).split('@')[0] : 'Hiker');

  db.prepare(
    `INSERT INTO posts (user_id, author, location, caption, media_type, media_path, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(req.user.sub, author, location, caption, mediaType, mediaPath, nowIso());

  res.json({ ok: true });
});

app.post('/media', authRequired, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Missing file.' });
  const publicPath = `/uploads/${req.file.filename}`;
  res.json({ ok: true, path: publicPath, url: publicPath });
});

app.get('/routes', (_req, res) => {
  const rows = db
    .prepare('SELECT id, name, difficulty, distance_km, duration, amenities, offline_ready FROM routes ORDER BY id DESC LIMIT 200')
    .all()
    .map((r) => ({
      ...r,
      amenities: safeJsonArray(r.amenities),
      offline_ready: Boolean(r.offline_ready),
    }));
  res.json({ data: rows });
});

app.get('/groups', (_req, res) => {
  const rows = db.prepare('SELECT id, name, type, members, next_event FROM groups ORDER BY id DESC LIMIT 200').all();
  res.json({ data: rows });
});

app.get('/profile', authRequired, (req, res) => {
  const row = db.prepare('SELECT * FROM profiles WHERE user_id = ?').get(req.user.sub);
  if (!row) return res.status(404).json({ message: 'Profile not found.' });
  res.json({
    data: {
      id: req.user.sub,
      name: row.name,
      membership: row.membership,
      xp: row.xp,
      streakDays: row.streak_days,
      medals: row.medals,
      monthlyPostsUsed: row.monthly_posts_used,
      monthlyPostLimit: row.monthly_post_limit,
      prayerModeEnabled: Boolean(row.prayer_mode_enabled),
    },
  });
});

app.put('/profile', authRequired, (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const prayerModeEnabled = Boolean(req.body.prayerModeEnabled);
  if (!name) return res.status(400).json({ message: 'name is required.' });

  db.prepare('UPDATE profiles SET name = ?, prayer_mode_enabled = ? WHERE user_id = ?').run(
    name,
    prayerModeEnabled ? 1 : 0,
    req.user.sub
  );
  res.json({ ok: true });
});

app.get('/safety-settings', authRequired, (req, res) => {
  const row = db.prepare('SELECT * FROM safety_settings WHERE user_id = ?').get(req.user.sub);
  if (!row) return res.status(404).json({ message: 'Safety settings not found.' });
  res.json({
    data: {
      emergencyContacts: row.emergency_contacts,
      autoCheckHours: row.auto_check_hours,
      extensionHours: row.extension_hours,
      graceMinutes: row.grace_minutes,
      sosEnabled: Boolean(row.sos_enabled),
    },
  });
});

app.put('/safety-settings', authRequired, (req, res) => {
  const emergencyContacts = Number(req.body.emergencyContacts ?? 0);
  const autoCheckHours = Number(req.body.autoCheckHours ?? 6);
  const extensionHours = Number(req.body.extensionHours ?? 2);
  const graceMinutes = Number(req.body.graceMinutes ?? 15);
  const sosEnabled = Boolean(req.body.sosEnabled);

  db.prepare(
    `UPDATE safety_settings
     SET emergency_contacts = ?, auto_check_hours = ?, extension_hours = ?, grace_minutes = ?, sos_enabled = ?
     WHERE user_id = ?`
  ).run(emergencyContacts, autoCheckHours, extensionHours, graceMinutes, sosEnabled ? 1 : 0, req.user.sub);
  res.json({ ok: true });
});

app.post('/sos', authOptional, (req, res) => {
  const latitude = req.body.latitude === null || req.body.latitude === undefined ? null : Number(req.body.latitude);
  const longitude = req.body.longitude === null || req.body.longitude === undefined ? null : Number(req.body.longitude);
  const message = typeof req.body.message === 'string' ? req.body.message.trim() : null;
  const userId = req.user?.sub ?? PUBLIC_USER_ID;

  db.prepare(
    `INSERT INTO sos_events (user_id, status, latitude, longitude, message, triggered_at)
     VALUES (?, 'open', ?, ?, ?, ?)`
  ).run(userId, latitude, longitude, message, nowIso());

  res.json({ ok: true, message: 'SOS activated.' });
});

app.use((err, _req, res, _next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  res.status(500).json({ message: 'Internal server error.' });
});

function safeJsonArray(value) {
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string') return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Backend listening on http://localhost:${PORT}`);
});

