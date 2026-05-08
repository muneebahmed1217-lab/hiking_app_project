const fs = require('node:fs');
const path = require('node:path');

const Database = require('better-sqlite3');

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function getDbPath(envPath) {
  const fallback = path.join(process.cwd(), 'data', 'dev.sqlite');
  const resolved = envPath ? path.resolve(process.cwd(), envPath) : fallback;
  ensureDir(path.dirname(resolved));
  return resolved;
}

function createDb(dbPath) {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  return db;
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oauth_accounts (
      provider TEXT NOT NULL,
      provider_user_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      email TEXT,
      created_at TEXT NOT NULL,
      PRIMARY KEY (provider, provider_user_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id TEXT PRIMARY KEY,
      name TEXT,
      membership TEXT NOT NULL DEFAULT 'free',
      xp INTEGER NOT NULL DEFAULT 0,
      streak_days INTEGER NOT NULL DEFAULT 0,
      medals INTEGER NOT NULL DEFAULT 0,
      monthly_posts_used INTEGER NOT NULL DEFAULT 0,
      monthly_post_limit TEXT NOT NULL DEFAULT '2',
      prayer_mode_enabled INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      author TEXT,
      location TEXT NOT NULL,
      caption TEXT,
      likes INTEGER NOT NULL DEFAULT 0,
      media_type TEXT NOT NULL DEFAULT 'photo',
      media_path TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS routes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      difficulty TEXT NOT NULL,
      distance_km REAL NOT NULL,
      duration TEXT NOT NULL,
      amenities TEXT NOT NULL DEFAULT '[]',
      offline_ready INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      members INTEGER NOT NULL DEFAULT 0,
      next_event TEXT NOT NULL DEFAULT 'TBD',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS safety_settings (
      user_id TEXT PRIMARY KEY,
      emergency_contacts INTEGER NOT NULL DEFAULT 0,
      auto_check_hours INTEGER NOT NULL DEFAULT 6,
      extension_hours INTEGER NOT NULL DEFAULT 2,
      grace_minutes INTEGER NOT NULL DEFAULT 15,
      sos_enabled INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sos_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      status TEXT NOT NULL,
      latitude REAL,
      longitude REAL,
      message TEXT,
      triggered_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);
}

function seedIfEmpty(db) {
  const routesCount = db.prepare('SELECT COUNT(*) as n FROM routes').get().n;
  const groupsCount = db.prepare('SELECT COUNT(*) as n FROM groups').get().n;

  if (routesCount === 0) {
    const now = new Date().toISOString();
    const insert = db.prepare(
      `INSERT INTO routes (name, difficulty, distance_km, duration, amenities, offline_ready, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    );
    const sample = [
      ['Canyon Loop', 'Moderate', 7.4, '2h 10m', JSON.stringify(['water', 'parking']), 1, now],
      ['Summit Ridge', 'Hard', 12.8, '4h 30m', JSON.stringify(['views', 'scramble']), 0, now],
      ['Lakeside Stroll', 'Easy', 3.2, '55m', JSON.stringify(['restrooms', 'picnic']), 1, now],
    ];
    const tx = db.transaction(() => sample.forEach((row) => insert.run(...row)));
    tx();
  }

  if (groupsCount === 0) {
    const now = new Date().toISOString();
    const insert = db.prepare(
      `INSERT INTO groups (name, type, members, next_event, created_at)
       VALUES (?, ?, ?, ?, ?)`
    );
    const sample = [
      ['Weekend Warriors', 'Mixed', 142, 'Sat 8:00am', now],
      ['Trail Runners', 'Running', 67, 'Wed 6:30pm', now],
      ['Beginner Hikes', 'Beginner', 89, 'Sun 9:00am', now],
    ];
    const tx = db.transaction(() => sample.forEach((row) => insert.run(...row)));
    tx();
  }
}

module.exports = {
  getDbPath,
  createDb,
  initSchema,
  seedIfEmpty,
};

