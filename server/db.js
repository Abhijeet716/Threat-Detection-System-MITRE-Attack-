import sqlite3 from 'sqlite3';
import fs from 'fs';
import path from 'path';
import config from './config.js';

let db = null;

function ensureDirectory() {
  const dir = path.dirname(config.dbPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function initializeDatabase() {
  ensureDirectory();
  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(config.dbPath, (error) => {
      if (error) return reject(error);
      db.serialize(async () => {
        try {
          await run('PRAGMA foreign_keys = ON');
          await createSchema();
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    });
  });
}

export function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

export function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

export function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function createSchema() {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )`);

  await run(`CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    description TEXT NOT NULL,
    mitre_id TEXT NOT NULL,
    tactic TEXT NOT NULL,
    ip TEXT,
    severity TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS monitor_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    enabled INTEGER DEFAULT 0,
    last_updated INTEGER DEFAULT 0
  )`);

  await run(`INSERT OR IGNORE INTO monitor_state (id, enabled, last_updated) VALUES (1, 0, strftime('%s','now'))`);
}
