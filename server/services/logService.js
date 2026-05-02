import fs from 'fs';
import path from 'path';
import config from '../config.js';

function ensureLogDirectory() {
  const dir = path.dirname(config.logPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

export function appendLog(entry) {
  ensureLogDirectory();
  const line = JSON.stringify(entry);
  fs.appendFileSync(config.logPath, `${line}\n`);
}

export function readLogs() {
  if (!fs.existsSync(config.logPath)) return [];
  const raw = fs.readFileSync(config.logPath, 'utf8');
  return raw.trim().split('\n').filter(Boolean);
}
