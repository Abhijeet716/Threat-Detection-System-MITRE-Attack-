import config from '../config.js';
import { get, run } from '../db.js';
import { appendLog } from './logService.js';
import { analyzeLogFile } from './detectionService.js';
import { saveAlerts } from './alertService.js';

let monitorInterval = null;

function getRandomIp() {
  const candidates = ['192.168.1.12', '192.168.1.14', '10.0.0.8', '172.16.0.5', '203.0.113.7'];
  return candidates[Math.floor(Math.random() * candidates.length)];
}

function getHostForIp(ip) {
  const map = {
    '192.168.1.12': 'github.com',
    '192.168.1.14': 'stackoverflow.com',
    '10.0.0.8': 'google.com',
    '172.16.0.5': 'microsoft.com',
    '203.0.113.7': 'amazon.com'
  };
  return map[ip] || 'unknown.com';
}

function generateTraffic() {
  const ip = getRandomIp();
  const host = getHostForIp(ip);
  const eventType = Math.random() > 0.2 ? 'request' : 'login';
  const failed = eventType === 'login' && Math.random() > 0.6;
  const event = {
    time: new Date().toISOString(),
    ip,
    host,
    type: eventType,
    username: eventType === 'login' ? `user${Math.ceil(Math.random() * 4)}` : null,
    status: eventType === 'login' ? (failed ? 'failed' : 'success') : 'ok',
    message: eventType === 'login' ? (failed ? 'Invalid password' : 'Login successful') : `HTTP GET https://${host}/api/data`
  };
  appendLog(event);
}

export async function getMonitorState() {
  const row = await get('SELECT enabled FROM monitor_state WHERE id = 1');
  return Boolean(row?.enabled);
}

export async function setMonitorState(enabled) {
  await run('UPDATE monitor_state SET enabled = ?, last_updated = ? WHERE id = 1', [enabled ? 1 : 0, Date.now()]);
  if (enabled) startMonitor(); else stopMonitor();
}

export function startMonitor() {
  if (monitorInterval) return;
  monitorInterval = setInterval(async () => {
    generateTraffic();
    try {
      const alerts = await analyzeLogFile();
      await saveAlerts(alerts);
    } catch (err) {
      console.error('Detection error:', err.message);
    }
  }, config.monitorIntervalMs);
}

export function stopMonitor() {
  if (!monitorInterval) return;
  clearInterval(monitorInterval);
  monitorInterval = null;
}

export async function initializeMonitor() {
  const enabled = await getMonitorState();
  if (enabled) startMonitor();
}

export async function triggerDetection() {
  generateTraffic();
  try {
    const alerts = await analyzeLogFile();
    await saveAlerts(alerts);
  } catch (err) {
    console.error('Detection error:', err.message);
  }
}
