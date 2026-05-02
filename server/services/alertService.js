import { run, all } from '../db.js';

export async function saveAlerts(alerts) {
  if (!Array.isArray(alerts) || alerts.length === 0) return;
  const statement = await new Promise((resolve, reject) => {
    run(`BEGIN TRANSACTION`).then(() => {
      resolve();
    }).catch(reject);
  });
  for (const alert of alerts) {
    await run(`INSERT INTO alerts (type, description, mitre_id, tactic, ip, severity, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [alert.type, alert.description, alert.mitre_id, alert.tactic, alert.ip, alert.severity, Date.now()]
    );
  }
  await run(`COMMIT`);
}

export async function getRecentAlerts(limit = 12) {
  return all(`SELECT id, type, description, mitre_id, tactic, ip, severity, created_at
    FROM alerts ORDER BY created_at DESC LIMIT ?`, [limit]);
}

export async function getAllAlerts() {
  return all(`SELECT id, type, description, mitre_id, tactic, ip, severity, created_at
    FROM alerts ORDER BY created_at DESC`, []);
}
