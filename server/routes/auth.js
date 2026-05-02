import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import { run, get } from '../db.js';
import config from '../config.js';
import { appendLog } from '../services/logService.js';
import { saveAlerts } from '../services/alertService.js';

const router = express.Router();
const SALT_ROUNDS = 10;

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });

  try {
    const existing = await get('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return res.status(409).json({ error: 'Username already exists.' });

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, passwordHash]);
    return res.json({ success: true, message: 'User registered successfully.' });
  } catch (error) {
    console.error('Register error:', error);
    return res.status(500).json({ error: 'Unable to register user.' });
  }
});

router.post('/login', async (req, res) => {
  const { username, password, ip = '127.0.0.1' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });

  try {
    const user = await get('SELECT * FROM users WHERE username = ?', [username]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    const now = Date.now();
    if (user.locked_until && now < user.locked_until) {
      const remaining = Math.ceil((user.locked_until - now) / 60000);
      return res.status(403).json({ error: `Account locked for ${remaining} more minutes.` });
    }

    const passwordValid = await bcrypt.compare(password, user.password_hash);
    if (!passwordValid) {
      const attempts = (user.failed_attempts || 0) + 1;
      const updateParams = [attempts, now, username];
      let errorMessage = 'Invalid credentials.';
      if (attempts >= 3) {
        const lockedUntil = now + 30 * 60 * 1000;
        await run('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?', [attempts, lockedUntil, username]);
        appendLog({ time: new Date().toISOString(), type: 'login', username, ip, status: 'failed', message: 'Account locked by brute-force protection' });
        await saveAlerts([{ type: 'Brute Force', description: 'Repeated failed login attempts were detected.', mitre_id: 'T1110', tactic: 'Credential Access', ip, severity: 'critical' }]);
        errorMessage = 'Account locked for 30 minutes after repeated failures.';
      } else {
        await run('UPDATE users SET failed_attempts = ?, locked_until = 0 WHERE username = ?', [attempts, username]);
        appendLog({ time: new Date().toISOString(), type: 'login', username, ip, status: 'failed', message: 'Invalid password' });
      }
      return res.status(401).json({ error: errorMessage });
    }

    await run('UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?', [username]);
    
    // Log successful login
    appendLog({ time: new Date().toISOString(), type: 'login', username, ip, status: 'success', message: 'Login successful' });
    
    // Reset all data on login - clear logs and alerts for fresh session
    try {
      fs.writeFileSync(config.logPath, '');
      await run('DELETE FROM alerts');
    } catch (err) {
      console.error('Failed to reset session data:', err);
    }

    const token = jwt.sign({ username }, config.jwtSecret, { expiresIn: '4h' });
    return res.json({ success: true, username, token });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Unable to process login.' });
  }
});

export default router;
