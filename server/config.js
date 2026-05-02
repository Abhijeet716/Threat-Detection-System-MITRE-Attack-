import dotenv from 'dotenv';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

dotenv.config();
const __dirname = dirname(fileURLToPath(import.meta.url));
const env = process.env;

const config = {
  port: Number(env.PORT || 4000),
  jwtSecret: env.JWT_SECRET || 'replace-with-a-secure-secret',
  dbPath: env.DB_PATH || join(__dirname, '../db/threat.db'),
  logPath: env.LOG_PATH || join(__dirname, 'logs/events.log'),
  clientOrigin: env.CLIENT_ORIGIN || 'http://localhost:5173',
  monitorIntervalMs: Number(env.MONITOR_INTERVAL_MS || 10000),
  pythonExecutable: env.PYTHON_EXECUTABLE || (process.platform === 'win32' ? 'python' : 'python3'),
  pythonScriptPath: env.PYTHON_SCRIPT_PATH || join(__dirname, '../detection/detection_engine.py')
};

export default config;
