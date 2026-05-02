# Threat Detection Project

A professional-level threat detection prototype built with React, Node.js, SQLite, and a Python analysis engine.

## What’s included
- Secure user authentication with password hashing and JWT
- Realistic log-based attack detection
- Brute force, DoS/traffic spike, and suspicious IP detection
- MITRE ATT&CK mapping for detected threats
- Modern React dashboard with collapsible sidebar, monitoring controls, and alert history

## Project structure
- `server/`: Express backend, SQLite persistence, route modules, analytics orchestration
- `client/`: React + Vite dashboard user interface with professional styling
- `detection/`: Python rule engine for log-based threat detection
- `db/`: SQLite database storage

## Setup
1. Install backend dependencies:
   ```powershell
   Set-Location -Path "d:\Abhijeet\Cyber Project\server"
   npm install
   ```
2. Install frontend dependencies:
   ```powershell
   Set-Location -Path "d:\Abhijeet\Cyber Project\client"
   npm install
   ```
3. Copy environment template for the backend:
   ```powershell
   Copy-Item .env.example .env
   ```
4. Start the backend:
   ```powershell
   npm start
   ```
5. Start the frontend in a separate terminal:
   ```powershell
   Set-Location -Path "d:\Abhijeet\Cyber Project\client"
   npm run dev
   ```
6. Open the dashboard:
   - `http://localhost:5173`

## Features
- **Authentication**: Register/login with secure password hashing
- **Monitoring**: Toggle on/off for real-time threat detection
- **Dashboard**: Collapsible sidebar, summary tiles, IP table, alerts with severity colors
- **Detection**: Automated analysis of logs for MITRE-mapped threats
- **Responsive**: Works on desktop and mobile devices

## API routes
- `POST /api/auth/register` — register a new user
- `POST /api/auth/login` — authenticate and receive JWT
- `GET /api/dashboard` — fetch alerts, summary, and active IPs
- `GET /api/monitor` — get current monitor state
- `POST /api/monitor` — toggle monitoring
- `POST /api/simulate` — force a detection cycle

## MITRE ATT&CK mapping
- Brute force → `T1110` (Credential Access)
- DoS / traffic spike → `T1499` (Impact)
- Suspicious IP tracking → `TA0005` (Defense Evasion)

## Notes
- The backend uses SQLite at `db/threat.db`
- Detection logs are written to `server/logs/events.log`
- Use a secure `JWT_SECRET` in `.env`
