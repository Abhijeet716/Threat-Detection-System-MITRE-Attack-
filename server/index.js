import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bodyParser from 'body-parser';
import config from './config.js';
import { initializeDatabase } from './db.js';
import { initializeMonitor } from './services/monitorService.js';
import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import monitorRoutes from './routes/monitor.js';
import simulateRoutes from './routes/simulate.js';

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({ origin: config.clientOrigin, credentials: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Auth routes have stricter limits
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.'
});
app.use('/api/auth/login', authLimiter);

app.use(bodyParser.json());

app.use('/api/auth', authRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/monitor', monitorRoutes);
app.use('/api/simulate', simulateRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

const port = config.port;

try {
  await initializeDatabase();
  await initializeMonitor();
  app.listen(port, () => {
    console.log(`Threat Detection API running on http://localhost:${port}`);
  });
} catch (error) {
  console.error('Failed to start server:', error);
  process.exit(1);
}
