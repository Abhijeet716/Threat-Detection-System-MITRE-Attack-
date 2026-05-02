import express from 'express';
import { requireAuth } from '../middleware/authMiddleware.js';
import { triggerDetection } from '../services/monitorService.js';

const router = express.Router();

router.post('/', requireAuth, async (req, res) => {
  try {
    await triggerDetection();
    res.json({ success: true });
  } catch (error) {
    console.error('Simulation error:', error);
    res.status(500).json({ error: 'Unable to simulate traffic.' });
  }
});

export default router;
