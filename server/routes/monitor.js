import express from 'express';
import { requireAuth } from '../middleware/authMiddleware.js';
import { getMonitorState, setMonitorState } from '../services/monitorService.js';

const router = express.Router();

router.get('/', requireAuth, async (req, res) => {
  const enabled = await getMonitorState();
  res.json({ enabled });
});

router.post('/', requireAuth, async (req, res) => {
  const enabled = Boolean(req.body.enabled);
  await setMonitorState(enabled);
  res.json({ enabled });
});

export default router;
