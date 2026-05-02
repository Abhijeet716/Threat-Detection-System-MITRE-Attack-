import express from 'express';
import { requireAuth } from '../middleware/authMiddleware.js';
import { getRecentAlerts, getAllAlerts } from '../services/alertService.js';
import { readLogs } from '../services/logService.js';
import dns from 'dns';
import { promisify } from 'util';

const router = express.Router();
const reverseLookup = promisify(dns.resolve4);
const dnsCache = new Map();

const commonDomains = {
  '127.0.0.1': 'dashboard.local',
  '0.0.0.0': 'server.local',
  '192.168': 'local-network',
  '10.0': 'private-network',
  '172.16': 'private-network'
};

function getBaseSecurityScore(ip) {
  if (ip === '127.0.0.1' || ip === '0.0.0.0') return 1;
  if (ip.startsWith('192.168.') || ip.startsWith('10.')) return 2;
  if (ip.startsWith('172.16.')) return 2;
  return Math.floor(Math.random() * 40) + 10;
}

async function resolveDnsName(ipAddress) {
  if (dnsCache.has(ipAddress)) return dnsCache.get(ipAddress);
  
  for (const [pattern, domain] of Object.entries(commonDomains)) {
    if (ipAddress.startsWith(pattern)) {
      dnsCache.set(ipAddress, domain);
      return domain;
    }
  }
  
  try {
    const results = await reverseLookup(ipAddress);
    const domain = results[0] || `host-${ipAddress.split('.').pop()}`;
    dnsCache.set(ipAddress, domain);
    return domain;
  } catch (err) {
    const fallback = `host-${ipAddress.split('.').pop()}`;
    dnsCache.set(ipAddress, fallback);
    return fallback;
  }
}

function parseActiveIps(lines) {
  const buckets = {};
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (!event.ip) continue;

      const bucket = buckets[event.ip] || { ip: event.ip, count: 0, lastActivity: event.time, suspiciousScore: 0, threatLevel: 'low', baseSecurityScore: getBaseSecurityScore(event.ip), dnsHint: null };
      bucket.count += 1;
      bucket.lastActivity = event.time;
      bucket.suspiciousScore += event.status === 'failed' ? 2 : 0;
      bucket.suspiciousScore += event.type === 'request' ? 0.3 : 0;

      if (event.host) bucket.dnsHint = event.host;
      if (!bucket.dnsHint && event.url) {
        try {
          bucket.dnsHint = new URL(event.url).hostname;
        } catch (err) {
          // ignore bad URL
        }
      }
      if (!bucket.dnsHint && event.message && event.message.includes('HTTP')) {
        const match = event.message.match(/https?:\/\/([^\/\s]+)/);
        if (match) bucket.dnsHint = match[1];
      }

      if (bucket.suspiciousScore > 5) bucket.threatLevel = 'critical';
      else if (bucket.suspiciousScore > 3) bucket.threatLevel = 'high';
      else if (bucket.suspiciousScore > 1) bucket.threatLevel = 'medium';

      buckets[event.ip] = bucket;
    } catch (err) {
      continue;
    }
  }

  const ips = Object.values(buckets).sort((a, b) => b.suspiciousScore - a.suspiciousScore).slice(0, 15);

  const promises = ips.map(async (ip) => {
    if (ip.dnsHint) {
      ip.dns = ip.dnsHint;
    } else {
      ip.dns = await resolveDnsName(ip.ip);
    }
    ip.riskScore = Math.min(100, Math.floor(ip.suspiciousScore * 15 + ip.baseSecurityScore));
    return ip;
  });

  return Promise.all(promises);
}

function computeTimeSeries(lines) {
  const now = Date.now();
  const buckets = {};
  for (let i = 0; i < 10; i++) {
    const time = now - (9 - i) * 60000; // last 10 minutes, 1 min buckets
    buckets[Math.floor(time / 60000)] = { time, count: 0 };
  }
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (event.time) {
        const timestamp = typeof event.time === 'string' ? Date.parse(event.time) : Number(event.time);
        if (!Number.isFinite(timestamp)) continue;
        const bucket = Math.floor(timestamp / 60000);
        if (buckets[bucket]) buckets[bucket].count += 1;
      }
    } catch (err) {
      continue;
    }
  }
  return Object.values(buckets).sort((a, b) => a.time - b.time);
}

function computeSummary(lines) {
  const totals = { requestCount: 0, failedLogins: 0, suspiciousIPs: new Set() };
  const eventsPerIp = {};
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      if (event.type === 'request') totals.requestCount += 1;
      if (event.type === 'login' && event.status === 'failed') totals.failedLogins += 1;
      if (!event.ip) continue;
      eventsPerIp[event.ip] = (eventsPerIp[event.ip] || 0) + 1;
    } catch (err) {
      continue;
    }
  }
  Object.entries(eventsPerIp).forEach(([ip, count]) => {
    if (count > 20) totals.suspiciousIPs.add(ip);
  });
  return {
    requestCount: totals.requestCount,
    failedLogins: totals.failedLogins,
    suspiciousIPs: totals.suspiciousIPs.size,
    attackTypes: [
      { name: 'Brute Force', count: totals.failedLogins > 3 ? 1 : 0 },
      { name: 'DoS / Traffic Spike', count: totals.suspiciousIPs.size > 0 ? 1 : 0 },
      { name: 'Suspicious IP', count: totals.suspiciousIPs.size }
    ]
  };
}

router.get('/', requireAuth, async (req, res) => {
  const logs = readLogs();
  const alerts = await getRecentAlerts();
  const activeIps = await parseActiveIps(logs);
  const summary = computeSummary(logs);
  const timeSeries = computeTimeSeries(logs);
  res.json({ alerts, activeIps, summary, timeSeries });
});

router.get('/all', requireAuth, async (req, res) => {
  const alerts = await getAllAlerts();
  res.json({ alerts });
});

export default router;
