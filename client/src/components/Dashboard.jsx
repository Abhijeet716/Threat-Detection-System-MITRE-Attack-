import { useState } from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

export default function Dashboard({ user, monitorEnabled, alerts, activeIps, summary, timeSeries, onToggleMonitor, onRefresh, onLogout }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const highestRisk = activeIps.reduce((max, ip) => Math.max(max, ip.riskScore || 0), 0);
  const overallThreat = highestRisk >= 75 ? 'Critical' : highestRisk >= 50 ? 'High' : highestRisk >= 25 ? 'Medium' : 'Low';

  return (
    <div className="dashboard-shell">
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'closed'}`}>
        <div className="sidebar-brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <h2>Threat SOC</h2>
            <p>Active monitoring console</p>
          </div>
        </div>

        <button className="monitor-toggle" onClick={onToggleMonitor}>
          {monitorEnabled ? 'Stop Monitoring' : 'Start Monitoring'}
        </button>

        <div className="stat-card">
          <h3>Active Alerts</h3>
          <p>{alerts.length}</p>
        </div>

        <div className="stat-card">
          <h3>Suspicious IPs</h3>
          <p>{summary.suspiciousIPs || 0}</p>
        </div>

        <button className="secondary large" onClick={onLogout}>Logout</button>
      </aside>

      <main className="content">
        <header>
          <button className="hamburger" onClick={() => setSidebarOpen(!sidebarOpen)}>
            ☰
          </button>
          <div>
            <h1>Welcome back, {user}</h1>
            <p>Monitoring is {monitorEnabled ? 'enabled' : 'disabled'}.</p>
          </div>
          <button className="action-button large" onClick={onRefresh}>Refresh</button>
        </header>

        <section className="tiles">
          <div className="tile">
            <span>Request volume</span>
            <strong>{summary.requestCount || 0}</strong>
          </div>
          <div className="tile">
            <span>Failed logins</span>
            <strong>{summary.failedLogins || 0}</strong>
          </div>
          <div className="tile">
            <span>Suspicious IPs</span>
            <strong>{summary.suspiciousIPs || 0}</strong>
          </div>
        </section>

        <section className="panel status-alert-row">
          <div className="status-panel">
            <h2>System Status</h2>
            <div className="status-grid">
              <div className="status-card">
                <span>Monitoring</span>
                <strong>{monitorEnabled ? 'Online' : 'Idle'}</strong>
              </div>
              <div className="status-card">
                <span>Alerts Active</span>
                <strong>{alerts.length}</strong>
              </div>
              <div className="status-card">
                <span>Threat Level</span>
                <strong>{overallThreat}</strong>
              </div>
              <div className="status-card">
                <span>Request Volume</span>
                <strong>{summary.requestCount || 0}</strong>
              </div>
            </div>
          </div>

          <div className="alerts-panel">
            <h2>Recent Alerts</h2>
            <div className="alerts-window">
              {alerts.length === 0 ? (
                <p>No active alerts</p>
              ) : (
                alerts.map((alert) => (
                  <div key={alert.id || `${alert.ip}-${alert.type}`} className={`alert-card ${alert.severity}`}>
                    <div className="alert-title">{alert.type}</div>
                    <div className="alert-desc">{alert.description}</div>
                    <div className="alert-meta">
                      <span>{alert.mitre_id}</span>
                      <span>{alert.tactic}</span>
                      <span>{alert.ip}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="panel">
          <h2>Live Network Scanning</h2>
          <div className="chart-container">
            <Line
              data={{
                labels: timeSeries.map(t => new Date(t.time).toLocaleTimeString()),
                datasets: [{
                  label: 'Requests per Minute',
                  data: timeSeries.map(t => t.count),
                  borderColor: 'rgb(75, 192, 192)',
                  tension: 0.1
                }]
              }}
              options={{
                responsive: true,
                plugins: {
                  legend: { position: 'top' },
                  title: { display: true, text: 'Network Activity Over Time' }
                }
              }}
            />
          </div>
        </section>

        <section className="panel">
          <h2>Active IPs & Threats</h2>
          <div className="ip-table-horizontal">
            {activeIps.length === 0 ? <p>No activity yet</p> : activeIps.map((ip) => (
              <div key={ip.ip} className={`ip-card ${ip.threatLevel}`}>
                <div className="ip-header">
                  <div className="ip-address">{ip.ip}</div>
                  <div className={`threat-badge ${ip.threatLevel}`}>{ip.threatLevel.toUpperCase()}</div>
                </div>
                <div className="ip-details">
                  <div className="detail-item">
                    <label>DNS</label>
                    <span className="detail-value">{ip.dns || 'Resolving...'}</span>
                  </div>
                  <div className="detail-item">
                    <label>Events</label>
                    <span className="detail-value">{ip.count}</span>
                  </div>
                  <div className="detail-item">
                    <label>Risk Score</label>
                    <span className="detail-value score">{ip.riskScore || 0}%</span>
                  </div>
                  <div className="detail-item">
                    <label>Threat Score</label>
                    <span className="detail-value">{ip.suspiciousScore.toFixed(1)}</span>
                  </div>
                </div>
                <div className="risk-meter">
                  <div className="risk-bar" style={{ width: `${ip.riskScore || 0}%` }}></div>
                </div>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}

