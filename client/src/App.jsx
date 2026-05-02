import { useEffect, useState } from 'react';
import AuthForm from './components/AuthForm.jsx';
import Dashboard from './components/Dashboard.jsx';
import { login, register, getDashboard, getMonitor, setMonitor } from './api.js';

const savedToken = localStorage.getItem('authToken');
const savedUser = localStorage.getItem('username');

function App() {
  const [token, setToken] = useState(savedToken);
  const [user, setUser] = useState(savedUser || 'Analyst');
  const [monitorEnabled, setMonitorEnabled] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [activeIps, setActiveIps] = useState([]);
  const [summary, setSummary] = useState({ attackTypes: [] });
  const [timeSeries, setTimeSeries] = useState([]);
  const [message, setMessage] = useState('');
  const [form, setForm] = useState({ username: '', password: '' });

  const authHeaders = token;

  const refreshDashboard = async () => {
    try {
      const data = await getDashboard(authHeaders);
      setAlerts(data.alerts || []);
      setActiveIps(data.activeIps || []);
      setSummary(data.summary || { attackTypes: [] });
      setTimeSeries(data.timeSeries || []);
    } catch (error) {
      setMessage(error.message);
      if (error.message === 'Invalid or expired token.') logout();
    }
  };

  const loadMonitorState = async () => {
    try {
      const data = await getMonitor(authHeaders);
      setMonitorEnabled(data.enabled);
    } catch (error) {
      setMessage(error.message);
    }
  };

  useEffect(() => {
    if (token) {
      loadMonitorState();
      refreshDashboard();
      const interval = setInterval(refreshDashboard, 9000);
      return () => clearInterval(interval);
    }
  }, [token]);

  const handleChange = (event) => {
    setForm({ ...form, [event.target.name]: event.target.value });
  };

  const handleAuth = async (mode) => {
    setMessage('');
    try {
      if (mode === 'login') {
        const result = await login(form.username, form.password);
        localStorage.setItem('authToken', result.token);
        localStorage.setItem('username', result.username);
        setToken(result.token);
        setUser(result.username);
        setForm({ username: '', password: '' });
      } else {
        await register(form.username, form.password);
        setMessage('Registration successful. Please login.');
      }
    } catch (error) {
      setMessage(error.message);
    }
  };

  const toggleMonitor = async () => {
    try {
      const data = await setMonitor(authHeaders, !monitorEnabled);
      setMonitorEnabled(data.enabled);
    } catch (error) {
      setMessage(error.message);
    }
  };

  const logout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    setToken(null);
    setUser('Analyst');
    setAlerts([]);
    setActiveIps([]);
    setSummary({ attackTypes: [] });
    setMessage('');
  };

  if (!token) {
    return (
      <AuthForm
        form={form}
        onChange={handleChange}
        onLogin={() => handleAuth('login')}
        onRegister={() => handleAuth('register')}
        message={message}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      monitorEnabled={monitorEnabled}
      alerts={alerts}
      activeIps={activeIps}
      summary={summary}
      timeSeries={timeSeries}
      onToggleMonitor={toggleMonitor}
      onRefresh={refreshDashboard}
      onLogout={logout}
    />
  );
}

export default App;
