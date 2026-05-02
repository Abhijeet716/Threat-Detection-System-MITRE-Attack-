const API_BASE = '/api';

function buildHeaders(token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function request(path, options = {}, token) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: buildHeaders(token),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || 'Request failed');
  }
  return data;
}

export function login(username, password) {
  return request('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export function register(username, password) {
  return request('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

export function getDashboard(token) {
  return request('/dashboard', { method: 'GET' }, token);
}

export function getMonitor(token) {
  return request('/monitor', { method: 'GET' }, token);
}

export function setMonitor(token, enabled) {
  return request('/monitor', {
    method: 'POST',
    body: JSON.stringify({ enabled }),
  }, token);
}

export function simulateTraffic(token) {
  return request('/simulate', { method: 'POST' }, token);
}
