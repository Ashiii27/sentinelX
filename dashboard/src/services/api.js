/**
 * REST client for the SentinelX backend.
 *
 * All paths are relative (/api/...) so the same bundle works in dev
 * (Vite proxy), production (nginx proxy), and any deployment where the
 * API is same-origin. `VITE_API_URL` can override the base if the API
 * is served from a different origin.
 */
import axios from 'axios';

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 10000,
});

export const api = {
  // Health
  health: () => client.get('/health').then((r) => r.data),

  // Alerts
  alerts: (params = {}) => client.get('/alerts', { params }).then((r) => r.data),
  alert: (id) => client.get(`/alerts/${encodeURIComponent(id)}`).then((r) => r.data),
  updateTriage: (id, patch) =>
    client
      .put(`/alerts/${encodeURIComponent(id)}`, patch)
      .then((r) => r.data),
  deleteAlert: (id) =>
    client.delete(`/alerts/${encodeURIComponent(id)}`).then((r) => r.data),

  // Stats
  summary: () => client.get('/stats/summary').then((r) => r.data),

  // YARA rules
  rules: () => client.get('/rules').then((r) => r.data),
  createRule: (filename, content) =>
    client
      .post('/rules', { filename, content })
      .then((r) => r.data),
  updateRule: (file, content) =>
    client
      .put(`/rules/${encodeURIComponent(file)}`, { content })
      .then((r) => r.data),
  deleteRule: (file) =>
    client
      .delete(`/rules/${encodeURIComponent(file)}`)
      .then((r) => r.data),
  reloadRules: () =>
    client.post('/rules/reload').then((r) => r.data),
};

/** Map an axios error to a short human-readable message. */
export function apiError(err) {
  if (err.response) {
    const data = err.response.data;
    if (data && data.error) return `${data.error} (HTTP ${err.response.status})`;
    return `HTTP ${err.response.status}`;
  }
  if (err.code === 'ECONNABORTED') return 'request timed out';
  return 'backend unreachable';
}

export default api;
