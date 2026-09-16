const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function request(path, options = {}, token) {
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers } })
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || 'The request could not be completed.')
  }
  return response
}

export const api = {
  authenticate: async (mode, email, password) => (await request(`/api/auth/${mode}`, { method: 'POST', body: JSON.stringify({ email, password }) })).json(),
  scan: async (target_url, token) => (await request('/api/scan', { method: 'POST', body: JSON.stringify({ target_url }) }, token)).json(),
  status: async (id, token) => (await request(`/api/scan/${id}/status`, {}, token)).json(),
  report: async (id, token) => (await request(`/api/scan/${id}`, {}, token)).json(),
  history: async (token) => (await request('/api/history', {}, token)).json(),
}
