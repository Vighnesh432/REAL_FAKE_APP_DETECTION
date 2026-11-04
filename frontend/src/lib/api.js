// Single place where the token is attached and errors are normalised. Components should
// never construct a fetch by hand — that is how auth headers get forgotten on one route.

const TOKEN_KEY = 'appxray_token'

export const getToken = () => localStorage.getItem(TOKEN_KEY)
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t)
export const clearToken = () => localStorage.removeItem(TOKEN_KEY)

async function parseError(res) {
  try {
    const body = await res.json()
    if (typeof body.detail === 'string') return body.detail
    if (Array.isArray(body.detail)) {
      return body.detail.map((d) => `${d.loc?.slice(-1)[0] ?? 'field'}: ${d.msg}`).join(', ')
    }
    return 'Request failed.'
  } catch {
    return res.status === 503
      ? 'The detection model is not loaded yet. Ask an administrator to run training.'
      : `Request failed (${res.status}).`
  }
}

async function request(path, { method = 'GET', body, form, raw } = {}) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  if (body) headers['Content-Type'] = 'application/json'

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: form ?? (body ? JSON.stringify(body) : undefined),
  })

  if (res.status === 401) {
    clearToken()
    window.dispatchEvent(new Event('appxray:signed-out'))
  }
  if (!res.ok) throw new Error(await parseError(res))
  if (raw) return res
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  health: () => request('/health'),

  register: (data) => request('/auth/register', { method: 'POST', body: data }),
  login: async (email, password) => {
    const form = new URLSearchParams({ username: email, password })
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    })
    if (!res.ok) throw new Error(await parseError(res))
    return res.json()
  },
  me: () => request('/auth/me'),

  predict: (app, modelName) => request('/predict', { method: 'POST', body: { app, model_name: modelName || null } }),
  compare: (app) => request('/predict/compare', { method: 'POST', body: app }),
  uploadCsv: (file) => {
    const fd = new FormData(); fd.append('file', file)
    return request('/predict/upload', { method: 'POST', form: fd })
  },
  uploadApk: (file, fields) => {
    const fd = new FormData(); fd.append('file', file)
    Object.entries(fields || {}).forEach(([k, v]) => fd.append(k, v))
    return request('/predict/apk', { method: 'POST', form: fd })
  },
  // Scans a pasted link — a Play Store listing gets fetched and run through the full
  // model + rule pipeline; any other URL gets the separate website trust check.
  // The backend decides which based on the host, so the client just sends the URL.
  predictUrl: (url) => request('/predict/url', { method: 'POST', body: { url } }),
  modelInfo: () => request('/model/info'),

  scans: (params) => request(`/scans?${new URLSearchParams(params)}`),
  scan: (id) => request(`/scans/${id}`),
  deleteScan: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
  reportUrl: (id) => `/api/scans/${id}/report.pdf`,
  downloadReport: async (id, name) => {
    const res = await request(`/scans/${id}/report.pdf`, { raw: true })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `security-report-${name || id}.pdf`
    a.click()
    URL.revokeObjectURL(url)
  },
  analytics: (days = 30) => request(`/analytics?days=${days}`),
  feedback: (data) => request('/feedback', { method: 'POST', body: data }),

  adminStats: () => request('/admin/stats'),
  adminUsers: () => request('/admin/users'),
  adminFeedback: (reviewed) =>
    request(`/admin/feedback${reviewed === undefined ? '' : `?reviewed=${reviewed}`}`),
  reviewFeedback: (id, accepted) =>
    request(`/admin/feedback/${id}?accepted=${accepted}`, { method: 'PATCH' }),
  retrain: (opts) => request('/admin/retrain', { method: 'POST', body: opts || {} }),
  trainingRuns: () => request('/admin/training-runs'),
  setUserStatus: (id, active) =>
    request(`/admin/users/${id}/status?is_active=${active}`, { method: 'PATCH' }),
}
