export const pct = (n, d = 1) => `${(Number(n || 0) * 100).toFixed(d)}%`

export const dateTime = (s) =>
  new Date(s).toLocaleString(undefined, {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  })

export const dateOnly = (s) =>
  new Date(s).toLocaleDateString(undefined, { day: '2-digit', month: 'short' })

export const compact = (n) => {
  const v = Number(n || 0)
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)}B`
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)}M`
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)}K`
  return String(v)
}

export const titleCase = (s) =>
  String(s || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())

export const BAND_VAR = {
  Critical: 'var(--critical)', High: 'var(--high)', Moderate: 'var(--moderate)',
  Low: 'var(--low)', Minimal: 'var(--minimal)',
}
