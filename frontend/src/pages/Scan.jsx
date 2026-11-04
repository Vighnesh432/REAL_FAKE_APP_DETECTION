import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import {
  ErrorNote, EvidenceList, FetchedFromNote, Loading, StaticAnalysis, VerdictPanel,
} from '../components/ui'

const CATEGORIES = [
  'Communication', 'Photography', 'Finance', 'Games', 'Productivity',
  'Health & Fitness', 'Shopping', 'Education', 'Music & Audio', 'Travel',
]

const BLANK = {
  app_name: '', package_name: '', category: 'Productivity', description: '',
  reviews: '', permissions: '', rating: '', rating_count: '', installs: '',
  size_mb: '', days_since_update: '', app_age_days: '', developer_app_count: '',
  has_developer_website: 0, has_privacy_policy: 0,
}

const URL_EXAMPLES = [
  { label: 'Play Store app', value: 'https://play.google.com/store/apps/details?id=com.whatsapp' },
  { label: 'Suspicious link', value: 'http://free-gift-verify-account.tk/claim' },
]

const num = (v) => (v === '' || v == null ? 0 : Number(v))

export default function Scan() {
  const [mode, setMode] = useState('apk')
  const [form, setForm] = useState(BLANK)
  const [file, setFile] = useState(null)
  const [linkUrl, setLinkUrl] = useState('')
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const navigate = useNavigate()

  const set = (k) => (e) => {
    const v = e.target.type === 'checkbox' ? (e.target.checked ? 1 : 0) : e.target.value
    setForm((f) => ({ ...f, [k]: v }))
  }

  const reset = () => { setResult(null); setError('') }

  const runApk = async (e) => {
    e.preventDefault()
    if (!file) { setError('Choose an APK file first.'); return }
    setBusy(true); reset()
    try {
      setResult(await api.uploadApk(file, {
        app_name: form.app_name, category: form.category, description: form.description,
        rating: num(form.rating), rating_count: num(form.rating_count), installs: num(form.installs),
      }))
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  const runUrl = async (e) => {
    e.preventDefault()
    if (!linkUrl.trim()) { setError('Paste a link to scan.'); return }
    setBusy(true); reset()
    try { setResult(await api.predictUrl(linkUrl.trim())) }
    catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return (
    <>
      <div className="page-head">
        <h1>Scan an application</h1>
        <p>
          Upload an APK file or paste a link to check it against the trained classifier
          and the certificate-based identity verification layer.
        </p>
      </div>

      <div className="tabs" style={{ maxWidth: 320 }}>
        {[['apk', 'Upload APK'], ['url', 'By link']].map(([k, label]) => (
          <button key={k} className={mode === k ? 'active' : ''}
                  onClick={() => { setMode(k); reset(); setFile(null) }}>
            {label}
          </button>
        ))}
      </div>

      <div className="split">
        {/* ----------------------------- input ----------------------------- */}
        <div className="card">
          {mode === 'apk' && (
            <form onSubmit={runApk}>
              <div className="card-head"><h2>Upload an APK</h2></div>
              <p className="small muted" style={{ marginTop: 0 }}>
                Permissions and the package name are read straight from the binary manifest,
                so they reflect what the package actually declares rather than what the
                listing claims.
              </p>
              <label className="field"><span>APK file *</span>
                <input type="file" accept=".apk" onChange={(e) => setFile(e.target.files[0])} />
                <div className="hint">Up to 150 MB. Nothing is executed — the archive is only read.</div>
              </label>
              <div className="grid grid-2">
                <label className="field"><span>App name</span>
                  <input value={form.app_name} onChange={set('app_name')} placeholder="Optional" />
                </label>
                <label className="field"><span>Category</span>
                  <select value={form.category} onChange={set('category')}>
                    {CATEGORIES.map((c) => <option key={c}>{c}</option>)}
                  </select>
                </label>
              </div>
              <label className="field"><span>Store description</span>
                <textarea value={form.description} onChange={set('description')} placeholder="Optional" />
              </label>
              <button className="btn" disabled={busy}>
                {busy ? <><span className="spinner" /> Analysing</> : 'Analyse APK'}
              </button>
            </form>
          )}

          {mode === 'url' && (
            <form onSubmit={runUrl}>
              <div className="card-head"><h2>Scan by link</h2></div>
              <p className="small muted" style={{ marginTop: 0 }}>
                Paste a Play Store listing link to fetch the real description, reviews,
                rating and permissions automatically. Paste a direct <code className="mono">.apk</code>{' '}
                download link to verify the actual binary. Paste any other website link to run
                a separate trust check for phishing and impersonation signals.
              </p>
              <label className="field"><span>Link *</span>
                <input
                  className="mono"
                  value={linkUrl}
                  onChange={(e) => setLinkUrl(e.target.value)}
                  placeholder="https://play.google.com/store/apps/details?id=..."
                />
              </label>
              <div className="row" style={{ marginBottom: 15 }}>
                {URL_EXAMPLES.map((ex) => (
                  <button key={ex.label} type="button" className="btn btn-ghost btn-sm"
                          onClick={() => setLinkUrl(ex.value)}>
                    {ex.label} example
                  </button>
                ))}
              </div>
              <button className="btn" disabled={busy}>
                {busy ? <><span className="spinner" /> Fetching &amp; scanning</> : 'Scan link'}
              </button>
              <div className="hint" style={{ marginTop: 10 }}>
                A Play Store link goes through the same classifier and rule engine as an
                uploaded APK. A plain website link uses a separate check — it has no
                permissions or install count for the app model to reason about.
              </div>
            </form>
          )}
        </div>

        {/* ----------------------------- results ----------------------------- */}
        <div className="stack">
          <ErrorNote>{error}</ErrorNote>
          {busy && !result && (
            <div className="card">
              <Loading label={mode === 'url' ? 'Fetching the link and scanning' : 'Running the classifier'} />
            </div>
          )}

          {result && (
            <>
              <FetchedFromNote evidence={result.evidence} app={result.app} />
              <VerdictPanel result={result} />
              {result.evidence?.static_analysis &&
                <StaticAnalysis data={result.evidence.static_analysis} />}
              <div className="card">
                <div className="card-head">
                  <h2>Findings</h2>
                  <span className="eyebrow">
                    {result.evidence?.risk_signal_count || 0} risk ·{' '}
                    {result.evidence?.trust_signal_count || 0} trust
                  </span>
                </div>
                <EvidenceList evidence={result.evidence} />
                {result.scan_id && (
                  <div className="row" style={{ marginTop: 15 }}>
                    <button className="btn btn-ghost btn-sm"
                            onClick={() => api.downloadReport(result.scan_id, result.app.app_name)}>
                      Download PDF report
                    </button>
                    <button className="btn btn-ghost btn-sm"
                            onClick={() => navigate(`/scans/${result.scan_id}`)}>
                      Open full record
                    </button>
                  </div>
                )}
              </div>
            </>
          )}

          {!result && !busy && !error && (
            <div className="card">
              <div className="empty">
                <h3>Nothing scanned yet</h3>
                <p className="small">
                  Upload an APK file or paste a link to see a real, evidence-based scan.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
