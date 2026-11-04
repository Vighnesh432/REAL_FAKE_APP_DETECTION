import { useState } from 'react'
import { useAuth } from '../lib/auth'
import { ErrorNote } from '../components/ui'

export default function Login() {
  const [mode, setMode] = useState('login')
  const [form, setForm] = useState({ email: '', password: '', full_name: '' })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { login, register } = useAuth()

  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      if (mode === 'login') await login(form.email, form.password)
      else await register(form)
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <div className="row" style={{ gap: 9, marginBottom: 14 }}>
          <div className="brand-mark">X</div>
          <div>
            <div className="brand-name" style={{ color: 'var(--ink)' }}>AppXray</div>
            <div className="eyebrow">Fake app detection</div>
          </div>
        </div>

        <h1>{mode === 'login' ? 'Sign in' : 'Create an account'}</h1>
        <p className="small muted" style={{ marginTop: 2 }}>
          {mode === 'login'
            ? 'Access your scan history and reports.'
            : 'Your scans are saved so you can revisit and export them.'}
        </p>

        <div className="tabs">
          <button className={mode === 'login' ? 'active' : ''}
                  onClick={() => { setMode('login'); setError('') }}>Sign in</button>
          <button className={mode === 'register' ? 'active' : ''}
                  onClick={() => { setMode('register'); setError('') }}>Register</button>
        </div>

        <form onSubmit={submit}>
          {mode === 'register' && (
            <label className="field"><span>Full name</span>
              <input value={form.full_name} onChange={set('full_name')} autoComplete="name" />
            </label>
          )}
          <label className="field"><span>Email</span>
            <input type="email" value={form.email} onChange={set('email')} required autoComplete="email" />
          </label>
          <label className="field"><span>Password</span>
            <input type="password" value={form.password} onChange={set('password')} required
                   minLength={8} autoComplete={mode === 'login' ? 'current-password' : 'new-password'} />
            {mode === 'register' && <div className="hint">At least 8 characters.</div>}
          </label>

          <div style={{ marginBottom: 12 }}><ErrorNote>{error}</ErrorNote></div>

          <button className="btn" style={{ width: '100%', justifyContent: 'center' }} disabled={busy}>
            {busy ? <span className="spinner" /> : mode === 'login' ? 'Sign in' : 'Create account'}
          </button>
        </form>

        <p className="small muted" style={{ marginTop: 16, marginBottom: 0 }}>
          Demo administrator: <code className="mono">admin@appxray.io</code> /{' '}
          <code className="mono">admin12345</code>
        </p>
      </div>
    </div>
  )
}
