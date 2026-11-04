import { useCallback, useEffect, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../lib/api'
import { dateTime, pct, titleCase } from '../lib/format'
import { Badge, Empty, ErrorNote, Loading, Stat } from '../components/ui'

const axis = { fontSize: 11, fill: '#6B7C93', fontFamily: 'JetBrains Mono, monospace' }

export default function Admin() {
  const [stats, setStats] = useState(null)
  const [feedback, setFeedback] = useState([])
  const [runs, setRuns] = useState([])
  const [users, setUsers] = useState([])
  const [error, setError] = useState('')
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    try {
      const [s, f, r, u] = await Promise.all([
        api.adminStats(), api.adminFeedback(false), api.trainingRuns(), api.adminUsers(),
      ])
      setStats(s); setFeedback(f); setRuns(r); setUsers(u); setError('')
    } catch (e) { setError(e.message) }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!runs.some((r) => r.status === 'running')) return
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [runs, load])

  const retrain = async () => {
    setBusy(true); setNote(''); setError('')
    try {
      await api.retrain({ include_feedback: true, quick: false })
      setNote('Training started. This page updates as it progresses — it usually takes a few minutes.')
      load()
    } catch (e) { setError(e.message) }
    finally { setBusy(false) }
  }

  const review = async (id, accepted) => {
    try { await api.reviewFeedback(id, accepted); load() } catch (e) { setError(e.message) }
  }

  const toggleUser = async (u) => {
    try { await api.setUserStatus(u.id, !u.is_active); load() } catch (e) { setError(e.message) }
  }

  if (!stats) return <Loading label="Loading admin data" />

  const metrics = stats.model?.all_metrics || {}
  const chartData = Object.entries(metrics).map(([name, m]) => ({
    model: titleCase(name).replace('Regression', 'Reg.'),
    f1: Number((m.f1 * 100).toFixed(2)),
    selected: name === stats.model?.model_name,
  }))

  return (
    <>
      <div className="page-head">
        <h1>Administration</h1>
        <p>Model status, user corrections, and retraining.</p>
      </div>

      <ErrorNote>{error}</ErrorNote>
      {note && <div className="alert alert-ok" style={{ marginBottom: 16 }}>{note}</div>}

      <div className="grid grid-4" style={{ marginBottom: 16 }}>
        <Stat label="Users" value={stats.users} note={`${stats.active_users} active`} />
        <Stat label="Total scans" value={stats.scans} note={`${stats.fake_scans} flagged fake`} />
        <Stat label="Pending corrections" value={stats.pending_feedback}
              color={stats.pending_feedback ? 'var(--moderate)' : undefined} />
        <Stat label="Training runs" value={stats.training_runs} />
      </div>

      <div className="split">
        <div className="stack">
          <div className="card">
            <div className="card-head">
              <h2>Model comparison</h2>
              {stats.model && <span className="eyebrow">in use · {titleCase(stats.model.model_name)}</span>}
            </div>
            {stats.model ? (
              <>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={chartData} layout="vertical" margin={{ left: 10 }}>
                    <CartesianGrid stroke="#E4E9F0" horizontal={false} />
                    <XAxis type="number" domain={[90, 100]} tick={axis} tickLine={false} axisLine={false} />
                    <YAxis type="category" dataKey="model" tick={axis} width={110} tickLine={false} axisLine={false} />
                    <Tooltip formatter={(v) => [`${v}%`, 'F1 score']}
                             contentStyle={{ border: '1px solid #D5DBE5', borderRadius: 6, fontSize: 12 }}
                             cursor={{ fill: '#F5F7FA' }} />
                    <Bar dataKey="f1" radius={[0, 3, 3, 0]}>
                      {chartData.map((d) => (
                        <Cell key={d.model} fill={d.selected ? '#4E3FD9' : '#B9C3D3'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>

                <table style={{ marginTop: 10 }}>
                  <thead>
                    <tr><th>Model</th><th>F1</th><th>ROC-AUC</th><th>Recall</th><th>False positives</th></tr>
                  </thead>
                  <tbody>
                    {Object.entries(metrics).map(([name, m]) => (
                      <tr key={name}>
                        <td>{titleCase(name)}
                          {name === stats.model.model_name &&
                            <span className="badge" style={{ marginLeft: 7 }}>in use</span>}
                        </td>
                        <td className="mono">{m.f1}</td>
                        <td className="mono">{m.roc_auc}</td>
                        <td className="mono">{m.recall}</td>
                        <td className="mono">{pct(m.false_positive_rate, 2)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <p className="small muted" style={{ marginTop: 10, marginBottom: 0 }}>
                  Selection favours the highest F1, breaking ties on the lower false-positive
                  rate — wrongly flagging a real app costs more trust than missing a fake one.
                </p>
              </>
            ) : <Empty title="No model loaded">Run training to build one.</Empty>}
          </div>

          <div className="card">
            <div className="card-head"><h2>Training runs</h2>
              <button className="btn btn-sm" onClick={retrain}
                      disabled={busy || runs.some((r) => r.status === 'running')}>
                {busy ? <><span className="spinner" /> Starting</> : 'Retrain model'}
              </button>
            </div>
            {runs.length ? (
              <table>
                <thead><tr><th>Started</th><th>By</th><th>Status</th><th>Best model</th><th>Rows</th></tr></thead>
                <tbody>
                  {runs.map((r) => (
                    <tr key={r.id}>
                      <td className="small muted">{dateTime(r.started_at)}</td>
                      <td className="small">{r.triggered_by}</td>
                      <td>
                        <Badge kind={r.status === 'success' ? 'Genuine' : r.status === 'failed' ? 'Fake' : ''}>
                          {r.status}
                        </Badge>
                        {r.error && <div className="small" style={{ color: 'var(--critical)' }}>{r.error}</div>}
                      </td>
                      <td className="small">{r.best_model || '—'}</td>
                      <td className="mono small">{r.dataset_rows || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <Empty title="No training runs recorded">Retraining will appear here.</Empty>}
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-head"><h2>Pending corrections</h2>
              <span className="eyebrow">{feedback.length} waiting</span></div>
            {feedback.length ? feedback.map((f) => (
              <div key={f.id} style={{ padding: '11px 0', borderBottom: '1px solid var(--line-soft)' }}>
                <div className="spread">
                  <div>
                    <div className="small">
                      Scan #{f.scan_id} reported as{' '}
                      <strong>{f.reported_label === 1 ? 'fake' : 'genuine'}</strong>
                    </div>
                    <div className="small muted">{dateTime(f.created_at)}</div>
                    {f.comment && <p className="small" style={{ margin: '5px 0 0' }}>{f.comment}</p>}
                  </div>
                  <div className="row">
                    <button className="btn btn-ghost btn-sm" onClick={() => review(f.id, true)}>Accept</button>
                    <button className="btn btn-ghost btn-sm" onClick={() => review(f.id, false)}>Reject</button>
                  </div>
                </div>
              </div>
            )) : (
              <Empty title="Nothing to review">
                Corrections submitted by users show up here before they can affect the model.
              </Empty>
            )}
          </div>

          <div className="card">
            <div className="card-head"><h2>Users</h2></div>
            <table>
              <thead><tr><th>Account</th><th>Role</th><th /></tr></thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>
                      <div className="small" style={{ fontWeight: 600 }}>{u.email}</div>
                      <div className="small muted">{u.full_name || '—'}</div>
                    </td>
                    <td><Badge>{u.role}</Badge></td>
                    <td>
                      <button className="btn btn-ghost btn-sm" onClick={() => toggleUser(u)}>
                        {u.is_active ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  )
}
