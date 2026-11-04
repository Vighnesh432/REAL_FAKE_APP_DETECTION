import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import { dateTime } from '../lib/format'
import { Badge, Empty, ErrorNote, Loading } from '../components/ui'

export default function History() {
  const [data, setData] = useState(null)
  const [page, setPage] = useState(1)
  const [verdict, setVerdict] = useState('')
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: 20 }
      if (verdict) params.verdict = verdict
      if (search.trim()) params.search = search.trim()
      setData(await api.scans(params)); setError('')
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }, [page, verdict, search])

  useEffect(() => { const t = setTimeout(load, 250); return () => clearTimeout(t) }, [load])

  const remove = async (id, e) => {
    e.stopPropagation()
    if (!confirm('Delete this scan? This cannot be undone.')) return
    try { await api.deleteScan(id); load() } catch (err) { setError(err.message) }
  }

  const pages = data ? Math.max(1, Math.ceil(data.total / data.page_size)) : 1

  return (
    <>
      <div className="page-head">
        <h1>Scan history</h1>
        <p>Every scan is kept with the evidence it was based on, so a past verdict stays auditable even after the model is retrained.</p>
      </div>

      <div className="card">
        <div className="row" style={{ marginBottom: 14 }}>
          <input placeholder="Search by app or package name" value={search}
                 onChange={(e) => { setSearch(e.target.value); setPage(1) }}
                 style={{ maxWidth: 300 }} />
          <select value={verdict} onChange={(e) => { setVerdict(e.target.value); setPage(1) }}
                  style={{ maxWidth: 160 }}>
            <option value="">All verdicts</option>
            <option value="Fake">Fake only</option>
            <option value="Genuine">Genuine only</option>
          </select>
          {data && <span className="small muted" style={{ marginLeft: 'auto' }}>{data.total} scans</span>}
        </div>

        <ErrorNote>{error}</ErrorNote>
        {loading && !data ? <Loading /> : !data?.items.length ? (
          <Empty title="No scans yet">
            {search || verdict ? 'Nothing matched that filter.' : 'Run a scan and it will appear here.'}
          </Empty>
        ) : (
          <>
            <table>
              <thead>
                <tr><th>Application</th><th>Verdict</th><th>Risk</th><th>Model</th><th>Scanned</th><th /></tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => navigate(`/scans/${s.id}`)}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{s.app_name}</div>
                      <div className="mono small muted">{s.package_name || '—'}</div>
                    </td>
                    <td><Badge kind={s.verdict}>{s.verdict}</Badge></td>
                    <td><Badge kind={s.risk_band}>{s.risk_score}</Badge></td>
                    <td className="small muted">{s.model_used}</td>
                    <td className="small muted">{dateTime(s.created_at)}</td>
                    <td>
                      <button className="btn btn-ghost btn-sm" onClick={(e) => remove(s.id, e)}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {pages > 1 && (
              <div className="row" style={{ marginTop: 14, justifyContent: 'center' }}>
                <button className="btn btn-ghost btn-sm" disabled={page <= 1}
                        onClick={() => setPage((p) => p - 1)}>Previous</button>
                <span className="small muted">Page {page} of {pages}</span>
                <button className="btn btn-ghost btn-sm" disabled={page >= pages}
                        onClick={() => setPage((p) => p + 1)}>Next</button>
              </div>
            )}
          </>
        )}
      </div>
    </>
  )
}
