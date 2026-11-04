import { useEffect, useState } from 'react'
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../lib/api'
import { BAND_VAR, dateOnly, dateTime, pct } from '../lib/format'
import { Badge, Empty, ErrorNote, Loading, Stat } from '../components/ui'

const BANDS = ['Minimal', 'Low', 'Moderate', 'High', 'Critical']
const axis = { fontSize: 11, fill: '#6B7C93', fontFamily: 'JetBrains Mono, monospace' }
const tooltipStyle = {
  border: '1px solid #D5DBE5', borderRadius: 6, fontSize: 12,
  fontFamily: 'Inter, sans-serif', boxShadow: '0 4px 16px rgba(11,21,36,.08)',
}

export default function Analytics() {
  const [data, setData] = useState(null)
  const [days, setDays] = useState(30)
  const [error, setError] = useState('')

  useEffect(() => {
    setData(null)
    api.analytics(days).then(setData).catch((e) => setError(e.message))
  }, [days])

  if (error) return <ErrorNote>{error}</ErrorNote>
  if (!data) return <Loading label="Building analytics" />

  const bandData = BANDS.map((b) => ({ band: b, count: data.by_band[b] || 0 }))

  return (
    <>
      <div className="page-head">
        <div className="spread">
          <div>
            <h1>Analytics</h1>
            <p>Detection activity across your scans.</p>
          </div>
          <select value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ maxWidth: 150 }}>
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
            <option value={365}>Last year</option>
          </select>
        </div>
      </div>

      {data.total_scans === 0 ? (
        <div className="card">
          <Empty title="No data for this period">Run a few scans and the charts will fill in.</Empty>
        </div>
      ) : (
        <>
          <div className="grid grid-4" style={{ marginBottom: 16 }}>
            <Stat label="Total scans" value={data.total_scans} />
            <Stat label="Flagged fake" value={data.fake_count} color="var(--critical)"
                  note={`${pct(data.fake_rate, 0)} of all scans`} />
            <Stat label="Average risk" value={data.avg_risk_score} note="out of 100" />
            <Stat label="Needs review" value={data.low_alignment_count}
                  color={data.low_alignment_count ? 'var(--moderate)' : undefined}
                  note="model and rules disagreed" />
          </div>

          <div className="grid grid-2">
            <div className="card">
              <div className="card-head"><h2>Scans over time</h2></div>
              <ResponsiveContainer width="100%" height={230}>
                <LineChart data={data.daily}>
                  <CartesianGrid stroke="#E4E9F0" vertical={false} />
                  <XAxis dataKey="date" tick={axis} tickFormatter={dateOnly} tickLine={false} axisLine={false} />
                  <YAxis tick={axis} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={tooltipStyle} labelFormatter={dateOnly} />
                  <Legend wrapperStyle={{ fontSize: 12 }} />
                  <Line type="monotone" dataKey="total" name="All scans" stroke="#4E3FD9" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="fake" name="Flagged fake" stroke="#B3243C" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <div className="card-head"><h2>Risk distribution</h2></div>
              <ResponsiveContainer width="100%" height={230}>
                <BarChart data={bandData}>
                  <CartesianGrid stroke="#E4E9F0" vertical={false} />
                  <XAxis dataKey="band" tick={axis} tickLine={false} axisLine={false} />
                  <YAxis tick={axis} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#F5F7FA' }} />
                  <Bar dataKey="count" name="Scans" radius={[3, 3, 0, 0]}>
                    {bandData.map((d) => <Cell key={d.band} fill={BAND_VAR[d.band]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <div className="card-head"><h2>Most frequent signals</h2></div>
              {data.top_signals.length ? (
                <table>
                  <thead><tr><th>Signal</th><th style={{ textAlign: 'right' }}>Count</th></tr></thead>
                  <tbody>
                    {data.top_signals.map((s) => (
                      <tr key={s.signal}>
                        <td>{s.signal}</td>
                        <td className="mono" style={{ textAlign: 'right' }}>{s.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : <Empty title="No signals recorded">Nothing has triggered a risk rule yet.</Empty>}
            </div>

            <div className="card">
              <div className="card-head"><h2>By category</h2></div>
              <table>
                <thead><tr><th>Category</th><th>Scanned</th><th>Fake</th></tr></thead>
                <tbody>
                  {data.by_category.map((c) => (
                    <tr key={c.category}>
                      <td>{c.category}</td>
                      <td className="mono">{c.total}</td>
                      <td className="mono" style={{ color: c.fake ? 'var(--critical)' : 'var(--muted)' }}>
                        {c.fake}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card">
            <div className="card-head"><h2>Recent scans</h2></div>
            <table>
              <thead><tr><th>Application</th><th>Verdict</th><th>Risk</th><th>Scanned</th></tr></thead>
              <tbody>
                {data.recent.map((s) => (
                  <tr key={s.id}>
                    <td>{s.app_name}</td>
                    <td><Badge kind={s.verdict}>{s.verdict}</Badge></td>
                    <td><Badge kind={s.risk_band}>{s.risk_score}</Badge></td>
                    <td className="small muted">{dateTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  )
}
