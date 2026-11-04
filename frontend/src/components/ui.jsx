import { BAND_VAR, pct, titleCase } from '../lib/format'

export function RiskSpine({ modelScore, ruleScore, alignment }) {
  const clamp = (n) => Math.max(0, Math.min(100, Number(n) || 0))
  const m = clamp(modelScore)
  const r = clamp(ruleScore)
  const diverged = Math.abs(m - r) > 30

  return (
    <div className="spine">
      <div className="spine-track" role="img"
           aria-label={`Model risk ${m} of 100, rule-based risk ${r} of 100`}>
        <div className="spine-tick" style={{ left: `${m}%` }} />
        <div className="spine-tick secondary" style={{ left: `${r}%` }} />
      </div>
      <div className="spine-scale eyebrow">
        <span>0 · safe</span><span>50</span><span>100 · critical</span>
      </div>
      <div className="spine-legend">
        <div><span className="legend-key" /> Model score {m.toFixed(0)}</div>
        <div><span className="legend-key secondary" /> Rule score {r.toFixed(0)}</div>
        {alignment != null && <div>Agreement {pct(alignment, 0)}</div>}
      </div>
      {diverged && (
        <div className="alert" style={{ marginTop: 11 }}>
          The classifier and the rule engine disagree by {Math.abs(m - r).toFixed(0)} points.
          Treat this verdict as provisional and check the findings yourself.
        </div>
      )}
    </div>
  )
}

export function Badge({ children, kind }) {
  return <span className={`badge badge-${kind || ''}`}>{children}</span>
}

export function Stat({ label, value, note, color }) {
  return (
    <div className="stat">
      <div className="eyebrow">{label}</div>
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      {note && <div className="stat-note">{note}</div>}
    </div>
  )
}

export function EvidenceItem({ item }) {
  return (
    <div className={`evidence sev-${item.severity} ${item.direction === 'trust' ? 'dir-trust' : ''}`}>
      <div className="evidence-bar" />
      <div>
        <div className="row" style={{ gap: 8, marginBottom: 2 }}>
          <h4>{item.signal}</h4>
          <Badge>{item.direction === 'trust' ? 'trust' : item.severity}</Badge>
        </div>
        <p>{item.detail}</p>
      </div>
    </div>
  )
}

export function EvidenceList({ evidence }) {
  const grouped = evidence?.grouped || {}
  const groups = Object.entries(grouped).filter(([, items]) => items?.length)

  if (!groups.length) {
    return (
      <div className="empty">
        <h3>No indicators triggered</h3>
        <p className="small">Nothing in this listing matched a known fraud pattern.</p>
      </div>
    )
  }
  return (
    <div>
      {groups.map(([group, items]) => (
        <div className="evidence-group" key={group}>
          <span className="eyebrow">{titleCase(group)}</span>
          {items.map((it, i) => <EvidenceItem key={`${group}-${i}`} item={it} />)}
        </div>
      ))}
    </div>
  )
}

export function VerdictPanel({ result }) {
  const band = result.risk_band
  const color = result.verdict === 'Fake' ? (BAND_VAR[band] || 'var(--critical)')
    : result.verdict === 'Unverified' ? 'var(--moderate)'
    : 'var(--minimal)'

  return (
    <div className="card">
      <div className="spread" style={{ alignItems: 'flex-start' }}>
        <div>
          <div className="eyebrow">Verdict</div>
          <div className="verdict-word" style={{ color }}>{result.verdict}</div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <Badge kind={band}>{band} risk</Badge>
          <div className="mono small muted" style={{ marginTop: 7 }}>
            {pct(result.fake_probability)} fake · {pct(result.confidence)} confidence
          </div>
          <div className="mono small muted">{titleCase(result.model_used)}</div>
        </div>
      </div>

      <RiskSpine
        modelScore={result.risk_score}
        ruleScore={result.evidence?.rule_risk_score}
        alignment={result.model_alignment}
      />

      <div className="alert" style={{ marginTop: 14 }}>
        <strong>What to do.</strong> {result.recommendation}
      </div>
    </div>
  )
}

export function StaticAnalysis({ data }) {
  if (!data) return null
  const rows = [
    ['Package', data.package_name || 'Not found'],
    ['Declared permissions', String(data.permission_count)],
    ['Uncompressed size', `${data.size_mb} MB`],
    ['Files in archive', String(data.file_count)],
    ['DEX files', String(data.dex_count)],
    ['Signed', data.is_signed ? 'Yes' : 'No — not from an official store'],
    ['Native libraries', data.native_abis?.length ? data.native_abis.join(', ') : 'None'],
  ]
  return (
    <div className="card">
      <div className="card-head"><h2>Static analysis</h2>
        <span className="eyebrow">read from the APK</span></div>
      <table>
        <tbody>
          {rows.map(([k, v]) => (
            <tr key={k}>
              <td className="muted" style={{ width: '46%' }}>{k}</td>
              <td className="mono">{v}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data.permissions?.length > 0 && (
        <>
          <div className="eyebrow" style={{ marginTop: 15, marginBottom: 7 }}>Permissions found</div>
          <div className="row" style={{ gap: 5 }}>
            {data.permissions.map((p) => <Badge key={p}>{p}</Badge>)}
          </div>
        </>
      )}
    </div>
  )
}

export function FetchedFromNote({ evidence, app }) {
  const src = evidence?.fetched_from
  if (!src) return null
  return (
    <div className="alert" style={{ marginBottom: 14 }}>
      Fetched live from {src.type === 'play_store' ? 'the Play Store' : 'the web'}: {' '}
      <a href={src.url} target="_blank" rel="noreferrer">{app?.app_name || src.url}</a>
      {src.developer && <> · Developer: {src.developer}</>}
    </div>
  )
}

export function Loading({ label = 'Loading' }) {
  return (
    <div className="row" style={{ padding: 22, color: 'var(--muted)' }}>
      <span className="spinner dark" /> <span className="small">{label}…</span>
    </div>
  )
}

export function ErrorNote({ children }) {
  return children ? <div className="alert alert-error">{children}</div> : null
}

export function Empty({ title, children }) {
  return <div className="empty"><h3>{title}</h3><p className="small">{children}</p></div>
}
