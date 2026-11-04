import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { api } from '../lib/api'
import { dateTime, pct, titleCase } from '../lib/format'
import {
  Badge, ErrorNote, EvidenceList, Loading, RiskSpine, StaticAnalysis,
} from '../components/ui'

const FEATURE_GROUPS = {
  Identity: ['name_brand_similarity', 'name_has_fake_suffix', 'name_has_leetspeak', 'package_depth_anomaly'],
  Permissions: ['perm_count', 'perm_dangerous_count', 'perm_mismatch_count', 'has_sms_permission',
                'has_accessibility_permission', 'has_install_packages_permission'],
  Description: ['desc_word_count', 'desc_spam_ratio', 'desc_unique_ratio', 'desc_exclaim_density'],
  Reviews: ['review_count_sampled', 'review_avg_length', 'review_duplicate_ratio',
            'review_sentiment_mean', 'review_sentiment_std', 'review_negative_ratio'],
  Marketplace: ['rating', 'ratings_per_install', 'installs_log', 'app_age_days_log',
                'developer_app_count', 'has_privacy_policy', 'has_developer_website'],
}

export default function ScanDetail() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [error, setError] = useState('')
  const [sent, setSent] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api.scan(id).then(setScan).catch((e) => setError(e.message))
  }, [id])

  const report = async (label) => {
    try {
      await api.feedback({ scan_id: Number(id), reported_label: label, comment: '' })
      setSent(true)
    } catch (e) { setError(e.message) }
  }

  if (error) return <ErrorNote>{error}</ErrorNote>
  if (!scan) return <Loading label="Loading scan" />

  const color = scan.verdict === 'Fake' ? 'var(--critical)' : 'var(--minimal)'
  const hasFeatures = scan.features && Object.keys(scan.features).length > 0

  return (
    <>
      <div className="row" style={{ marginBottom: 14 }}>
        <button className="btn btn-ghost btn-sm" onClick={() => navigate(-1)}>← Back</button>
      </div>

      <div className="page-head">
        <div className="spread">
          <div>
            <h1>{scan.app_name}</h1>
            <p className="mono small">{scan.package_name || 'No package name recorded'} · {scan.category}</p>
          </div>
          <div className="row">
            <button className="btn btn-ghost btn-sm"
                    onClick={() => api.downloadReport(scan.id, scan.app_name)}>
              Download PDF
            </button>
          </div>
        </div>
      </div>

      <div className="split">
        <div className="stack">
          <div className="card">
            <div className="spread" style={{ alignItems: 'flex-start' }}>
              <div>
                <div className="eyebrow">Verdict</div>
                <div className="verdict-word" style={{ color }}>{scan.verdict}</div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <Badge kind={scan.risk_band}>{scan.risk_band} risk</Badge>
                <div className="mono small muted" style={{ marginTop: 7 }}>
                  {pct(scan.fake_probability)} fake · {pct(scan.confidence)} confidence
                </div>
                <div className="mono small muted">{dateTime(scan.created_at)}</div>
              </div>
            </div>
            <RiskSpine modelScore={scan.risk_score}
                       ruleScore={scan.evidence?.rule_risk_score}
                       alignment={scan.model_alignment} />
            <div className="alert" style={{ marginTop: 14 }}>
              <strong>What to do.</strong> {scan.recommendation}
            </div>
          </div>

          {scan.evidence?.static_analysis && <StaticAnalysis data={scan.evidence.static_analysis} />}

          <div className="card">
            <div className="card-head"><h2>Findings</h2>
              <span className="eyebrow">{scan.evidence?.risk_signal_count || 0} risk signals</span>
            </div>
            <EvidenceList evidence={scan.evidence} />
          </div>
        </div>

        <div className="stack">
          <div className="card">
            <div className="card-head"><h2>Is this verdict wrong?</h2></div>
            {sent ? (
              <div className="alert alert-ok">
                Thanks — an administrator will review this. Accepted corrections are folded
                into the next training run.
              </div>
            ) : (
              <>
                <p className="small muted" style={{ marginTop: 0 }}>
                  Telling us what this app really is improves the model for everyone.
                </p>
                <div className="row">
                  <button className="btn btn-ghost btn-sm" onClick={() => report(0)}>
                    It is genuine
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => report(1)}>
                    It is fake
                  </button>
                </div>
              </>
            )}
          </div>

          {hasFeatures && (
            <div className="card">
              <div className="card-head"><h2>Computed features</h2>
                <span className="eyebrow">{titleCase(scan.model_used)}</span></div>
              {Object.entries(FEATURE_GROUPS).map(([group, keys]) => (
                <div key={group} style={{ marginBottom: 14 }}>
                  <span className="eyebrow">{group}</span>
                  <table>
                    <tbody>
                      {keys.filter((k) => scan.features?.[k] !== undefined).map((k) => (
                        <tr key={k}>
                          <td className="small muted">{k.replace(/_/g, ' ')}</td>
                          <td className="mono small" style={{ textAlign: 'right' }}>
                            {Number(scan.features[k]).toFixed(3).replace(/\.?0+$/, '')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  )
}
