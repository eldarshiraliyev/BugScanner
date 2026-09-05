import { useEffect, useState, useRef } from 'react'

const API = 'http://localhost:8000'

const SEV_COLORS = {
  critical: { bg: '#450a0a', border: '#dc2626', text: '#fca5a5' },
  high:     { bg: '#431407', border: '#ea580c', text: '#fdba74' },
  medium:   { bg: '#422006', border: '#ca8a04', text: '#fde047' },
  low:      { bg: '#1e3a5f', border: '#3b82f6', text: '#93c5fd' },
  info:     { bg: '#1e293b', border: '#475569', text: '#94a3b8' },
}

const SEV_EMOJI = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪'
}

function Badge({ sev }) {
  const c = SEV_COLORS[sev] || SEV_COLORS.info
  return (
    <span style={{
      background: c.bg, border: `1px solid ${c.border}`,
      color: c.text, padding: '0.15rem 0.6rem',
      borderRadius: '6px', fontSize: '0.72rem', fontWeight: 700,
    }}>
      {SEV_EMOJI[sev]} {sev?.toUpperCase()}
    </span>
  )
}

function VulnCard({ vuln }) {
  const [open, setOpen] = useState(false)
  const c = SEV_COLORS[vuln.severity] || SEV_COLORS.info

  return (
    <div style={{
      background: '#1e293b',
      border: `1px solid ${open ? c.border : '#334155'}`,
      borderRadius: '10px', marginBottom: '0.7rem',
      overflow: 'hidden', transition: 'border-color 0.2s',
    }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.9rem 1.2rem', cursor: 'pointer',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.2rem' }}>
            <Badge sev={vuln.severity} />
            <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{vuln.title}</span>
          </div>
          <div style={{ color: '#64748b', fontSize: '0.78rem' }}>
            {vuln.vuln_type} · CVSS {vuln.cvss_score} · {vuln.url?.slice(0, 55)}
          </div>
        </div>
        <span style={{ color: '#475569', fontSize: '1rem' }}>{open ? '▲' : '▼'}</span>
      </div>

      {open && (
        <div style={{ padding: '1.2rem', borderTop: '1px solid #334155' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '1rem'
          }}>
            {[
              ['📋 Təsvir', vuln.description],
              ['🔍 Evidence', vuln.evidence],
              ['💥 Exploitation', vuln.exploitation],
              ['🛡️ Remediation', vuln.remediation],
            ].map(([title, content]) => (
              <div key={title} style={{
                background: '#0f1117',
                border: '1px solid #1e293b',
                borderRadius: '8px', padding: '1rem',
              }}>
                <div style={{
                  fontSize: '0.72rem', color: '#64748b',
                  textTransform: 'uppercase', letterSpacing: '0.05em',
                  marginBottom: '0.5rem', fontWeight: 600,
                }}>
                  {title}
                </div>
                <pre style={{
                  whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                  fontSize: '0.82rem', color: '#cbd5e1', fontFamily: 'inherit',
                }}>
                  {content}
                </pre>
              </div>
            ))}
          </div>

          {vuln.curl_poc && (
            <div style={{
              marginTop: '1rem', background: '#0a0f1a',
              border: '1px solid #1e293b', borderRadius: '8px',
              padding: '0.8rem 1rem',
            }}>
              <div style={{ fontSize: '0.72rem', color: '#64748b', marginBottom: '0.4rem' }}>
                ⚡ PoC
              </div>
              <code style={{ color: '#a5f3fc', fontSize: '0.82rem' }}>
                {vuln.curl_poc}
              </code>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, color }) {
  return (
    <div style={{
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: '10px', padding: '1.2rem', textAlign: 'center',
    }}>
      <div style={{ fontSize: '1.8rem', fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.2rem' }}>{label}</div>
    </div>
  )
}

export default function Results({ scanId, onResult }) {
  const [logs, setLogs] = useState([])
  const [result, setResult] = useState(null)
  const [status, setStatus] = useState('connecting')
  const [activeTab, setActiveTab] = useState('vulns')
  const [sevFilter, setSevFilter] = useState('all')
  const logsRef = useRef(null)
  const wsRef = useRef(null)

  useEffect(() => {
    if (!scanId) return

    const ws = new WebSocket(`ws://localhost:8000/ws/${scanId}`)
    wsRef.current = ws

    ws.onopen = () => setStatus('running')

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data)

      if (msg.type === 'log') {
        setLogs(l => [...l, { text: msg.message, time: msg.timestamp }])
        setTimeout(() => {
          logsRef.current?.scrollTo(0, logsRef.current.scrollHeight)
        }, 50)
      }

      if (msg.type === 'completed') {
        setResult(msg.result)
        setStatus('completed')
        onResult?.(msg.result)
      }

      if (msg.type === 'error') {
        setStatus('error')
        setLogs(l => [...l, { text: `❌ Xəta: ${msg.message}`, time: new Date().toISOString() }])
      }
    }

    ws.onerror = () => setStatus('error')
    ws.onclose = () => {
      if (status !== 'completed') setStatus('disconnected')
    }

    return () => ws.close()
  }, [scanId])

  const filteredVulns = result?.vulnerabilities?.filter(v =>
    sevFilter === 'all' || v.severity === sevFilter
  ) || []

  const summary = result?.summary || {}
  const bySev = summary.by_severity || {}

  if (!scanId) {
    return (
      <div style={{ textAlign: 'center', color: '#475569', marginTop: '5rem' }}>
        <div style={{ fontSize: '3rem' }}>🎯</div>
        <p style={{ marginTop: '1rem' }}>Scan başlatmaq üçün Scanner-ə keç</p>
      </div>
    )
  }

  return (
    <div>
      {/* Status bar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: '1rem',
        marginBottom: '1.5rem', padding: '1rem 1.2rem',
        background: '#1e293b', border: '1px solid #334155',
        borderRadius: '10px',
      }}>
        <div style={{
          width: 10, height: 10, borderRadius: '50%',
          background: status === 'completed' ? '#22c55e'
            : status === 'error' ? '#ef4444' : '#38bdf8',
          boxShadow: status === 'running' ? '0 0 8px #38bdf8' : 'none',
          animation: status === 'running' ? 'pulse 1.5s infinite' : 'none',
        }} />
        <span style={{ fontWeight: 600 }}>
          {status === 'running' ? 'Skan davam edir...'
            : status === 'completed' ? '✅ Tamamlandı'
            : status === 'error' ? '❌ Xəta baş verdi'
            : 'Qoşulur...'}
        </span>
        {result && (
          <span style={{ marginLeft: 'auto', color: '#64748b', fontSize: '0.85rem' }}>
            Risk skoru:&nbsp;
            <strong style={{ color: '#f59e0b' }}>{result.summary?.risk_score}/10</strong>
          </span>
        )}
      </div>

      {/* Summary cards */}
      {result && (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
          gap: '0.8rem', marginBottom: '1.5rem',
        }}>
          <StatCard label="Subdomains"     value={summary.subdomains_found || 0} color="#38bdf8" />
          <StatCard label="Açıq Portlar"   value={summary.open_ports || 0}       color="#38bdf8" />
          <StatCard label="Endpoints"      value={summary.endpoints_found || 0}  color="#38bdf8" />
          <StatCard label="Critical"       value={bySev.critical || 0}           color="#f87171" />
          <StatCard label="High"           value={bySev.high || 0}               color="#fb923c" />
          <StatCard label="Medium"         value={bySev.medium || 0}             color="#fbbf24" />
          <StatCard label="Low"            value={bySev.low || 0}                color="#60a5fa" />
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '1rem' }}>
        {['vulns', 'logs', 'ports', 'subdomains'].map(tab => (
          <button key={tab} onClick={() => setActiveTab(tab)} style={{
            padding: '0.5rem 1rem', borderRadius: '8px',
            border: 'none', cursor: 'pointer',
            background: activeTab === tab ? '#38bdf8' : '#1e293b',
            color: activeTab === tab ? '#0f1117' : '#94a3b8',
            fontWeight: 600, fontSize: '0.82rem',
          }}>
            {tab === 'vulns' ? `Vulnerabilities (${result?.vulnerabilities?.length || 0})`
              : tab === 'logs' ? `Logs (${logs.length})`
              : tab === 'ports' ? `Portlar (${result?.open_ports?.length || 0})`
              : `Subdomains (${result?.subdomains?.length || 0})`}
          </button>
        ))}
      </div>

      {/* Vulns tab */}
      {activeTab === 'vulns' && (
        <div>
          {/* Severity filter */}
          <div style={{ display: 'flex', gap: '0.4rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
            {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding: '0.3rem 0.8rem', borderRadius: '6px',
                border: `1px solid ${sevFilter === s ? '#38bdf8' : '#334155'}`,
                background: sevFilter === s ? '#0c4a6e' : 'transparent',
                color: sevFilter === s ? '#38bdf8' : '#64748b',
                cursor: 'pointer', fontSize: '0.8rem',
              }}>
                {s === 'all' ? 'Hamısı' : s}
                {s !== 'all' && bySev[s] > 0 && (
                  <span style={{ marginLeft: 4, opacity: 0.7 }}>({bySev[s]})</span>
                )}
              </button>
            ))}
          </div>

          {filteredVulns.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#475569', padding: '3rem' }}>
              {status === 'running' ? '⏳ Scan davam edir...' : '✅ Bu kateqoriyada vulnerability tapılmadı'}
            </div>
          ) : (
            filteredVulns.map((v, i) => <VulnCard key={i} vuln={v} />)
          )}
        </div>
      )}

      {/* Logs tab */}
      {activeTab === 'logs' && (
        <div
          ref={logsRef}
          style={{
            background: '#0a0f1a', border: '1px solid #1e293b',
            borderRadius: '10px', padding: '1rem',
            height: '500px', overflowY: 'auto',
            fontFamily: 'Courier New, monospace', fontSize: '0.82rem',
          }}
        >
          {logs.map((log, i) => (
            <div key={i} style={{ marginBottom: '0.3rem', color: '#a5f3fc' }}>
              <span style={{ color: '#334155', marginRight: '0.5rem' }}>
                {new Date(log.time).toLocaleTimeString()}
              </span>
              {log.text}
            </div>
          ))}
          {status === 'running' && (
            <div style={{ color: '#38bdf8', animation: 'blink 1s infinite' }}>▌</div>
          )}
        </div>
      )}

      {/* Ports tab */}
      {activeTab === 'ports' && (
        <div style={{
          background: '#1e293b', border: '1px solid #334155',
          borderRadius: '10px', overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: '#0f1117' }}>
                {['Port', 'Protocol', 'Service', 'Version'].map(h => (
                  <th key={h} style={{
                    padding: '0.7rem 1rem', textAlign: 'left',
                    color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(result?.open_ports || []).map((p, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.7rem 1rem', color: '#38bdf8', fontWeight: 700 }}>{p.port}</td>
                  <td style={{ padding: '0.7rem 1rem' }}>{p.protocol}</td>
                  <td style={{ padding: '0.7rem 1rem', color: '#fbbf24' }}>{p.service}</td>
                  <td style={{ padding: '0.7rem 1rem', color: '#64748b', fontSize: '0.8rem' }}>
                    {p.version || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!result?.open_ports?.length && (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
              Açıq port tapılmadı
            </div>
          )}
        </div>
      )}

      {/* Subdomains tab */}
      {activeTab === 'subdomains' && (
        <div style={{
          background: '#1e293b', border: '1px solid #334155',
          borderRadius: '10px', overflow: 'hidden',
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
            <thead>
              <tr style={{ background: '#0f1117' }}>
                {['Subdomain', 'IP', 'Status', 'Texnologiyalar'].map(h => (
                  <th key={h} style={{
                    padding: '0.7rem 1rem', textAlign: 'left',
                    color: '#64748b', fontSize: '0.75rem', textTransform: 'uppercase',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(result?.subdomains || []).map((s, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '0.7rem 1rem', color: '#38bdf8' }}>{s.subdomain}</td>
                  <td style={{ padding: '0.7rem 1rem', color: '#64748b' }}>{s.ip || '—'}</td>
                  <td style={{ padding: '0.7rem 1rem' }}>
                    <span style={{
                      color: s.status < 400 ? '#22c55e' : '#f87171',
                      fontWeight: 600,
                    }}>
                      {s.status || '—'}
                    </span>
                  </td>
                  <td style={{ padding: '0.7rem 1rem', color: '#94a3b8', fontSize: '0.8rem' }}>
                    {s.technologies?.join(', ') || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!result?.subdomains?.length && (
            <div style={{ textAlign: 'center', padding: '2rem', color: '#475569' }}>
              Subdomain tapılmadı
            </div>
          )}
        </div>
      )}

      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
      `}</style>
    </div>
  )
}