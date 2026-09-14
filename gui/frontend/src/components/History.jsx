import { useEffect, useState } from 'react'

const API = 'http://localhost:8000'

export default function History({ onSelect }) {
  const [scans, setScans] = useState([])

  useEffect(() => {
    fetch(`${API}/api/scans`)
      .then(r => r.json())
      .then(setScans)
      .catch(() => {})
  }, [])

  const statusColor = {
    completed: '#22c55e',
    running: '#38bdf8',
    error: '#ef4444',
    queued: '#f59e0b',
  }

  return (
    <div>
      <h2 style={{ marginBottom: '1.5rem', color: '#94a3b8' }}>Scan History</h2>
      {scans.length === 0 ? (
        <div style={{ textAlign: 'center', color: '#475569', padding: '4rem' }}>
          No scans yet
        </div>
      ) : (
        scans.map(scan => (
          <div
            key={scan.id}
            onClick={() => onSelect(scan.id)}
            style={{
              background: '#1e293b', border: '1px solid #334155',
              borderRadius: '10px', padding: '1.2rem 1.5rem',
              marginBottom: '0.8rem', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              transition: 'border-color 0.2s',
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#38bdf8'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#334155'}
          >
            <div>
              <div style={{ fontWeight: 600, marginBottom: '0.3rem' }}>
                {scan.url}
              </div>
              <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
                ID: {scan.id} · {new Date(scan.started_at).toLocaleString()}
              </div>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div style={{
                color: statusColor[scan.status] || '#94a3b8',
                fontWeight: 700, fontSize: '0.85rem',
              }}>
                {scan.status.toUpperCase()}
              </div>
              {scan.result && (
                <div style={{ fontSize: '0.78rem', color: '#64748b', marginTop: '0.2rem' }}>
                  {scan.result.summary?.total_vulnerabilities || 0} vulns ·
                  Risk: {scan.result.summary?.risk_score}/10
                </div>
              )}
            </div>
          </div>
        ))
      )}
    </div>
  )
}