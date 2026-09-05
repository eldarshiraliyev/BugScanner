import { useState } from 'react'

const API = 'http://localhost:8000'

const inputStyle = {
  width: '100%',
  background: '#0f1117',
  border: '1px solid #334155',
  borderRadius: '8px',
  padding: '0.75rem 1rem',
  color: '#e2e8f0',
  fontSize: '0.95rem',
  outline: 'none',
}

const selectStyle = { ...inputStyle }

const labelStyle = {
  display: 'block',
  color: '#94a3b8',
  fontSize: '0.8rem',
  fontWeight: 600,
  marginBottom: '0.4rem',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
}

export default function Scanner({ onScanStart }) {
  const [form, setForm] = useState({
    url: '',
    mode: 'all',
    port_mode: 'common',
    skip_subdomains: false,
    rps: 10,
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const update = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const handleScan = async () => {
    if (!form.url.trim()) {
      setError('URL daxil et')
      return
    }
    setError(null)
    setLoading(true)

    try {
      const res = await fetch(`${API}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const data = await res.json()
      onScanStart(data.scan_id)
    } catch (e) {
      setError('Server ilə əlaqə qurulmadı. Backend işləyirmi?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{ maxWidth: 680, margin: '0 auto' }}>
      <div style={{
        background: '#1e293b',
        border: '1px solid #334155',
        borderRadius: '16px',
        padding: '2rem',
      }}>
        <h2 style={{ marginBottom: '1.5rem', color: '#e2e8f0' }}>
          Yeni Scan
        </h2>

        {/* URL */}
        <div style={{ marginBottom: '1.2rem' }}>
          <label style={labelStyle}>Hədəf URL</label>
          <input
            style={inputStyle}
            placeholder="https://target.com"
            value={form.url}
            onChange={e => update('url', e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
        </div>

        {/* Mode + Port */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.2rem' }}>
          <div>
            <label style={labelStyle}>Scan Modu</label>
            <select style={selectStyle} value={form.mode}
              onChange={e => update('mode', e.target.value)}>
              <option value="all">Tam (All)</option>
              <option value="recon">Yalnız Recon</option>
              <option value="vulns">Yalnız Vulns</option>
            </select>
          </div>
          <div>
            <label style={labelStyle}>Port Scan</label>
            <select style={selectStyle} value={form.port_mode}
              onChange={e => update('port_mode', e.target.value)}>
              <option value="common">Common (19 port)</option>
              <option value="extended">Extended (25+ port)</option>
              <option value="full">Full (1-65535)</option>
            </select>
          </div>
        </div>

        {/* RPS */}
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={labelStyle}>
            Rate Limit — {form.rps} req/s
          </label>
          <input
            type="range" min="1" max="50" step="1"
            value={form.rps}
            onChange={e => update('rps', Number(e.target.value))}
            style={{ width: '100%', accentColor: '#38bdf8' }}
          />
          <div style={{
            display: 'flex', justifyContent: 'space-between',
            fontSize: '0.75rem', color: '#475569', marginTop: '0.3rem'
          }}>
            <span>1 (yavaş)</span>
            <span>50 (sürətli)</span>
          </div>
        </div>

        {/* Skip subdomains */}
        <div style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
          <input
            type="checkbox"
            id="skip_sub"
            checked={form.skip_subdomains}
            onChange={e => update('skip_subdomains', e.target.checked)}
            style={{ accentColor: '#38bdf8', width: 16, height: 16 }}
          />
          <label htmlFor="skip_sub" style={{ color: '#94a3b8', fontSize: '0.9rem' }}>
            Subdomain scan-ı atla
          </label>
        </div>

        {error && (
          <div style={{
            background: '#450a0a', border: '1px solid #dc2626',
            borderRadius: '8px', padding: '0.75rem 1rem',
            color: '#fca5a5', fontSize: '0.875rem', marginBottom: '1rem'
          }}>
            ⚠️ {error}
          </div>
        )}

        <button
          onClick={handleScan}
          disabled={loading}
          style={{
            width: '100%',
            padding: '0.9rem',
            borderRadius: '10px',
            border: 'none',
            cursor: loading ? 'not-allowed' : 'pointer',
            background: loading ? '#334155' : 'linear-gradient(135deg, #0ea5e9, #38bdf8)',
            color: loading ? '#64748b' : '#0f1117',
            fontWeight: 700,
            fontSize: '1rem',
            transition: 'all 0.2s',
          }}
        >
          {loading ? '⏳ Başladılır...' : '🚀 Scan Başlat'}
        </button>
      </div>
    </div>
  )
}