import { useState } from 'react'
import Scanner from './components/Scanner'
import Results from './components/Results'
import History from './components/History'

const TABS = [
  { id: 'scan',    label: '🎯 Scanner' },
  { id: 'results', label: '📊 Results' },
  { id: 'history', label: '🕐 History' },
]

export default function App() {
  const [tab, setTab] = useState('scan')
  const [scanId, setScanId] = useState(null)
  const [historyKey, setHistoryKey] = useState(0)

  const handleScanStart = (id) => {
    setScanId(id)
    setTab('results')
    setHistoryKey(k => k + 1)
  }

  const handleSelectFromHistory = (id) => {
    setScanId(id)
    setTab('results')
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0f1117',
      color: '#e2e8f0',
      fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    }}>
      {/* ── Header ───────────────────────────────── */}
      <header style={{
        borderBottom: '1px solid #1e293b',
        padding: '1rem 2rem',
        display: 'flex',
        alignItems: 'center',
        gap: '2rem',
        position: 'sticky',
        top: 0,
        background: 'rgba(15,17,23,0.95)',
        backdropFilter: 'blur(8px)',
        zIndex: 10,
      }}>
        <div style={{
          fontSize: '1.25rem',
          fontWeight: 700,
          color: '#38bdf8',
          letterSpacing: '0.5px',
        }}>
          🐛 BugScanner
          <span style={{
            fontSize: '0.7rem',
            color: '#64748b',
            marginLeft: '0.5rem',
            fontWeight: 400,
          }}>v2.0</span>
        </div>

        <nav style={{ display: 'flex', gap: '0.4rem' }}>
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              style={{
                padding: '0.5rem 1rem',
                borderRadius: '8px',
                border: 'none',
                cursor: 'pointer',
                fontWeight: 600,
                fontSize: '0.85rem',
                background: tab === t.id ? '#38bdf8' : 'transparent',
                color: tab === t.id ? '#0f1117' : '#94a3b8',
                transition: 'all 0.15s',
              }}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <div style={{
          marginLeft: 'auto',
          fontSize: '0.75rem',
          color: '#475569',
        }}>
          Authorized use only
        </div>
      </header>

      {/* ── Main Content ─────────────────────────── */}
      <main style={{
        padding: '2rem',
        maxWidth: 1100,
        margin: '0 auto',
      }}>
        {tab === 'scan' && <Scanner onScanStart={handleScanStart} />}
        {tab === 'results' && <Results scanId={scanId} />}
        {tab === 'history' && (
          <History key={historyKey} onSelect={handleSelectFromHistory} />
        )}
      </main>

      {/* ── Footer ───────────────────────────────── */}
      <footer style={{
        textAlign: 'center',
        padding: '2rem',
        color: '#334155',
        fontSize: '0.75rem',
        borderTop: '1px solid #1e293b',
        marginTop: '3rem',
      }}>
        BugScanner v2.0 · Bug Bounty Automation Tool · For authorized testing only
      </footer>

      {/* ── Global Styles ────────────────────────── */}
      <style>{`
        * { box-sizing: border-box; }
        body { margin: 0; background: #0f1117; color: #e2e8f0; }
        button { font-family: inherit; }
        input, select { font-family: inherit; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #0f1117; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #475569; }
      `}</style>
    </div>
  )
}