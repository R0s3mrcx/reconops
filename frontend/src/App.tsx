import { useState, useEffect, useRef, useCallback } from 'react'
import {
  Shield, ScanLine, AlertTriangle, CheckCircle2,
  Activity, Download, RefreshCw, ChevronDown,
  Server, Database, Terminal, Cpu, Globe, RotateCcw
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell,
  PieChart, Pie, ResponsiveContainer
} from 'recharts'

type ScanType = 'quick' | 'full' | 'stealth'
type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'
type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
type Category = 'standard' | 'dev_exposed' | 'db_exposed' | 'admin_panel' | 'legacy' | 'iot' | 'high_risk'

interface Finding {
  id: string
  host: string
  port: number
  protocol: string
  service: string
  product: string
  version: string
  state: string
  risk_score: number
  risk_level: RiskLevel
  category: Category
  is_shadow: boolean
  description: string
  anomaly_score: number
  discovered_at: string
}

interface Severity { critical: number; high: number; medium: number; low: number }

interface Summary {
  target: string
  total_services: number
  shadow_count: number
  avg_risk: number
  max_risk: number
  severity: Severity
  categories: Record<string, number>
  scanned_at: string
}

interface LogLine {
  id: string
  ts: string
  text: string
  level: 'info' | 'warn' | 'error' | 'success'
}


const RISK_COLOR: Record<RiskLevel, string> = {
  low:      '#48bb78',
  medium:   '#f6ad55',
  high:     '#ed8936',
  critical: '#fc8181',
}

const RISK_BG: Record<RiskLevel, string> = {
  low:      'rgba(72,187,120,.12)',
  medium:   'rgba(246,173,85,.12)',
  high:     'rgba(237,137,54,.12)',
  critical: 'rgba(252,129,129,.12)',
}

const CAT_LABEL: Record<Category, string> = {
  standard:    'Standard',
  dev_exposed: 'Dev Exposed',
  db_exposed:  'DB Exposed',
  admin_panel: 'Admin Panel',
  legacy:      'Legacy',
  iot:         'IoT',
  high_risk:   'High Risk',
}

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'
const WS  = API
	.replace('https://', 'wss://')
	.replace('http://', 'ws://')

const riskColor = (score: number) =>
  score >= 80 ? '#fc8181' : score >= 60 ? '#ed8936' : score >= 40 ? '#f6ad55' : '#48bb78'

const riskLevel = (score: number): RiskLevel =>
  score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low'

const riskLabel = (score: number) =>
  score >= 80 ? 'Critical' : score >= 60 ? 'High' : score >= 40 ? 'Medium' : 'Low'

const fmt = (d: string) =>
  new Date(d).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })


function StatTile({ label, value, sub, color }: {
  label: string; value: string | number; sub?: string; color?: string
}) {
  return (
    <div className="card card-sm flex flex-col gap-1">
      <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
        {label}
      </span>
      <span style={{ fontSize: 22, fontWeight: 700, color: color || 'var(--text)', lineHeight: 1 }}>
        {value}
      </span>
      {sub && <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>{sub}</span>}
    </div>
  )
}

function RiskBadge({ score }: { score: number }) {
  const color = riskColor(score)
  return (
    <span className="badge" style={{ background: `${color}18`, color, border: `1px solid ${color}33` }}>
      {riskLabel(score)}
    </span>
  )
}

function CategoryBadge({ cat }: { cat: Category }) {
  const colors: Record<Category, string> = {
    high_risk:   '#fc8181',
    db_exposed:  '#9f7aea',
    admin_panel: '#ed8936',
    legacy:      '#718096',
    dev_exposed: '#4299e1',
    iot:         '#38b2ac',
    standard:    '#48bb78',
  }
  const c = colors[cat]
  return (
    <span className="badge" style={{ background: `${c}15`, color: c, border: `1px solid ${c}28` }}>
      {CAT_LABEL[cat]}
    </span>
  )
}

function FindingRow({ f, delay }: { f: Finding; delay: number }) {
  const [open, setOpen] = useState(false)
  const color = riskColor(f.risk_score)

  return (
    <div
      className="finding-row"
      style={{
        animationDelay: `${delay}ms`,
        background: open ? 'var(--surface-2)' : 'var(--surface)',
        border: `1px solid var(--border)`,
        borderLeft: `3px solid ${f.is_shadow ? color : 'var(--border)'}`,
        borderRadius: 6,
        padding: '10px 14px',
        cursor: 'pointer',
        transition: 'background .12s',
      }}
      onClick={() => setOpen(o => !o)}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span className="mono" style={{ color, fontWeight: 600, minWidth: 60, fontSize: 13 }}>
          :{f.port}
        </span>
        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 11, minWidth: 36 }}>
          {f.protocol.toUpperCase()}
        </span>
        <span style={{ fontSize: 12, color: 'var(--text)', flexShrink: 0 }}>{f.service}</span>
        {f.product && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>{f.product}</span>
        )}
        <div style={{ flex: 1 }} />
        {f.is_shadow && <CategoryBadge cat={f.category} />}
        <RiskBadge score={f.risk_score} />
        <ChevronDown
          size={14}
          style={{ color: 'var(--text-dim)', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .15s' }}
        />
      </div>

      {open && (
        <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Description</p>
            <p style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.5 }}>{f.description}</p>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <Row label="Host" value={f.host} />
            <Row label="Version" value={f.version || '—'} />
            <Row label="Anomaly Score" value={`${(f.anomaly_score * 100).toFixed(0)}%`} />
            <Row label="Detected" value={fmt(f.discovered_at)} />
          </div>
          <div style={{ gridColumn: '1/-1' }}>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Risk Score</p>
            <div style={{ height: 4, background: 'var(--surface-3)', borderRadius: 2, overflow: 'hidden' }}>
              <div
                className="risk-bar-fill"
                style={{ height: '100%', width: `${f.risk_score}%`, background: color, borderRadius: 2 }}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</span>
      <span className="mono" style={{ fontSize: 11, color: 'var(--text)' }}>{value}</span>
    </div>
  )
}

function LogTerminal({ logs }: { logs: LogLine[] }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => { ref.current?.scrollTo(0, ref.current.scrollHeight) }, [logs])

  const col: Record<string, string> = {
    info: 'var(--text-muted)', warn: '#f6ad55', error: '#fc8181', success: '#48bb78'
  }

  return (
    <div className="terminal" style={{ height: 240 }} ref={ref}>
      {logs.length === 0 && (
        <span style={{ color: 'var(--text-dim)' }}>Waiting for scan to start...</span>
      )}
      {logs.map(l => (
        <div key={l.id} style={{ display: 'flex', gap: 10 }}>
          <span style={{ color: 'var(--text-dim)', flexShrink: 0 }}>{l.ts}</span>
          <span style={{ color: col[l.level] }}>{l.text}</span>
        </div>
      ))}
    </div>
  )
}

export default function App() {
  const [target, setTarget]       = useState('127.0.0.1')
  const [scanType, setScanType]   = useState<ScanType>('quick')
  const [runAmass, setRunAmass]   = useState(false)
  const [status, setStatus]       = useState<ScanStatus | 'idle'>('idle')
  const [scanId, setScanId]       = useState<string | null>(null)
  const [findings, setFindings]   = useState<Finding[]>([])
  const [summary, setSummary]     = useState<Summary | null>(null)
  const [logs, setLogs]           = useState<LogLine[]>([])
  const [tab, setTab]             = useState<'log' | 'findings' | 'analytics'>('log')
  const [catFilter, setCatFilter] = useState<Category | 'all'>('all')
  const wsRef = useRef<WebSocket | null>(null)

  const addLog = useCallback((text: string, level: LogLine['level'] = 'info') => {
    setLogs(p => [...p.slice(-300), {
      id: Math.random().toString(36).slice(2),
      ts: new Date().toLocaleTimeString('en-GB', { hour12: false }),
      text, level,
    }])
  }, [])

  const reset = () => {
    wsRef.current?.close()
    setStatus('idle'); setScanId(null)
    setFindings([]); setSummary(null); setLogs([])
    setTab('log')
  }

  const launch = async () => {
    reset()
    setStatus('pending')

    try {
      const res = await fetch(`${API}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, scan_type: scanType, run_amass: runAmass }),
      })
      if (!res.ok) throw new Error(`API error ${res.status}`)
      const data = await res.json()
      const id: string = data.scan_id
      setScanId(id)
      setStatus('running')
      addLog(`Scan initiated — ID: ${id}`)
      addLog(`Target: ${target} | Mode: ${scanType}`)

      const ws = new WebSocket(`${WS}/api/scans/${id}/ws`)
      wsRef.current = ws

      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data)

        if (msg.type === 'log') {
          addLog(msg.data, 'info')
        } else if (msg.type === 'finding') {
          const f: Finding = msg.data
          setFindings(p => {
            if (p.find(x => x.id === f.id)) return p
            return [...p, f].sort((a, b) => b.risk_score - a.risk_score)
          })
          if (f.is_shadow) addLog(`Shadow service detected — :${f.port} ${f.service} (risk ${f.risk_score})`, 'warn')
        } else if (msg.type === 'asset') {
          addLog(`Asset: ${msg.data.name}`, 'info')
        } else if (msg.type === 'complete') {
          setSummary(msg.data.summary)
          setStatus('completed')
          addLog(msg.data.message, 'success')
          setTab('findings')
        } else if (msg.type === 'error') {
          addLog(msg.data, 'error')
          setStatus('failed')
        }
      }

      ws.onerror = () => { addLog('WebSocket error', 'error'); setStatus('failed') }
    } catch (err: any) {
      addLog(`Failed to start scan: ${err.message}`, 'error')
      setStatus('failed')
    }
  }

  const downloadReport = () => {
    if (scanId) window.open(`${API}/api/scans/${scanId}/report`, '_blank')
  }

  const visibleFindings = catFilter === 'all'
    ? findings
    : findings.filter(f => f.category === catFilter)

  const shadowFindings = findings.filter(f => f.is_shadow)

  const severityData = summary ? [
    { name: 'Critical', v: summary.severity.critical, fill: '#fc8181' },
    { name: 'High',     v: summary.severity.high,     fill: '#ed8936' },
    { name: 'Medium',   v: summary.severity.medium,   fill: '#f6ad55' },
    { name: 'Low',      v: summary.severity.low,       fill: '#48bb78' },
  ].filter(d => d.v > 0) : []

  const catData = summary
    ? Object.entries(summary.categories).map(([name, v]) => ({ name: CAT_LABEL[name as Category] || name, v }))
    : []

  const isActive = status === 'running' || status === 'pending'
  const isDone   = status === 'completed'
  const hasScan  = status !== 'idle'

  const categories = [...new Set(findings.map(f => f.category))]

  return (
    <div style={{ minHeight: '100vh', background: '#0f1117', display: 'flex', flexDirection: 'column' }}>

      <header className="header-accent" style={{
        background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        position: 'sticky', top: 0, zIndex: 50,
      }}>
        <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', height: 52, display: 'flex', alignItems: 'center', gap: 14 }}>
          <Shield size={18} style={{ color: 'var(--blue)' }} />
          <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '-.01em' }}>ReconOps</span>
          <span style={{ color: 'var(--text-dim)', fontSize: 12 }}>Attack Surface Intelligence</span>

          <div style={{ flex: 1 }} />

          {isActive && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span className="pulsing" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--blue)', display: 'inline-block' }} />
              <span style={{ fontSize: 12, color: 'var(--blue)', fontFamily: 'JetBrains Mono' }}>SCANNING</span>
            </div>
          )}
          {isDone && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle2 size={14} style={{ color: 'var(--green)' }} />
              <span style={{ fontSize: 12, color: 'var(--green)', fontFamily: 'JetBrains Mono' }}>COMPLETE</span>
            </div>
          )}

          {isDone && (
            <button className="btn btn-ghost" onClick={downloadReport} style={{ fontSize: 12 }}>
              <Download size={13} /> Report
            </button>
          )}
          {hasScan && (
            <button className="btn btn-ghost" onClick={reset} style={{ fontSize: 12 }}>
              <RotateCcw size={13} /> New Scan
            </button>
          )}
        </div>
      </header>

      <main style={{ flex: 1, maxWidth: 1280, margin: '0 auto', padding: '24px', width: '100%' }}>

        {!hasScan && (
          <div style={{ maxWidth: 640, margin: '48px auto' }}>
            <div style={{ marginBottom: 32 }}>
              <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 6 }}>
                Attack Surface Scanner
              </h1>
              <p style={{ color: 'var(--text-muted)', fontSize: 14, lineHeight: 1.6 }}>
                Discover and classify exposed services using Nmap, OWASP Amass, and ML-based anomaly detection.
              </p>
            </div>

            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                  TARGET
                </label>
                <input
                  className="input"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  placeholder="127.0.0.1 · 192.168.1.0/24 · hostname"
                />
              </div>

              <div>
                <label style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)', display: 'block', marginBottom: 6 }}>
                  SCAN MODE
                </label>
                <div style={{ display: 'flex', gap: 4, background: 'var(--surface-3)', padding: 4, borderRadius: 7, border: '1px solid var(--border)' }}>
                  {(['quick', 'stealth', 'full'] as ScanType[]).map(t => (
                    <button key={t} className={`seg-btn ${scanType === t ? 'active' : ''}`} onClick={() => setScanType(t)}>
                      {t.charAt(0).toUpperCase() + t.slice(1)}
                    </button>
                  ))}
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 6 }}>
                  {scanType === 'quick'   && 'Top 100 ports · Service detection · ~30s'}
                  {scanType === 'stealth' && 'Top 200 ports · SYN scan · Low network noise · ~60s'}
                  {scanType === 'full'    && 'All 65535 ports · Comprehensive · ~5–10min'}
                </p>
              </div>

              <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
                <div
                  onClick={() => setRunAmass(v => !v)}
                  style={{
                    width: 36, height: 20, borderRadius: 10,
                    background: runAmass ? 'var(--blue)' : 'var(--surface-3)',
                    border: '1px solid var(--border)',
                    position: 'relative', cursor: 'pointer', transition: 'background .15s',
                  }}
                >
                  <div style={{
                    position: 'absolute', top: 2, left: runAmass ? 16 : 2,
                    width: 14, height: 14, borderRadius: '50%',
                    background: '#fff', transition: 'left .15s',
                  }} />
                </div>
                <div>
                  <span style={{ fontSize: 13, fontWeight: 500 }}>OWASP Amass</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 6 }}>passive asset enumeration (domain targets)</span>
                </div>
              </label>

              <button className="btn btn-primary" onClick={launch} style={{ marginTop: 4, justifyContent: 'center', padding: '10px' }}>
                <Activity size={15} /> Start Scan
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 12, marginTop: 20 }}>
              {[
                { icon: Server,   title: 'Nmap',         desc: 'Active port scanning with service detection' },
                { icon: Globe,    title: 'OWASP Amass',  desc: 'Passive DNS-based asset enumeration' },
                { icon: Cpu,      title: 'Isolation Forest', desc: 'Unsupervised ML anomaly detection' },
              ].map(({ icon: Icon, title, desc }) => (
                <div key={title} className="card card-sm" style={{ textAlign: 'center' }}>
                  <Icon size={18} style={{ color: 'var(--blue)', margin: '0 auto 8px' }} />
                  <p style={{ fontWeight: 600, fontSize: 12, marginBottom: 4 }}>{title}</p>
                  <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>{desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {hasScan && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 320px', gap: 20 }}>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
                <StatTile label="Services" value={findings.length} />
                <StatTile
                  label="Shadow"
                  value={shadowFindings.length}
                  color={shadowFindings.length > 0 ? '#fc8181' : 'var(--green)'}
                />
                <StatTile
                  label="Avg Risk"
                  value={findings.length
                    ? Math.round(findings.reduce((a, f) => a + f.risk_score, 0) / findings.length)
                    : '—'}
                  sub="out of 100"
                  color={findings.length
                    ? riskColor(Math.round(findings.reduce((a, f) => a + f.risk_score, 0) / findings.length))
                    : undefined}
                />
                <StatTile
                  label="Max Risk"
                  value={findings.length ? Math.max(...findings.map(f => f.risk_score)) : '—'}
                  sub="out of 100"
                  color={findings.length ? riskColor(Math.max(...findings.map(f => f.risk_score))) : undefined}
                />
              </div>

              <div style={{ display: 'flex', gap: 4, padding: '4px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 7, width: 'fit-content' }}>
                <button className={`tab-btn ${tab === 'log' ? 'active' : ''}`} onClick={() => setTab('log')}>
                  <Terminal size={12} style={{ display: 'inline', marginRight: 4 }} />Log
                </button>
                <button className={`tab-btn ${tab === 'findings' ? 'active' : ''}`} onClick={() => setTab('findings')}>
                  Findings ({findings.length})
                </button>
                <button className={`tab-btn ${tab === 'analytics' ? 'active' : ''}`} onClick={() => setTab('analytics')} disabled={!summary}>
                  Analytics
                </button>
              </div>

              {tab === 'log' && <LogTerminal logs={logs} />}

              {tab === 'findings' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {categories.length > 0 && (
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        className="badge"
                        style={{
                          background: catFilter === 'all' ? 'var(--blue)' : 'var(--surface-3)',
                          color: catFilter === 'all' ? '#fff' : 'var(--text-muted)',
                          border: '1px solid var(--border)', cursor: 'pointer', padding: '4px 10px',
                        }}
                        onClick={() => setCatFilter('all')}
                      >
                        All
                      </button>
                      {categories.map(cat => (
                        <button
                          key={cat}
                          className="badge"
                          style={{
                            background: catFilter === cat ? 'var(--blue)' : 'var(--surface-3)',
                            color: catFilter === cat ? '#fff' : 'var(--text-muted)',
                            border: '1px solid var(--border)', cursor: 'pointer', padding: '4px 10px',
                          }}
                          onClick={() => setCatFilter(cat)}
                        >
                          {CAT_LABEL[cat]}
                        </button>
                      ))}
                    </div>
                  )}

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: '60vh', overflowY: 'auto' }}>
                    {visibleFindings.length === 0 ? (
                      <div className="card" style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)' }}>
                        No findings yet
                      </div>
                    ) : (
                      visibleFindings.map((f, i) => <FindingRow key={f.id} f={f} delay={i * 30} />)
                    )}
                  </div>
                </div>
              )}

              {tab === 'analytics' && summary && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                  <div className="card">
                    <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                      Severity Distribution
                    </p>
                    <ResponsiveContainer width="100%" height={180}>
                      <PieChart>
                        <Pie data={severityData} dataKey="v" cx="50%" cy="50%" outerRadius={65} label={({ name, v }) => `${name} (${v})`} labelLine={false}>
                          {severityData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="card">
                    <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                      Service Categories
                    </p>
                    <ResponsiveContainer width="100%" height={180}>
                      <BarChart data={catData} margin={{ left: -20 }}>
                        <XAxis dataKey="name" tick={{ fill: '#4a5568', fontSize: 9 }} />
                        <YAxis tick={{ fill: '#4a5568', fontSize: 9 }} />
                        <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                        <Bar dataKey="v" radius={[3, 3, 0, 0]}>
                          {catData.map((_, i) => <Cell key={i} fill={`hsl(${210 + i * 35}, 60%, 55%)`} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>

                  <div className="card" style={{ gridColumn: '1/-1' }}>
                    <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                      Risk Score by Port (top 20)
                    </p>
                    <ResponsiveContainer width="100%" height={140}>
                      <BarChart data={findings.slice(0, 20).map(f => ({ name: `:${f.port}`, v: f.risk_score, rl: f.risk_level }))} margin={{ left: -20 }}>
                        <XAxis dataKey="name" tick={{ fill: '#4a5568', fontSize: 9, fontFamily: 'JetBrains Mono' }} />
                        <YAxis domain={[0, 100]} tick={{ fill: '#4a5568', fontSize: 9 }} />
                        <Tooltip contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 12 }} />
                        <Bar dataKey="v" radius={[3, 3, 0, 0]}>
                          {findings.slice(0, 20).map((f, i) => <Cell key={i} fill={riskColor(f.risk_score)} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

              <div className="card card-sm">
                <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  Scan Info
                </p>
                {[
                  { label: 'Target',  value: target },
                  { label: 'Mode',    value: scanType },
                  { label: 'Amass',   value: runAmass ? 'Enabled' : 'Disabled' },
                  { label: 'Status',  value: status },
                  { label: 'ID',      value: scanId?.slice(0, 8) + '...' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{label}</span>
                    <span className="mono" style={{ fontSize: 12, color: 'var(--text)' }}>{value}</span>
                  </div>
                ))}
              </div>

              <div className="card card-sm">
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                  <AlertTriangle size={13} style={{ color: shadowFindings.length > 0 ? '#fc8181' : 'var(--green)' }} />
                  <p style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.06em' }}>
                    Shadow Services
                  </p>
                </div>
                {shadowFindings.length === 0 ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--green)', fontSize: 12 }}>
                    <CheckCircle2 size={13} /> None detected
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {shadowFindings.slice(0, 10).map(f => (
                      <div key={f.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="mono" style={{ fontSize: 12, color: riskColor(f.risk_score) }}>:{f.port}</span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.service}</span>
                        </div>
                        <span className="mono" style={{ fontSize: 11, color: riskColor(f.risk_score) }}>{f.risk_score}</span>
                      </div>
                    ))}
                    {shadowFindings.length > 10 && (
                      <button className="btn-ghost" style={{ fontSize: 11, cursor: 'pointer', padding: '2px 0', background: 'none', border: 'none', color: 'var(--blue)', textAlign: 'left' }}
                        onClick={() => { setTab('findings'); setCatFilter('all') }}>
                        +{shadowFindings.length - 10} more →
                      </button>
                    )}
                  </div>
                )}
              </div>

              <div className="card card-sm">
                <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  ML Classifier
                </p>
                {[
                  { label: 'Algorithm',    value: 'Isolation Forest' },
                  { label: 'Library',      value: 'Scikit-learn' },
                  { label: 'Contamination', value: '15%' },
                  { label: 'Features',     value: '8-dim vector' },
                  { label: 'Scoring',      value: '60% rule + 40% ML' },
                ].map(({ label, value }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text)' }}>{value}</span>
                  </div>
                ))}
              </div>

              {summary && (
                <div className="card card-sm">
                  <p style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                    Severity
                  </p>
                  {[
                    { label: 'Critical', value: summary.severity.critical, color: '#fc8181' },
                    { label: 'High',     value: summary.severity.high,     color: '#ed8936' },
                    { label: 'Medium',   value: summary.severity.medium,   color: '#f6ad55' },
                    { label: 'Low',      value: summary.severity.low,       color: '#48bb78' },
                  ].map(({ label, value, color }) => (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 7 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{ width: 8, height: 8, borderRadius: '50%', background: color, flexShrink: 0 }} />
                        <span style={{ fontSize: 12 }}>{label}</span>
                      </div>
                      <span className="mono" style={{ fontSize: 12, color }}>{value}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      <footer style={{ borderTop: '1px solid var(--border)', padding: '12px 24px', textAlign: 'center' }}>
        <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
          ReconOps v1.0 · Nmap · OWASP Amass · Scikit-learn · DevSecOps Lab Project
        </span>
      </footer>
    </div>
  )
}
