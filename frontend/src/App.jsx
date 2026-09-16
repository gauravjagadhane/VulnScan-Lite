import { useCallback, useEffect, useRef, useState } from 'react'

import { api } from './services/api'
import AppHeader from './components/AppHeader'
import AuthCard from './components/AuthCard'
import HistoryView from './components/HistoryView'
import Results from './components/Results'
import ScanProgress from './components/ScanProgress'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function Landing({ error, isSubmitting, onSubmit, url, setUrl }) {
  return (
    <>
      <section className="landing">
        <div className="landing-copy">
          <span className="eyebrow">Defensive web health checks</span>
          <h1>Know your web security posture in minutes.</h1>
          <p>VulnScan Lite reviews publicly observable headers, TLS configuration, certificate status, and CMS fingerprints - without exploiting anything.</p>
          <div className="trust-row"><span>Passive only</span><span>SSRF protected</span><span>PDF-ready</span></div>
        </div>
        <form className="scan-form" onSubmit={onSubmit}>
          <label htmlFor="target">Website URL</label>
          <div className="url-row">
            <input id="target" type="url" placeholder="https://example.com" value={url} onChange={(event) => setUrl(event.target.value)} required />
            <button disabled={isSubmitting}>{isSubmitting ? 'Queuing…' : 'Run health scan'}</button>
          </div>
          {error && <p className="form-error" role="alert">{error}</p>}
          <p className="disclaimer">Only scan websites you own or have permission to assess. This tool performs passive analysis only.</p>
        </form>
      </section>
      <section className="method">
        <h2>What the assessment checks</h2>
        <div className="method-grid">
          <article><b>01</b><h3>Response hardening</h3><p>Baseline browser security headers and clear, actionable remediation.</p></article>
          <article><b>02</b><h3>Verified TLS</h3><p>Certificate validity, hostname verification, protocol and negotiated cipher policy.</p></article>
          <article><b>03</b><h3>Passive fingerprints</h3><p>Conservative CMS identification with an explicit confidence level.</p></article>
        </div>
      </section>
    </>
  )
}

function Dashboard({ token, onSignOut }) {
  const [url, setUrl] = useState('')
  const [scan, setScan] = useState(null)
  const [history, setHistory] = useState([])
  const [view, setView] = useState('home')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')
  const pollTimer = useRef(null)
  const activeScanId = useRef(null)

  const stopPolling = useCallback(() => {
    activeScanId.current = null
    if (pollTimer.current !== null) {
      window.clearTimeout(pollTimer.current)
      pollTimer.current = null
    }
  }, [])

  useEffect(() => stopPolling, [stopPolling])

  const loadHistory = useCallback(async () => {
    try {
      setHistory(await api.history(token))
    } catch {
      setHistory([])
    }
  }, [token])

  useEffect(() => { loadHistory() }, [loadHistory])

  const pollStatus = useCallback(async (scanId) => {
    if (activeScanId.current !== scanId) return
    try {
      const current = await api.status(scanId, token)
      setScan((previous) => ({ ...previous, ...current }))
      if (current.status === 'completed') {
        const report = await api.report(scanId, token)
        setScan(report)
        setView('results')
        setIsSubmitting(false)
        loadHistory()
        stopPolling()
        return
      }
      if (current.status === 'failed') {
        setError(current.error || 'The scan did not complete.')
        setView('home')
        setIsSubmitting(false)
        stopPolling()
        return
      }
      pollTimer.current = window.setTimeout(() => pollStatus(scanId), 2000)
    } catch (requestError) {
      setError(requestError.message)
      setView('home')
      setIsSubmitting(false)
      stopPolling()
    }
  }, [loadHistory, stopPolling, token])

  async function startScan(event) {
    event.preventDefault()
    setError('')
    setIsSubmitting(true)
    try {
      const created = await api.scan(url, token)
      setScan({ ...created, progress: 0 })
      setView('scanning')
      stopPolling()
      activeScanId.current = created.scan_id
      pollStatus(created.scan_id)
    } catch (requestError) {
      setError(requestError.message)
      setIsSubmitting(false)
    }
  }

  async function openReport(scanId) {
    try {
      setScan(await api.report(scanId, token))
      setView('results')
    } catch (requestError) {
      setError(requestError.message)
      setView('home')
    }
  }

  async function downloadPdf() {
    if (!scan) return
    try {
      const response = await fetch(`${API_BASE}/api/scan/${scan.scan_id}/pdf`, { headers: { Authorization: `Bearer ${token}` } })
      if (!response.ok) throw new Error('The PDF report is unavailable.')
      const blob = await response.blob()
      const href = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = href
      link.download = `vulnscan-${scan.scan_id}.pdf`
      link.click()
      URL.revokeObjectURL(href)
    } catch (requestError) {
      setError(requestError.message)
    }
  }

  return (
    <main className="shell">
      <AppHeader onHistory={() => setView('history')} onSignOut={onSignOut} />
      {view === 'history' && <HistoryView history={history} onBack={() => setView('home')} onOpenReport={openReport} />}
      {view === 'results' && scan?.result && <Results scan={scan} onHistory={() => setView('history')} onDownload={downloadPdf} />}
      {view === 'scanning' && <ScanProgress progress={scan?.progress || 0} />}
      {view === 'home' && <Landing error={error} isSubmitting={isSubmitting} onSubmit={startScan} setUrl={setUrl} url={url} />}
    </main>
  )
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem('vulnscan_token'))

  async function authenticate(mode, email, password) {
    const result = await api.authenticate(mode, email, password)
    localStorage.setItem('vulnscan_token', result.access_token)
    setToken(result.access_token)
  }

  function signOut() {
    localStorage.removeItem('vulnscan_token')
    setToken(null)
  }

  return token ? <Dashboard token={token} onSignOut={signOut} /> : <AuthCard onToken={authenticate} />
}
