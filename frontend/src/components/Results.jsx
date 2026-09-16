import ScoreGauge from './ScoreGauge'
import FindingCard from './FindingCard'
export default function Results({ scan, onHistory, onDownload }) {
  const report = scan.result
  const groups = ['Security Headers', 'TLS / HTTPS', 'CMS Detection', 'Other Findings']
  const counts = report.findings.reduce((acc, finding) => ({ ...acc, [finding.status]: (acc[finding.status] || 0) + 1 }), {})
  return <section className="results"><div className="result-hero"><div><span className="eyebrow">VulnScan Lite Passive Security Score</span><h2>{report.target_url}</h2><p>Scanned {new Date(report.scanned_at).toLocaleString()} · HTTP {report.http_status || 'n/a'}</p></div><ScoreGauge score={report.score} grade={report.grade} /></div><div className="summary-grid"><div><b>{counts.passed || 0}</b><span>Passed</span></div><div><b>{counts.warning || 0}</b><span>Warnings</span></div><div><b>{counts.failed || 0}</b><span>Failed</span></div><div><b>{report.duration_ms}ms</b><span>Assessment time</span></div></div><div className="result-actions"><button onClick={onDownload}>Download PDF report</button><button className="secondary" onClick={onHistory}>View history</button></div>{groups.map(group => { const findings = report.findings.filter(item => item.category === group); return findings.length ? <section className="finding-group" key={group}><h3>{group}</h3>{findings.map((item, index) => <FindingCard key={`${item.name}-${index}`} finding={item} />)}</section> : null })}</section>
}
