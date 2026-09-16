const icon = { passed: '✓', failed: '×', warning: '!', info: 'i' }
export default function FindingCard({ finding }) {
  return <article className={`finding ${finding.status}`}><div className="finding-icon" aria-hidden="true">{icon[finding.status]}</div><div className="finding-body"><div className="finding-heading"><h4>{finding.name}</h4><span className={`pill ${finding.severity}`}>{finding.severity}</span></div><p>{finding.explanation}</p><dl><dt>Evidence</dt><dd>{finding.evidence}</dd>{finding.remediation && <><dt>Recommended action</dt><dd>{finding.remediation}</dd></>}</dl></div></article>
}
