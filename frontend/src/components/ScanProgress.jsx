const stages = [
  { progress: 5, label: 'Initializing assessment' },
  { progress: 20, label: 'Fetching target safely' },
  { progress: 40, label: 'Analyzing response headers' },
  { progress: 60, label: 'Checking TLS configuration' },
  { progress: 80, label: 'Detecting CMS fingerprints' },
  { progress: 95, label: 'Calculating score' },
]

function currentStage(progress) {
  if (progress === 0) return { progress: 0, label: 'Queued for assessment' }
  return stages.reduce((active, stage) => (progress >= stage.progress ? stage : active), stages[0])
}

export default function ScanProgress({ progress }) {
  const active = currentStage(progress)
  return (
    <section className="progress-card" aria-live="polite">
      <span className="eyebrow">Passive assessment in progress</span>
      <h1>{active.label}</h1>
      <div className="progress" aria-label={`${progress}% complete`}>
        <i style={{ width: `${Math.max(5, progress)}%` }} />
      </div>
      <p>{progress}% complete. A dedicated worker is performing the assessment.</p>
      <ol>
        {stages.map((stage) => (
          <li className={stage.progress <= progress ? 'active' : ''} key={stage.label}>{stage.label}</li>
        ))}
      </ol>
    </section>
  )
}
