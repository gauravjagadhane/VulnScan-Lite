export default function ScoreGauge({ score, grade }) {
  const color = score >= 90 ? '#16a34a' : score >= 80 ? '#0f766e' : score >= 70 ? '#d97706' : '#dc2626'
  return <div className="gauge" style={{ '--score': `${score * 3.6}deg`, '--gauge': color }} aria-label={`Security score ${score} out of 100, grade ${grade}`}>
    <div className="gauge-inner"><strong>{score}</strong><span>/100</span><b style={{ color }}>{grade}</b></div>
  </div>
}
