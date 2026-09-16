import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

function historyChartData(history) {
  return [...history]
    .reverse()
    .filter((scan) => scan.score !== null)
    .map((scan) => ({ score: scan.score, date: new Date(scan.created_at).toLocaleDateString() }))
}

export default function HistoryView({ history, onBack, onOpenReport }) {
  const chartData = historyChartData(history)
  return (
    <section className="history">
      <button className="back" onClick={onBack}>← New scan</button>
      <h1>Assessment history</h1>
      <p>Track the passive security score of your authorized targets over time.</p>
      <div className="chart-card">
        <h3>Score trend</h3>
        {chartData.length ? (
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="score" x1="0" y1="0" x2="0" y2="1">
                  <stop stopColor="#0f766e" stopOpacity=".35" />
                  <stop offset="1" stopColor="#0f766e" stopOpacity="0" />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Area dataKey="score" stroke="#0f766e" fill="url(#score)" strokeWidth={3} />
            </AreaChart>
          </ResponsiveContainer>
        ) : <p>No completed scans yet.</p>}
      </div>
      <div className="table-wrap">
        {history.length ? (
          <table>
            <thead><tr><th>Target</th><th>Score</th><th>Grade</th><th>Date</th><th>Status</th><th /></tr></thead>
            <tbody>
              {history.map((scan) => (
                <tr key={scan.id}>
                  <td>{scan.target_url}</td>
                  <td>{scan.score ?? '—'}</td>
                  <td><span className="grade">{scan.grade ?? '—'}</span></td>
                  <td>{new Date(scan.created_at).toLocaleString()}</td>
                  <td><span className={'status ' + scan.status}>{scan.status}</span></td>
                  <td>{scan.status === 'completed' && <button className="text-button" onClick={() => onOpenReport(scan.id)}>Open report</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="empty-state">No previous scans yet. Run an authorized passive assessment to begin your history.</p>}
      </div>
    </section>
  )
}
