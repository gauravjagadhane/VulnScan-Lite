export default function AppHeader({ onHistory, onSignOut }) {
  return (
    <header>
      <a className="logo" href="#">
        <span>V</span>VulnScan <em>Lite</em>
      </a>
      <nav>
        <button className="nav-link" onClick={onHistory}>History</button>
        <button className="nav-link" onClick={onSignOut}>Sign out</button>
      </nav>
    </header>
  )
}
