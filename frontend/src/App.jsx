import { useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useAuth } from './lib/auth'
import { Loading } from './components/ui'
import Admin from './pages/Admin'
import Analytics from './pages/Analytics'
import History from './pages/History'
import Login from './pages/Login'
import Scan from './pages/Scan'
import ScanDetail from './pages/ScanDetail'

function Sidebar({ open, close }) {
  const { isAdmin } = useAuth()
  return (
    <aside className={`sidebar ${open ? 'open' : ''}`} onClick={close}>
      <div className="brand">
        <div className="brand-mark">X</div>
        <div>
          <div className="brand-name">AppXray</div>
          <div className="eyebrow" style={{ color: '#6E7F96' }}>ML + NLP</div>
        </div>
      </div>

      <nav className="nav">
        <div className="eyebrow nav-label">Detect</div>
        <NavLink to="/" end>Scan an app</NavLink>
        <NavLink to="/history">Scan history</NavLink>

        <div className="eyebrow nav-label">Insight</div>
        <NavLink to="/analytics">Analytics</NavLink>

        {isAdmin && (
          <>
            <div className="eyebrow nav-label">Manage</div>
            <NavLink to="/admin">Administration</NavLink>
          </>
        )}
      </nav>

      <div className="sidebar-foot">
        Real-Time Fake App Detection System
        <br />v1.1.0
      </div>
    </aside>
  )
}

export default function App() {
  const { user, loading, logout } = useAuth()
  const [navOpen, setNavOpen] = useState(false)

  if (loading) return <div style={{ display: 'grid', placeItems: 'center', height: '100vh' }}><Loading /></div>
  if (!user) return <Login />

  return (
    <div className="shell">
      <Sidebar open={navOpen} close={() => setNavOpen(false)} />
      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost btn-sm menu-btn" onClick={() => setNavOpen((o) => !o)}
                  aria-label="Toggle navigation">☰</button>
          <div className="row" style={{ marginLeft: 'auto' }}>
            <div style={{ textAlign: 'right' }}>
              <div className="small" style={{ fontWeight: 600 }}>{user.full_name || user.email}</div>
              <div className="eyebrow">{user.role}</div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={logout}>Sign out</button>
          </div>
        </header>

        <main className="content">
          <Routes>
            <Route path="/" element={<Scan />} />
            <Route path="/history" element={<History />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/analytics" element={<Analytics />} />
            <Route path="/admin"
                   element={user.role === 'admin' ? <Admin /> : <Navigate to="/" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  )
}
