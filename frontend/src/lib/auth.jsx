import { createContext, useContext, useEffect, useState } from 'react'
import { api, clearToken, getToken, setToken } from './api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!getToken()) { setLoading(false); return }
    api.me().then(setUser).catch(() => clearToken()).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const onSignedOut = () => setUser(null)
    window.addEventListener('appxray:signed-out', onSignedOut)
    return () => window.removeEventListener('appxray:signed-out', onSignedOut)
  }, [])

  const login = async (email, password) => {
    const data = await api.login(email, password)
    setToken(data.access_token); setUser(data.user); return data.user
  }
  const register = async (payload) => {
    const data = await api.register(payload)
    setToken(data.access_token); setUser(data.user); return data.user
  }
  const logout = () => { clearToken(); setUser(null) }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, isAdmin: user?.role === 'admin' }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
