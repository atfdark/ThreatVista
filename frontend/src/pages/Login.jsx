import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Lock, User, AlertCircle, Info } from 'lucide-react';
import { api } from '../services/mockData';

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.login(username, password);
      localStorage.setItem('threatvista_token', data.access_token);
      localStorage.setItem('threatvista_user', JSON.stringify({
        username: data.username || username,
        role: data.role || 'admin'
      }));
      navigate('/');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen items-center justify-center bg-cyber-bg cyber-grid relative scanline-overlay">
      {/* Decorative ambient glowing backdrops */}
      <div className="absolute top-1/4 left-1/4 h-72 w-72 rounded-full bg-cyber-primary/10 blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 h-72 w-72 rounded-full bg-cyber-secondary/10 blur-[100px] pointer-events-none"></div>

      <div className="w-full max-w-md p-8 glass-panel border border-cyber-border/80 relative z-10">
        {/* Header Icon */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-16 w-16 rounded-full bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center mb-3 shadow-cyber">
            <ShieldCheck className="h-10 w-10 text-cyber-primary animate-cyber-pulse" />
          </div>
          <h2 className="text-2xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-secondary">
            THREATVISTA
          </h2>
          <p className="text-xs text-cyber-muted tracking-widest uppercase font-mono mt-1">INSIDER DETECTION SYSTEM</p>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="mb-6 p-4 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-cyber-danger shrink-0 mt-0.5" />
            <p className="text-xs text-cyber-danger font-medium">{error}</p>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Username</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                <User className="h-4 w-4" />
              </span>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                className="w-full pl-10 pr-4 py-3 bg-cyber-bg/80 border border-cyber-border/80 rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary focus:shadow-cyber transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                <Lock className="h-4 w-4" />
              </span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full pl-10 pr-4 py-3 bg-cyber-bg/80 border border-cyber-border/80 rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary focus:shadow-cyber transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50"
          >
            {loading ? 'AUTHENTICATING...' : 'ACCESS CONTROL CENTER'}
          </button>
        </form>

        {/* Credentials Info Note */}
        <div className="mt-8 p-3.5 bg-cyber-border/30 border border-cyber-border/50 rounded-lg flex gap-3 text-cyber-muted">
          <Info className="h-4.5 w-4.5 text-cyber-secondary shrink-0 mt-0.5" />
          <div className="text-[11px] font-mono leading-relaxed">
            <span className="text-cyber-text font-semibold">Demo Credentials:</span>
            <div className="mt-1">Administrator: <span className="text-cyber-primary">admin / admin123</span></div>
            <div>Security Analyst: <span className="text-cyber-primary">analyst / analyst123</span></div>
            <div>Read-Only Auditor: <span className="text-cyber-primary">auditor / auditor123</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
