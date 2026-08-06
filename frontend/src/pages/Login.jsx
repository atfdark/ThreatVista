import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck, Lock, User, Mail, UserPlus, LogIn, AlertCircle, Info
} from 'lucide-react';
import { api } from '../services/mockData';

function storeSession(data, fallbackName) {
  localStorage.setItem('threatvista_token', data.access_token);
  localStorage.setItem('threatvista_user', JSON.stringify({
    username: data.username,
    role: data.role || 'employee',
    name: data.name || fallbackName || data.username
  }));
}

export default function Login() {
  const navigate = useNavigate();
  const [accountType, setAccountType] = useState('soc'); // 'soc' | 'employee'
  const [employeeMode, setEmployeeMode] = useState('signin'); // 'signin' | 'signup'

  // SOC / Admin form
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Employee form
  const [empName, setEmpName] = useState('');
  const [empEmail, setEmpEmail] = useState('');
  const [empPassword, setEmpPassword] = useState('');
  const [empConfirm, setEmpConfirm] = useState('');

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSocLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(username, password);
      storeSession(data, username);
      navigate('/');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleEmployeeLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const data = await api.login(empEmail, empPassword);
      storeSession(data, empEmail);
      navigate('/me');
    } catch (err) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleEmployeeRegister = async (e) => {
    e.preventDefault();
    setError('');
    if (empPassword.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }
    if (empPassword !== empConfirm) {
      setError('Passwords do not match.');
      return;
    }
    setLoading(true);
    try {
      const data = await api.register(empName, empEmail, empPassword);
      storeSession(data, empName);
      navigate('/me');
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const inputCls =
    "w-full pl-10 pr-4 py-3 bg-cyber-bg/80 border border-cyber-border/80 rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary focus:shadow-cyber transition-all";

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-bg cyber-grid relative scanline-overlay py-8">
      {/* Decorative ambient glowing backdrops */}
      <div className="absolute top-1/4 left-1/4 h-72 w-72 rounded-full bg-cyber-primary/10 blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 h-72 w-72 rounded-full bg-cyber-secondary/10 blur-[100px] pointer-events-none"></div>

      <div className="w-full max-w-md p-8 glass-panel border border-cyber-border/80 relative z-10">
        {/* Header Icon */}
        <div className="flex flex-col items-center mb-6">
          <div className="h-16 w-16 rounded-full bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center mb-3 shadow-cyber">
            <ShieldCheck className="h-10 w-10 text-cyber-primary animate-cyber-pulse" />
          </div>
          <h2 className="text-2xl font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-secondary">
            THREATVISTA
          </h2>
          <p className="text-xs text-cyber-muted tracking-widest uppercase font-mono mt-1">INSIDER DETECTION SYSTEM</p>
        </div>

        {/* Account type toggle */}
        <div className="grid grid-cols-2 gap-1 mb-6 p-1 bg-cyber-bg/80 border border-cyber-border/60 rounded-lg">
          <button
            type="button"
            onClick={() => setAccountType('soc')}
            className={`py-2 rounded-md text-xs font-mono uppercase tracking-wider transition-all ${
              accountType === 'soc'
                ? 'bg-gradient-to-r from-cyber-primary to-cyber-secondary text-cyber-bg font-bold shadow-cyber'
                : 'text-cyber-muted hover:text-cyber-text'
            }`}
          >
            SOC / Admin
          </button>
          <button
            type="button"
            onClick={() => setAccountType('employee')}
            className={`py-2 rounded-md text-xs font-mono uppercase tracking-wider transition-all ${
              accountType === 'employee'
                ? 'bg-gradient-to-r from-cyber-primary to-cyber-secondary text-cyber-bg font-bold shadow-cyber'
                : 'text-cyber-muted hover:text-cyber-text'
            }`}
          >
            Employee
          </button>
        </div>

        {/* Error Notification */}
        {error && (
          <div className="mb-6 p-4 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg flex items-start gap-3">
            <AlertCircle className="h-5 w-5 text-cyber-danger shrink-0 mt-0.5" />
            <p className="text-xs text-cyber-danger font-medium">{error}</p>
          </div>
        )}

        {/* ================= SOC / Admin ================= */}
        {accountType === 'soc' && (
          <form onSubmit={handleSocLogin} className="space-y-5">
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
                  className={inputCls}
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
                  className={inputCls}
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

            {/* SOC Demo Credentials */}
            <div className="p-3.5 bg-cyber-border/30 border border-cyber-border/50 rounded-lg flex gap-3 text-cyber-muted">
              <Info className="h-4.5 w-4.5 text-cyber-secondary shrink-0 mt-0.5" />
              <div className="text-[11px] font-mono leading-relaxed">
                <span className="text-cyber-text font-semibold">SOC Demo Accounts:</span>
                <div className="mt-1">Administrator: <span className="text-cyber-primary">admin / admin123</span></div>
                <div>Security Analyst: <span className="text-cyber-primary">analyst / analyst123</span></div>
                <div>Read-Only Auditor: <span className="text-cyber-primary">auditor / auditor123</span></div>
              </div>
            </div>
          </form>
        )}

        {/* ================= Employee ================= */}
        {accountType === 'employee' && (
          <div>
            {/* Sign in / Create account sub-toggle */}
            <div className="flex gap-4 mb-5 border-b border-cyber-border/60">
              {[
                { key: 'signin', label: 'Sign In' },
                { key: 'signup', label: 'Create Account' },
              ].map((m) => (
                <button
                  key={m.key}
                  type="button"
                  onClick={() => { setEmployeeMode(m.key); setError(''); }}
                  className={`pb-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 ${
                    employeeMode === m.key
                      ? 'text-cyber-primary border-cyber-primary'
                      : 'text-cyber-muted border-transparent hover:text-cyber-text'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {employeeMode === 'signin' ? (
              <form onSubmit={handleEmployeeLogin} className="space-y-5">
                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Email</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                      <Mail className="h-4 w-4" />
                    </span>
                    <input
                      type="email"
                      value={empEmail}
                      onChange={(e) => setEmpEmail(e.target.value)}
                      placeholder="you@threatvista.com"
                      required
                      className={inputCls}
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
                      value={empPassword}
                      onChange={(e) => setEmpPassword(e.target.value)}
                      placeholder="••••••••"
                      required
                      className={inputCls}
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <LogIn className="h-4 w-4" />
                  {loading ? 'SIGNING IN...' : 'SIGN IN'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleEmployeeRegister} className="space-y-4">
                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Full Name</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                      <UserPlus className="h-4 w-4" />
                    </span>
                    <input
                      type="text"
                      value={empName}
                      onChange={(e) => setEmpName(e.target.value)}
                      placeholder="Your name"
                      required
                      className={inputCls}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Work Email</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                      <Mail className="h-4 w-4" />
                    </span>
                    <input
                      type="email"
                      value={empEmail}
                      onChange={(e) => setEmpEmail(e.target.value)}
                      placeholder="you@company.com"
                      required
                      className={inputCls}
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
                      value={empPassword}
                      onChange={(e) => setEmpPassword(e.target.value)}
                      placeholder="Min. 6 characters"
                      required
                      className={inputCls}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider">Confirm Password</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
                      <Lock className="h-4 w-4" />
                    </span>
                    <input
                      type="password"
                      value={empConfirm}
                      onChange={(e) => setEmpConfirm(e.target.value)}
                      placeholder="Re-enter password"
                      required
                      className={inputCls}
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <UserPlus className="h-4 w-4" />
                  {loading ? 'CREATING ACCOUNT...' : 'CREATE ACCOUNT & SIGN IN'}
                </button>

                <p className="text-[10px] text-cyber-muted font-mono text-center">
                  Your account is stored in the ThreatVista database. Activity on this device is monitored.
                </p>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
