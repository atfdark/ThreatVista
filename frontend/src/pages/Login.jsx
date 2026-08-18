import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck, Lock, User, Mail, UserPlus, LogIn, AlertCircle, Briefcase, Sparkles, CheckCircle2
} from 'lucide-react';
import { api } from '../services/mockData';

const ROLE_DESCRIPTIONS = {
  Developer: {
    dept: 'Engineering',
    desc: 'High file ops & source code repository modifications are normal.',
    badge: 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/30',
    allowed: 'Code files (.py, .js, .cpp, .json) & build outputs normal'
  },
  HR: {
    dept: 'Human Resources',
    desc: 'PDFs & payroll spreadsheets are normal. Source code & mass file creation will be flagged.',
    badge: 'text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/30',
    allowed: 'PDFs & employee sheets common; Code & mass file creation flagged'
  },
  Finance: {
    dept: 'Finance',
    desc: 'Excel & CSV financial records normal. Staging ZIP archives & source code are flagged.',
    badge: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    allowed: 'Excel, CSV & budget sheets common; ZIP archives & source code flagged'
  },
  Sales: {
    dept: 'Sales',
    desc: 'Client proposals & contracts normal. Source code file operations will be flagged.',
    badge: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    allowed: 'Client docs & decks normal; Code repositories flagged'
  },
  'Security Analyst': {
    dept: 'Security',
    desc: 'Diagnostics & elevated process execution activity are normal.',
    badge: 'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/30',
    allowed: 'Diagnostics & elevated process executions permitted'
  },
  'IT Support': {
    dept: 'IT Support',
    desc: 'System maintenance utilities & workstation scripts are normal.',
    badge: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    allowed: 'System tools & workstation setup scripts permitted'
  },
  Manager: {
    dept: 'Management',
    desc: 'Cross-functional review & strategic documentation are normal.',
    badge: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30',
    allowed: 'Management reviews & office documents common'
  },
  Administrator: {
    dept: 'Executive Admin',
    desc: 'Administrative workstation tasks & enterprise configuration.',
    badge: 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30',
    allowed: 'Enterprise administrative privileges'
  },
  General: {
    dept: 'General Operations',
    desc: 'Standard corporate workstation baseline behavior.',
    badge: 'text-cyber-muted bg-cyber-bg border-cyber-border',
    allowed: 'Standard office document handling'
  }
};

const SUPPORTED_ROLES = Object.keys(ROLE_DESCRIPTIONS);

function storeSession(data, fallbackName) {
  localStorage.setItem('threatvista_token', data.access_token);
  localStorage.setItem('threatvista_user', JSON.stringify({
    username: data.username,
    role: data.role || 'employee',
    role_type: data.role_type || 'Developer',
    department: data.department || 'General',
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
  const [empRole, setEmpRole] = useState('Developer');
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
      const dept = ROLE_DESCRIPTIONS[empRole]?.dept || 'General';
      const data = await api.register(empName, empEmail, empPassword, empRole, dept);
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

  const selectedRoleMeta = ROLE_DESCRIPTIONS[empRole] || ROLE_DESCRIPTIONS.General;

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
            className={`py-2 rounded-md text-xs font-mono uppercase tracking-wider transition-all cursor-pointer ${accountType === 'soc'
              ? 'bg-gradient-to-r from-cyber-primary to-cyber-secondary text-cyber-bg font-bold shadow-cyber'
              : 'text-cyber-muted hover:text-cyber-text'
              }`}
          >
            SOC / Admin
          </button>
          <button
            type="button"
            onClick={() => setAccountType('employee')}
            className={`py-2 rounded-md text-xs font-mono uppercase tracking-wider transition-all cursor-pointer ${accountType === 'employee'
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
              className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50 cursor-pointer"
            >
              {loading ? 'AUTHENTICATING...' : 'ACCESS CONTROL CENTER'}
            </button>
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
                  className={`pb-2 text-xs font-mono uppercase tracking-wider transition-colors border-b-2 cursor-pointer ${employeeMode === m.key
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
                      placeholder="••••••••"
                      required
                      className={inputCls}
                    />
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
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
                      placeholder="e.g. Alok Kumar"
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

                {/* Role-Based Selection */}
                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-2 tracking-wider flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Briefcase className="h-3.5 w-3.5 text-cyber-primary" /> Employee Role
                    </span>
                    <span className="text-[10px] text-cyber-primary font-bold">{empRole}</span>
                  </label>
                  <div className="relative">
                    <select
                      value={empRole}
                      onChange={(e) => setEmpRole(e.target.value)}
                      className="w-full px-4 py-3 bg-cyber-bg/90 border border-cyber-border rounded-lg text-xs font-mono font-bold text-cyber-text focus:outline-none focus:border-cyber-primary focus:shadow-cyber transition-all appearance-none cursor-pointer"
                    >
                      {SUPPORTED_ROLES.map(role => (
                        <option key={role} value={role} className="bg-cyber-card text-cyber-text">
                          {role} — {ROLE_DESCRIPTIONS[role]?.dept}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Role Baseline Intel Hint */}
                  <div className="mt-2 p-2.5 bg-cyber-bg/60 border border-cyber-border/80 rounded-lg text-[11px] font-mono space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-cyber-muted uppercase">ROLE BASELINE PROFILE:</span>
                      <span className={`text-[9px] px-2 py-0.5 rounded border uppercase font-bold ${selectedRoleMeta.badge}`}>
                        {empRole}
                      </span>
                    </div>
                    <p className="text-cyber-text text-[10.5px] leading-tight">
                      {selectedRoleMeta.desc}
                    </p>
                    <p className="text-cyber-muted text-[10px]">
                      › {selectedRoleMeta.allowed}
                    </p>
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
                  className="w-full py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-sm transition-all focus:outline-none shadow-cyber-glow hover:shadow-cyber hover:scale-[1.01] active:scale-100 disabled:opacity-50 flex items-center justify-center gap-2 cursor-pointer"
                >
                  <UserPlus className="h-4 w-4" />
                  {loading ? 'CREATING ACCOUNT...' : 'CREATE ACCOUNT & SIGN IN'}
                </button>

                <p className="text-[10px] text-cyber-muted font-mono text-center">
                  Account is stored with assigned role in ThreatVista. Activity will be monitored against {empRole} behavior baseline.
                </p>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
