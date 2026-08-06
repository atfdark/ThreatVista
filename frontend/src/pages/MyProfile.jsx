import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, LogOut, User, Mail, BadgeCheck, Activity } from 'lucide-react';
import { api } from '../services/mockData';

export default function MyProfile() {
  const navigate = useNavigate();
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('threatvista_user') || '{}');
    } catch {
      return {};
    }
  });
  const [now, setNow] = useState(new Date());

  // Employees land here; SOC staff should be on the command center instead.
  useEffect(() => {
    if (user.role && user.role !== 'employee') {
      navigate('/');
    }
  }, [user.role, navigate]);

  // Live clock.
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  const handleLogout = async () => {
    await api.logout();
    localStorage.removeItem('threatvista_token');
    localStorage.removeItem('threatvista_user');
    navigate('/login');
  };

  const initials = (user.name || user.username || 'ME').split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
  const roleLabel = user.role === 'employee' ? 'Employee' : (user.role || '').toUpperCase();

  return (
    <div className="flex min-h-screen items-center justify-center bg-cyber-bg cyber-grid relative scanline-overlay p-6">
      <div className="absolute top-1/4 left-1/4 h-72 w-72 rounded-full bg-cyber-primary/10 blur-[100px] pointer-events-none"></div>
      <div className="absolute bottom-1/4 right-1/4 h-72 w-72 rounded-full bg-cyber-secondary/10 blur-[100px] pointer-events-none"></div>

      <div className="w-full max-w-lg p-8 glass-panel border border-cyber-border/80 relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-cyber-primary" />
            <h1 className="text-lg font-bold tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-secondary">
              THREATVISTA
            </h1>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-cyber-muted hover:text-cyber-danger transition-colors"
          >
            <LogOut className="h-4 w-4" /> Logout
          </button>
        </div>

        {/* Profile card */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-20 w-20 rounded-full bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center mb-4 shadow-cyber">
            <span className="font-mono font-bold text-2xl text-cyber-primary">{initials}</span>
          </div>
          <h2 className="text-2xl font-bold text-cyber-text tracking-tight">{user.name || user.username || 'Employee'}</h2>
          <span className="mt-2 inline-flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded border uppercase font-medium text-cyber-success bg-cyber-success/10 border-cyber-success/25">
            <BadgeCheck className="h-3.5 w-3.5" /> {roleLabel} · Signed In
          </span>
        </div>

        {/* Details */}
        <div className="space-y-3 mb-8">
          <div className="flex items-center gap-3 p-3 bg-cyber-bg/60 border border-cyber-border/60 rounded-lg">
            <Mail className="h-4 w-4 text-cyber-secondary shrink-0" />
            <div className="min-w-0">
              <div className="text-[9px] font-mono uppercase text-cyber-muted tracking-wider">Email</div>
              <div className="text-sm text-cyber-text truncate">{user.username}</div>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 bg-cyber-bg/60 border border-cyber-border/60 rounded-lg">
            <User className="h-4 w-4 text-cyber-accent shrink-0" />
            <div>
              <div className="text-[9px] font-mono uppercase text-cyber-muted tracking-wider">Signed in at</div>
              <div className="text-sm text-cyber-text font-mono">{now.toLocaleTimeString()}</div>
            </div>
          </div>
        </div>

        {/* Monitoring notice */}
        <div className="p-4 bg-cyber-primary/5 border border-cyber-primary/20 rounded-lg flex gap-3 items-start">
          <Activity className="h-5 w-5 text-cyber-primary shrink-0 mt-0.5 animate-pulse" />
          <p className="text-[11px] font-mono leading-relaxed text-cyber-muted">
            This device is being monitored by the ThreatVista endpoint agent.
            File, USB, and system activity is logged in the Security Operations Center.
            Your session was recorded with your sign-in details.
          </p>
        </div>
      </div>
    </div>
  );
}
