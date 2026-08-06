import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck, LogOut, User, Mail, BadgeCheck, Laptop, Download, RefreshCw, CheckCircle2, AlertTriangle
} from 'lucide-react';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST, toISTDate, IST_TIME_ZONE } from '../utils/time';

/** Build + trigger the browser download of the agent config file. */
function downloadAgentConfig(data) {
  const blob = new Blob(
    [JSON.stringify({ token: data.token, backend_url: data.backend_url }, null, 2)],
    { type: 'application/json' }
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'threatvista-agent-config.json';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

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

  // Live device status for this machine.
  const [device, setDevice] = useState(null);       // serialized Device or null
  const [online, setOnline] = useState(false);
  const [statusLoading, setStatusLoading] = useState(true);
  const [enrolling, setEnrolling] = useState(false);
  const [enrollMsg, setEnrollMsg] = useState(null); // {type:'ok'|'error', text}

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

  const refreshStatus = async (silent = false) => {
    if (!silent) setStatusLoading(true);
    try {
      const data = await api.getAgentStatus();
      setDevice(data.device || null);
      setOnline(!!data.online);
    } catch (err) {
      console.error('Failed to load agent status', err);
    } finally {
      if (!silent) setStatusLoading(false);
    }
  };

  useEffect(() => {
    refreshStatus();
    const poll = setInterval(() => refreshStatus(true), 10000); // heartbeat cadence
    return () => clearInterval(poll);
  }, []);

  // Live: registration broadcasts device_connected — refresh immediately.
  useWebSocket((msg) => {
    if (msg.type === 'device_connected') {
      refreshStatus(true);
    }
  });

  const handleConnect = async () => {
    setEnrolling(true);
    setEnrollMsg(null);
    try {
      const data = await api.enrollDevice();
      downloadAgentConfig(data);
      const expiresAt = toISTDate(data.expires_at);
      setEnrollMsg({
        type: 'ok',
        text: `Config downloaded — token expires ${formatIST(expiresAt, { hour: '2-digit', minute: '2-digit' })}.`,
      });
      // The agent will register shortly; refresh status so the badge flips.
      setTimeout(() => refreshStatus(true), 3000);
    } catch (err) {
      setEnrollMsg({
        type: 'error',
        text: err?.response?.data?.detail || 'Could not enroll this device. Try again.',
      });
    } finally {
      setEnrolling(false);
    }
  };

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
              <div className="text-sm text-cyber-text font-mono">{now.toLocaleTimeString([], { timeZone: IST_TIME_ZONE })}</div>
            </div>
          </div>
        </div>

        {/* This Device — token-based enrollment */}
        <div className="p-4 bg-cyber-bg/60 border border-cyber-border/60 rounded-lg mb-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Laptop className="h-4 w-4 text-cyber-primary" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted">This Device</span>
            </div>
            <button
              onClick={() => refreshStatus()}
              disabled={statusLoading}
              className="flex items-center gap-1 text-cyber-muted hover:text-cyber-primary transition-colors focus:outline-none"
              title="Refresh device status"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${statusLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {/* Status badge */}
          <div className="flex items-center gap-2 mb-3">
            <span
              className={`inline-flex items-center gap-1.5 text-[10px] font-mono px-2.5 py-1 rounded border uppercase font-bold ${
                online
                  ? 'text-cyber-success bg-cyber-success/10 border-cyber-success/30'
                  : 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30'
              }`}
            >
              <span className={`h-2 w-2 rounded-full ${online ? 'bg-cyber-success animate-pulse shadow-[0_0_8px_#10b981]' : 'bg-cyber-danger'}`} />
              {online ? 'Online' : 'Disconnected'}
            </span>
            {device?.hostname && (
              <span className="text-[10px] font-mono text-cyber-muted">{device.hostname}</span>
            )}
          </div>

          {online && device ? (
            <div className="text-[11px] font-mono text-cyber-muted space-y-1 mb-3">
              <p><span className="text-cyber-text">Device:</span> {device.device_id}</p>
              <p><span className="text-cyber-text">Last heartbeat:</span> {device.last_seen_at ? formatIST(device.last_seen_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}</p>
            </div>
          ) : (
            <p className="text-[11px] font-mono leading-relaxed text-cyber-muted mb-3">
              This laptop is not connected yet. Connect it below to start secure
              monitoring — no email or IP needed.
            </p>
          )}

          {/* Connect action */}
          {online ? (
            <div className="flex items-center gap-2 text-[11px] font-mono text-cyber-success">
              <CheckCircle2 className="h-4 w-4" />
              Device is streaming telemetry to the SOC dashboard.
            </div>
          ) : (
            <button
              onClick={handleConnect}
              disabled={enrolling}
              className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyber-primary/15 hover:bg-cyber-primary text-cyber-primary hover:text-cyber-bg rounded-lg border border-cyber-primary/30 text-xs font-bold tracking-wider transition-all disabled:opacity-50"
            >
              {enrolling ? (
                <RefreshCw className="h-4 w-4 animate-spin" />
              ) : (
                <Download className="h-4 w-4" />
              )}
              {enrolling ? 'GENERATING TOKEN...' : 'CONNECT THIS DEVICE'}
            </button>
          )}

          {enrollMsg && (
            <div
              className={`mt-3 flex items-center gap-2 px-3 py-2 rounded-lg border text-[11px] font-mono ${
                enrollMsg.type === 'ok'
                  ? 'bg-cyber-success/10 border-cyber-success/30 text-cyber-success'
                  : 'bg-cyber-danger/10 border-cyber-danger/30 text-cyber-danger'
              }`}
            >
              {enrollMsg.type === 'ok' ? <CheckCircle2 className="h-3.5 w-3.5 shrink-0" /> : <AlertTriangle className="h-3.5 w-3.5 shrink-0" />}
              {enrollMsg.text}
            </div>
          )}
        </div>

        {/* Enrollment instructions */}
        <div className="p-4 bg-cyber-primary/5 border border-cyber-primary/20 rounded-lg">
          <p className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted mb-2">How to connect</p>
          <ol className="text-[11px] font-mono leading-relaxed text-cyber-muted list-decimal list-inside space-y-1">
            <li>Click <span className="text-cyber-primary">Connect This Device</span> — a config file downloads.</li>
            <li>Keep <span className="text-cyber-text">threatvista-agent-config.json</span> next to the agent folder.</li>
            <li>Double-click <span className="text-cyber-text">start_agent.bat</span> on this laptop.</li>
            <li>Status above flips to <span className="text-cyber-success">Online</span> automatically.</li>
          </ol>
        </div>
      </div>
    </div>
  );
}
