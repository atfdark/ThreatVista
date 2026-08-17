import React, { useState, useEffect, useMemo } from 'react';
import {
  Laptop, Radio, Activity, Clock, RefreshCw, AlertTriangle, Database
} from 'lucide-react';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST, toISTDate } from '../utils/time';

function relativeTime(iso) {
  if (!iso) return 'never';
  const diff = Math.max(0, (Date.now() - (toISTDate(iso)?.getTime() ?? 0)) / 1000);
  if (diff < 5) return 'just now';
  if (diff < 60) return `${Math.floor(diff)}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

function eventBadge(type) {
  const label = (type || 'event').replace(/_/g, ' ');
  if (type && type.includes('usb')) return { label, cls: 'text-cyber-primary border-cyber-primary/20 bg-cyber-primary/5' };
  if (type && type.includes('file')) return { label, cls: 'text-cyber-accent border-cyber-accent/20 bg-cyber-accent/5' };
  if (type && type.includes('network')) return { label, cls: 'text-cyber-secondary border-cyber-secondary/20 bg-cyber-secondary/5' };
  if (type && type.includes('process')) return { label, cls: 'text-cyber-warning border-cyber-warning/20 bg-cyber-warning/5' };
  return { label, cls: 'text-cyber-muted border-cyber-border bg-cyber-bg/50' };
}

function riskBadge(score) {
  if (typeof score !== 'number') return { label: 'N/A', cls: 'text-cyber-muted border-cyber-border/60 bg-cyber-bg/40' };
  if (score >= 81) return { label: 'CRITICAL', cls: 'text-cyber-danger border-cyber-danger/30 bg-cyber-danger/10' };
  if (score >= 61) return { label: 'HIGH', cls: 'text-cyber-warning border-cyber-warning/30 bg-cyber-warning/10' };
  if (score >= 31) return { label: 'MEDIUM', cls: 'text-cyber-secondary border-cyber-secondary/30 bg-cyber-secondary/10' };
  return { label: 'SAFE', cls: 'text-cyber-success border-cyber-success/30 bg-cyber-success/10' };
}

const WATCHED = ['DESKTOP', 'DOCUMENTS', 'DOWNLOADS', 'USB', 'PROCESSES'];

export default function ActiveSessions() {
  const [endpoints, setEndpoints] = useState([]);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);

  // Live telemetry: prepend each new event from the backend WebSocket. When a
  // device registers, refetch endpoints so it appears Online immediately.
  const { isConnected } = useWebSocket((message) => {
    if (message.type === 'new_event') {
      setEvents(prev => [message.data, ...prev].slice(0, 100));
    } else if (message.type === 'batch_event') {
      // Agent batches arrive in collection order — sort newest-first so the
      // stream always shows the most recent event on top.
      const evs = (message.data?.events || []).slice().sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
      if (evs.length) setEvents(prev => [...evs, ...prev].slice(0, 100));
    } else if (message.type === 'device_connected') {
      api.getEndpoints().then(eps => setEndpoints(eps || [])).catch(() => {});
    } else if (message.type === 'risk_update' || message.type === 'incident_resolved' || message.type === 'incident_archived') {
      api.getEndpoints().then(eps => setEndpoints(eps || [])).catch(() => {});
    }
  });

  useEffect(() => {
    setWsConnected(isConnected);
  }, [isConnected]);

  // Initial load + a short poll so heartbeat / CPU / RAM stay fresh.
  useEffect(() => {
    async function load() {
      try {
        const [eps, evts] = await Promise.all([api.getEndpoints(), api.getEvents(null, 100)]);
        setEndpoints(eps || []);
        setEvents(evts || []);
      } catch (err) {
        console.error('Failed to load active sessions', err);
      } finally {
        setLoading(false);
      }
    }
    load();
    const poll = setInterval(async () => {
      try {
        const eps = await api.getEndpoints();
        setEndpoints(eps || []);
      } catch (err) {
        console.error('Failed to poll endpoints', err);
      }
    }, 5000);
    return () => clearInterval(poll);
  }, []);

  const employeeNameById = useMemo(() => {
    const map = {};
    for (const ep of endpoints) {
      if (ep.employee) map[ep.employee.id] = ep.employee.name;
    }
    return map;
  }, [endpoints]);

  const eventsByEmployee = useMemo(() => {
    const map = {};
    for (const evt of events) {
      const list = (map[evt.employee_id] = map[evt.employee_id] || []);
      if (list.length < 2) list.push(evt);
    }
    return map;
  }, [events]);

  const total = endpoints.length;
  const online = endpoints.filter(e => e.device && e.device.online).length;
  const offline = total - online;

  const statChips = [
    { label: 'Total Endpoints', value: total, color: 'text-cyber-text', icon: Laptop },
    { label: 'Online', value: online, color: 'text-cyber-success', icon: Radio },
    { label: 'Offline', value: offline, color: 'text-cyber-danger', icon: AlertTriangle },
  ];

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">QUERYING CONNECTED ENDPOINTS...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Active Sessions</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">CONNECTED ENDPOINTS &amp; LIVE TELEMETRY</p>
        </div>
        <div className="flex items-center gap-2 bg-cyber-card border border-cyber-border px-3 py-1.5 rounded-lg text-xs font-mono">
          <Radio className={`h-4 w-4 ${wsConnected ? 'text-cyber-success animate-pulse' : 'text-cyber-muted'}`} />
          <span className="text-cyber-text">{wsConnected ? 'LIVE FEED ACTIVE' : 'OFFLINE MODE'}</span>
        </div>
      </div>

      {/* Stat chips */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
        {statChips.map((chip, i) => {
          const Icon = chip.icon;
          return (
            <div key={i} className="p-5 glass-panel flex items-center gap-4">
              <div className="p-3 bg-cyber-bg border border-cyber-border rounded-lg">
                <Icon className={`h-5 w-5 ${chip.color}`} />
              </div>
              <div>
                <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">{chip.label}</span>
                <span className={`text-2xl font-extrabold font-mono ${chip.color}`}>{chip.value}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Endpoint cards */}
      <div>
        <h3 className="text-sm font-bold font-mono uppercase text-cyber-muted tracking-wider mb-4 flex items-center gap-2">
          <Laptop className="h-4.5 w-4.5 text-cyber-primary" /> Connected Endpoints
        </h3>
        {endpoints.length === 0 ? (
          <div className="text-center py-16 glass-panel">
            <Database className="h-10 w-10 text-cyber-muted mx-auto mb-3" />
            <p className="text-sm font-mono text-cyber-muted">NO ENDPOINT AGENTS REGISTERED YET</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {endpoints.map((ep) => {
              const emp = ep.employee || {};
              const dev = ep.device || {};
              const initials = (emp.name || '?').split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();
              const onlineNow = !!dev.online;
              const recent = eventsByEmployee[emp.id] || [];
              const risk = riskBadge(emp.risk_score);
              return (
                <div key={dev.device_id || emp.id} className={`p-6 glass-panel border ${onlineNow ? 'border-cyber-success/20' : 'border-cyber-danger/20'}`}>
                  {/* Header */}
                  <div className="flex justify-between items-start gap-4 mb-4">
                    <div className="flex items-center gap-3">
                      <div className="h-11 w-11 rounded-full bg-cyber-primary/10 border border-cyber-primary/20 flex items-center justify-center font-mono font-bold text-cyber-primary">
                        {initials}
                      </div>
                      <div>
                        <div className="flex items-center gap-1.5">
                          <span className={`h-2 w-2 rounded-full ${onlineNow ? 'bg-cyber-success shadow-[0_0_8px_#10b981] animate-pulse' : 'bg-cyber-danger shadow-[0_0_8px_#ef4444]'}`}></span>
                          <h4 className="font-bold text-cyber-text text-sm">{emp.name || 'Unknown'}</h4>
                        </div>
                        <span className="text-[10px] text-cyber-muted font-mono">{emp.department || ''}</span>
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1.5">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                        onlineNow ? 'text-cyber-success bg-cyber-success/10 border-cyber-success/25' : 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25'
                      }`}>
                        {onlineNow ? 'ONLINE' : 'OFFLINE'}
                      </span>
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${risk.cls}`}>
                        {risk.label} · {emp.risk_score}
                      </span>
                    </div>
                  </div>

                  {/* Device details */}
                  <div className="space-y-1.5 text-[11px] font-mono mb-4">
                    <div className="flex justify-between"><span className="text-cyber-muted">HOSTNAME</span><span className="text-cyber-text font-semibold">{dev.hostname || '-'}</span></div>
                    <div className="flex justify-between"><span className="text-cyber-muted">IP ADDRESS</span><span className="text-cyber-text">{dev.ip_address || '-'}</span></div>
                    <div className="flex justify-between"><span className="text-cyber-muted">OS</span><span className="text-cyber-text">{dev.os_version || '-'}{dev.agent_version ? ` · v${dev.agent_version}` : ''}</span></div>
                    <div className="flex justify-between"><span className="text-cyber-muted">LAST HEARTBEAT</span><span className={onlineNow ? 'text-cyber-success' : 'text-cyber-danger'}>{relativeTime(dev.last_seen_at)}</span></div>
                    <div className="flex justify-between"><span className="text-cyber-muted">ACTIVITY (1H)</span><span className="text-cyber-text">{ep.recent_event_count ?? 0} events</span></div>
                  </div>

                  {/* Health bars */}
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    {[
                      { label: 'CPU', value: dev.last_cpu_usage, color: 'text-cyber-secondary' },
                      { label: 'RAM', value: dev.last_ram_usage, color: 'text-cyber-accent' },
                      { label: 'DISK', value: dev.last_disk_usage, color: 'text-cyber-warning' },
                    ].map((m) => {
                      const pct = typeof m.value === 'number' ? Math.min(100, Math.max(0, m.value)) : 0;
                      return (
                        <div key={m.label}>
                          <div className="flex justify-between items-center mb-1">
                            <span className="text-[8px] text-cyber-muted font-mono uppercase">{m.label}</span>
                            <span className={`text-[9px] font-mono font-bold ${m.color}`}>{m.value !== null && m.value !== undefined ? `${Math.round(m.value)}%` : '--'}</span>
                          </div>
                          <div className="w-full bg-cyber-bg border border-cyber-border h-1.5 rounded-full overflow-hidden">
                            <div className={`h-full ${m.color} bg-current`} style={{ width: `${pct}%` }}></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Latest activity on this endpoint */}
                  <div className="border-t border-cyber-border/50 pt-3">
                    <span className="text-[9px] text-cyber-muted font-mono uppercase tracking-wider block mb-2">Latest Activity</span>
                    {recent.length ? recent.map((evt, i) => {
                      const badge = eventBadge(evt.event_type);
                      return (
                        <div key={i} className="flex items-center gap-2 mb-1.5">
                          <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${badge.cls}`}>{badge.label}</span>
                          <span className="text-[10px] text-cyber-text truncate">{evt.details || evt.event_type}</span>
                        </div>
                      );
                    }) : (
                      <span className="text-[10px] text-cyber-muted font-mono">NO RECENT EVENTS</span>
                    )}
                  </div>

                  {/* Monitored surface */}
                  <div className="border-t border-cyber-border/50 pt-2 mt-3 flex flex-wrap gap-1">
                    {WATCHED.map(w => (
                      <span key={w} className="text-[8px] font-mono text-cyber-muted px-1.5 py-0.5 rounded border border-cyber-border/60 bg-cyber-bg/40 uppercase">{w}</span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Live event stream */}
      <div className="glass-panel overflow-hidden">
        <div className="flex items-center justify-between px-5 pt-5">
          <div>
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono">Live Event Stream</h4>
            <p className="text-xs text-cyber-muted">Real-time telemetry from all connected endpoints</p>
          </div>
          <RefreshCw className="h-4 w-4 text-cyber-muted" />
        </div>
        <div className="overflow-x-auto mt-4">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[9px] tracking-wider">
                <th className="pb-3 pl-5">Time</th>
                <th className="pb-3">Endpoint</th>
                <th className="pb-3">Event Type</th>
                <th className="pb-3 pr-5">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono">
              {[...events].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 20).map((evt, i) => {
                const badge = eventBadge(evt.event_type);
                return (
                  <tr key={evt.id || i} className="hover:bg-cyber-border/10">
                    <td className="py-2.5 pl-5 text-cyber-muted text-[10px] whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5 text-cyber-muted" />
                        {evt.timestamp ? formatIST(evt.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}
                      </div>
                    </td>
                    <td className="py-2.5 text-cyber-text whitespace-nowrap">
                      {employeeNameById[evt.employee_id] || `Employee #${evt.employee_id}`}
                    </td>
                    <td className="py-2.5">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded border uppercase ${badge.cls}`}>{badge.label}</span>
                    </td>
                    <td className="py-2.5 pr-5 text-cyber-text">{evt.details || '—'}</td>
                  </tr>
                );
              })}
              {events.length === 0 && (
                <tr>
                  <td colSpan="4" className="text-center py-12 text-cyber-muted">
                    <Activity className="h-8 w-8 text-cyber-muted mx-auto mb-2" />
                    WAITING FOR ENDPOINT TELEMETRY...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
