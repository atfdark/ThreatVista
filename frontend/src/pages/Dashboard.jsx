import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Users,
  AlertTriangle,
  TrendingUp,
  ShieldAlert,
  ChevronRight,
  ArrowRight,
  Radio,
  Clock,
  CheckCircle2
} from 'lucide-react';
import { ResponsiveContainer, XAxis, YAxis, Tooltip, BarChart, Bar, CartesianGrid } from 'recharts';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST, formatISTClock, toISTDate } from '../utils/time';
import IncidentCard from '../components/IncidentCard';
import ActionApprovalModal from '../components/ActionApprovalModal';

const LIVE_WINDOW_MINUTES = 15;

// Bucket live events into the last LIVE_WINDOW_MINUTES minutes (one bucket per
// minute, newest on the right). Counts events per type so the dashboard chart
// mirrors the real-time agent feed instead of the old static 7-day summary.
function buildLiveSeries(events, now = Date.now()) {
  const buckets = [];
  for (let i = LIVE_WINDOW_MINUTES - 1; i >= 0; i--) {
    buckets.push({
      name: formatISTClock(new Date(now - i * 60_000), { hour: '2-digit', minute: '2-digit' }),
      usb: 0,
      network: 0,
      files: 0,
      total: 0,
    });
  }
  for (const evt of events || []) {
    if (!evt?.timestamp) continue;
    const minutesAgo = Math.floor((now - (toISTDate(evt.timestamp)?.getTime() ?? 0)) / 60_000);
    if (minutesAgo < 0 || minutesAgo >= LIVE_WINDOW_MINUTES) continue;
    const bucket = buckets[LIVE_WINDOW_MINUTES - 1 - minutesAgo];
    bucket.total += 1;
    if (evt.event_type === 'usb_insert') bucket.usb += 1;
    else if (evt.event_type.startsWith('file_') || evt.event_type.startsWith('folder_')) bucket.files += 1;
    else if (evt.event_type === 'network_upload') bucket.network += 1;
  }
  return buckets;
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [employees, setEmployees] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [recentEvents, setRecentEvents] = useState([]);
  const [liveEvents, setLiveEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [pendingApprovals, setPendingApprovals] = useState([]);
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [loading, setLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  // Forces the live chart's sliding window to advance even during quiet periods.
  const [, setClock] = useState(() => Date.now());

  const fetchPending = () => {
    api.getActionRequests('PENDING').then(setPendingApprovals).catch(() => {});
  };

  const { isConnected } = useWebSocket((message) => {
    if (message.type === 'new_event') {
      setRecentEvents(prev => [message.data, ...prev].slice(0, 10));
      setLiveEvents(prev => [message.data, ...prev].slice(0, 200));
    } else if (message.type === 'new_alert') {
      setAlerts(prev => [message.data, ...prev].slice(0, 3));
    } else if (message.type === 'action_request_created' || message.type === 'action_request_resolved' || message.type === 'REQUEST_EXPIRED') {
      fetchPending();
    } else if (message.type === 'incident_created') {
      setIncidents(prev => [message.data, ...prev.filter(i => i.id !== message.data.id)].slice(0, 20));
    } else if (message.type === 'incident_updated' || message.type === 'incident_resolved' || message.type === 'incident_archived') {
      setIncidents(prev => {
        if (message.type === 'incident_resolved' || message.type === 'incident_archived') {
          return prev.filter(i => i.id !== message.data.id);
        }
        return prev.map(i => (i.id === message.data.id ? message.data : i));
      });
      Promise.all([api.getStats(), api.getEmployees()])
        .then(([statsData, empsData]) => {
          setStats(statsData);
          setEmployees(empsData.sort((a, b) => primaryRisk(b) - primaryRisk(a)));
        })
        .catch((err) => console.error('Failed to refresh dashboard on incident lifecycle', err));
    } else if (message.type === 'risk_update') {
      const data = message.data || {};
      setEmployees((prev) =>
        prev.map((emp) => {
          const upd = data[emp.id] ?? data[String(emp.id)];
          if (!upd) return emp;
          return { ...emp, risk_score: upd.score, status: upd.status, incident: null };
        }).sort((a, b) => primaryRisk(b) - primaryRisk(a))
      );
      api.getStats().then(setStats).catch(() => {});
    } else if (message.type === 'device_connected') {
      // A new endpoint enrolled — refresh stats / rankings / incidents live so
      // the device shows Online without a manual reload.
      Promise.all([api.getStats(), api.getEmployees(), api.getIncidents()])
        .then(([statsData, empsData, incidentsData]) => {
          setStats(statsData);
          setEmployees(empsData.sort((a, b) => primaryRisk(b) - primaryRisk(a)));
          setIncidents((incidentsData || []).filter(i => i.status === 'ACTIVE' || i.status === 'INVESTIGATING'));
        })
        .catch((err) => console.error('Failed to refresh dashboard on device_connected', err));
    } else if (message.type === 'batch_event') {
      const d = message.data || {};
      // Prefer the persistent incident lifecycle changes attached to the batch;
      // fall back to the legacy burst-summary card for older agents/broadcasts.
      const changes = d.incident_changes || [];
      if (changes.length) {
        for (const ch of changes) {
          const inc = ch.incident;
          if (ch.event_type === 'incident_created') {
            setIncidents(prev => [inc, ...prev.filter(i => i.id !== inc.id)].slice(0, 20));
          } else if (ch.event_type === 'incident_updated') {
            setIncidents(prev => prev.map(i => (i.id === inc.id ? inc : i)));
          } else if (ch.event_type === 'incident_resolved' || ch.event_type === 'incident_archived') {
            setIncidents(prev => prev.filter(i => i.id !== inc.id));
          }
        }
      } else if (d.incidents && d.incidents.length) {
        setIncidents(prev => [...d.incidents, ...prev.filter(i => !d.incidents.some(ni => ni.id === i.id))].slice(0, 20));
      }
      if (d.events && d.events.length) {
        setRecentEvents(prev => [...d.events.slice().reverse(), ...prev].slice(0, 10));
        setLiveEvents(prev => [...d.events, ...prev].slice(0, 200));
      }
      if (d.alerts && d.alerts.length) {
        setAlerts(prev => [...d.alerts, ...prev].slice(0, 3));
      }
    } else if (message.type === 'new_login' || message.type === 'role_updated' || message.type === 'employee_deleted') {
      Promise.all([api.getStats(), api.getEmployees(), api.getIncidents()])
        .then(([statsData, empsData, incidentsData]) => {
          setStats(statsData);
          setEmployees(empsData.sort((a, b) => primaryRisk(b) - primaryRisk(a)));
          setIncidents((incidentsData || []).filter(i => i.status === 'ACTIVE' || i.status === 'INVESTIGATING'));
        })
        .catch((err) => console.error('Failed to refresh dashboard on login/role/employee change', err));
    }
  });

  useEffect(() => {
    setWsConnected(isConnected);
  }, [isConnected]);

  // Primary risk score helper — mirrors EmployeeProfile/IncidentCard logic so
  // employee ranking respects active incident scores.
  const primaryRisk = (emp) => {
    return (emp.incident && (emp.incident.status === 'ACTIVE' || emp.incident.status === 'INVESTIGATING'))
      ? emp.incident.risk_score
      : emp.risk_score;
  };

  useEffect(() => {
    const loadData = async () => {
      try {
        const [statsData, empsData, alertsData, eventsData, incidentsData, actionReqsData] = await Promise.all([
          api.getStats(),
          api.getEmployees(),
          api.getAlerts(),
          api.getEvents(200),
          api.getIncidents(),
          api.getActionRequests('PENDING')
        ]);
        setStats(statsData);
        setEmployees(empsData.sort((a, b) => primaryRisk(b) - primaryRisk(a)));
        setAlerts(alertsData.slice(0, 3));
        setRecentEvents(eventsData.slice(0, 10));
        setLiveEvents(eventsData);
        // Only show active/investigating incidents in the live ticker
        setIncidents((incidentsData || []).filter(i => i.status === 'ACTIVE' || i.status === 'INVESTIGATING'));
        setPendingApprovals(actionReqsData || []);
      } catch (error) {
        console.error("Failed to load dashboard data", error);
      } finally {
        setLoading(false);
      }
    };
    loadData();

    // Fallback polling every 5s for stats/employees/incidents
    const t = setInterval(async () => {
      try {
        const [statsData, empsData, incidentsData, actionReqsData] = await Promise.all([
          api.getStats(),
          api.getEmployees(),
          api.getIncidents(),
          api.getActionRequests('PENDING')
        ]);
        setStats(statsData);
        setEmployees(empsData.sort((a, b) => primaryRisk(b) - primaryRisk(a)));
        setIncidents((incidentsData || []).filter(i => i.status === 'ACTIVE' || i.status === 'INVESTIGATING'));
        setPendingApprovals(actionReqsData || []);
      } catch {
        /* ignore background poll error */
      }
    }, 5000);
    return () => clearInterval(t);
  }, []);

  // Slide the live chart's time window forward every 30s so buckets age out and
  // the axis keeps flowing even when no telemetry is arriving.
  useEffect(() => {
    const t = setInterval(() => setClock(Date.now()), 30000);
    return () => clearInterval(t);
  }, []);

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING COMMAND OVERVIEW...</p>
        </div>
      </div>
    );
  }

  const totalEmployees = stats?.total_employees || 0;
  const highRisk = stats?.high_risk || 0;
  const activeAlerts = stats?.active_alerts || 0;
  const averageRisk = stats?.average_risk !== undefined ? Math.round(stats.average_risk) : 0;
  const onlineEmployees = stats?.online_employees ?? 0;
  const offlineEmployees = stats?.offline_employees ?? 0;

  const liveSeries = buildLiveSeries(liveEvents);

  const statCards = [
    { label: 'Total Employees', value: totalEmployees, sub: 'Active Monitoring', icon: Users, color: 'text-cyber-secondary border-cyber-secondary/20 bg-cyber-secondary/5' },
    { label: 'Online Endpoints', value: `${onlineEmployees}/${totalEmployees}`, sub: `${offlineEmployees} offline`, icon: Radio, color: 'text-cyber-success border-cyber-success/20 bg-cyber-success/5' },
    { label: 'High Risk Users', value: highRisk, sub: 'Immediate Action Required', icon: ShieldAlert, color: 'text-cyber-danger border-cyber-danger/30 bg-cyber-danger/5 animate-pulse' },
    { label: 'Active Threat Alerts', value: activeAlerts, sub: 'Requires Review', icon: AlertTriangle, color: 'text-cyber-warning border-cyber-warning/20 bg-cyber-warning/5' },
    { label: 'Average Risk Score', value: `${averageRisk}%`, sub: 'Healthy Baseline', icon: TrendingUp, color: 'text-cyber-success border-cyber-success/20 bg-cyber-success/5' },
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* JIT Action Approval Modal */}
      <ActionApprovalModal
        isOpen={showApprovalModal}
        onClose={() => setShowApprovalModal(false)}
        onActionResolved={fetchPending}
      />

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Security Command Center</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">LATEST SECURITY STANDINGS & ANOMALIES</p>
        </div>
        <div className="flex items-center gap-2 bg-cyber-card border border-cyber-border px-3 py-1.5 rounded-lg text-xs font-mono">
          <Radio className={`h-4 w-4 ${wsConnected ? 'text-cyber-success animate-pulse' : 'text-cyber-muted'}`} />
          <span className="text-cyber-text">{wsConnected ? 'LIVE FEED ACTIVE' : 'OFFLINE MODE'}</span>
        </div>
      </div>

      {/* Pending JIT Approvals Alert Banner */}
      {pendingApprovals.length > 0 && (
        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3 animate-fade-in shadow-lg shadow-amber-500/5">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 shrink-0">
              <ShieldAlert className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <div className="text-xs font-mono font-bold uppercase text-amber-400">
                {pendingApprovals.length} Action Authorization Request{pendingApprovals.length > 1 ? 's' : ''} Pending
              </div>
              <div className="text-xs text-cyber-text mt-0.5">
                Endpoint interceptor prevented unauthorized file deletion. Security Admin review required before disk execution.
              </div>
            </div>
          </div>
          <button
            onClick={() => setShowApprovalModal(true)}
            className="px-4 py-2 rounded-lg bg-amber-500 hover:bg-amber-400 text-black text-xs font-mono font-bold transition-colors cursor-pointer shrink-0 text-center"
          >
            Review Authorization Queue ({pendingApprovals.length}) →
          </button>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-6">
        {statCards.map((card, i) => {
          const Icon = card.icon;
          return (
            <div key={i} className={`p-6 border rounded-xl glass-panel relative overflow-hidden group ${card.color}`}>
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-xs font-mono uppercase text-cyber-muted tracking-wider">{card.label}</p>
                  <h3 className="text-3xl font-extrabold mt-2 text-cyber-text">{card.value}</h3>
                </div>
                <div className="p-2.5 rounded-lg bg-cyber-bg border border-cyber-border">
                  <Icon className="h-5 w-5" />
                </div>
              </div>
              <p className="text-[10px] text-cyber-muted mt-3 font-mono tracking-wider">{card.sub}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-6 glass-panel flex flex-col">
          <div className="flex justify-between items-center mb-6">
            <div>
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono">Live Telemetry Stream</h4>
              <p className="text-xs text-cyber-muted">Per-minute event volume from the live agent feed</p>
            </div>
            <span className="flex items-center gap-1.5 text-[10px] bg-cyber-danger/10 border border-cyber-danger/25 text-cyber-danger px-2.5 py-1 rounded font-mono font-bold">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-cyber-danger animate-pulse"></span>
              LIVE · LAST {LIVE_WINDOW_MINUTES} MIN
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={liveSeries}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} minTickGap={24} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="usb" fill="#06b6d4" name="USB Inserts" radius={[4, 4, 0, 0]} />
                <Bar dataKey="network" fill="#3b82f6" name="Network Uploads" radius={[4, 4, 0, 0]} />
                <Bar dataKey="files" fill="#a855f7" name="File Activity" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-6 glass-panel flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center mb-6">
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono">High Risk Alerts</h4>
              <span className="text-[10px] text-cyber-danger animate-pulse font-mono font-bold">LATEST EVENTS</span>
            </div>
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div key={alert.id} className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg space-y-1.5 hover:border-cyber-primary/30 transition-colors">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-semibold text-cyber-text">{alert.employee.name}</span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                      alert.severity === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                      alert.severity === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/25'
                    }`}>
                      {alert.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-cyber-muted line-clamp-2 leading-relaxed">{alert.reason}</p>
                  <p className="text-[9px] text-cyber-muted font-mono pt-1">
                    {formatIST(alert.timestamp, { hour: '2-digit', minute: '2-digit' })}
                  </p>
                </div>
              ))}
            </div>
          </div>
          <button 
            onClick={() => navigate('/alerts')}
            className="w-full mt-6 py-2 bg-cyber-border/40 hover:bg-cyber-border/80 border border-cyber-border rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-1 text-cyber-text transition-colors"
          >
            VIEW ALL ALERTS <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="p-6 glass-panel">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono">Active Incidents</h4>
            <p className="text-xs text-cyber-muted">Persistent incident state — stays open until an analyst resolves or archives it</p>
          </div>
          <span className="flex items-center gap-1.5 text-[10px] bg-cyber-primary/10 border border-cyber-primary/25 text-cyber-primary px-2.5 py-1 rounded font-mono font-bold">
            {incidents.length} INCIDENT{incidents.length === 1 ? '' : 'S'}
          </span>
        </div>
        {incidents.length === 0 ? (
          <div className="text-center py-12 text-cyber-muted text-xs font-mono">
            <ShieldAlert className="h-8 w-8 text-cyber-muted mx-auto mb-2" />
            NO ACTIVE INCIDENTS — monitoring is clear
          </div>
        ) : (
          <div className="space-y-4">
            {incidents.map((inc) => (
              <IncidentCard
                key={inc.id ?? `${inc.timestamp}-${inc.employee_id}-${inc.total_events}`}
                incident={inc}
                onChange={() => {
                  // Actions resolve/archive server-side; the 15s refresh keeps
                  // the panel in sync with the authoritative incident list.
                }}
              />
            ))}
          </div>
        )}
      </div>

      <div className="p-6 glass-panel">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono">Monitored Employee Rankings</h4>
            <p className="text-xs text-cyber-muted">Overview of active employees sorted by risk score</p>
          </div>
          <button 
            onClick={() => navigate('/employees')}
            className="text-xs text-cyber-primary font-mono font-bold flex items-center gap-1 hover:underline"
          >
            MANAGE EMPLOYEES <ChevronRight className="h-4 w-4" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[10px] tracking-wider">
                <th className="pb-3 pl-4">Employee</th>
                <th className="pb-3">Role & Dept</th>
                <th className="pb-3">Risk Assessment</th>
                <th className="pb-3">Classification</th>
                <th className="pb-3 text-right pr-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border">
              {employees.slice(0, 6).map((emp) => {
                const incident = emp.incident || null;
                const hasIncident = !!incident;
                const riskScore = hasIncident ? incident.risk_score : emp.risk_score;
                const status = hasIncident ? incident.severity : emp.status;
                const roleType = emp.role_type || 'General';

                const getRoleColor = (r) => {
                  switch (r) {
                    case 'Developer': return 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/30';
                    case 'Finance': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
                    case 'HR': return 'text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/30';
                    case 'Security Analyst': return 'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/30';
                    case 'Administrator': return 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30';
                    case 'IT Support': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
                    case 'Sales': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
                    default: return 'text-cyber-muted bg-cyber-bg border-cyber-border';
                  }
                };

                return (
                  <tr key={emp.id} className="hover:bg-cyber-border/10 transition-colors group">
                    <td className="py-3.5 pl-4 flex items-center gap-3">
                      <div className="h-8 w-8 rounded-full bg-cyber-primary/10 border border-cyber-primary/20 flex items-center justify-center font-mono font-bold text-cyber-primary">
                        {emp.name.split(' ').map(n => n[0]).join('')}
                      </div>
                      <div>
                        <span className="font-semibold text-cyber-text block flex items-center gap-1.5">
                          <span className={`inline-block h-1.5 w-1.5 rounded-full ${emp.online ? 'bg-cyber-success' : 'bg-cyber-danger'}`}></span>
                          {emp.name}
                          {hasIncident && (
                            <span className="text-sm" title={`Active incident: ${incident.title}`}>🚨</span>
                          )}
                        </span>
                        <span className="text-[10px] text-cyber-muted font-mono">{emp.email}</span>
                      </div>
                    </td>
                    <td className="py-3.5">
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-mono px-2 py-0.5 rounded border font-semibold uppercase ${getRoleColor(roleType)}`}>
                          {roleType}
                        </span>
                        <span className="text-[11px] text-cyber-muted font-mono">{emp.department}</span>
                      </div>
                    </td>
                    <td className="py-3.5">
                      <div className="flex items-center gap-3">
                        <div className="w-24 bg-cyber-bg border border-cyber-border h-2 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              riskScore > 75 ? 'bg-cyber-danger' :
                              riskScore > 50 ? 'bg-cyber-warning' :
                              'bg-cyber-success'
                            }`}
                            style={{ width: `${riskScore}%` }}
                          ></div>
                        </div>
                        <span className="font-mono font-semibold">{riskScore}%</span>
                      </div>
                    </td>
                    <td className="py-3.5">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                        status === 'Critical' || status === 'High Risk' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                        status === 'Medium' || status === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                        'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                      }`}>
                        {hasIncident ? incident.severity : status}
                      </span>
                    </td>
                    <td className="py-3.5 text-right pr-4">
                      <button 
                        onClick={() => navigate(`/employees/${emp.id}`)}
                        className="px-3 py-1.5 bg-cyber-primary/10 border border-cyber-primary/25 hover:bg-cyber-primary text-cyber-primary hover:text-cyber-bg rounded text-[11px] font-mono font-bold transition-all"
                      >
                        DNA PROFILE
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      <div className="p-6 glass-panel">
        <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Live Metadata Stream</h4>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border text-cyber-muted font-mono uppercase text-[9px] tracking-wider">
                <th className="pb-3 pl-3">Event Type</th>
                <th className="pb-3">Details</th>
                <th className="pb-3 text-right pr-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono">
              {[...recentEvents].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 10).map((evt) => {
                const isDelete = (evt.event_type || '').toLowerCase().includes('delete');
                const isCreate = (evt.event_type || '').toLowerCase().includes('create');
                const isModify = (evt.event_type || '').toLowerCase().includes('modify');
                const isCopy = (evt.event_type || '').toLowerCase().includes('copy') || (evt.event_type || '').toLowerCase().includes('move');
                const isUsb = (evt.event_type || '').toLowerCase().includes('usb');
                
                const badgeCls = isDelete
                  ? 'text-rose-400 border-rose-500/30 bg-rose-500/10 font-bold'
                  : isCreate
                  ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10 font-bold'
                  : isModify
                  ? 'text-amber-400 border-amber-500/30 bg-amber-500/10 font-bold'
                  : isCopy
                  ? 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10 font-bold'
                  : isUsb
                  ? 'text-purple-400 border-purple-500/30 bg-purple-500/10 font-bold'
                  : 'text-cyber-muted border-cyber-border bg-cyber-bg/50';

                return (
                  <tr key={evt.id || Math.random()} className="hover:bg-cyber-border/10">
                    <td className="py-2.5 pl-3 align-top">
                      <span className={`text-[10px] px-2 py-0.5 rounded border uppercase inline-block whitespace-nowrap ${badgeCls}`}>
                        {evt.event_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-2.5 text-xs text-cyber-text">
                      <div className="font-medium text-cyber-text">
                        {evt.filename || evt.details || '-'}
                      </div>
                      {(evt.folder || (evt.details && evt.details.includes(' in '))) && (
                        <div className="text-[10.5px] text-cyber-muted font-mono mt-0.5 flex items-center gap-1 break-all">
                          <span className="text-[9px] uppercase text-cyber-muted font-bold">
                            {isDelete ? 'Location:' : 'Path:'}
                          </span>
                          <span className="text-cyber-text/80">{evt.folder || evt.details}</span>
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 text-right pr-3 text-cyber-muted text-[10px] whitespace-nowrap align-top">
                      {formatIST(evt.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>
                  </tr>
                );
              })}
              {recentEvents.length === 0 && (
                <tr>
                  <td colSpan="3" className="text-center py-8 text-cyber-muted text-xs font-mono">
                    NO TELEMETRY EVENTS COLLECTED YET
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
