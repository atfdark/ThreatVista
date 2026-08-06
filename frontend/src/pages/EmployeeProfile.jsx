import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, 
  Search, 
  Filter, 
  Calendar, 
  FileCode, 
  Laptop, 
  Monitor, 
  HardDrive, 
  Activity, 
  BrainCircuit, 
  AlertOctagon, 
  CheckCircle,
  Database,
  ArrowRight
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST, toISTDate } from '../utils/time';
import IncidentCard from '../components/IncidentCard';

export default function EmployeeProfile() {
  const { id } = useParams();
  const navigate = useNavigate();
  
  // List Mode States
  const [employees, setEmployees] = useState([]);
  const [aiScores, setAiScores] = useState({});
  const [searchTerm, setSearchTerm] = useState('');
  const [deptFilter, setDeptFilter] = useState('All');
  
  // Detail Mode States
  const [employee, setEmployee] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [commands, setCommands] = useState([]);
  const [commandMsg, setCommandMsg] = useState('');
  const [commandErr, setCommandErr] = useState('');
  const [activityTab, setActivityTab] = useState('all');
  const [loading, setLoading] = useState(true);

  // Simulated remote-command actions from the SOC console
  const handleCommand = async (command, label) => {
    if (!id) return;
    setCommandMsg('');
    setCommandErr('');
    try {
      const cmd = await api.requestCommand(parseInt(id), command);
      setCommands(prev => [cmd, ...prev]);
      setCommandMsg(`✓ "${label}" dispatched to endpoint agent (simulated).`);
      setTimeout(() => setCommandMsg(''), 5000);
    } catch (err) {
      setCommandErr(err?.response?.data?.detail || `Failed to dispatch "${label}".`);
    }
  };

  const RELATIVE_TIME = (iso) => {
    if (!iso) return 'never';
    const diff = Math.max(0, (Date.now() - (toISTDate(iso)?.getTime() ?? 0)) / 1000);
    if (diff < 5) return 'just now';
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  };

  // Load appropriate data
  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      if (id) {
        const detail = await api.getEmployeeDetail(parseInt(id));
        setEmployee(detail);
        setAiAnalysis(detail.ai_analysis || null);
        setCommands(detail.commands || []);
      } else {
        const list = await api.getEmployees();
        setEmployees(list);
        const scores = {};
        for (const emp of list) {
          const ai = await api.getAIAnalysis(emp.id);
          if (ai) scores[emp.id] = ai;
        }
        setAiScores(scores);
      }
    } catch (err) {
      console.error("Failed to load employee data", err);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Live: keep the profile / directory fresh without a manual refresh.
  useEffect(() => {
    const t = setInterval(() => loadData(true), 15000);
    return () => clearInterval(t);
  }, [loadData]);

  // Live telemetry / risk / incidents → refresh this employee's detail so
  // Activity Explorer, Behavior DNA, and Historical Risk stay current.
  // Debounced so a busy endpoint's batch flood doesn't hammer the AI endpoint.
  const refreshTimer = useRef(null);
  useWebSocket((msg) => {
    const empId = id ? parseInt(id, 10) : null;
    const data = msg.data || {};
    const matchesEmployee = (() => {
      if (!empId) return true; // directory view — any device/event may matter
      if (msg.type === 'device_connected') return data.employee?.id === empId;
      if (msg.type === 'batch_event') {
        if (data.employee_id === empId) return true;
        return (data.events || []).some(e => e.employee_id === empId);
      }
      if (msg.type === 'risk_update') return Object.prototype.hasOwnProperty.call(data, empId) || Object.prototype.hasOwnProperty.call(data, String(empId));
      if (data.employee_id != null) return data.employee_id === empId;
      if (data.employee?.id != null) return data.employee.id === empId;
      return false;
    })();

    if (!matchesEmployee) return;

    if ([
      'device_connected',
      'new_event',
      'new_alert',
      'batch_event',
      'risk_update',
      'incident_created',
      'incident_updated',
      'incident_resolved',
      'incident_archived',
    ].includes(msg.type)) {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      refreshTimer.current = setTimeout(() => loadData(true), 800);
    }
  });

  useEffect(() => () => {
    if (refreshTimer.current) clearTimeout(refreshTimer.current);
  }, []);

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING TELEMETRY PORTAL...</p>
        </div>
      </div>
    );
  }

  // ==========================================
  // RENDER DETAILED PROFILE
  // ==========================================
  if (id && employee) {
    const events = Array.isArray(employee.events) ? employee.events : [];
    const alerts = Array.isArray(employee.alerts) ? employee.alerts : [];
    const dna = employee.behavior_profile || {
      working_hours_baseline: "09:00 - 17:00",
      avg_usb_inserts_per_day: 0,
      avg_file_copies_per_day: 0,
      avg_upload_mb_per_day: 0,
    };
    const fmtAvg = (n) => {
      const v = Number(n);
      if (!Number.isFinite(v)) return '0';
      return v < 10 ? v.toFixed(2) : String(Math.round(v * 10) / 10);
    };

    // Format chart date
    const chartData = (employee.risk_scores || []).map(score => ({
      date: formatIST(score.recorded_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
      score: score.score
    }));

    const matchesActivityTab = (evt) => {
      const t = evt.event_type || '';
      if (activityTab === 'usb') return t.includes('usb');
      if (activityTab === 'process') return t.includes('process');
      if (activityTab === 'files') return t.includes('file') || t.includes('folder');
      if (activityTab === 'system') return t.includes('system') || t.includes('network') || t.includes('login');
      return true;
    };

    // AI recommendation rules
    const getRecommendations = (score) => {
      if (score > 75) {
        return [
          { action: "Revoke USB Access", desc: "Instantly disable read/write USB mass storage access on the client machine via endpoint agent policy." },
          { action: "Trigger Audit Logs Extraction", desc: "Force endpoint agent to upload detailed process tree execution logs for the last 24 hours." },
          { action: "Flag with HR & Security", desc: "Coordinate immediate security audit meeting. Flag employee profile for restricted source code repository access." }
        ];
      } else if (score > 40) {
        return [
          { action: "Increase Baseline Frequency", desc: "Reduce Behavior DNA recalculation window from 14 days to 48 hours." },
          { action: "Enable Network Rate Limiting", desc: "Restrict outbound network speeds to external domains to prevent large-volume packet transfers." }
        ];
      }
      return [
        { action: "Standard Monitoring", desc: "Behavior matches baseline DNA bounds. Continue standard background metadata ingestion." }
      ];
    };

    return (
      <div className="space-y-8 animate-fade-in">
        {/* Back navigation */}
        <button 
          onClick={() => navigate('/employees')}
          className="flex items-center gap-2 text-xs font-mono font-bold text-cyber-primary uppercase hover:underline focus:outline-none"
        >
          <ArrowLeft className="h-4 w-4" /> BACK TO MONITORING DIRECTORY
        </button>

        {/* Employee Header Panel */}
        <div className="p-6 glass-panel border border-cyber-border/80 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="flex items-center gap-4">
            <div className="h-16 w-16 rounded-full bg-cyber-primary/10 border-2 border-cyber-primary/30 flex items-center justify-center font-mono font-bold text-cyber-primary text-xl shadow-cyber">
              {employee.name.split(' ').map(n => n[0]).join('')}
            </div>
            <div>
              <h2 className="text-2xl font-bold tracking-tight">{employee.name}</h2>
              <p className="text-xs font-mono text-cyber-muted mt-1 uppercase">{employee.email} • {employee.department}</p>
            </div>
          </div>

          <div className="flex items-center gap-6 bg-cyber-bg/50 border border-cyber-border px-5 py-3 rounded-lg">
            <div>
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Risk Assessment</span>
              <span className="text-3xl font-extrabold text-cyber-text font-mono">
                {aiAnalysis ? `${aiAnalysis.risk_score}%` : `${employee.risk_score}%`}
              </span>
            </div>
            <div className="h-10 w-px bg-cyber-border"></div>
            <div>
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Classification</span>
              <span className={`text-xs font-mono px-2 py-0.5 rounded border inline-block mt-1 font-semibold uppercase ${
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Critical' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
              }`}>
                {aiAnalysis ? aiAnalysis.status : employee.status}
              </span>
            </div>
          </div>
        </div>

        {/* Current Incident (persistent lifecycle, monotonic risk) */}
        {employee.incident && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold font-mono uppercase text-cyber-muted tracking-wider flex items-center gap-2">
              <AlertOctagon className="h-5 w-5 text-cyber-danger" /> Current Incident
            </h3>
            <IncidentCard incident={employee.incident} onChange={() => loadData(true)} />
          </div>
        )}

        {/* Resolution History */}
        {employee.incident_history && employee.incident_history.length > 0 && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold font-mono uppercase text-cyber-muted tracking-wider flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-cyber-success" /> Resolution History
            </h3>
            <div className="glass-panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[9px] tracking-wider">
                      <th className="py-3 pl-4">Incident</th>
                      <th className="py-3">Severity</th>
                      <th className="py-3">Status</th>
                      <th className="py-3">Resolved By</th>
                      <th className="py-3">Reason</th>
                      <th className="py-3 text-right pr-4">Resolved At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-cyber-border/40 font-mono">
                    {employee.incident_history.map((h) => (
                      <tr key={h.id} className="hover:bg-cyber-border/10">
                        <td className="py-3 pl-4 text-cyber-text">{h.title}</td>
                        <td className="py-3 whitespace-nowrap">
                          <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase ${
                            h.severity === 'Critical' || h.severity === 'High'
                              ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25'
                              : 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25'
                          }`}>
                            {h.severity}
                          </span>
                        </td>
                        <td className="py-3 text-cyber-muted uppercase">{h.status}</td>
                        <td className="py-3 text-cyber-muted">{h.resolved_by || '—'}</td>
                        <td className="py-3 text-cyber-muted">{h.resolution_reason || '—'}</td>
                        <td className="py-3 pr-4 text-right text-cyber-muted whitespace-nowrap">
                          {h.resolved_at ? formatIST(h.resolved_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* EDR: Endpoint Status / Device Info / Health */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Online status */}
          <div className="p-5 glass-panel border border-cyber-border/80 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">Endpoint Status</span>
              <span className={`h-2.5 w-2.5 rounded-full ${employee.online ? 'bg-cyber-success shadow-[0_0_10px_#10b981] animate-pulse' : 'bg-cyber-danger shadow-[0_0_10px_#ef4444]'}`}></span>
            </div>
            <div className="mt-3">
              <span className={`text-xl font-extrabold font-mono ${employee.online ? 'text-cyber-success' : 'text-cyber-danger'}`}>
                {employee.online ? 'ONLINE' : 'OFFLINE'}
              </span>
              <p className="text-[10px] text-cyber-muted font-mono mt-1">
                Last heartbeat {RELATIVE_TIME(employee.endpoint_health?.last_seen_at)}
              </p>
            </div>
          </div>

          {/* Device info */}
          <div className="p-5 glass-panel border border-cyber-border/80 md:col-span-2">
            <div className="flex items-center gap-2 border-b border-cyber-border/50 pb-3 mb-3">
              <Laptop className="h-4 w-4 text-cyber-secondary" />
              <h4 className="text-xs font-bold uppercase font-mono">Endpoint Device Profile</h4>
            </div>
            {employee.device ? (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-[11px]">
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">Hostname</span><span className="text-cyber-text font-semibold">{employee.device.hostname || '-'}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">OS</span><span className="text-cyber-text">{employee.device.os_version || '-'}{employee.device.os_build ? ` (${employee.device.os_build})` : ''}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">CPU</span><span className="text-cyber-text">{employee.device.cpu_model || '-'}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">IP Address</span><span className="text-cyber-text font-mono">{employee.device.ip_address || '-'}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">RAM</span><span className="text-cyber-text">{employee.device.ram_gb ? `${employee.device.ram_gb} GB` : '-'}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">Disk Free</span><span className="text-cyber-text">{employee.device.disk_free_gb ? `${employee.device.disk_free_gb} GB` : '-'}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">Device ID</span><span className="text-cyber-text font-mono">{employee.device.device_id}</span></div>
                <div><span className="block text-[9px] text-cyber-muted uppercase font-mono">Agent</span><span className="text-cyber-text">v{employee.device.agent_version || '-'}</span></div>
              </div>
            ) : (
              <div className="text-cyber-muted text-xs font-mono py-4">NO ENDPOINT AGENT REGISTERED FOR THIS EMPLOYEE</div>
            )}
          </div>
        </div>

        {/* Endpoint health strip */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
          {[
            { label: 'CPU USAGE', value: employee.endpoint_health?.cpu_usage, color: 'text-cyber-secondary' },
            { label: 'MEMORY USAGE', value: employee.endpoint_health?.ram_usage, color: 'text-cyber-accent' },
            { label: 'DISK USAGE', value: employee.endpoint_health?.disk_usage, color: 'text-cyber-warning' },
          ].map(metric => {
            const val = metric.value;
            const pct = typeof val === 'number' ? Math.min(100, Math.max(0, val)) : 0;
            return (
              <div key={metric.label} className="p-4 glass-panel border border-cyber-border/80">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-[9px] text-cyber-muted font-mono uppercase tracking-wider">{metric.label}</span>
                  <span className={`text-xs font-bold font-mono ${metric.color}`}>{val !== null && val !== undefined ? `${Math.round(val)}%` : '--'}</span>
                </div>
                <div className="w-full bg-cyber-bg border border-cyber-border h-1.5 rounded-full overflow-hidden">
                  <div className={`h-full ${metric.color} bg-current`} style={{ width: `${pct}%` }}></div>
                </div>
              </div>
            );
          })}
        </div>
        {/* EDR: Behavior Timeline + Activity Explorer */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Behavior timeline */}
          <div className="lg:col-span-2 p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-5 flex items-center gap-2">
              <Activity className="h-4.5 w-4.5 text-cyber-primary" /> Behavior Timeline
            </h4>
            <div className="space-y-0">
              {(() => {
                // Chronological newest-first. File/folder activity (created /
                // deleted / modified files) is the DLP signal that matters, so
                // keep those entries always visible instead of letting process /
                // network noise push them off the window.
                const sorted = [...events].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
                const isFile = (e) => (e.event_type || '').startsWith('file_') || (e.event_type || '').startsWith('folder_');
                const files = sorted.filter(isFile);
                const others = sorted.filter((e) => !isFile(e));
                const list = [...files.slice(0, 8), ...others.slice(0, 12)]
                  .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
                return list.map((evt, i) => {
                  const dotColor =
                    evt.event_type === 'usb_insert' || evt.event_type === 'usb_remove' ? 'bg-cyber-primary' :
                    evt.event_type === 'file_create' || evt.event_type === 'folder_create' || evt.event_type === 'file_copy' ? 'bg-cyber-accent' :
                    evt.event_type === 'file_delete' || evt.event_type === 'folder_delete' ? 'bg-cyber-danger' :
                    evt.event_type === 'file_modify' ? 'bg-cyber-warning' :
                    evt.event_type === 'network_upload' ? 'bg-cyber-secondary' :
                    evt.event_type === 'login' ? 'bg-cyber-success' : 'bg-cyber-muted';
                  return (
                    <div key={evt.id} className="flex gap-4">
                      <div className="flex flex-col items-center">
                        <div className={`mt-1.5 h-2.5 w-2.5 rounded-full ${dotColor} shadow-[0_0_6px_rgba(0,0,0,0.5)]`}></div>
                        {i < list.length - 1 && <div className="w-px flex-1 bg-cyber-border/60 my-1"></div>}
                      </div>
                      <div className="pb-4">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-cyber-muted font-mono">
                            {formatIST(evt.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </span>
                          <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase bg-cyber-bg/60 border-cyber-border">
                            {(evt.event_type || '').replace(/_/g, ' ')}
                          </span>
                        </div>
                        <p className="text-[11px] text-cyber-text leading-relaxed mt-1">{evt.details || 'No detail'}</p>
                      </div>
                    </div>
                  );
                });
              })()}
              {events.length === 0 && (
                <div className="text-cyber-muted text-xs font-mono py-6 text-center">NO TELEMETRY TO TIMELINE</div>
              )}
            </div>
          </div>

          {/* Activity category explorer + remote commands */}
          <div className="space-y-6">
            <div className="p-6 glass-panel">
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Activity Explorer</h4>
              <div className="flex flex-wrap gap-2 mb-4">
                {[
                  { key: 'all', label: 'All' },
                  { key: 'usb', label: 'USB' },
                  { key: 'process', label: 'Processes' },
                  { key: 'files', label: 'Files' },
                  { key: 'system', label: 'System' },
                ].map(tab => (
                  <button
                    key={tab.key}
                    onClick={() => setActivityTab(tab.key)}
                    className={`px-2.5 py-1 rounded text-[10px] font-mono font-bold uppercase border transition-colors ${
                      activityTab === tab.key
                        ? 'bg-cyber-primary text-cyber-bg border-cyber-primary'
                        : 'text-cyber-muted border-cyber-border hover:text-cyber-text'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
              <div className="max-h-56 overflow-y-auto space-y-2 pr-1">
                {events
                  .filter(matchesActivityTab)
                  .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
                  .slice(0, 20)
                  .map(evt => (
                    <div key={evt.id} className="flex justify-between items-start gap-2 p-2 bg-cyber-bg/50 border border-cyber-border rounded">
                      <div className="min-w-0">
                        <span className="text-[9px] font-mono uppercase text-cyber-muted block">
                          {(evt.event_type || '').replace(/_/g, ' ')}
                        </span>
                        <span className="text-[10px] text-cyber-text break-words">{evt.details || (evt.event_type || '').replace(/_/g, ' ')}</span>
                      </div>
                      <span className="text-[9px] text-cyber-muted font-mono shrink-0">
                        {formatIST(evt.timestamp, { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  ))}
                {events.filter(matchesActivityTab).length === 0 && (
                  <div className="text-cyber-muted text-xs font-mono text-center py-4">NO ACTIVITY IN THIS CATEGORY</div>
                )}
              </div>
            </div>

            {/* Remote commands (simulated) */}
            <div className="p-6 glass-panel">
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-1 flex items-center gap-2">
                <Monitor className="h-4.5 w-4.5 text-cyber-secondary" /> Remote Endpoint Commands
              </h4>
              <p className="text-[9px] text-cyber-muted font-mono mb-4">SIMULATED — NO MACHINE CONTROL</p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { cmd: 'disable_usb', label: 'Disable USB', color: 'border-cyber-danger/35 text-cyber-danger bg-cyber-danger/10 hover:bg-cyber-danger hover:text-cyber-bg' },
                  { cmd: 'restart_agent', label: 'Restart Agent', color: 'border-cyber-warning/35 text-cyber-warning bg-cyber-warning/10 hover:bg-cyber-warning hover:text-cyber-bg' },
                  { cmd: 'collect_logs', label: 'Collect Logs', color: 'border-cyber-secondary/35 text-cyber-secondary bg-cyber-secondary/10 hover:bg-cyber-secondary hover:text-cyber-bg' },
                  { cmd: 'refresh_config', label: 'Refresh Config', color: 'border-cyber-primary/35 text-cyber-primary bg-cyber-primary/10 hover:bg-cyber-primary hover:text-cyber-bg' },
                ].map(btn => (
                  <button
                    key={btn.cmd}
                    onClick={() => handleCommand(btn.cmd, btn.label)}
                    className={`px-2 py-2 rounded border text-[10px] font-mono font-bold uppercase tracking-wide transition-colors ${btn.color}`}
                  >
                    {btn.label}
                  </button>
                ))}
              </div>

              {commandMsg && (
                <div className="mt-3 p-2.5 bg-cyber-success/10 border border-cyber-success/30 rounded text-[10px] text-cyber-success font-mono">
                  {commandMsg}
                </div>
              )}
              {commandErr && (
                <div className="mt-3 p-2.5 bg-cyber-danger/10 border border-cyber-danger/30 rounded text-[10px] text-cyber-danger font-mono">
                  {commandErr}
                </div>
              )}

              {commands.length > 0 && (
                <div className="mt-4 space-y-2">
                  <span className="text-[9px] text-cyber-muted font-mono uppercase tracking-wider block">Command History</span>
                  {commands.slice(0, 5).map(cmd => (
                    <div key={cmd.id} className="flex justify-between items-center p-2 bg-cyber-bg/50 border border-cyber-border rounded text-[10px]">
                      <span className="text-cyber-text font-mono">{cmd.label}</span>
                      <span className="text-[9px] text-cyber-success font-mono">{cmd.status} · {RELATIVE_TIME(cmd.completed_at)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Behavior DNA Profiling (Baseline) */}
        <div>
          <h3 className="text-sm font-bold font-mono uppercase text-cyber-muted tracking-wider mb-4 flex items-center gap-2">
            <BrainCircuit className="h-5 w-5 text-cyber-primary" /> Personalized Behavior DNA (Rolling Baseline)
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Baseline Shift Hours</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{dna.working_hours_baseline || '09:00 - 17:00'}</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Normal daily working boundary</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily USB Inserts</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{fmtAvg(dna.avg_usb_inserts_per_day)} insertions/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Plug & Play hardware interactions</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily Copies</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{fmtAvg(dna.avg_file_copies_per_day)} operations/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">File system read & copy transfers</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily Network Upload</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{fmtAvg(dna.avg_upload_mb_per_day)} MB/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Outbound packet bandwidth baseline</span>
            </div>
          </div>
        </div>

        {/* Risk Trend & AI summary */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Line Chart */}
          <div className="lg:col-span-2 p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-6">Historical Risk Progression</h4>
            <div className="h-64">
              {chartData.length === 0 ? (
                <div className="h-full flex items-center justify-center text-cyber-muted text-xs font-mono text-center px-6">
                  NO RISK HISTORY YET — SCORES APPEAR AS TELEMETRY IS ANALYZED
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={chartData}>
                    <defs>
                      <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0.4}/>
                        <stop offset="95%" stopColor={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                    <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
                    <YAxis stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 100]} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                      itemStyle={{ color: '#f8fafc' }}
                    />
                    <Area 
                      type="monotone" 
                      dataKey="score" 
                      stroke={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} 
                      strokeWidth={2}
                      fillOpacity={1} 
                      fill="url(#colorRisk)" 
                      name="Risk score %"
                    />
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          {/* Explainable AI Recommendations */}
          <div className="p-6 glass-panel flex flex-col justify-between">
            <div>
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4 flex items-center gap-2">
                <BrainCircuit className="h-4.5 w-4.5 text-cyber-primary" /> Explainable AI (XAI) Recommendation
              </h4>
              {aiAnalysis ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <span className="text-3xl font-extrabold text-cyber-text font-mono">{aiAnalysis.risk_score}%</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                      aiAnalysis.status === 'Critical' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                      aiAnalysis.status === 'High' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      aiAnalysis.status === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                    }`}>
                      {aiAnalysis.status}
                    </span>
                    {aiAnalysis.model_anomaly && (
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded border border-cyber-danger/25 text-cyber-danger bg-cyber-danger/10">
                        ISOLATION FOREST ANOMALY
                      </span>
                    )}
                  </div>
                  {/* AI confidence */}
                  <div className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg">
                    <div className="flex justify-between items-center mb-1.5">
                      <span className="text-[9px] text-cyber-muted font-mono uppercase tracking-wider">Model Confidence</span>
                      <span className="text-xs font-bold text-cyber-primary font-mono">{aiAnalysis.confidence ?? 0}%</span>
                    </div>
                    <div className="w-full bg-cyber-bg border border-cyber-border h-1.5 rounded-full overflow-hidden">
                      <div className="h-full bg-cyber-primary" style={{ width: `${aiAnalysis.confidence ?? 0}%` }}></div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">Detected Risk Factors</span>
                    {(aiAnalysis.reasons || []).map((reason, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <CheckCircle className={`h-3.5 w-3.5 shrink-0 mt-0.5 ${aiAnalysis.risk_score > 75 ? 'text-cyber-danger' : 'text-cyber-primary'}`} />
                        <span className="text-[11px] text-cyber-text leading-relaxed">{reason}</span>
                      </div>
                    ))}
                    {(aiAnalysis.reasons || []).length === 0 && (
                      <p className="text-[11px] text-cyber-muted font-mono">No elevated risk factors detected.</p>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {getRecommendations(employee.risk_score).map((rec, i) => (
                    <div key={i} className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg space-y-1">
                      <div className="flex items-center gap-2">
                        <CheckCircle className={`h-4 w-4 shrink-0 ${employee.risk_score > 75 ? 'text-cyber-danger' : 'text-cyber-primary'}`} />
                        <span className="text-xs font-bold text-cyber-text uppercase font-mono">{rec.action}</span>
                      </div>
                      <p className="text-[10px] text-cyber-muted leading-relaxed">{rec.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {aiAnalysis && (
              <div className="text-[10.5px] text-cyber-muted font-mono leading-relaxed mt-4 p-3 bg-cyber-border/20 border border-cyber-border rounded">
                <span className="text-cyber-text font-bold uppercase block mb-1">AI Model Output</span>
                Isolation Forest raw score: {Number(aiAnalysis.model_score ?? 0).toFixed(4)} | Anomaly: {aiAnalysis.model_anomaly ? 'Yes' : 'No'}
                <br/>
                Recommended: {(aiAnalysis.recommendations || []).slice(0, 2).join('; ') || 'Continue monitoring'}
              </div>
            )}
          </div>
        </div>

        {/* Telemetry Event Streams */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Events Log */}
          <div className="lg:col-span-2 p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Raw Metadata Telemetry Stream</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-cyber-border text-cyber-muted font-mono uppercase text-[9px] tracking-wider">
                    <th className="pb-3 pl-3">Event Type</th>
                    <th className="pb-3">Telemetry Details</th>
                    <th className="pb-3 text-right pr-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/40 font-mono">
                  {events.map((evt) => (
                    <tr key={evt.id} className="hover:bg-cyber-border/10">
                      <td className="py-2.5 pl-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase ${
                          evt.event_type === 'usb_insert' ? 'text-cyber-primary border-cyber-primary/20 bg-cyber-primary/5' :
                          evt.event_type === 'file_copy' ? 'text-cyber-accent border-cyber-accent/20 bg-cyber-accent/5' :
                          evt.event_type === 'network_upload' ? 'text-cyber-secondary border-cyber-secondary/20 bg-cyber-secondary/5' :
                          'text-cyber-muted border-cyber-border bg-cyber-bg/50'
                        }`}>
                          {(evt.event_type || '').replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="py-2.5 text-xs text-cyber-text">{evt.details}</td>
                      <td className="py-2.5 text-right pr-3 text-cyber-muted text-[10px]">
                        {formatIST(evt.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  ))}
                  {events.length === 0 && (
                    <tr>
                      <td colSpan={3} className="py-8 text-center text-cyber-muted font-mono text-xs">
                        NO TELEMETRY EVENTS YET
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Connected Alerts List */}
          <div className="p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Correlated Security Alerts</h4>
            <div className="space-y-4">
              {alerts.length === 0 ? (
                <div className="text-center py-8 text-cyber-muted text-xs font-mono">
                  NO ACTIVE CORRELATED ALERTS
                </div>
              ) : (
                alerts.map((alert) => (
                  <div key={alert.id} className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg space-y-1.5">
                    <div className="flex justify-between items-center">
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                        alert.severity === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                        'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25'
                      }`}>
                        {alert.severity} Severity
                      </span>
                      <span className="text-[10px] text-cyber-muted font-mono">{alert.status}</span>
                    </div>
                    <p className="text-[11px] text-cyber-text leading-relaxed">{alert.reason}</p>
                    <p className="text-[9px] text-cyber-muted font-mono">
                      {formatIST(alert.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

      </div>
    );
  }

  // ==========================================
  // RENDER MONITORED EMPLOYEES DIRECTORY
  // ==========================================
  const filteredEmployees = employees.filter(emp => {
    const matchesSearch = emp.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          emp.email.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesDept = deptFilter === 'All' || emp.department === deptFilter;
    return matchesSearch && matchesDept;
  });

  const departments = ['All', ...new Set(employees.map(emp => emp.department))];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Monitored Employees Directory</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">SEARCH EMPLOYEES & VIEW BEHAVIOR DNA PROFILES</p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search Input */}
        <div className="relative flex-1">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
            <Search className="h-4 w-4" />
          </span>
          <input
            type="text"
            placeholder="Search employees by name or email..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary transition-colors"
          />
        </div>

        {/* Department Filter Select */}
        <div className="relative min-w-[200px]">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
            <Filter className="h-4 w-4" />
          </span>
          <select
            value={deptFilter}
            onChange={(e) => setDeptFilter(e.target.value)}
            className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
          >
            {departments.map(dept => (
              <option key={dept} value={dept} className="bg-cyber-card">{dept}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Grid of Employees Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredEmployees.map((emp) => {
          const ai = aiScores[emp.id];
          const riskScore = ai ? ai.risk_score : emp.risk_score;
          const status = ai ? ai.status : emp.status;
          return (
            <div key={emp.id} className="p-6 glass-panel border border-cyber-border/80 flex flex-col justify-between h-56">
              <div>
                {/* Header */}
                <div className="flex justify-between items-start gap-4 mb-4">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-cyber-primary/10 border border-cyber-primary/20 flex items-center justify-center font-mono font-bold text-cyber-primary">
                      {emp.name.split(' ').map(n => n[0]).join('')}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className={`h-2 w-2 rounded-full ${emp.online ? 'bg-cyber-success' : 'bg-cyber-danger'}`}></span>
                        <h4 className="font-bold text-cyber-text text-sm">{emp.name}</h4>
                      </div>
                      <span className="text-[10px] text-cyber-muted font-mono">{emp.department}{emp.hostname ? ` · ${emp.hostname}` : ''}</span>
                    </div>
                  </div>
                  <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                    status === 'Critical' || status === 'High Risk' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                    status === 'Medium' || status === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                    'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                  }`}>
                    {status}
                  </span>
                </div>

                {/* Risk Score bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono">
                    <span className="text-cyber-muted">RISK INDEX</span>
                    <span className="font-bold text-cyber-text">{riskScore}%</span>
                  </div>
                  <div className="w-full bg-cyber-bg border border-cyber-border h-2 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${
                        riskScore > 75 ? 'bg-cyber-danger' : 
                        riskScore > 50 ? 'bg-cyber-warning' : 
                        'bg-cyber-success'
                      }`}
                      style={{ width: `${riskScore}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Bottom Navigate button */}
              <button 
                onClick={() => navigate(`/employees/${emp.id}`)}
                className="w-full mt-4 py-2 bg-cyber-border/40 hover:bg-cyber-primary text-cyber-text hover:text-cyber-bg hover:border-cyber-primary rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-1 border border-cyber-border transition-all"
              >
                ANALYZE BEHAVIOR DNA <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}

        {filteredEmployees.length === 0 && (
          <div className="col-span-full text-center py-16 glass-panel">
            <AlertOctagon className="h-10 w-10 text-cyber-warning mx-auto mb-3" />
            <p className="text-sm font-mono text-cyber-muted">NO MONITORED EMPLOYEES MATCHED SEARCH CRITERIA</p>
          </div>
        )}
      </div>
    </div>
  );
}
