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
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Key,
  Tag,
  Lock,
  Sparkles,
  Layers,
  FileText,
  UserCheck
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST, toISTDate } from '../utils/time';
import IncidentCard from '../components/IncidentCard';

const SUPPORTED_ROLES = [
  'Developer', 
  'HR', 
  'Finance', 
  'Manager', 
  'Sales', 
  'IT Support', 
  'Security Analyst', 
  'Administrator', 
  'General'
];

export default function EmployeeProfile() {
  const { id } = useParams();
  const navigate = useNavigate();
  
  // List Mode States
  const [employees, setEmployees] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [deptFilter, setDeptFilter] = useState('All');
  const [roleFilter, setRoleFilter] = useState('All');
  
  // Detail Mode States
  const [employee, setEmployee] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [commands, setCommands] = useState([]);
  const [commandMsg, setCommandMsg] = useState('');
  const [commandErr, setCommandErr] = useState('');
  const [activityTab, setActivityTab] = useState('all');
  const [loading, setLoading] = useState(true);
  const [resetRiskBusy, setResetRiskBusy] = useState(false);
  const [resetRiskMsg, setResetRiskMsg] = useState('');
  const [resetRiskErr, setResetRiskErr] = useState('');
  const [roleSaving, setRoleSaving] = useState(false);
  const [roleMsg, setRoleMsg] = useState('');

  const userRole = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin'; }
    catch { return 'admin'; }
  })();
  const isAdmin = userRole === 'admin';

  const handleResetRisk = async () => {
    if (!id || !isAdmin) return;
    setResetRiskBusy(true);
    setResetRiskMsg('');
    setResetRiskErr('');
    try {
      const res = await api.resetEmployeeRisk(parseInt(id, 10));
      const score = res?.employee?.risk_score ?? 0;
      const status = res?.employee?.status ?? 'Safe';
      setEmployee((prev) => prev ? { ...prev, risk_score: score, status, incident: null } : prev);
      setAiAnalysis((prev) => prev
        ? { ...prev, risk_score: score, status }
        : { risk_score: score, status, reasons: [], recommendations: [] });
      setResetRiskMsg('✓ Risk reset to 0% / Safe. Active incident resolved (Manual Override).');
      setTimeout(() => setResetRiskMsg(''), 5000);
      await loadData(true);
    } catch (err) {
      setResetRiskErr(err?.response?.data?.detail || 'Failed to reset risk.');
    } finally {
      setResetRiskBusy(false);
    }
  };

  const handleRoleChange = async (newRole) => {
    if (!id) return;
    setRoleSaving(true);
    setRoleMsg('');
    try {
      const updated = await api.updateEmployeeRole(parseInt(id), newRole);
      setEmployee(updated);
      setAiAnalysis(updated.ai_analysis || null);
      setRoleMsg(`✓ Role updated to "${newRole}". AI risk recalculation complete.`);
      setTimeout(() => setRoleMsg(''), 4000);
    } catch (err) {
      console.error("Failed to update role", err);
    } finally {
      setRoleSaving(false);
    }
  };

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

  // Live WebSocket updates
  const { lastMessage } = useWebSocket();
  const reloadDebounceRef = useRef(null);

  useEffect(() => {
    if (!lastMessage) return;

    if (id && lastMessage.type === 'risk_update' && lastMessage.data) {
      const { employee_id, risk_score, status, reasons, recommendations, deviation, model_anomaly, model_score } = lastMessage.data;
      if (employee_id === parseInt(id)) {
        setEmployee(prev => prev ? { ...prev, risk_score, status } : prev);
        setAiAnalysis(prev => ({
          ...(prev || {}),
          risk_score,
          status,
          reasons: reasons || prev?.reasons || [],
          recommendations: recommendations || prev?.recommendations || [],
          deviation: deviation || prev?.deviation || {},
          model_anomaly: model_anomaly ?? prev?.model_anomaly ?? false,
          model_score: model_score ?? prev?.model_score ?? 0,
        }));
      }
    }

    if (
      lastMessage.type === 'batch_ingested' ||
      lastMessage.type === 'incident_created' ||
      lastMessage.type === 'incident_updated' ||
      lastMessage.type === 'incident_resolved' ||
      lastMessage.type === 'role_updated'
    ) {
      if (reloadDebounceRef.current) clearTimeout(reloadDebounceRef.current);
      reloadDebounceRef.current = setTimeout(() => {
        loadData(true);
      }, 500);
    }
  }, [lastMessage, id, loadData]);

  const getRecommendations = (score) => {
    if (score > 75) {
      return [
        { action: 'Block USB Access Immediately', desc: 'Revoke local mass-storage permissions.' },
        { action: 'Isolate Endpoint Device', desc: 'Sever local TCP network sockets.' },
        { action: 'Notify SOC Incident Lead', desc: 'Flag profile for urgent investigation.' },
      ];
    } else if (score > 50) {
      return [
        { action: 'Increase Audit Frequency', desc: 'Set endpoint heartbeat window to 30s.' },
        { action: 'Monitor Active Processes', desc: 'Capture running task trees.' },
      ];
    }
    return [
      { action: 'Routine Monitoring', desc: 'Telemetry within normal baseline limits.' }
    ];
  };

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case 'Developer': return 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/30';
      case 'Finance': return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'HR': return 'text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/30';
      case 'Security Analyst': return 'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/30';
      case 'Administrator': return 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30';
      case 'IT Support': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'Sales': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'Manager': return 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30';
      default: return 'text-cyber-muted bg-cyber-bg border-cyber-border';
    }
  };

  if (loading && !employee && employees.length === 0) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">EXTRACTING BEHAVIOR TELEMETRY & BASELINE PROFILES...</p>
        </div>
      </div>
    );
  }

  // ==========================================
  // RENDER DETAILED PROFILE
  // ==========================================
  if (id && employee) {
    const dna = employee.behavior_profile || {};
    const chartData = (employee.risk_scores || []).map(r => ({
      date: formatIST(r.recorded_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
      score: r.score
    }));

    const activeInc = employee.incident || null;
    const headerRisk = activeInc ? activeInc.risk_score : employee.risk_score;
    const headerStatus = activeInc ? activeInc.severity : employee.status;

    const fmtAvg = (val) => {
      if (val === undefined || val === null || isNaN(val)) return '0.00';
      return Number(val).toFixed(2);
    };

    const roleBaseline = employee.role_baseline || {};
    const sensitiveFiles = employee.sensitive_files_accessed || [];
    const topKeywords = employee.top_matched_keywords || [];
    const lastRule = employee.last_triggered_rule || aiAnalysis?.last_triggered_rule || 'Standard Monitoring';

    const eventsList = employee.events || [];
    const filteredEvents = eventsList.filter(e => {
      if (activityTab === 'all') return true;
      if (activityTab === 'sensitive') {
        const fname = (e.filename || '').toLowerCase();
        const details = (e.details || '').toLowerCase();
        return topKeywords.some(k => fname.includes(k.keyword) || details.includes(k.keyword));
      }
      if (activityTab === 'files') return (e.event_type || '').startsWith('file_');
      if (activityTab === 'usb') return (e.event_type || '').startsWith('usb_');
      if (activityTab === 'processes') return (e.event_type || '').startsWith('process_');
      if (activityTab === 'network') return e.event_type === 'network_upload';
      return true;
    });

    return (
      <div className="space-y-8 animate-fade-in pb-12">
        {/* Top Navigation */}
        <div className="flex items-center justify-between">
          <button 
            onClick={() => navigate('/employees')}
            className="flex items-center gap-2 text-xs font-mono text-cyber-muted hover:text-cyber-primary transition-colors cursor-pointer"
          >
            <ArrowLeft className="h-4 w-4" /> BACK TO MONITORED EMPLOYEES DIRECTORY
          </button>
        </div>

        {/* Employee Header Panel */}
        <div className="p-6 glass-panel border border-cyber-border/80 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="flex items-center gap-4">
            <div className="h-16 w-16 rounded-full bg-cyber-primary/10 border-2 border-cyber-primary/30 flex items-center justify-center font-mono font-bold text-cyber-primary text-xl shadow-cyber">
              {employee.name.split(' ').map(n => n[0]).join('')}
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-3">
                <h2 className="text-2xl font-bold tracking-tight">{employee.name}</h2>
                <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded border uppercase font-bold ${getRoleBadgeColor(employee.role_type)}`}>
                  {employee.role_type || 'General'}
                </span>
              </div>
              <p className="text-xs font-mono text-cyber-muted uppercase">
                {employee.email} • {employee.department} {employee.hostname ? `• Host: ${employee.hostname}` : ''}
              </p>
              {/* Admin Role Selector Dropdown */}
              <div className="flex items-center gap-2 pt-1">
                <span className="text-[10px] font-mono uppercase text-cyber-muted flex items-center gap-1">
                  <UserCheck className="h-3.5 w-3.5 text-cyber-primary" /> Assigned Role:
                </span>
                <select
                  value={employee.role_type || 'General'}
                  onChange={(e) => handleRoleChange(e.target.value)}
                  disabled={roleSaving}
                  className="bg-cyber-bg border border-cyber-border rounded px-2.5 py-1 text-xs font-mono font-bold text-cyber-primary focus:outline-none focus:border-cyber-primary cursor-pointer disabled:opacity-50"
                >
                  {SUPPORTED_ROLES.map(r => (
                    <option key={r} value={r} className="bg-cyber-card text-cyber-text">{r}</option>
                  ))}
                </select>
                {roleSaving && <span className="text-[10px] font-mono text-cyber-muted animate-pulse">RECALCULATING RISK...</span>}
              </div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
            <div className="flex items-center gap-6 bg-cyber-bg/50 border border-cyber-border px-5 py-3 rounded-lg">
              <div>
                <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Risk Assessment</span>
                <span className="text-3xl font-extrabold text-cyber-text font-mono">
                  {headerRisk}%
                </span>
              </div>
              <div className="h-10 w-px bg-cyber-border"></div>
              <div>
                <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Classification</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded border inline-block mt-1 font-semibold uppercase ${
                  headerStatus === 'Critical' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                  headerStatus === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                  headerStatus === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                  headerStatus === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                  'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                }`}>
                  {headerStatus}
                </span>
              </div>
            </div>
            {isAdmin && (
              <button
                type="button"
                onClick={handleResetRisk}
                disabled={resetRiskBusy}
                title="Force risk to 0% / Safe and resolve active incident (Manual Override)"
                className="px-3 py-2 bg-cyber-danger/10 hover:bg-cyber-danger text-cyber-danger hover:text-cyber-bg rounded border border-cyber-danger/30 text-[10px] font-mono font-bold uppercase tracking-wide transition-colors disabled:opacity-50 cursor-pointer"
              >
                {resetRiskBusy ? 'RESETTING…' : 'RESET RISK TO 0'}
              </button>
            )}
          </div>
        </div>

        {roleMsg && (
          <div className="p-3 bg-cyber-success/10 border border-cyber-success/30 rounded-lg text-xs text-cyber-success font-mono flex items-center gap-2 animate-fade-in">
            <CheckCircle className="h-4 w-4" /> {roleMsg}
          </div>
        )}
        {resetRiskMsg && (
          <div className="p-2.5 bg-cyber-success/10 border border-cyber-success/30 rounded text-[10px] text-cyber-success font-mono">
            {resetRiskMsg}
          </div>
        )}
        {resetRiskErr && (
          <div className="p-2.5 bg-cyber-danger/10 border border-cyber-danger/30 rounded text-[10px] text-cyber-danger font-mono">
            {resetRiskErr}
          </div>
        )}

        {/* Role Baseline & Sensitive Asset Intelligence Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: Role Baseline Profile */}
          <div className="p-5 glass-panel border border-cyber-border/80 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-cyber-border/50 pb-2.5">
                <span className="text-xs font-bold font-mono uppercase text-cyber-primary flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4" /> Role Baseline Profile
                </span>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getRoleBadgeColor(employee.role_type)}`}>
                  {employee.role_type}
                </span>
              </div>
              <p className="text-[11px] text-cyber-muted mt-2 leading-relaxed">
                {roleBaseline.description || 'Standard corporate baseline configuration.'}
              </p>
              
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between py-1 border-b border-cyber-border/30">
                  <span className="text-cyber-muted text-[10px]">COMMON EXTENSIONS</span>
                  <span className="text-cyber-text text-[10px] font-semibold truncate max-w-[160px]">
                    {(roleBaseline.common_extensions || ['.docx', '.pdf', '.xlsx']).join(', ')}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-cyber-border/30">
                  <span className="text-cyber-muted text-[10px]">DAILY FILE OPS NORM</span>
                  <span className="text-cyber-secondary text-[10px] font-bold">
                    ≤ {roleBaseline.max_daily_file_operations || 200} ops/day
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-cyber-border/30">
                  <span className="text-cyber-muted text-[10px]">SOURCE CODE OPERATIONS</span>
                  <span className={`text-[10px] font-bold ${roleBaseline.source_code_normal ? 'text-cyber-success' : 'text-cyber-danger'}`}>
                    {roleBaseline.source_code_normal ? 'Permitted (Normal)' : 'Abnormal (+Risk)'}
                  </span>
                </div>
              </div>
            </div>
            <div className="text-[9px] font-mono text-cyber-muted bg-cyber-bg p-2 rounded border border-cyber-border">
              Config: {roleBaseline.process_activity_norm || 'Standard office workstation activity'}
            </div>
          </div>

          {/* Card 2: Last Triggered Security Rule */}
          <div className="p-5 glass-panel border border-cyber-border/80 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-cyber-border/50 pb-2.5">
                <span className="text-xs font-bold font-mono uppercase text-cyber-warning flex items-center gap-2">
                  <Sparkles className="h-4 w-4" /> Last Triggered Rule
                </span>
                <span className="text-[9px] font-mono text-cyber-muted uppercase">EVALUATION ENGINE</span>
              </div>

              <div className="mt-3 p-3 bg-cyber-bg/80 border border-cyber-border rounded-lg space-y-1.5">
                <span className="text-[10px] text-cyber-muted font-mono uppercase block">ACTIVE SECURITY TRIGGER</span>
                <span className="text-xs font-mono font-bold text-cyber-text block text-cyber-warning">
                  {lastRule}
                </span>
              </div>

              <div className="mt-3 space-y-1.5 text-[11px] text-cyber-text">
                <span className="text-[10px] font-mono text-cyber-muted uppercase block">AI REASONING LOG</span>
                {(aiAnalysis?.reasons || []).slice(0, 2).map((r, idx) => (
                  <div key={idx} className="flex items-start gap-1.5 text-cyber-muted text-[10.5px] leading-tight">
                    <span className="text-cyber-primary font-bold">›</span>
                    <span>{r}</span>
                  </div>
                ))}
                {(!aiAnalysis?.reasons || aiAnalysis.reasons.length === 0) && (
                  <p className="text-[10px] font-mono text-cyber-muted">Operating within normal baseline tolerances.</p>
                )}
              </div>
            </div>
            <div className="text-[9px] font-mono text-cyber-muted bg-cyber-bg p-2 rounded border border-cyber-border">
              Evaluation Confidence: <strong className="text-cyber-primary">{aiAnalysis?.confidence ?? 0}%</strong>
            </div>
          </div>

          {/* Card 3: Sensitive Company Assets Accessed */}
          <div className="p-5 glass-panel border border-cyber-border/80 flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between border-b border-cyber-border/50 pb-2.5">
                <span className="text-xs font-bold font-mono uppercase text-cyber-secondary flex items-center gap-2">
                  <Key className="h-4 w-4" /> Sensitive Files Accessed
                </span>
                <span className="text-[10px] font-mono font-bold text-cyber-danger bg-cyber-danger/10 border border-cyber-danger/30 px-2 py-0.5 rounded">
                  {sensitiveFiles.length} DETECTED
                </span>
              </div>

              <div className="mt-3 space-y-2">
                <span className="text-[10px] text-cyber-muted font-mono uppercase block">TOP MATCHED KEYWORDS</span>
                <div className="flex flex-wrap gap-1.5">
                  {topKeywords.map((k, i) => (
                    <span key={i} className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary rounded">
                      <Tag className="h-2.5 w-2.5" /> {k.keyword} <strong className="text-cyber-text">({k.count})</strong>
                    </span>
                  ))}
                  {topKeywords.length === 0 && (
                    <span className="text-[10px] font-mono text-cyber-muted">No sensitive asset keywords matched.</span>
                  )}
                </div>
              </div>

              {sensitiveFiles.length > 0 && (
                <div className="mt-3 space-y-1">
                  <span className="text-[10px] text-cyber-muted font-mono uppercase block">RECENT SENSITIVE MOVEMENTS</span>
                  {sensitiveFiles.slice(0, 2).map((m, i) => (
                    <div key={i} className="p-1.5 bg-cyber-bg rounded border border-cyber-border text-[10px] font-mono flex justify-between items-center">
                      <span className="truncate max-w-[150px] text-cyber-text">{m.filename}</span>
                      <span className="text-cyber-warning font-bold shrink-0">+{m.risk_added} Risk</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
            <div className="text-[9px] font-mono text-cyber-muted bg-cyber-bg p-2 rounded border border-cyber-border">
              Real-time pattern match over filename, path & archive headers
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
                        <td className="py-3 text-cyber-text">{h.resolved_by || '—'}</td>
                        <td className="py-3 text-cyber-muted max-w-xs truncate">{h.resolution_reason || '—'}</td>
                        <td className="py-3 text-right pr-4 text-cyber-muted whitespace-nowrap">
                          {formatIST(h.resolved_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

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
                        <stop offset="5%" stopColor={headerRisk > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0.4}/>
                        <stop offset="95%" stopColor={headerRisk > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0}/>
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
                      stroke={headerRisk > 75 ? '#ef4444' : '#06b6d4'} 
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

        {/* Activity Logs & Telemetry Events */}
        <div className="p-6 glass-panel border border-cyber-border/80 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border/50 pb-4">
            <h3 className="text-sm font-bold uppercase font-mono text-cyber-text flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyber-primary" /> Telemetry & Activity Stream
            </h3>
            {/* Filter Tabs */}
            <div className="flex flex-wrap gap-1.5">
              {[
                { id: 'all', label: 'All Telemetry' },
                { id: 'sensitive', label: 'Sensitive Files' },
                { id: 'files', label: 'File Ops' },
                { id: 'usb', label: 'USB Events' },
                { id: 'processes', label: 'Processes' },
                { id: 'network', label: 'Network' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActivityTab(tab.id)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors cursor-pointer ${
                    activityTab === tab.id
                      ? 'bg-cyber-primary text-cyber-bg font-bold'
                      : 'bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-text'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
            {filteredEvents.map((evt, idx) => (
              <div key={idx} className="p-3 bg-cyber-bg/60 border border-cyber-border/60 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono hover:border-cyber-primary/40 transition-colors">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-cyber-border/50 text-cyber-secondary shrink-0">
                    {evt.event_type}
                  </span>
                  <span className="text-cyber-text truncate">
                    {evt.filename || evt.details || evt.folder || 'Telemetry event'}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[10px] text-cyber-muted shrink-0">
                  {evt.size && <span>{evt.size}</span>}
                  {evt.usb_status && <span className="text-cyber-warning">{evt.usb_status}</span>}
                  <span>{formatIST(evt.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
                </div>
              </div>
            ))}
            {filteredEvents.length === 0 && (
              <div className="py-8 text-center text-xs font-mono text-cyber-muted">
                No activity records found matching this filter.
              </div>
            )}
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
    const matchesRole = roleFilter === 'All' || (emp.role_type || 'General') === roleFilter;
    return matchesSearch && matchesDept && matchesRole;
  });

  const departments = ['All', ...new Set(employees.map(emp => emp.department).filter(Boolean))];
  const roles = ['All', ...SUPPORTED_ROLES];

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Monitored Employees Directory</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
          SEARCH EMPLOYEES, ASSIGN ROLES & VIEW BEHAVIOR DNA PROFILES
        </p>
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

        {/* Role Filter Select */}
        <div className="relative min-w-[160px]">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
            <UserCheck className="h-4 w-4" />
          </span>
          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
          >
            {roles.map(r => (
              <option key={r} value={r} className="bg-cyber-card">Role: {r}</option>
            ))}
          </select>
        </div>

        {/* Department Filter Select */}
        <div className="relative min-w-[180px]">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
            <Filter className="h-4 w-4" />
          </span>
          <select
            value={deptFilter}
            onChange={(e) => setDeptFilter(e.target.value)}
            className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
          >
            {departments.map(dept => (
              <option key={dept} value={dept} className="bg-cyber-card">Dept: {dept}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Grid of Employees Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredEmployees.map((emp) => {
          const incident = emp.incident || null;
          const riskScore = incident ? incident.risk_score : emp.risk_score;
          const status = incident ? incident.severity : emp.status;
          return (
            <div key={emp.id} className="p-6 glass-panel border border-cyber-border/80 flex flex-col justify-between min-h-60 hover:border-cyber-primary/60 transition-all">
              <div>
                {/* Header */}
                <div className="flex justify-between items-start gap-3 mb-4">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-cyber-primary/10 border border-cyber-primary/20 flex items-center justify-center font-mono font-bold text-cyber-primary">
                      {emp.name.split(' ').map(n => n[0]).join('')}
                    </div>
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span className={`h-2 w-2 rounded-full ${emp.online ? 'bg-cyber-success' : 'bg-cyber-danger'}`}></span>
                        <h4 className="font-bold text-cyber-text text-sm">{emp.name}</h4>
                      </div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className="text-[10px] text-cyber-muted font-mono">{emp.department}</span>
                        <span className="text-[10px] text-cyber-muted">•</span>
                        <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border font-semibold ${getRoleBadgeColor(emp.role_type)}`}>
                          {emp.role_type || 'General'}
                        </span>
                      </div>
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
                className="w-full mt-4 py-2 bg-cyber-border/40 hover:bg-cyber-primary text-cyber-text hover:text-cyber-bg hover:border-cyber-primary rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-1 border border-cyber-border transition-all cursor-pointer"
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
