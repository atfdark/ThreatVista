import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  Filter,
  Search,
  ShieldAlert,
  CheckCircle2,
  Clock,
  ChevronDown,
  ChevronRight,
  RefreshCw,
  Bot,
  RotateCcw,
  Sparkles
} from 'lucide-react';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST } from '../utils/time';
import ThreatCopilotDrawer from '../components/ThreatCopilotDrawer';
import MassRecoveryModal from '../components/MassRecoveryModal';


const RESOLVE_REASONS = ['False Positive', 'Threat Removed', 'Manual Override'];

/** Timeline dot colour per entry type (matches IncidentCard). */
const TIMELINE_DOT = {
  created: 'bg-cyber-primary',
  evidence: 'bg-cyber-accent',
  risk_increase: 'bg-cyber-danger',
  status_change: 'bg-cyber-warning',
  resolved: 'bg-cyber-success',
  archived: 'bg-cyber-muted',
};

function SeverityBadge({ severity }) {
  const cls =
    severity === 'Critical'
      ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30 shadow-[0_0_8px_rgba(239,68,68,0.15)]'
      : severity === 'High'
      ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25'
      : 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25';
  return (
    <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${cls}`}>
      {severity || 'Medium'}
    </span>
  );
}

function StatusBadge({ status }) {
  const cls =
    status === 'ACTIVE'
      ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30'
      : status === 'INVESTIGATING'
      ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30'
      : status === 'RESOLVED'
      ? 'text-cyber-success bg-cyber-success/10 border-cyber-success/30'
      : 'text-cyber-muted bg-cyber-bg/50 border-cyber-border';
  return (
    <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${cls}`}>
      {status || 'ACTIVE'}
    </span>
  );
}

export default function Incidents() {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState([]);
  const [statusFilter, setStatusFilter] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [resolvingId, setResolvingId] = useState(null);
  const [reason, setReason] = useState(RESOLVE_REASONS[0]);
  const [busyId, setBusyId] = useState(null);
  const [actionError, setActionError] = useState('');
  const [loading, setLoading] = useState(true);
  const [showCopilotDrawer, setShowCopilotDrawer] = useState(false);
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const [selectedEmpForCopilot, setSelectedEmpForCopilot] = useState(null);

  // Role gates: investigate/resolve = admin+analyst; archive + reset-risk = admin.
  const role = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin'; }
    catch { return 'admin'; }
  })();
  const canAct = role === 'admin' || role === 'analyst';
  const canArchive = role === 'admin';

  const loadIncidents = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await api.getIncidents();
      setIncidents(data);
    } catch (err) {
      console.error("Failed to load incidents", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  // Live: refetch on any incident lifecycle broadcast + 10s polling fallback.
  useWebSocket((msg) => {
    if (['incident_created', 'incident_updated', 'incident_resolved', 'incident_archived', 'device_connected', 'risk_update'].includes(msg.type)) {
      loadIncidents(true);
    }
  });
  useEffect(() => {
    const t = setInterval(() => loadIncidents(true), 10000);
    return () => clearInterval(t);
  }, []);

  const runAction = async (incidentId, fn) => {
    setActionError('');
    setBusyId(incidentId);
    try {
      await fn();
      await loadIncidents(true);
    } catch (err) {
      setActionError(err?.response?.data?.detail || 'Action failed. Try again.');
    } finally {
      setBusyId(null);
      setResolvingId(null);
      setReason(RESOLVE_REASONS[0]);
    }
  };

  const handleResolve = (incidentId) => {
    runAction(incidentId, () => api.resolveIncident(incidentId, reason));
  };

  const handleArchive = (incidentId) => {
    runAction(incidentId, () => api.archiveIncident(incidentId));
  };

  const handleResetRisk = (incidentId) => {
    runAction(incidentId, () => api.resetIncidentRisk(incidentId));
  };

  const filteredIncidents = incidents.filter((inc) => {
    const matchesStatus =
      statusFilter === 'All' ? true : inc.status === statusFilter;
    const matchesSeverity =
      severityFilter === 'All' ? true : inc.severity === severityFilter;
    const matchesSearch =
      searchTerm === ''
        ? true
        : (inc.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
          (inc.employee?.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
          (inc.employee?.department || '').toLowerCase().includes(searchTerm.toLowerCase());
    return matchesStatus && matchesSeverity && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING INCIDENT LEDGER...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Mass Rollback Demo Modal */}
      <MassRecoveryModal
        isOpen={showRecoveryModal}
        onClose={() => setShowRecoveryModal(false)}
      />

      {/* ARGUS Drawer */}
      <ThreatCopilotDrawer
        isOpen={showCopilotDrawer}
        onClose={() => setShowCopilotDrawer(false)}
        selectedEmployee={selectedEmpForCopilot}
      />

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Incident Management</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
            PERSISTENT INCIDENTS · MONOTONIC RISK · FULL TIMELINE
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => setShowRecoveryModal(true)}
            className="flex items-center gap-1.5 px-3 py-2 bg-cyber-primary/20 text-cyber-primary border border-cyber-primary/50 hover:bg-cyber-primary/30 rounded-lg text-xs font-mono font-bold transition-all shadow-cyber"
            title="Open Ransomware Mass Rollback Demo"
          >
            <RotateCcw className="h-4 w-4" />
            <span>MASS ROLLBACK DEMO</span>
          </button>

          <button
            onClick={() => {
              setSelectedEmpForCopilot(null);
              setShowCopilotDrawer(true);
            }}
            className="flex items-center gap-1.5 px-3 py-2 bg-cyber-accent/20 text-cyber-accent border border-cyber-accent/50 hover:bg-cyber-accent/30 rounded-lg text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(168,85,247,0.2)]"
            title="Ask ARGUS"
          >
            <Bot className="h-4 w-4 animate-pulse" />
            <span>ARGUS</span>
          </button>

          <button
            onClick={loadIncidents}
            className="flex items-center gap-2 px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text hover:text-cyber-primary transition-colors focus:outline-none"
          >
            <RefreshCw className="h-4 w-4" /> REFRESH LEDGER
          </button>
        </div>
      </div>

      {actionError && (
        <div className="flex items-center gap-2 px-4 py-3 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg text-xs text-cyber-danger font-mono">
          <AlertTriangle className="h-4 w-4" />
          {actionError}
        </div>
      )}
      {!canAct && (
        <div className="flex items-center gap-2 px-4 py-3 bg-cyber-warning/10 border border-cyber-warning/30 rounded-lg text-xs text-cyber-warning font-mono">
          <ShieldAlert className="h-4 w-4" />
          READ-ONLY AUDITOR — investigate / resolve / archive actions are disabled.
        </div>
      )}

      {/* Filter + Search Bar */}
      <div className="flex flex-col xl:flex-row gap-4">
        <div className="relative flex-1">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
            <Search className="h-4 w-4" />
          </span>
          <input
            type="text"
            placeholder="Search incidents by employee name or title..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary transition-colors"
          />
        </div>

        <div className="flex flex-col sm:flex-row gap-4">
          <div className="relative min-w-[160px]">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
              <Filter className="h-4 w-4" />
            </span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
            >
              <option value="All" className="bg-cyber-card">All Severities</option>
              <option value="Critical" className="bg-cyber-card text-cyber-danger">Critical</option>
              <option value="High" className="bg-cyber-card text-cyber-danger">High</option>
              <option value="Medium" className="bg-cyber-card text-cyber-warning">Medium</option>
              <option value="Low" className="bg-cyber-card text-cyber-secondary">Low</option>
            </select>
          </div>

          <div className="relative min-w-[160px]">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
              <Filter className="h-4 w-4" />
            </span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
            >
              <option value="All" className="bg-cyber-card">All Statuses</option>
              <option value="ACTIVE" className="bg-cyber-card text-cyber-danger">ACTIVE</option>
              <option value="INVESTIGATING" className="bg-cyber-card text-cyber-warning">INVESTIGATING</option>
              <option value="RESOLVED" className="bg-cyber-card text-cyber-success">RESOLVED</option>
              <option value="ARCHIVED" className="bg-cyber-card text-cyber-muted">ARCHIVED</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[9px] tracking-wider">
                <th className="py-4 pl-4">Employee</th>
                <th className="py-4">Incident</th>
                <th className="py-4">Severity</th>
                <th className="py-4">Status</th>
                <th className="py-4">Risk</th>
                <th className="py-4">Confidence</th>
                <th className="py-4">Created</th>
                <th className="py-4 text-right pr-4">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono">
              {filteredIncidents.map((inc) => {
                const isExpanded = expandedId === inc.id;
                const isClosed = inc.status === 'RESOLVED' || inc.status === 'ARCHIVED';
                const busy = busyId === inc.id;
                return (
                  <React.Fragment key={inc.id}>
                    <tr className="hover:bg-cyber-border/10 transition-colors group">
                      <td className="py-4 pl-4 font-semibold text-cyber-text whitespace-nowrap">
                        <button
                          onClick={() => navigate(`/employees/${inc.employee_id}`)}
                          className="hover:underline hover:text-cyber-primary transition-colors text-left"
                        >
                          {inc.employee?.name || `Employee #${inc.employee_id}`}
                        </button>
                      </td>
                      <td className="py-4 max-w-[240px]">
                        <button
                          onClick={() => setExpandedId(isExpanded ? null : inc.id)}
                          className="flex items-center gap-1.5 text-cyber-text text-left hover:text-cyber-primary transition-colors"
                        >
                          <ChevronRight className={`h-3.5 w-3.5 shrink-0 text-cyber-muted transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                          <span className="truncate">{inc.title}</span>
                        </button>
                      </td>
                      <td className="py-4 whitespace-nowrap"><SeverityBadge severity={inc.severity} /></td>
                      <td className="py-4 whitespace-nowrap"><StatusBadge status={inc.status} /></td>
                      <td className="py-4 whitespace-nowrap">
                        <span className={`font-bold ${inc.risk_score >= 75 ? 'text-cyber-danger' : inc.risk_score >= 50 ? 'text-cyber-warning' : 'text-cyber-success'}`}>
                          {inc.risk_score}
                        </span>
                      </td>
                      <td className="py-4 text-cyber-muted">{inc.confidence}%</td>
                      <td className="py-4 text-cyber-muted whitespace-nowrap text-[10px]">
                        <div className="flex items-center gap-1.5">
                          <Clock className="h-3 w-3" />
                          {formatIST(inc.created_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </div>
                      </td>
                      <td className="py-4 text-right pr-4 whitespace-nowrap">
                        <div className="flex justify-end gap-2">
                          {canAct && inc.status === 'ACTIVE' && (
                            <button
                              disabled={busy}
                              onClick={() => runAction(inc.id, () => api.investigateIncident(inc.id))}
                              className="px-2 py-1 bg-cyber-warning/15 hover:bg-cyber-warning text-cyber-warning hover:text-cyber-bg rounded border border-cyber-warning/35 text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
                            >
                              INVESTIGATE
                            </button>
                          )}
                          {canAct && !isClosed && (
                            <button
                              disabled={busy}
                              onClick={() => { setResolvingId(resolvingId === inc.id ? null : inc.id); setReason(RESOLVE_REASONS[0]); }}
                              className="px-2 py-1 bg-cyber-success/15 hover:bg-cyber-success text-cyber-success hover:text-cyber-bg rounded border border-cyber-success/35 text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
                            >
                              RESOLVE
                            </button>
                          )}
                          {canArchive && inc.status !== 'ARCHIVED' && (
                            <button
                              disabled={busy}
                              onClick={() => runAction(inc.id, () => api.archiveIncident(inc.id))}
                              className="px-2 py-1 bg-cyber-muted/10 hover:bg-cyber-muted text-cyber-muted hover:text-cyber-bg rounded border border-cyber-border text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
                            >
                              ARCHIVE
                            </button>
                          )}
                          {canArchive && (
                            <button
                              disabled={busy}
                              onClick={() => runAction(inc.id, () => api.resetEmployeeRisk(inc.employee_id))}
                              title="Admin-only: force employee risk to 0 and resolve the active incident as a Manual Override"
                              className="px-2 py-1 bg-cyber-danger/10 hover:bg-cyber-danger text-cyber-danger hover:text-cyber-bg rounded border border-cyber-danger/30 text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
                            >
                              RESET RISK
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Expandable detail row */}
                    {isExpanded && (
                      <tr>
                        <td colSpan="8" className="px-4 py-4 bg-cyber-bg/30 border-t border-cyber-border/40">
                          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* Timeline */}
                            <div>
                              <p className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted mb-3">
                                Evidence Timeline ({inc.timeline?.length || 0})
                              </p>
                              <ul className="space-y-3">
                                {(inc.timeline || []).map((entry, idx) => (
                                  <li key={idx} className="relative flex gap-3 pl-5">
                                    <span className={`absolute left-0 top-1.5 h-2 w-2 rounded-full ${TIMELINE_DOT[entry.type] || 'bg-cyber-muted'}`} />
                                    <div>
                                      <p className="text-[11px] text-cyber-text">{entry.title}</p>
                                      {entry.detail && <p className="text-[10px] text-cyber-muted break-words">{entry.detail}</p>}
                                      <p className="text-[9px] text-cyber-muted/70 mt-0.5">
                                        {formatIST(entry.ts, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                                      </p>
                                    </div>
                                  </li>
                                ))}
                                {(inc.timeline || []).length === 0 && (
                                  <li className="text-[10px] font-mono text-cyber-muted">No timeline entries recorded.</li>
                                )}
                              </ul>
                            </div>

                            {/* Resolution + quick resolve */}
                            <div className="space-y-4">
                              <div>
                                <p className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted mb-2">Resolution</p>
                                {isClosed ? (
                                  <div className="text-[11px] font-mono text-cyber-muted space-y-1">
                                    <p><span className="text-cyber-text">Status:</span> {inc.status}</p>
                                    <p><span className="text-cyber-text">Resolved by:</span> {inc.resolved_by || '—'}</p>
                                    <p><span className="text-cyber-text">Reason:</span> {inc.resolution_reason || '—'}</p>
                                    <p><span className="text-cyber-text">Resolved at:</span> {inc.resolved_at ? formatIST(inc.resolved_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}</p>
                                  </div>
                                ) : (
                                  <p className="text-[11px] font-mono text-cyber-muted">Still open — no resolution recorded.</p>
                                )}
                              </div>

                              {resolvingId === inc.id && canAct && !isClosed && (
                                <div className="flex flex-wrap items-center gap-2 p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg">
                                  <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted">Reason:</span>
                                  <select
                                    value={reason}
                                    onChange={(e) => setReason(e.target.value)}
                                    className="px-2 py-1.5 bg-cyber-card border border-cyber-border rounded text-[11px] text-cyber-text focus:outline-none focus:border-cyber-success"
                                  >
                                    {RESOLVE_REASONS.map(r => (
                                      <option key={r} value={r} className="bg-cyber-card">{r}</option>
                                    ))}
                                    <option value="__custom" className="bg-cyber-card">Custom…</option>
                                  </select>
                                  <input
                                    value={reason === '__custom' ? '' : reason}
                                    onChange={(e) => setReason(e.target.value)}
                                    placeholder="Custom reason"
                                    className="px-2 py-1.5 bg-cyber-card border border-cyber-border rounded text-[11px] text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-success"
                                  />
                                  <button
                                    disabled={busy || !reason}
                                    onClick={() => runAction(inc.id, () => api.resolveIncident(inc.id, reason))}
                                    className="px-3 py-1.5 bg-cyber-success text-cyber-bg rounded text-[10px] font-bold tracking-wider hover:bg-cyber-success/80 transition-all disabled:opacity-50"
                                  >
                                    CONFIRM
                                  </button>
                                  <button
                                    onClick={() => setResolvingId(null)}
                                    className="px-3 py-1.5 bg-transparent border border-cyber-border text-cyber-muted rounded text-[10px] font-bold tracking-wider hover:text-cyber-text transition-all"
                                  >
                                    CANCEL
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}

              {filteredIncidents.length === 0 && (
                <tr>
                  <td colSpan="8" className="text-center py-12 text-cyber-muted">
                    <CheckCircle2 className="h-8 w-8 text-cyber-success mx-auto mb-2" />
                    NO INCIDENTS MATCHING THE FILTERS
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
