import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  X,
  Clock,
  Folder,
  FileText,
  User,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Lock,
  FileLock,
  Globe,
  Cpu,
  HelpCircle,
  Timer
} from 'lucide-react';
import { api } from '../services/mockData';
import { formatIST } from '../utils/time';
import EmployeeBehaviorPanel from './EmployeeBehaviorPanel';

function getClassificationBadge(classification) {
  switch ((classification || '').toUpperCase()) {
    case 'RESTRICTED':
      return {
        label: 'RESTRICTED',
        style: 'text-purple-400 bg-purple-500/10 border-purple-500/40 shadow-sm shadow-purple-500/20',
        icon: Lock,
      };
    case 'CONFIDENTIAL':
      return {
        label: 'CONFIDENTIAL',
        style: 'text-rose-400 bg-rose-500/10 border-rose-500/40 shadow-sm shadow-rose-500/20',
        icon: FileLock,
      };
    case 'INTERNAL':
      return {
        label: 'INTERNAL',
        style: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
        icon: FileText,
      };
    case 'PUBLIC':
      return {
        label: 'PUBLIC',
        style: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
        icon: Globe,
      };
    default:
      return {
        label: 'INTERNAL',
        style: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
        icon: FileText,
      };
  }
}

function getRiskLevelBadge(level, score) {
  const lvl = (level || (score >= 61 ? 'HIGH' : score >= 26 ? 'MEDIUM' : 'LOW')).toUpperCase();
  if (lvl === 'HIGH') {
    return {
      label: `HIGH (${score}%)`,
      style: 'text-rose-400 bg-rose-500/10 border-rose-500/40 font-bold animate-pulse',
    };
  }
  if (lvl === 'MEDIUM') {
    return {
      label: `MEDIUM (${score}%)`,
      style: 'text-amber-400 bg-amber-500/10 border-amber-500/30 font-bold',
    };
  }
  return {
    label: `LOW (${score}%)`,
    style: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
  };
}

export default function ActionApprovalModal({ isOpen, onClose, onActionResolved }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('pending'); // 'pending' | 'history'
  const [actionNotes, setActionNotes] = useState({});
  const [processingId, setProcessingId] = useState(null);

  const loadRequests = async () => {
    setLoading(true);
    try {
      const data = await api.getActionRequests(tab === 'pending' ? 'PENDING' : null);
      setRequests(data || []);
    } catch (err) {
      console.error('Failed to load action requests', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadRequests();
    }
  }, [isOpen, tab]);

  if (!isOpen) return null;

  const handleApprove = async (id) => {
    setProcessingId(id);
    try {
      const notes = actionNotes[id] || 'Approved by Security Administrator';
      await api.approveActionRequest(id, notes);
      await loadRequests();
      if (onActionResolved) onActionResolved();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to approve action');
    } finally {
      setProcessingId(null);
    }
  };

  const handleReject = async (id) => {
    setProcessingId(id);
    try {
      const reason = actionNotes[id] || 'Action denied: security policy violation';
      await api.rejectActionRequest(id, reason);
      await loadRequests();
      if (onActionResolved) onActionResolved();
    } catch (err) {
      alert(err.response?.data?.detail || 'Failed to reject action');
    } finally {
      setProcessingId(null);
    }
  };

  // Filter and deduplicate pending items defensively
  const uniquePending = [];
  const seenPendingKeys = new Set();
  for (const r of requests) {
    if (r.status === 'PENDING' && !r.is_expired) {
      const key = `${r.employee_id}_${r.action_type}_${r.target_file}`;
      if (!seenPendingKeys.has(key)) {
        seenPendingKeys.add(key);
        uniquePending.push(r);
      }
    }
  }

  const pendingList = uniquePending;
  const historyList = requests.filter(r => r.status !== 'PENDING' || r.is_expired);
  const currentList = tab === 'pending' ? pendingList : historyList;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-3xl bg-cyber-card border border-cyber-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="p-5 border-b border-cyber-border/80 flex items-center justify-between bg-cyber-bg/90">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyber-warning/10 border border-cyber-warning/30 text-cyber-warning">
              <ShieldAlert className="h-6 w-6 animate-pulse" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-cyber-text tracking-wide flex items-center gap-2">
                JIT Action Authorization Center
              </h2>
              <p className="text-xs font-mono text-cyber-muted">
                AI File Classification • Dynamic Risk Scoring • 5-Minute Auto-Expiry Queue
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/40 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Controls */}
        <div className="px-5 pt-3 border-b border-cyber-border/60 flex items-center justify-between bg-cyber-bg/40">
          <div className="flex gap-2">
            <button
              onClick={() => setTab('pending')}
              className={`px-3 py-1.5 rounded-t text-xs font-mono font-bold transition-all border-b-2 cursor-pointer ${
                tab === 'pending'
                  ? 'text-cyber-primary border-cyber-primary bg-cyber-card'
                  : 'text-cyber-muted border-transparent hover:text-cyber-text'
              }`}
            >
              Pending Authorization ({pendingList.length})
            </button>
            <button
              onClick={() => setTab('history')}
              className={`px-3 py-1.5 rounded-t text-xs font-mono font-bold transition-all border-b-2 cursor-pointer ${
                tab === 'history'
                  ? 'text-cyber-primary border-cyber-primary bg-cyber-card'
                  : 'text-cyber-muted border-transparent hover:text-cyber-text'
              }`}
            >
              Resolved & Expired History ({historyList.length})
            </button>
          </div>
          <button
            onClick={loadRequests}
            disabled={loading}
            className="text-[11px] font-mono text-cyber-muted hover:text-cyber-primary flex items-center gap-1 pb-1 cursor-pointer"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>

        {/* Content List */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {loading && (
            <div className="py-12 text-center text-xs font-mono text-cyber-muted">
              Loading intercepted action tickets...
            </div>
          )}

          {!loading && currentList.length === 0 && (
            <div className="py-12 text-center font-mono">
              <ShieldCheck className="h-10 w-10 text-cyber-success/50 mx-auto mb-2" />
              <p className="text-sm font-bold text-cyber-text">All Clear</p>
              <p className="text-xs text-cyber-muted mt-1">
                {tab === 'pending' ? 'No action authorization requests pending review.' : 'No historical action records found.'}
              </p>
            </div>
          )}

          {!loading && currentList.map((req) => {
            const isPending = req.status === 'PENDING' && !req.is_expired;
            const isApproved = req.status === 'APPROVED';
            const isRejected = req.status === 'REJECTED';
            const isExpired = req.status === 'EXPIRED' || req.is_expired;

            const clsBadge = getClassificationBadge(req.file_classification);
            const ClsIcon = clsBadge.icon;
            const riskBadge = getRiskLevelBadge(req.calculated_risk_level, req.calculated_risk_score ?? req.employee_risk_score ?? 0);
            const explanations = req.risk_explanation || [];

            return (
              <div
                key={req.id}
                className={`p-4 rounded-lg border transition-all ${
                  isPending
                    ? 'bg-cyber-bg/80 border-cyber-warning/40 shadow-lg shadow-cyber-warning/5'
                    : isApproved
                    ? 'bg-cyber-bg/40 border-cyber-success/30'
                    : isRejected
                    ? 'bg-cyber-bg/40 border-cyber-danger/30'
                    : 'bg-cyber-bg/30 border-cyber-border/40 opacity-80'
                }`}
              >
                {/* Header row */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-cyber-border/40">
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 rounded-full bg-cyber-primary/20 border border-cyber-primary/40 flex items-center justify-center font-bold text-cyber-primary text-xs font-mono">
                      {req.employee_name ? req.employee_name.slice(0, 2).toUpperCase() : 'EM'}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-sm text-cyber-text">{req.employee_name}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyber-card border border-cyber-border text-cyber-muted">
                          {req.employee_role}
                        </span>
                        <span className="text-[10px] font-mono text-cyber-muted">
                          • {req.employee_department}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Badges: File Sensitivity + Dynamic Risk Level + Status */}
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    {/* File Sensitivity Badge */}
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase flex items-center gap-1 ${clsBadge.style}`}>
                      <ClsIcon className="h-3 w-3" />
                      {clsBadge.label}
                    </span>

                    {/* Dynamic Risk Score & Level Badge */}
                    <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${riskBadge.style}`}>
                      RISK: {riskBadge.label}
                    </span>

                    {/* Request Status Badge */}
                    <span className={`px-2 py-0.5 rounded border text-[10px] font-bold uppercase flex items-center gap-1 ${
                      isPending
                        ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/40 animate-pulse'
                        : isApproved
                        ? 'text-cyber-success bg-cyber-success/10 border-cyber-success/30'
                        : isRejected
                        ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30'
                        : 'text-cyber-muted bg-cyber-card border-cyber-border'
                    }`}>
                      {isPending && <Clock className="h-3 w-3" />}
                      {isApproved && <CheckCircle2 className="h-3 w-3" />}
                      {isRejected && <XCircle className="h-3 w-3" />}
                      {isExpired && <Timer className="h-3 w-3" />}
                      {req.status}
                    </span>
                  </div>
                </div>

                {/* Target File & Path Details */}
                <div className="mt-3 space-y-2 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger text-[10px] uppercase font-bold">
                      {req.action_type.replace('_', ' ')}
                    </span>
                    <span className="font-bold text-cyber-text break-all">
                      {req.target_file}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 text-[11px] text-cyber-muted bg-cyber-card/60 p-2 rounded border border-cyber-border/40 break-all">
                    <Folder className="h-3.5 w-3.5 text-cyber-primary shrink-0" />
                    <span className="text-cyber-muted uppercase text-[9px] font-bold tracking-wider">Path:</span>
                    <span className="text-cyber-text">{req.file_path}</span>
                  </div>

                  {/* Feature 2: Explainable AI Risk Analysis Panel */}
                  <div className="p-2.5 rounded bg-cyber-bg/70 border border-cyber-border/60 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-cyber-primary font-bold flex items-center gap-1">
                        <Cpu className="h-3.5 w-3.5" /> AI Risk Analysis
                      </span>
                      <span className="text-[10px] text-cyber-muted">
                        Confidence: {Math.round((req.classification_confidence || 0.85) * 100)}%
                      </span>
                    </div>

                    {req.classification_reason && (
                      <div className="text-[10.5px] text-cyber-muted">
                        <span className="text-cyber-text font-medium">Sensitivity Insight:</span> {req.classification_reason}
                      </div>
                    )}

                    {explanations.length > 0 && (
                      <div className="pt-1">
                        <span className="text-[10px] text-cyber-muted uppercase tracking-wider font-bold">Contributing Risk Factors:</span>
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {explanations.map((exp, i) => (
                            <span key={i} className="px-2 py-0.5 rounded bg-cyber-card border border-cyber-border text-[10px] text-cyber-text">
                              • {exp}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Priority 2: Employee Digital Twin & Behavioral Anomaly Panel */}
                  <EmployeeBehaviorPanel employeeId={req.employee_id} compact={true} />

                  {/* Timestamp & Expiry Info */}
                  <div className="text-[10px] text-cyber-muted flex flex-col sm:flex-row sm:items-center justify-between gap-1 pt-1">
                    <span>Requested: {formatIST(req.requested_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                    {isPending && req.expires_at && (
                      <span className="text-amber-400 font-bold flex items-center gap-1">
                        <Timer className="h-3 w-3" /> Auto-expires at: {formatIST(req.expires_at, { hour: '2-digit', minute: '2-digit', second: '2-digit' })} (5m TTL)
                      </span>
                    )}
                    {isExpired && (
                      <span className="text-rose-400 font-bold">
                        Expired (5-minute TTL elapsed • Protection held)
                      </span>
                    )}
                    {req.resolved_by && (
                      <span>Resolved by {req.resolved_by} ({req.resolution_notes})</span>
                    )}
                  </div>
                </div>

                {/* Admin Actions (Only for PENDING) */}
                {isPending && (
                  <div className="mt-4 pt-3 border-t border-cyber-border/50 flex flex-col sm:flex-row items-center gap-3">
                    <input
                      type="text"
                      placeholder="Optional Admin justification / notes..."
                      value={actionNotes[req.id] || ''}
                      onChange={(e) => setActionNotes({ ...actionNotes, [req.id]: e.target.value })}
                      className="w-full sm:flex-1 px-3 py-1.5 text-xs font-mono bg-cyber-card border border-cyber-border rounded text-cyber-text focus:outline-none focus:border-cyber-primary"
                    />

                    <div className="flex items-center gap-2 w-full sm:w-auto shrink-0">
                      <button
                        onClick={() => handleApprove(req.id)}
                        disabled={processingId === req.id}
                        className="flex-1 sm:flex-none px-3.5 py-1.5 rounded bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/50 text-emerald-300 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        {processingId === req.id ? 'Executing...' : 'Approve & Execute'}
                      </button>

                      <button
                        onClick={() => handleReject(req.id)}
                        disabled={processingId === req.id}
                        className="flex-1 sm:flex-none px-3.5 py-1.5 rounded bg-rose-500/20 hover:bg-rose-500/30 border border-rose-500/50 text-rose-300 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                      >
                        <XCircle className="h-3.5 w-3.5" />
                        {processingId === req.id ? 'Blocking...' : 'Reject & Block'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-cyber-border bg-cyber-bg/90 flex items-center justify-between text-xs font-mono text-cyber-muted">
          <span>Zero-Data-Loss Protection Active • 5-Minute Request TTL</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-cyber-card border border-cyber-border rounded text-cyber-text hover:border-cyber-primary text-xs transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
