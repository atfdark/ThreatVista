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
  Timer,
  CheckSquare,
  Square,
  ArrowRight,
  HardDrive,
  Usb,
  Trash2,
  FileWarning,
  Sparkles,
  Layers,
  ArrowUpRight,
  Shield
} from 'lucide-react';
import { api } from '../services/mockData';
import { formatIST } from '../utils/time';
import EmployeeBehaviorPanel from './EmployeeBehaviorPanel';

function getClassificationBadge(classification) {
  switch ((classification || '').toUpperCase()) {
    case 'RESTRICTED':
      return {
        label: 'RESTRICTED',
        style: 'text-purple-300 bg-purple-500/15 border-purple-500/50 shadow-sm shadow-purple-500/30 font-bold',
        icon: Lock,
      };
    case 'CONFIDENTIAL':
      return {
        label: 'CONFIDENTIAL',
        style: 'text-rose-300 bg-rose-500/15 border-rose-500/50 shadow-sm shadow-rose-500/30 font-bold',
        icon: FileLock,
      };
    case 'INTERNAL':
      return {
        label: 'INTERNAL',
        style: 'text-cyan-300 bg-cyan-500/15 border-cyan-500/40',
        icon: FileText,
      };
    case 'PUBLIC':
      return {
        label: 'PUBLIC',
        style: 'text-emerald-300 bg-emerald-500/15 border-emerald-500/40',
        icon: Globe,
      };
    default:
      return {
        label: 'INTERNAL',
        style: 'text-cyan-300 bg-cyan-500/15 border-cyan-500/40',
        icon: FileText,
      };
  }
}

function getRiskLevelBadge(level, score) {
  const lvl = (level || (score >= 61 ? 'HIGH' : score >= 26 ? 'MEDIUM' : 'LOW')).toUpperCase();
  if (lvl === 'HIGH') {
    return {
      label: `CRITICAL / HIGH (${score}%)`,
      style: 'text-rose-400 bg-rose-500/20 border-rose-500/50 font-extrabold animate-pulse shadow-[0_0_12px_rgba(244,63,94,0.3)]',
    };
  }
  if (lvl === 'MEDIUM') {
    return {
      label: `ELEVATED (${score}%)`,
      style: 'text-amber-400 bg-amber-500/20 border-amber-500/40 font-bold',
    };
  }
  return {
    label: `LOW RISK (${score}%)`,
    style: 'text-cyan-400 bg-cyan-500/20 border-cyan-500/40 font-bold',
  };
}

/**
 * Generate a rich, human-readable action narrative and path breakdown.
 */
function analyzeActionContext(req) {
  const act = (req.action_type || '').toLowerCase();
  const path = req.file_path || req.target_file || '';
  const file = req.target_file || 'Protected Document';
  const cls = (req.file_classification || 'INTERNAL').toUpperCase();
  const empName = req.employee_name || `Employee #${req.employee_id || ''}`;

  // Check if USB / external removable drive is involved
  const isUsb = act.includes('usb') || /^[D-Z]:\\/i.test(path) || path.toLowerCase().includes('usb') || path.toLowerCase().includes('removable');
  const isDelete = act.includes('delete') || act.includes('remove') || act.includes('unlink') || act.includes('wipe');
  const isModify = act.includes('modify') || act.includes('tamper') || act.includes('encrypt') || act.includes('rename');
  const isMove = act.includes('move') || act.includes('export') || act.includes('transfer');

  if (isUsb || isMove) {
    // Extract source and destination if possible
    let source = "Local System (C:\\)";
    let dest = path;
    if (path.includes(' -> ')) {
      const parts = path.split(' -> ');
      source = parts[0];
      dest = parts[1];
    } else if (/^[D-Z]:\\/i.test(path)) {
      source = `C:\\Users\\${empName.toLowerCase().replace(/\s+/g, '.')}\\Downloads`;
      dest = path;
    }

    return {
      category: 'USB EXFILTRATION & TRANSFER',
      categoryColor: 'text-amber-400 bg-amber-500/10 border-amber-500/40',
      icon: Usb,
      summary: `Data Exfiltration Alert: Protected ${cls} file "${file}" is being copied / transferred from local workstation drive to external removable storage.`,
      sourcePath: source,
      destPath: dest,
      isTransfer: true,
      protectionAction: 'Held in Shadow Vault • Quarantined pending admin approval'
    };
  }

  if (isDelete) {
    return {
      category: 'FILE DESTRUCTION / DELETION',
      categoryColor: 'text-rose-400 bg-rose-500/10 border-rose-500/40',
      icon: Trash2,
      summary: `Permanent Deletion Intercepted: Protected critical asset "${file}" (${cls}) was targeted for deletion on local disk.`,
      sourcePath: path,
      destPath: 'PERMANENT DELETION / DISK UNLINK',
      isTransfer: false,
      protectionAction: 'Instant Rollback Snapshot created in AES-256 Shadow Vault'
    };
  }

  if (isModify) {
    return {
      category: 'FILE MODIFICATION / RANSOMWARE PATTERN',
      categoryColor: 'text-purple-400 bg-purple-500/10 border-purple-500/40',
      icon: FileWarning,
      summary: `Suspicious Integrity Violation: Protected file "${file}" (${cls}) underwent unexpected binary change or mass extension rename pattern.`,
      sourcePath: path,
      destPath: 'ENCRYPTED / MODIFIED STATE',
      isTransfer: false,
      protectionAction: 'Original pristine copy preserved in AES-256 Encrypted Vault'
    };
  }

  return {
    category: 'PRIVILEGED JIT ACCESS REQUEST',
    categoryColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/40',
    icon: Shield,
    summary: `Privileged Operation Intercepted: ${empName} attempted to perform "${req.action_type.replace('_', ' ')}" on protected asset "${file}".`,
    sourcePath: path,
    destPath: 'EXECUTION AUTHORIZATION',
    isTransfer: false,
    protectionAction: 'Blocked by Zero-Trust JIT Policy • Awaiting Quorum Sign-off'
  };
}

export default function ActionApprovalModal({ isOpen, onClose, onActionResolved }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('pending'); // 'pending' | 'history'
  const [actionNotes, setActionNotes] = useState({});
  const [processingId, setProcessingId] = useState(null);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchMsg, setBatchMsg] = useState('');

  const loadRequests = async () => {
    setLoading(true);
    try {
      const data = await api.getActionRequests(tab === 'pending' ? 'PENDING' : null);
      setRequests(data || []);
      setSelectedIds(new Set());
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

  // Multi-select handlers
  const toggleSelectOne = (id) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === pendingList.length && pendingList.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(pendingList.map(r => r.id)));
    }
  };

  const isAllSelected = pendingList.length > 0 && selectedIds.size === pendingList.length;
  const isPartiallySelected = selectedIds.size > 0 && selectedIds.size < pendingList.length;

  // Single Actions
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

  // Batch Actions
  const handleBatchResolve = async (actionType) => {
    const idsToProcess = selectedIds.size > 0
      ? Array.from(selectedIds)
      : pendingList.map(r => r.id);

    if (idsToProcess.length === 0) return;

    const actionWord = actionType === 'approve' ? 'APPROVE & AUTHORIZE' : 'REJECT & BLOCK';
    const confirmMsg = `Are you sure you want to ${actionWord} ${idsToProcess.length} pending request(s)?`;
    if (!window.confirm(confirmMsg)) return;

    setBatchBusy(true);
    setBatchMsg(`Processing batch ${actionType} on ${idsToProcess.length} request(s)...`);

    try {
      const res = await api.batchResolveActionRequests(
        idsToProcess,
        actionType,
        `Batch ${actionType} performed via JIT Authorization Console`
      );

      setBatchMsg(`✓ Successfully processed ${res.success_count || idsToProcess.length} action request(s)!`);
      setTimeout(() => setBatchMsg(''), 4000);
      setSelectedIds(new Set());
      await loadRequests();
      if (onActionResolved) onActionResolved();
    } catch (err) {
      alert(err.response?.data?.detail || `Failed to perform batch ${actionType}`);
    } finally {
      setBatchBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/85 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-5xl bg-[#090d16] border border-cyber-border/80 rounded-2xl shadow-[0_0_50px_rgba(6,182,212,0.15)] overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Top Header */}
        <div className="p-6 border-b border-cyber-border/80 flex items-center justify-between bg-[#0b1120]">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-cyber-warning/15 border border-cyber-warning/40 text-cyber-warning shadow-[0_0_20px_rgba(234,179,8,0.2)]">
              <ShieldAlert className="h-7 w-7 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h2 className="text-xl font-bold text-cyber-text tracking-wide">
                  JIT Action Authorization Center
                </h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyber-primary/15 text-cyber-primary border border-cyber-primary/40">
                  v2.0 ZERO-TRUST
                </span>
              </div>
              <p className="text-xs font-mono text-cyber-muted mt-1">
                AI File Classification • Removable Drive Exfiltration Interception • AES-256 Vault Quorum
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/40 transition-colors cursor-pointer"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Tab & Batch Action Controls Bar */}
        <div className="px-6 py-3 border-b border-cyber-border/60 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 bg-[#0d1527]">
          {/* Tabs */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setTab('pending'); setSelectedIds(new Set()); }}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all border cursor-pointer flex items-center gap-2 ${
                tab === 'pending'
                  ? 'text-cyber-primary border-cyber-primary/60 bg-cyber-primary/10 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                  : 'text-cyber-muted border-transparent hover:text-cyber-text hover:bg-cyber-card/60'
              }`}
            >
              <Clock className="h-3.5 w-3.5" />
              <span>Pending Authorization</span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                pendingList.length > 0 ? 'bg-cyber-warning text-black animate-pulse' : 'bg-cyber-card text-cyber-muted'
              }`}>
                {pendingList.length}
              </span>
            </button>

            <button
              onClick={() => { setTab('history'); setSelectedIds(new Set()); }}
              className={`px-4 py-2 rounded-lg text-xs font-mono font-bold transition-all border cursor-pointer flex items-center gap-2 ${
                tab === 'history'
                  ? 'text-cyber-primary border-cyber-primary/60 bg-cyber-primary/10 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
                  : 'text-cyber-muted border-transparent hover:text-cyber-text hover:bg-cyber-card/60'
              }`}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              <span>Resolved & Expired History</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] bg-cyber-card text-cyber-muted">
                {historyList.length}
              </span>
            </button>
          </div>

          {/* Batch Controls (Only in Pending tab) */}
          {tab === 'pending' && pendingList.length > 0 && (
            <div className="flex items-center gap-3 flex-wrap">
              {/* Select All Toggle */}
              <button
                type="button"
                onClick={toggleSelectAll}
                className="flex items-center gap-2 px-3 py-1.5 rounded bg-cyber-card border border-cyber-border text-xs font-mono text-cyber-text hover:border-cyber-primary transition-all cursor-pointer"
                title={isAllSelected ? "Deselect All" : "Select All Pending Tickets"}
              >
                {isAllSelected ? (
                  <CheckSquare className="h-4 w-4 text-cyber-primary" />
                ) : isPartiallySelected ? (
                  <div className="h-4 w-4 bg-cyber-primary/40 border border-cyber-primary rounded-sm flex items-center justify-center text-[10px] font-bold text-cyber-bg">−</div>
                ) : (
                  <Square className="h-4 w-4 text-cyber-muted" />
                )}
                <span className="font-bold">
                  {selectedIds.size > 0 ? `${selectedIds.size} of ${pendingList.length} Selected` : 'Select All'}
                </span>
              </button>

              {/* Accept All / Selected Button */}
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => handleBatchResolve('approve')}
                className="px-3.5 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500 text-emerald-300 hover:text-black border border-emerald-500/50 text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(16,185,129,0.25)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <CheckCircle2 className="h-4 w-4" />
                <span>{selectedIds.size > 0 ? `Accept Selected (${selectedIds.size})` : `Accept All (${pendingList.length})`}</span>
              </button>

              {/* Reject All / Selected Button */}
              <button
                type="button"
                disabled={batchBusy}
                onClick={() => handleBatchResolve('reject')}
                className="px-3.5 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500 text-rose-300 hover:text-black border border-rose-500/50 text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(244,63,94,0.25)] flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
              >
                <XCircle className="h-4 w-4" />
                <span>{selectedIds.size > 0 ? `Reject Selected (${selectedIds.size})` : `Reject All (${pendingList.length})`}</span>
              </button>

              {/* Refresh Button */}
              <button
                onClick={loadRequests}
                disabled={loading}
                className="p-2 text-cyber-muted hover:text-cyber-primary rounded hover:bg-cyber-card transition-colors cursor-pointer"
                title="Refresh Pending List"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          )}

          {tab === 'history' && (
            <button
              onClick={loadRequests}
              disabled={loading}
              className="text-xs font-mono text-cyber-muted hover:text-cyber-primary flex items-center gap-1.5 py-1 cursor-pointer"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh History
            </button>
          )}
        </div>

        {/* Batch Status Message Banner */}
        {batchMsg && (
          <div className="px-6 py-2.5 bg-cyber-primary/15 border-b border-cyber-primary/30 text-xs font-mono text-cyber-primary flex items-center gap-2 animate-fade-in">
            <Sparkles className="h-4 w-4 animate-spin" />
            <span>{batchMsg}</span>
          </div>
        )}

        {/* Content List */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading && (
            <div className="py-16 text-center">
              <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin mx-auto mb-3"></div>
              <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">
                RETRIEVING INTERCEPTED JIT ACTION TICKETS...
              </p>
            </div>
          )}

          {!loading && currentList.length === 0 && (
            <div className="py-20 text-center font-mono">
              <div className="h-16 w-16 rounded-full bg-cyber-success/10 border border-cyber-success/30 flex items-center justify-center mx-auto mb-4 text-cyber-success shadow-[0_0_30px_rgba(16,185,129,0.2)]">
                <ShieldCheck className="h-8 w-8" />
              </div>
              <p className="text-base font-bold text-cyber-text">All Clear — Zero Pending Threats</p>
              <p className="text-xs text-cyber-muted mt-1 max-w-md mx-auto">
                {tab === 'pending'
                  ? 'No action authorization requests pending SOC review. All files and USB endpoints are actively protected.'
                  : 'No historical authorization tickets logged in this session.'}
              </p>
            </div>
          )}

          {!loading && currentList.map((req) => {
            const isPending = req.status === 'PENDING' && !req.is_expired;
            const isApproved = req.status === 'APPROVED';
            const isRejected = req.status === 'REJECTED';
            const isExpired = req.status === 'EXPIRED' || req.is_expired;
            const isSelected = selectedIds.has(req.id);

            const clsBadge = getClassificationBadge(req.file_classification);
            const ClsIcon = clsBadge.icon;
            const riskBadge = getRiskLevelBadge(req.calculated_risk_level, req.calculated_risk_score ?? req.employee_risk_score ?? 0);
            const explanations = req.risk_explanation || [];
            const actionContext = analyzeActionContext(req);
            const ContextIcon = actionContext.icon;

            return (
              <div
                key={req.id}
                className={`p-5 rounded-xl border transition-all relative ${
                  isPending
                    ? isSelected
                      ? 'bg-[#11192e] border-cyber-primary shadow-[0_0_25px_rgba(6,182,212,0.2)]'
                      : 'bg-[#0f172a]/90 border-cyber-warning/50 shadow-[0_0_20px_rgba(234,179,8,0.1)]'
                    : isApproved
                    ? 'bg-[#0f172a]/50 border-cyber-success/30'
                    : isRejected
                    ? 'bg-[#0f172a]/50 border-cyber-danger/30'
                    : 'bg-[#0f172a]/40 border-cyber-border/40 opacity-80'
                }`}
              >
                {/* Header Row with Checkbox, User & Badges */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-cyber-border/40">
                  <div className="flex items-center gap-3">
                    {/* Checkbox (Only for Pending) */}
                    {isPending && (
                      <button
                        type="button"
                        onClick={() => toggleSelectOne(req.id)}
                        className="p-1 text-cyber-muted hover:text-cyber-primary cursor-pointer transition-colors"
                        title={isSelected ? "Deselect ticket" : "Select ticket for batch action"}
                      >
                        {isSelected ? (
                          <CheckSquare className="h-5 w-5 text-cyber-primary" />
                        ) : (
                          <Square className="h-5 w-5 text-cyber-muted hover:text-cyber-text" />
                        )}
                      </button>
                    )}

                    <div className="h-9 w-9 rounded-full bg-cyber-primary/20 border border-cyber-primary/40 flex items-center justify-center font-bold text-cyber-primary text-xs font-mono shadow-sm">
                      {req.employee_name ? req.employee_name.slice(0, 2).toUpperCase() : 'EM'}
                    </div>

                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-bold text-base text-cyber-text">{req.employee_name}</span>
                        <span className="text-[10.5px] font-mono px-2 py-0.5 rounded bg-cyber-card border border-cyber-border text-cyber-primary font-bold">
                          {req.employee_role}
                        </span>
                        <span className="text-[11px] font-mono text-cyber-muted">
                          • {req.employee_department}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Badges: Action Category + Sensitivity + Risk + Status */}
                  <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                    {/* Action Category Badge */}
                    <span className={`px-2.5 py-1 rounded-md border text-[10px] font-bold uppercase flex items-center gap-1.5 ${actionContext.categoryColor}`}>
                      <ContextIcon className="h-3.5 w-3.5" />
                      {actionContext.category}
                    </span>

                    {/* File Sensitivity Badge */}
                    <span className={`px-2.5 py-1 rounded-md border text-[10px] font-bold uppercase flex items-center gap-1.5 ${clsBadge.style}`}>
                      <ClsIcon className="h-3.5 w-3.5" />
                      {clsBadge.label}
                    </span>

                    {/* Dynamic Risk Score Badge */}
                    <span className={`px-2.5 py-1 rounded-md border text-[10px] uppercase ${riskBadge.style}`}>
                      {riskBadge.label}
                    </span>

                    {/* Request Status Badge */}
                    <span className={`px-2.5 py-1 rounded-md border text-[10px] font-bold uppercase flex items-center gap-1.5 ${
                      isPending
                        ? 'text-cyber-warning bg-cyber-warning/15 border-cyber-warning/50 animate-pulse font-extrabold'
                        : isApproved
                        ? 'text-cyber-success bg-cyber-success/15 border-cyber-success/40'
                        : isRejected
                        ? 'text-cyber-danger bg-cyber-danger/15 border-cyber-danger/40'
                        : 'text-cyber-muted bg-cyber-card border-cyber-border'
                    }`}>
                      {isPending && <Clock className="h-3.5 w-3.5" />}
                      {isApproved && <CheckCircle2 className="h-3.5 w-3.5" />}
                      {isRejected && <XCircle className="h-3.5 w-3.5" />}
                      {isExpired && <Timer className="h-3.5 w-3.5" />}
                      {req.status}
                    </span>
                  </div>
                </div>

                {/* 🌟 Prominent Action Summary Banner (What is going on) */}
                <div className="mt-4 p-4 rounded-xl bg-[#070b14] border border-cyber-border/80 space-y-3 font-mono">
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-lg bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary shrink-0 mt-0.5">
                      <ContextIcon className="h-4 w-4" />
                    </div>
                    <div className="flex-1">
                      <span className="text-[10px] uppercase font-bold text-cyber-primary tracking-wider block">
                        Action Summary & Behavioral Threat Context
                      </span>
                      <p className="text-xs text-cyber-text leading-relaxed mt-1 font-sans font-medium">
                        {actionContext.summary}
                      </p>
                    </div>
                  </div>

                  {/* Visual Source -> Destination Path Route */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-2 items-center pt-2 border-t border-cyber-border/40 text-xs">
                    <div className="md:col-span-5 p-2.5 rounded-lg bg-[#0d1527] border border-cyber-border/60">
                      <span className="text-[9px] uppercase font-bold text-cyber-muted block flex items-center gap-1">
                        <Folder className="h-3 w-3 text-cyber-primary" /> Source Location / Workstation Drive
                      </span>
                      <span className="text-cyber-text font-bold text-[11px] break-all block mt-0.5">
                        {actionContext.sourcePath}
                      </span>
                    </div>

                    <div className="md:col-span-2 flex flex-col items-center justify-center py-1">
                      <div className="flex items-center gap-1 text-[10px] font-bold text-cyber-warning uppercase">
                        <ArrowRight className="h-4 w-4 animate-pulse text-cyber-primary" />
                      </div>
                      <span className="text-[8.5px] text-cyber-muted uppercase tracking-tight">
                        {req.action_type.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="md:col-span-5 p-2.5 rounded-lg bg-[#0d1527] border border-cyber-border/60">
                      <span className="text-[9px] uppercase font-bold text-cyber-muted block flex items-center gap-1">
                        {actionContext.isTransfer ? <Usb className="h-3 w-3 text-amber-400" /> : <HardDrive className="h-3 w-3 text-rose-400" />} Target Destination / Endpoint
                      </span>
                      <span className={`font-bold text-[11px] break-all block mt-0.5 ${actionContext.isTransfer ? 'text-amber-300' : 'text-rose-300'}`}>
                        {actionContext.destPath}
                      </span>
                    </div>
                  </div>

                  {/* Protection Held Tag */}
                  <div className="flex items-center justify-between text-[10px] text-cyber-muted pt-1">
                    <span className="flex items-center gap-1.5 text-cyber-success font-medium">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      <span>{actionContext.protectionAction}</span>
                    </span>
                    {req.file_size && (
                      <span>Payload Size: <strong className="text-cyber-text">{req.file_size}</strong></span>
                    )}
                  </div>
                </div>

                {/* AI Risk Analysis & Contributing Factors */}
                <div className="mt-4 p-3.5 rounded-xl bg-[#090e1a] border border-cyber-border/60 space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-cyber-primary font-bold flex items-center gap-1.5">
                      <Cpu className="h-4 w-4" /> AI Risk Scoring & Explanations
                    </span>
                    <span className="text-[10.5px] text-cyber-muted">
                      Classification Confidence: <strong className="text-cyber-primary">{Math.round((req.classification_confidence || 0.85) * 100)}%</strong>
                    </span>
                  </div>

                  {req.classification_reason && (
                    <div className="text-[11px] text-cyber-muted">
                      <span className="text-cyber-text font-semibold">Sensitivity Justification:</span> {req.classification_reason}
                    </div>
                  )}

                  {explanations.length > 0 && (
                    <div className="pt-1">
                      <span className="text-[10px] text-cyber-muted uppercase tracking-wider font-bold block mb-1.5">
                        Detected Contributing Threat Factors:
                      </span>
                      <div className="flex flex-wrap gap-1.5">
                        {explanations.map((exp, i) => (
                          <span key={i} className="px-2.5 py-1 rounded bg-[#0f172a] border border-cyber-border text-[10.5px] text-cyber-text flex items-center gap-1.5">
                            <span className="h-1.5 w-1.5 rounded-full bg-cyber-warning shrink-0"></span>
                            {exp}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Employee Behavioral Anomaly DNA Panel */}
                <div className="mt-4">
                  <EmployeeBehaviorPanel employeeId={req.employee_id} compact={true} />
                </div>

                {/* Multi-Level Approval Quorum Progress */}
                {req.required_approvals > 1 && (
                  <div className="mt-4 p-3.5 rounded-xl bg-cyber-card/80 border border-cyber-border space-y-2 font-mono">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-cyber-accent font-bold flex items-center gap-2">
                        ⚖️ Multi-Level Dual Quorum Policy
                        <span className="text-[9.5px] px-2 py-0.5 rounded bg-cyber-accent/20 border border-cyber-accent/40 text-cyber-accent">
                          {req.policy_tier || 'DUAL_QUORUM'}
                        </span>
                      </span>
                      <span className="text-xs font-bold text-cyber-primary">
                        {req.current_approvals || 0} of {req.required_approvals} Approvals Recorded
                      </span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-cyber-bg rounded-full h-2 overflow-hidden border border-cyber-border/80">
                      <div
                        className="h-full bg-gradient-to-r from-cyber-primary via-cyber-accent to-cyber-success transition-all duration-300"
                        style={{ width: `${Math.min(100, (((req.current_approvals || 0) / (req.required_approvals || 1)) * 100))}%` }}
                      />
                    </div>

                    {req.approval_chain && req.approval_chain.length > 0 && (
                      <div className="text-[10.5px] text-cyber-muted space-y-1 pt-1">
                        {req.approval_chain.map((step, sIdx) => (
                          <div key={sIdx} className="flex items-center gap-2 text-cyber-text">
                            <CheckCircle2 className="h-3.5 w-3.5 text-cyber-success shrink-0" />
                            <span>Step {step.step}: Signed off by <strong>{step.approver_name}</strong> ({step.approver_role})</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {/* Timestamp & Expiry Info */}
                <div className="mt-4 pt-3 border-t border-cyber-border/40 text-[10.5px] font-mono text-cyber-muted flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span>Requested: {formatIST(req.requested_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
                  {isPending && req.expires_at && (
                    <span className="text-amber-400 font-bold flex items-center gap-1 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30">
                      <Timer className="h-3.5 w-3.5" /> Auto-expires at: {formatIST(req.expires_at, { hour: '2-digit', minute: '2-digit', second: '2-digit' })} (5m TTL)
                    </span>
                  )}
                  {isExpired && (
                    <span className="text-rose-400 font-bold bg-rose-500/10 px-2 py-0.5 rounded border border-rose-500/30">
                      Expired (5-Minute TTL Elapsed • Zero-Data-Loss Held)
                    </span>
                  )}
                  {req.resolved_by && (
                    <span className="text-cyber-text">Resolved by: <strong>{req.resolved_by}</strong> ({req.resolution_notes})</span>
                  )}
                </div>

                {/* Individual Action Execution Buttons (Only for PENDING) */}
                {isPending && (
                  <div className="mt-4 pt-3 border-t border-cyber-border/60 flex flex-col sm:flex-row items-center gap-3">
                    <input
                      type="text"
                      placeholder="Optional Admin justification / audit notes..."
                      value={actionNotes[req.id] || ''}
                      onChange={(e) => setActionNotes({ ...actionNotes, [req.id]: e.target.value })}
                      className="w-full sm:flex-1 px-3.5 py-2 text-xs font-mono bg-cyber-bg border border-cyber-border rounded-lg text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary"
                    />

                    <div className="flex items-center gap-2.5 w-full sm:w-auto shrink-0">
                      <button
                        onClick={() => handleApprove(req.id)}
                        disabled={processingId === req.id || batchBusy}
                        className="flex-1 sm:flex-none px-4 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500 text-emerald-300 hover:text-black border border-emerald-500/50 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all shadow-[0_0_15px_rgba(16,185,129,0.2)] cursor-pointer disabled:opacity-50"
                      >
                        <CheckCircle2 className="h-4 w-4" />
                        {processingId === req.id ? 'Authorizing...' : 'Approve & Execute'}
                      </button>

                      <button
                        onClick={() => handleReject(req.id)}
                        disabled={processingId === req.id || batchBusy}
                        className="flex-1 sm:flex-none px-4 py-2 rounded-lg bg-rose-500/20 hover:bg-rose-500 text-rose-300 hover:text-black border border-rose-500/50 text-xs font-mono font-bold flex items-center justify-center gap-1.5 transition-all shadow-[0_0_15px_rgba(244,63,94,0.2)] cursor-pointer disabled:opacity-50"
                      >
                        <XCircle className="h-4 w-4" />
                        {processingId === req.id ? 'Blocking...' : 'Reject & Block'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-cyber-border bg-[#0b1120] flex items-center justify-between text-xs font-mono text-cyber-muted">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyber-success" />
            <span>Zero-Data-Loss Active • 5-Minute Request TTL • AES-256 Vault Backed</span>
          </div>
          <button
            onClick={onClose}
            className="px-5 py-2 bg-cyber-card border border-cyber-border rounded-lg text-cyber-text hover:border-cyber-primary text-xs font-bold transition-colors cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
