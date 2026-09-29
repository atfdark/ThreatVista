import React, { useState } from 'react';
import {
  ShieldAlert,
  HardDrive,
  KeyRound,
  FileText,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RotateCcw,
  UserCheck,
  ChevronDown,
  ChevronUp,
  Filter,
  Layers,
  Activity,
  Upload,
  Wifi,
  Cpu,
  Lock,
  Search,
  ExternalLink,
  ShieldCheck
} from 'lucide-react';
import { formatIST } from '../utils/time';

export default function ThreatTimeline({ items = [], employeeName = 'Employee' }) {
  const [filter, setFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  const getCategoryConfig = (item) => {
    const category = item.category || 'FILE';
    const severity = item.severity || 'LOW';
    const approvalStatus = (item.approval_status || '').toUpperCase();

    if (category === 'APPROVAL') {
      if (approvalStatus === 'APPROVED' || approvalStatus === 'PARTIALLY_APPROVED') {
        return {
          icon: ShieldCheck,
          color: 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20 shadow-[0_0_10px_rgba(16,185,129,0.25)]',
          badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          label: 'JIT Approved',
          statusBadge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
        };
      }
      if (approvalStatus === 'REJECTED') {
        return {
          icon: XCircle,
          color: 'text-rose-400 border-rose-500/40 bg-rose-950/20 shadow-[0_0_10px_rgba(244,63,94,0.25)]',
          badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          label: 'JIT Rejected',
          statusBadge: 'bg-rose-500/20 text-rose-300 border-rose-500/40'
        };
      }
      return {
        icon: UserCheck,
        color: 'text-amber-400 border-amber-500/40 bg-amber-950/20 shadow-[0_0_10px_rgba(245,158,11,0.25)]',
        badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        label: 'JIT Pending',
        statusBadge: 'bg-amber-500/20 text-amber-300 border-amber-500/40'
      };
    }

    switch (category) {
      case 'AUTH':
        return {
          icon: KeyRound,
          color: 'text-purple-400 border-purple-500/40 bg-purple-950/20',
          badge: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
          label: 'Authentication'
        };
      case 'USB':
        return {
          icon: HardDrive,
          color: 'text-amber-400 border-amber-500/40 bg-amber-950/20 shadow-[0_0_10px_rgba(245,158,11,0.2)]',
          badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          label: 'USB Media'
        };
      case 'VAULT':
        return {
          icon: RotateCcw,
          color: 'text-cyan-400 border-cyan-500/40 bg-cyan-950/20 shadow-[0_0_10px_rgba(6,182,212,0.3)]',
          badge: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
          label: 'Shadow Vault'
        };
      case 'ALERT':
        return {
          icon: ShieldAlert,
          color: 'text-rose-400 border-rose-500/40 bg-rose-950/20 shadow-[0_0_10px_rgba(244,63,94,0.3)]',
          badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          label: 'Security Alert'
        };
      case 'SENSITIVE':
        return {
          icon: Lock,
          color: 'text-amber-300 border-amber-500/40 bg-amber-950/20',
          badge: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          label: 'Sensitive Asset'
        };
      case 'NETWORK':
        return {
          icon: Upload,
          color: 'text-sky-400 border-sky-500/40 bg-sky-950/20',
          badge: 'bg-sky-500/10 text-sky-400 border-sky-500/30',
          label: 'Network Transfer'
        };
      case 'PROCESS':
        return {
          icon: Cpu,
          color: 'text-indigo-400 border-indigo-500/40 bg-indigo-950/20',
          badge: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
          label: 'Process Exec'
        };
      default:
        return {
          icon: FileText,
          color: 'text-cyber-muted border-cyber-border bg-cyber-bg/60',
          badge: 'bg-cyber-border/40 text-cyber-text border-cyber-border',
          label: 'File Activity'
        };
    }
  };

  // Filter Categories
  const FILTER_TABS = [
    { id: 'ALL', label: 'All Activities', count: items.length },
    { id: 'APPROVAL', label: 'JIT Approvals', count: items.filter(i => i.category === 'APPROVAL').length },
    { id: 'THREAT', label: 'Threat & Attack Trail', count: items.filter(i => ['ALERT', 'VAULT', 'USB'].includes(i.category) || i.severity === 'CRITICAL').length },
    { id: 'SENSITIVE', label: 'Sensitive Files', count: items.filter(i => i.category === 'SENSITIVE' || i.is_sensitive).length },
    { id: 'FILE', label: 'File Operations', count: items.filter(i => ['FILE', 'VAULT', 'SENSITIVE'].includes(i.category)).length },
    { id: 'USB', label: 'USB & Hardware', count: items.filter(i => i.category === 'USB').length },
    { id: 'NETWORK_PROCESS', label: 'Network & Processes', count: items.filter(i => ['NETWORK', 'PROCESS'].includes(i.category)).length },
  ];

  const filteredItems = items.filter((item) => {
    // 1. Tab filter
    if (filter === 'APPROVAL' && item.category !== 'APPROVAL') return false;
    if (filter === 'THREAT' && !(['ALERT', 'VAULT', 'USB'].includes(item.category) || item.severity === 'CRITICAL' || item.category === 'APPROVAL')) return false;
    if (filter === 'SENSITIVE' && !(item.category === 'SENSITIVE' || item.is_sensitive)) return false;
    if (filter === 'FILE' && !(['FILE', 'VAULT', 'SENSITIVE'].includes(item.category))) return false;
    if (filter === 'USB' && item.category !== 'USB') return false;
    if (filter === 'NETWORK_PROCESS' && !(['NETWORK', 'PROCESS'].includes(item.category))) return false;

    // 2. Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = (item.title || '').toLowerCase().includes(q);
      const matchDetail = (item.detail || '').toLowerCase().includes(q);
      const matchFile = (item.filename || item.target_file || '').toLowerCase().includes(q);
      const matchAuthorizer = (item.resolved_by || '').toLowerCase().includes(q);
      const matchStatus = (item.approval_status || item.category || '').toLowerCase().includes(q);
      if (!matchTitle && !matchDetail && !matchFile && !matchAuthorizer && !matchStatus) return false;
    }
    return true;
  });

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const formatTimestamp = (isoStr) => {
    if (!isoStr) return '--:--:--';
    return formatIST(isoStr, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  return (
    <div className="bg-cyber-card/90 border border-cyber-border rounded-xl p-6 backdrop-blur-md shadow-cyber space-y-6">
      {/* Header Toolbar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-cyber-border/80">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-cyber-primary animate-pulse" />
            <h3 className="text-base font-bold text-cyber-text tracking-wide uppercase font-mono">
              Unified Forensic Timeline & Telemetry Stream
            </h3>
          </div>
          <p className="text-xs text-cyber-muted mt-0.5 font-mono">
            Full chronological reconstruction of endpoint telemetry, security alerts, AES-256 vault restorations, and JIT approvals for <span className="text-cyber-primary font-bold">{employeeName}</span>
          </p>
        </div>

        {/* Search Bar */}
        <div className="relative min-w-[240px]">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-cyber-muted" />
          <input
            type="text"
            placeholder="Search files, actions, authorizers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-cyber-bg border border-cyber-border/80 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-primary"
          />
        </div>
      </div>

      {/* Filter Tabs Pills */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {FILTER_TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setFilter(tab.id)}
            className={`px-3 py-1.5 text-xs rounded-lg font-mono transition-all duration-200 border flex items-center gap-1.5 cursor-pointer ${
              filter === tab.id
                ? 'bg-cyber-primary text-black border-cyber-primary shadow-[0_0_15px_rgba(6,182,212,0.3)] font-bold'
                : 'bg-cyber-bg/70 text-cyber-muted border-cyber-border/60 hover:text-cyber-text hover:border-cyber-primary/40'
            }`}
          >
            <span>{tab.label}</span>
            {tab.count > 0 && (
              <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${
                filter === tab.id ? 'bg-black/20 text-black font-extrabold' : 'bg-cyber-card border border-cyber-border text-cyber-muted'
              }`}>
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Timeline Stream */}
      <div className="mt-4 relative">
        {filteredItems.length === 0 ? (
          <div className="text-center py-14 text-cyber-muted border border-dashed border-cyber-border/50 rounded-xl bg-cyber-bg/30">
            <Clock className="h-10 w-10 mx-auto mb-2 opacity-40 text-cyber-primary" />
            <p className="text-sm font-mono font-bold text-cyber-text">No timeline records match this filter or search.</p>
            <p className="text-xs font-mono text-cyber-muted mt-1">Try switching tabs or resetting the search query.</p>
          </div>
        ) : (
          <div className="relative pl-6 space-y-4 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyber-primary/60 before:via-cyber-secondary/40 before:to-cyber-border/20 max-h-[600px] overflow-y-auto pr-2">
            {filteredItems.map((item, idx) => {
              const cfg = getCategoryConfig(item);
              const Icon = cfg.icon;
              const isExpanded = expandedId === item.id;
              const isApproval = item.category === 'APPROVAL';
              const approvalStatus = (item.approval_status || '').toUpperCase();

              return (
                <div
                  key={item.id || idx}
                  className="relative group transition-all duration-200"
                >
                  {/* Timeline Node Indicator */}
                  <div
                    className={`absolute -left-6 top-3 h-6 w-6 rounded-full border flex items-center justify-center transition-transform duration-200 group-hover:scale-110 ${cfg.color}`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                  </div>

                  {/* Event Content Card */}
                  <div
                    onClick={() => toggleExpand(item.id)}
                    className={`ml-4 rounded-xl p-4 cursor-pointer transition-all duration-200 border ${
                      isApproval
                        ? approvalStatus === 'APPROVED'
                          ? 'bg-emerald-950/10 border-emerald-500/40 hover:border-emerald-500/70 hover:bg-emerald-950/20'
                          : approvalStatus === 'REJECTED'
                          ? 'bg-rose-950/10 border-rose-500/40 hover:border-rose-500/70 hover:bg-rose-950/20'
                          : 'bg-amber-950/10 border-amber-500/40 hover:border-amber-500/70 hover:bg-amber-950/20'
                        : item.category === 'VAULT'
                        ? 'bg-cyan-950/10 border-cyan-500/40 hover:border-cyan-500/70'
                        : item.category === 'ALERT'
                        ? 'bg-rose-950/10 border-rose-500/40 hover:border-rose-500/70'
                        : 'bg-cyber-bg/80 border-cyber-border hover:border-cyber-primary/40 hover:bg-cyber-card'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                      <div className="space-y-1.5 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          {/* Timestamp */}
                          <span className="font-mono text-xs text-cyber-primary font-bold flex items-center gap-1">
                            <Clock className="h-3 w-3 text-cyber-muted" />
                            {formatTimestamp(item.timestamp)}
                          </span>

                          {/* Category Badge */}
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold flex items-center gap-1 ${cfg.badge}`}>
                            <Icon className="h-3 w-3" />
                            {cfg.label}
                          </span>

                          {/* JIT Specific Approval Status Pill */}
                          {isApproval && (
                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-extrabold flex items-center gap-1 ${
                              approvalStatus === 'APPROVED'
                                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]'
                                : approvalStatus === 'REJECTED'
                                ? 'bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-[0_0_10px_rgba(244,63,94,0.2)]'
                                : 'bg-amber-500/20 text-amber-300 border-amber-500/50 animate-pulse'
                            }`}>
                              {approvalStatus === 'APPROVED' && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
                              {approvalStatus === 'REJECTED' && <XCircle className="h-3 w-3 text-rose-400" />}
                              {approvalStatus === 'PENDING' && <Clock className="h-3 w-3 text-amber-400" />}
                              {approvalStatus}
                            </span>
                          )}

                          {/* Policy Tier */}
                          {item.policy_tier && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border bg-cyber-card border-cyber-border text-cyber-muted uppercase">
                              Tier: {item.policy_tier}
                            </span>
                          )}

                          {/* Quorum Progress Badge */}
                          {isApproval && (item.required_approvals > 1 || item.current_approvals > 0) && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded border bg-purple-950/30 text-purple-300 border-purple-500/40 font-bold">
                              Quorum: {item.current_approvals}/{item.required_approvals} Approvals
                            </span>
                          )}

                          {/* Network Upload MB Badge */}
                          {item.network_upload && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold border bg-sky-500/20 text-sky-300 border-sky-500/40 flex items-center gap-1">
                              <Upload className="h-3 w-3" />
                              {item.network_upload}
                            </span>
                          )}

                          {/* File Size */}
                          {item.size && item.size !== 'Unknown' && item.size !== '0.0MB' && (
                            <span className="px-1.5 py-0.5 bg-cyber-card border border-cyber-border rounded text-[10px] font-mono text-cyber-text">
                              {item.size}
                            </span>
                          )}

                          {/* Severity Pill */}
                          {item.severity && item.severity !== 'LOW' && !isApproval && (
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase font-bold ${
                                item.severity === 'CRITICAL'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse'
                                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                              }`}
                            >
                              {item.severity}
                            </span>
                          )}
                        </div>

                        {/* Event / Action Title */}
                        <h4 className="text-sm font-bold text-cyber-text group-hover:text-cyber-primary transition-colors font-mono">
                          {item.title}
                        </h4>
                      </div>

                      <button
                        className="text-cyber-muted hover:text-cyber-text p-1 transition-colors self-start shrink-0"
                        title={isExpanded ? 'Collapse forensic details' : 'Expand forensic details'}
                      >
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </button>
                    </div>

                    {/* Detailed Context Line */}
                    <p className="text-xs text-cyber-muted mt-2 font-mono leading-relaxed break-words">
                      {item.detail}
                    </p>

                    {/* Specific JIT Authorization Result Banner */}
                    {isApproval && (
                      <div className={`mt-2.5 p-2.5 rounded-lg border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                        approvalStatus === 'APPROVED'
                          ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
                          : approvalStatus === 'REJECTED'
                          ? 'bg-rose-950/20 border-rose-500/40 text-rose-300'
                          : 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                      }`}>
                        <div>
                          <span className="font-bold">Authorizer: </span>
                          <span>{item.resolved_by ? `${item.resolved_by}` : 'Pending Admin / Multi-Sign Quorum Review'}</span>
                          {item.resolution_notes && (
                            <span className="text-cyber-text ml-2 italic">"{item.resolution_notes}"</span>
                          )}
                        </div>
                        {item.file_classification && (
                          <span className="px-2 py-0.5 rounded bg-black/40 border border-current text-[10px] font-bold uppercase shrink-0">
                            Class: {item.file_classification}
                          </span>
                        )}
                      </div>
                    )}

                    {/* Expandable Forensic Inspector */}
                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-cyber-border/60 bg-cyber-card/60 p-3 rounded-md text-xs space-y-2 font-mono animate-fade-in">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                          <div>
                            <span className="text-cyber-muted">Raw Category: </span>
                            <span className="text-cyber-text font-bold">{item.category}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Event Signature: </span>
                            <span className="text-cyber-accent font-bold">{item.raw_type || item.category}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Event ID: </span>
                            <span className="text-cyber-text">{item.id}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Full Timestamp: </span>
                            <span className="text-cyber-text">{item.timestamp}</span>
                          </div>
                          {item.file_path && (
                            <div className="md:col-span-2">
                              <span className="text-cyber-muted">Target Path: </span>
                              <span className="text-cyber-text break-all">{item.file_path}</span>
                            </div>
                          )}
                        </div>

                        {item.category === 'VAULT' && (
                          <div className="mt-2 p-2 bg-cyan-950/30 border border-cyan-500/40 rounded text-[11px] text-cyan-300">
                            🛡️ <strong>Zero-Knowledge AES-256 Vault:</strong> File snapshot held in encrypted storage. Decryption and instant rollback validated with SHA-256 integrity tag (&lt;5ms).
                          </div>
                        )}

                        {item.category === 'APPROVAL' && (
                          <div className="mt-2 p-2 bg-amber-950/30 border border-amber-500/40 rounded text-[11px] text-amber-300">
                            ⚖️ <strong>Zero-Trust JIT Policy Engine:</strong> Action intercepted before disk execution. Requires authorized quorum approval before release.
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
