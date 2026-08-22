import React, { useState } from 'react';
import {
  ShieldAlert,
  HardDrive,
  KeyRound,
  FileText,
  Clock,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  UserCheck,
  ChevronDown,
  ChevronUp,
  Filter,
  Layers
} from 'lucide-react';

export default function ThreatTimeline({ items = [], employeeName = 'Employee' }) {
  const [filter, setFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  const getCategoryConfig = (category, severity) => {
    switch (category) {
      case 'AUTH':
        return {
          icon: KeyRound,
          color: 'text-cyber-accent border-cyber-accent/40 bg-cyber-accent/10',
          badge: 'bg-cyber-accent/10 text-cyber-accent border-cyber-accent/30',
          label: 'Authentication'
        };
      case 'USB':
        return {
          icon: HardDrive,
          color: 'text-cyber-warning border-cyber-warning/40 bg-cyber-warning/10',
          badge: 'bg-cyber-warning/10 text-cyber-warning border-cyber-warning/30',
          label: 'USB Media'
        };
      case 'VAULT':
        return {
          icon: RotateCcw,
          color: 'text-cyber-primary border-cyber-primary/40 bg-cyber-primary/10 shadow-[0_0_10px_rgba(6,182,212,0.3)]',
          badge: 'bg-cyber-primary/10 text-cyber-primary border-cyber-primary/30',
          label: 'Shadow Vault'
        };
      case 'APPROVAL':
        return {
          icon: UserCheck,
          color: severity === 'CRITICAL' ? 'text-cyber-danger border-cyber-danger/40 bg-cyber-danger/10' : 'text-cyber-warning border-cyber-warning/40 bg-cyber-warning/10',
          badge: severity === 'CRITICAL' ? 'bg-cyber-danger/10 text-cyber-danger border-cyber-danger/30' : 'bg-cyber-warning/10 text-cyber-warning border-cyber-warning/30',
          label: 'JIT Quorum'
        };
      case 'ALERT':
        return {
          icon: ShieldAlert,
          color: 'text-cyber-danger border-cyber-danger/40 bg-cyber-danger/10 shadow-[0_0_10px_rgba(239,68,68,0.3)]',
          badge: 'bg-cyber-danger/10 text-cyber-danger border-cyber-danger/30',
          label: 'Security Alert'
        };
      default:
        return {
          icon: FileText,
          color: 'text-cyber-muted border-cyber-border bg-cyber-bg/60',
          badge: 'bg-cyber-border/40 text-cyber-text border-cyber-border',
          label: 'Telemetry'
        };
    }
  };

  const filteredItems = items.filter((item) => {
    if (filter === 'ALL') return true;
    return item.category === filter;
  });

  const toggleExpand = (id) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const formatTimestamp = (isoStr) => {
    if (!isoStr) return '--:--:--';
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
      return isoStr;
    }
  };

  return (
    <div className="bg-cyber-card/90 border border-cyber-border rounded-xl p-6 backdrop-blur-md shadow-cyber">
      {/* Header & Filter Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-cyber-border/80">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-cyber-primary animate-pulse" />
            <h3 className="text-base font-bold text-cyber-text tracking-wide">
              Threat Timeline & Attack Forensic Trail
            </h3>
          </div>
          <p className="text-xs text-cyber-muted mt-0.5">
            Chronological reconstruction of endpoint events, intercepted deletions, and approval steps for <span className="text-cyber-primary font-medium">{employeeName}</span>
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {['ALL', 'AUTH', 'USB', 'VAULT', 'APPROVAL', 'ALERT'].map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-2.5 py-1 text-xs rounded-md font-mono transition-all duration-200 border ${
                filter === cat
                  ? 'bg-cyber-primary/20 text-cyber-primary border-cyber-primary/50 shadow-cyber font-semibold'
                  : 'bg-cyber-bg/60 text-cyber-muted border-cyber-border/60 hover:text-cyber-text hover:bg-cyber-border/30'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Timeline Stream */}
      <div className="mt-6 relative">
        {filteredItems.length === 0 ? (
          <div className="text-center py-12 text-cyber-muted">
            <Clock className="h-10 w-10 mx-auto mb-2 opacity-40 text-cyber-primary" />
            <p className="text-sm">No timeline events recorded under this filter.</p>
          </div>
        ) : (
          <div className="relative pl-6 space-y-6 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyber-primary/60 before:via-cyber-secondary/40 before:to-cyber-border/20">
            {filteredItems.map((item, idx) => {
              const cfg = getCategoryConfig(item.category, item.severity);
              const Icon = cfg.icon;
              const isExpanded = expandedId === item.id;

              return (
                <div
                  key={item.id || idx}
                  className="relative group transition-all duration-200"
                >
                  {/* Timeline Node Icon Indicator */}
                  <div
                    className={`absolute -left-6 top-1.5 h-6 w-6 rounded-full border flex items-center justify-center transition-transform duration-200 group-hover:scale-110 ${cfg.color}`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                  </div>

                  {/* Event Content Card */}
                  <div
                    onClick={() => toggleExpand(item.id)}
                    className="ml-4 bg-cyber-bg/80 border border-cyber-border/80 rounded-lg p-4 cursor-pointer hover:border-cyber-primary/40 hover:bg-cyber-card transition-all duration-200 shadow-sm"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-xs text-cyber-primary font-bold">
                            {formatTimestamp(item.timestamp)}
                          </span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${cfg.badge}`}>
                            {cfg.label}
                          </span>
                          {item.severity && item.severity !== 'LOW' && (
                            <span
                              className={`text-[10px] font-mono px-1.5 py-0.5 rounded uppercase ${
                                item.severity === 'CRITICAL'
                                  ? 'bg-cyber-danger/20 text-cyber-danger border border-cyber-danger/40 animate-pulse'
                                  : 'bg-cyber-warning/20 text-cyber-warning border border-cyber-warning/40'
                              }`}
                            >
                              {item.severity}
                            </span>
                          )}
                        </div>

                        <h4 className="text-sm font-semibold text-cyber-text group-hover:text-cyber-primary transition-colors">
                          {item.title}
                        </h4>
                      </div>

                      <button
                        className="text-cyber-muted hover:text-cyber-text p-1 transition-colors"
                        title={isExpanded ? 'Collapse forensic details' : 'Expand forensic details'}
                      >
                        {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </button>
                    </div>

                    <p className="text-xs text-cyber-muted mt-2 font-mono leading-relaxed break-words">
                      {item.detail}
                    </p>

                    {/* Expandable Forensic Inspector */}
                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-cyber-border/60 bg-cyber-card/60 p-3 rounded-md text-xs space-y-2">
                        <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                          <div>
                            <span className="text-cyber-muted">Raw Category: </span>
                            <span className="text-cyber-text font-bold">{item.category}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Full Timestamp: </span>
                            <span className="text-cyber-text">{item.timestamp}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Event ID: </span>
                            <span className="text-cyber-text">{item.id}</span>
                          </div>
                          <div>
                            <span className="text-cyber-muted">Event Signature: </span>
                            <span className="text-cyber-accent font-bold">{item.raw_type || item.category}</span>
                          </div>
                        </div>

                        {item.category === 'VAULT' && (
                          <div className="mt-2 p-2 bg-cyber-primary/10 border border-cyber-primary/30 rounded text-[11px] text-cyber-primary">
                            🛡️ <strong>Zero-Knowledge Protection:</strong> File snapshot decrypted and restored instantly in &lt; 5ms with SHA-256 integrity tag verification.
                          </div>
                        )}

                        {item.category === 'APPROVAL' && (
                          <div className="mt-2 p-2 bg-cyber-warning/10 border border-cyber-warning/30 rounded text-[11px] text-cyber-warning">
                            ⚖️ <strong>Multi-Tier Quorum:</strong> Authorization ticket evaluated by policy engine. Action requires independent multi-level authorization before release.
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
