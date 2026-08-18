import React, { useState } from 'react';
import { ChevronDown, ChevronUp, FileStack, ShieldAlert } from 'lucide-react';
import { formatIST } from '../utils/time';
import { api } from '../services/mockData';

/** Severity chip shared with the rest of the SOC UI. */
function SeverityBadge({ severity }) {
  const cls =
    severity === 'High' || severity === 'Critical'
      ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25'
      : 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25';
  return (
    <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${cls}`}>
      {severity || 'Medium'}
    </span>
  );
}

/** Incident lifecycle status pill. */
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

/** A single label/value stat in the incident card. */
function Stat({ label, value, accent }) {
  return (
    <div className="bg-cyber-bg/50 border border-cyber-border rounded-lg px-3 py-2">
      <span className="block text-[9px] text-cyber-muted font-mono uppercase tracking-wider">{label}</span>
      <span className={`block mt-0.5 text-sm font-bold font-mono truncate ${accent || 'text-cyber-text'}`}>{value}</span>
    </div>
  );
}

/** Timeline dot colour per entry type. */
const TIMELINE_DOT = {
  created: 'bg-cyber-primary',
  evidence: 'bg-cyber-accent',
  role_baseline: 'bg-fuchsia-500',
  sensitive_asset: 'bg-amber-500',
  risk_increase: 'bg-cyber-danger',
  status_change: 'bg-cyber-warning',
  resolved: 'bg-cyber-success',
  archived: 'bg-cyber-muted',
};

/** One timeline entry in the expanded incident view. */
function TimelineEntry({ entry }) {
  return (
    <li className="relative flex gap-3 pl-5">
      <span className={`absolute left-0 top-1.5 h-2 w-2 rounded-full ${TIMELINE_DOT[entry.type] || 'bg-cyber-muted'}`} />
      <div className="min-w-0">
        <p className="text-[11px] font-mono text-cyber-text">{entry.title}</p>
        {entry.detail && <p className="text-[10px] font-mono text-cyber-muted break-words">{entry.detail}</p>}
        <p className="text-[9px] font-mono text-cyber-muted/70 mt-0.5">
          {formatIST(entry.ts, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </p>
      </div>
    </li>
  );
}

/**
 * Role gate: who may mutate an incident. Investigate/Resolve = admin+analyst,
 * Archive = admin only (matches the Alerts page convention).
 */
export function useIncidentRoles() {
  const role = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin'; }
    catch { return 'admin'; }
  })();
  return {
    role,
    canAct: role === 'admin' || role === 'analyst',
    canArchive: role === 'admin',
  };
}

const RESOLVE_REASONS = ['False Positive', 'Threat Removed', 'Manual Override'];

/**
 * One security incident card.
 *
 * Accepts EITHER the persistent Incident-model shape (has `risk_score` +
 * `timeline` + lifecycle) OR the legacy batch `summary` shape (`{summary,
 * events, risk}`) so older broadcasts keep rendering unchanged.
 *
 * When the incident is actionable (ACTIVE / INVESTIGATING) role-gated buttons
 * let an analyst investigate / resolve / archive without leaving the panel.
 */
export default function IncidentCard({ incident, onChange }) {
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [resolving, setResolving] = useState(false);
  const [reason, setReason] = useState(RESOLVE_REASONS[0]);
  const [error, setError] = useState('');
  const { canAct, canArchive } = useIncidentRoles();

  const isIncidentModel = incident.risk_score !== undefined;

  // --- Legacy batch summary shape -------------------------------------------
  if (!isIncidentModel) {
    const s = incident.summary || {};
    const events = incident.events || [];
    const risk = incident.risk || {};
    const duration = typeof s.duration_seconds === 'number' ? s.duration_seconds : null;
    const durationLabel = duration === null ? '—' : `${duration.toFixed(1)} sec`;
    const fileCount = s.files ?? incident.total_events ?? 0;
    const employeeName = incident.employee_name || (incident.employee_id ? `Employee #${incident.employee_id}` : 'Unknown');

    return (
      <div className="glass-panel border border-cyber-border/80 rounded-xl overflow-hidden">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-cyber-bg/40 transition-colors text-left"
        >
          <div className="flex items-center gap-3 min-w-0">
            <span className="text-2xl leading-none">{s.icon || '🚨'}</span>
            <div className="min-w-0">
              <h4 className="text-sm font-bold text-cyber-text truncate">{s.title || 'Suspicious Activity Detected'}</h4>
              <p className="text-[10px] font-mono text-cyber-muted truncate">
                {s.reason || `${fileCount} file operations in one batch`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <span className="hidden sm:block text-[10px] font-mono text-cyber-muted">
              {formatIST(incident.timestamp, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
            </span>
            <SeverityBadge severity={s.severity} />
            <span className="text-cyber-muted">
              {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </span>
          </div>
        </button>

        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 px-4 pb-4">
          <Stat label="Employee" value={employeeName} />
          <Stat label="Files" value={fileCount} accent="text-cyber-accent" />
          <Stat label="Folder" value={s.folder || '—'} />
          <Stat label="Duration" value={durationLabel} />
          <Stat label="AI Confidence" value={`${risk.confidence ?? 0}%`} accent="text-cyber-primary" />
          <Stat
            label="Risk"
            value={risk.score !== undefined && risk.score !== null ? `${risk.score} · ${risk.status || ''}` : '—'}
            accent={risk.score >= 75 ? 'text-cyber-danger' : risk.score >= 50 ? 'text-cyber-warning' : 'text-cyber-success'}
          />
        </div>

        {expanded && (
          <div className="border-t border-cyber-border/60 px-4 py-3 bg-cyber-bg/30">
            <div className="flex items-center gap-2 mb-2">
              <FileStack className="h-3.5 w-3.5 text-cyber-muted" />
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted">
                Raw Events ({events.length})
              </span>
            </div>
            <ul className="max-h-64 overflow-y-auto space-y-1 pr-1">
              {events.length === 0 && (
                <li className="text-[10px] font-mono text-cyber-muted">No raw events attached to this broadcast.</li>
              )}
              {events.map((evt) => (
                <li key={evt.id} className="flex items-center gap-2 py-1 border-b border-cyber-border/30">
                  <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded border uppercase shrink-0 ${
                    evt.event_type === 'usb_insert' || evt.event_type === 'usb_remove'
                      ? 'text-cyber-primary border-cyber-primary/20 bg-cyber-primary/5'
                      : evt.event_type === 'file_delete'
                      ? 'text-cyber-danger border-cyber-danger/20 bg-cyber-danger/5'
                      : evt.event_type === 'network_upload'
                      ? 'text-cyber-secondary border-cyber-secondary/20 bg-cyber-secondary/5'
                      : 'text-cyber-accent border-cyber-accent/20 bg-cyber-accent/5'
                  }`}>
                    {evt.event_type.replace('_', ' ')}
                  </span>
                  <span className="text-[10px] text-cyber-text truncate flex-1">{evt.details || evt.filename || evt.event_type}</span>
                  <span className="text-[9px] font-mono text-cyber-muted shrink-0">
                    {formatIST(evt.timestamp, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  }

  // --- Persistent Incident-model shape --------------------------------------
  const emp = incident.employee || {};
  const employeeName = emp.name || `Employee #${incident.employee_id}`;
  const timeline = incident.timeline || [];
  const isClosed = incident.status === 'RESOLVED' || incident.status === 'ARCHIVED';
  const canResolve = canAct && !isClosed && incident.status !== 'ARCHIVED';

  const runAction = async (fn) => {
    setError('');
    setBusy(true);
    try {
      await fn();
      if (onChange) onChange();
    } catch (err) {
      setError(err?.response?.data?.detail || 'Action failed. Try again.');
    } finally {
      setBusy(false);
      setResolving(false);
    }
  };

  return (
    <div className="glass-panel border border-cyber-border/80 rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-cyber-bg/40 transition-colors text-left"
      >
        <div className="flex items-center gap-3 min-w-0">
          <span className="text-2xl leading-none">🚨</span>
          <div className="min-w-0">
            <h4 className="text-sm font-bold text-cyber-text truncate">{incident.title}</h4>
            <p className="text-[10px] font-mono text-cyber-muted truncate">
              {emp.name || `Employee #${incident.employee_id}`} · {formatIST(incident.created_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <SeverityBadge severity={incident.severity} />
          <StatusBadge status={incident.status} />
          <span className="text-cyber-muted">
            {expanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </span>
        </div>
      </button>

      {/* Summary grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 px-4 pb-4">
        <Stat label="Employee" value={employeeName} />
        <Stat label="Status" value={incident.status} />
        <Stat label="Severity" value={incident.severity} />
        <Stat label="Confidence" value={`${incident.confidence ?? 0}%`} accent="text-cyber-primary" />
        <Stat
          label="Incident Risk"
          value={incident.risk_score ?? 0}
          accent={incident.risk_score >= 75 ? 'text-cyber-danger' : incident.risk_score >= 50 ? 'text-cyber-warning' : 'text-cyber-success'}
        />
        <Stat label="Created" value={formatIST(incident.created_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })} />
      </div>

      {/* Action buttons */}
      {(canAct || canArchive) && (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
          {!isClosed && incident.status === 'ACTIVE' && (
            <button
              disabled={busy}
              onClick={() => runAction(() => api.investigateIncident(incident.id))}
              className="px-3 py-1.5 bg-cyber-warning/15 hover:bg-cyber-warning text-cyber-warning hover:text-cyber-bg rounded border border-cyber-warning/35 text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
            >
              INVESTIGATE
            </button>
          )}
          {canResolve && !resolving && (
            <button
              disabled={busy}
              onClick={() => setResolving(true)}
              className="px-3 py-1.5 bg-cyber-success/15 hover:bg-cyber-success text-cyber-success hover:text-cyber-bg rounded border border-cyber-success/35 text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
            >
              RESOLVE
            </button>
          )}
          {canArchive && incident.status !== 'ARCHIVED' && (
            <button
              disabled={busy}
              onClick={() => runAction(() => api.archiveIncident(incident.id))}
              className="px-3 py-1.5 bg-cyber-muted/10 hover:bg-cyber-muted text-cyber-muted hover:text-cyber-bg rounded border border-cyber-border text-[10px] font-bold tracking-wider transition-all disabled:opacity-50"
            >
              ARCHIVE
            </button>
          )}
          {!canAct && !canArchive && (
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-cyber-warning">
              <ShieldAlert className="h-3.5 w-3.5" /> READ-ONLY
            </span>
          )}
        </div>
      )}

      {/* Resolve reason picker */}
      {resolving && (
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3 bg-cyber-bg/40 border-t border-cyber-border/60">
          <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted">Resolution reason:</span>
          <select
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="px-2 py-1.5 bg-cyber-card border border-cyber-border rounded text-[11px] text-cyber-text focus:outline-none focus:border-cyber-success"
          >
            {RESOLVE_REASONS.map((r) => (
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
            onClick={() => runAction(() => api.resolveIncident(incident.id, reason))}
            className="px-3 py-1.5 bg-cyber-success text-cyber-bg rounded text-[10px] font-bold tracking-wider hover:bg-cyber-success/80 transition-all disabled:opacity-50"
          >
            CONFIRM
          </button>
          <button
            onClick={() => { setResolving(false); setReason(RESOLVE_REASONS[0]); }}
            className="px-3 py-1.5 bg-transparent border border-cyber-border text-cyber-muted rounded text-[10px] font-bold tracking-wider hover:text-cyber-text transition-all"
          >
            CANCEL
          </button>
        </div>
      )}

      {error && (
        <p className="px-4 pb-3 text-[10px] font-mono text-cyber-danger">{error}</p>
      )}

      {/* Expanded timeline */}
      {expanded && (
        <div className="border-t border-cyber-border/60 px-4 py-3 bg-cyber-bg/30">
          <div className="flex items-center gap-2 mb-2">
            <FileStack className="h-3.5 w-3.5 text-cyber-muted" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-cyber-muted">
              Timeline ({timeline.length})
            </span>
          </div>
          {timeline.length === 0 ? (
            <p className="text-[10px] font-mono text-cyber-muted">No timeline entries recorded.</p>
          ) : (
            <ul className="max-h-64 overflow-y-auto space-y-3 pr-1">
              {timeline.map((entry, idx) => (
                <TimelineEntry key={idx} entry={entry} />
              ))}
            </ul>
          )}
          {isClosed && (
            <div className="mt-3 pt-3 border-t border-cyber-border/40 text-[10px] font-mono text-cyber-muted">
              {incident.status} by {incident.resolved_by || '—'}
              {incident.resolution_reason ? ` · ${incident.resolution_reason}` : ''}
              {incident.resolved_at ? ` · ${formatIST(incident.resolved_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}` : ''}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
