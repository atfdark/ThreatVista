import React, { useState, useEffect, useCallback } from 'react';
import { ScrollText, RefreshCw, Search } from 'lucide-react';
import { api } from '../services/mockData';
import { formatIST } from '../utils/time';

const ACTIONS = [
  'All',
  'login',
  'login.failed',
  'logout',
  'settings.update',
  'ai.analyze',
  'alert.update',
  'session.revoke',
  'report.download',
];

function fmtDate(iso) {
  if (!iso) return '—';
  return formatIST(iso, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export default function Audit() {
  const [logs, setLogs] = useState([]);
  const [actionFilter, setActionFilter] = useState('All');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const loadLogs = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = actionFilter !== 'All' ? { action: actionFilter, limit: 200 } : { limit: 200 };
      setLogs(await api.getAuditLogs(params));
    } catch (err) {
      setError(err?.response?.data?.detail || 'Failed to load audit trail.');
    } finally {
      setLoading(false);
    }
  }, [actionFilter]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Security Audit Trail</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
            ADMINISTRATOR-ONLY &middot; EVERY SENSITIVE ACTION RECORDED
          </p>
        </div>
        <button
          onClick={loadLogs}
          className="flex items-center gap-2 px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text hover:text-cyber-primary transition-colors focus:outline-none"
        >
          <RefreshCw className="h-4 w-4" /> REFRESH TRAIL
        </button>
      </div>

      {/* Action filter */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative min-w-[200px]">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
            <Search className="h-4 w-4" />
          </span>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
          >
            {ACTIONS.map((a) => (
              <option key={a} value={a} className="bg-cyber-card">{a === 'All' ? 'All Actions' : a}</option>
            ))}
          </select>
        </div>
        <span className="text-[10px] text-cyber-muted font-mono">{logs.length} records</span>
      </div>

      {error && (
        <div className="px-4 py-3 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg text-xs text-cyber-danger font-mono">{error}</div>
      )}

      {loading ? (
        <div className="flex h-[50vh] items-center justify-center">
          <div className="flex flex-col items-center gap-3">
            <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
            <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING AUDIT TRAIL...</p>
          </div>
        </div>
      ) : (
        <div className="glass-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[9px] tracking-wider">
                  <th className="py-4 pl-4">Timestamp</th>
                  <th className="py-4">User</th>
                  <th className="py-4">Role</th>
                  <th className="py-4">Action</th>
                  <th className="py-4">Resource</th>
                  <th className="py-4">Details</th>
                  <th className="py-4 pr-4 text-right">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-border/40 font-mono">
                {logs.map((log) => (
                  <tr key={log.id} className="hover:bg-cyber-border/10 transition-colors">
                    <td className="py-3 pl-4 text-cyber-muted whitespace-nowrap text-[10px]">{fmtDate(log.created_at)}</td>
                    <td className="py-3 font-semibold text-cyber-text whitespace-nowrap">{log.username || '—'}</td>
                    <td className="py-3 whitespace-nowrap">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                        log.role === 'admin' ? 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/25' :
                        log.role === 'analyst' ? 'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/25' :
                        log.role === 'auditor' ? 'text-cyber-accent bg-cyber-accent/10 border-cyber-accent/25' :
                        'text-cyber-muted bg-cyber-border/30 border-cyber-border'
                      }`}>
                        {log.role || 'system'}
                      </span>
                    </td>
                    <td className="py-3 whitespace-nowrap">
                      <span className={`text-[10px] px-2 py-0.5 rounded ${
                        String(log.action).endsWith('failed') ? 'text-cyber-danger bg-cyber-danger/10' :
                        String(log.action).startsWith('login') || String(log.action).startsWith('logout') ? 'text-cyber-secondary bg-cyber-secondary/10' :
                        'text-cyber-warning bg-cyber-warning/10'
                      }`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 text-cyber-muted whitespace-nowrap">{log.resource}{log.resource_id ? ` #${log.resource_id}` : ''}</td>
                    <td className="py-3 text-cyber-text max-w-md truncate">{log.details || ''}</td>
                    <td className="py-3 pr-4 text-right text-cyber-muted text-[10px] whitespace-nowrap">{log.ip_address || '—'}</td>
                  </tr>
                ))}

                {logs.length === 0 && !error && (
                  <tr>
                    <td colSpan="7" className="text-center py-12 text-cyber-muted">
                      <ScrollText className="h-8 w-8 text-cyber-muted mx-auto mb-2" />
                      NO AUDIT RECORDS FOR THIS FILTER
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
