import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  Filter, 
  Search, 
  ShieldAlert,
  CheckCircle2,
  Clock,
  ChevronRight,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';

export default function Alerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState('');

  // Role gates the INVESTIGATE / RESOLVE actions (read-only auditor can't mutate).
  const role = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin'; }
    catch { return 'admin'; }
  })();
  const canAct = role === 'admin' || role === 'analyst';

  const loadAlerts = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const data = await api.getAlerts();
      setAlerts(data);
    } catch (err) {
      console.error("Failed to load alerts", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, []);

  // Live: re-fetch the ledger when the backend broadcasts a new alert, and poll
  // every 10s as a fallback so missed broadcasts / status changes still land.
  useWebSocket((msg) => {
    if (msg.type === 'new_alert') loadAlerts(true);
  });
  useEffect(() => {
    const t = setInterval(() => loadAlerts(true), 10000);
    return () => clearInterval(t);
  }, []);

  const handleUpdateStatus = async (alertId, newStatus) => {
    setActionError('');
    const previous = alerts.map(a => ({ ...a }));
    setAlerts(prevAlerts =>
      prevAlerts.map(alert => (alert.id === alertId ? { ...alert, status: newStatus } : alert))
    );
    try {
      await api.updateAlertStatus(alertId, newStatus);
    } catch (err) {
      // Revert optimistic update on failure.
      setAlerts(previous);
      setActionError(err?.response?.data?.detail || 'Failed to update alert status.');
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSeverity = severityFilter === 'All' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'All' || alert.status === statusFilter;
    const matchesSearch = alert.employee.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          alert.reason.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSeverity && matchesStatus && matchesSearch;
  });

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">INGESTING ALERTS CORRELATIONS...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Security Alert Ledger</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">CORRELATED BEHAVIOR ANOMALIES & EXCURSIONS</p>
        </div>
        <button 
          onClick={loadAlerts}
          className="flex items-center gap-2 px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text hover:text-cyber-primary transition-colors focus:outline-none"
        >
          <RefreshCw className="h-4 w-4" /> REFRESH LEDGER
        </button>
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
          READ-ONLY AUDITOR — alert mitigation actions are disabled.
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col xl:flex-row gap-4">
        {/* Search */}
        <div className="relative flex-1">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
            <Search className="h-4 w-4" />
          </span>
          <input
            type="text"
            placeholder="Search alerts by employee name or reason..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary transition-colors"
          />
        </div>

        <div className="flex flex-col sm:flex-row gap-4">
          {/* Severity Filter */}
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
              <option value="High" className="bg-cyber-card text-cyber-danger">High Severity</option>
              <option value="Medium" className="bg-cyber-card text-cyber-warning">Medium Severity</option>
              <option value="Low" className="bg-cyber-card text-cyber-secondary">Low Severity</option>
            </select>
          </div>

          {/* Status Filter */}
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
              <option value="Active" className="bg-cyber-card">Active</option>
              <option value="Investigating" className="bg-cyber-card">Investigating</option>
              <option value="Resolved" className="bg-cyber-card">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Ledger Table */}
      <div className="glass-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-cyber-border text-cyber-muted uppercase font-mono text-[9px] tracking-wider">
                <th className="py-4 pl-4">Timestamp</th>
                <th className="py-4">Monitored User</th>
                <th className="py-4">Severity</th>
                <th className="py-4">Threat Diagnosis (Correlation Engine)</th>
                <th className="py-4">Status</th>
                <th className="py-4 text-right pr-4">Mitigation Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/40 font-mono">
              {filteredAlerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-cyber-border/10 transition-colors group">
                  <td className="py-4 pl-4 text-cyber-muted whitespace-nowrap text-[10px]">
                    <div className="flex items-center gap-1.5">
                      <Clock className="h-3.5 w-3.5 text-cyber-muted" />
                      {new Date(alert.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </td>
                  <td className="py-4 font-semibold text-cyber-text whitespace-nowrap">
                    <button 
                      onClick={() => navigate(`/employees/${alert.employee.id}`)}
                      className="hover:underline hover:text-cyber-primary transition-colors text-left"
                    >
                      {alert.employee.name}
                      <span className="text-[10px] text-cyber-muted block font-normal">{alert.employee.department}</span>
                    </button>
                  </td>
                  <td className="py-4 whitespace-nowrap">
                    <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                      alert.severity === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25 shadow-[0_0_8px_rgba(239,68,68,0.1)]' :
                      alert.severity === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      'text-cyber-secondary bg-cyber-secondary/10 border-cyber-secondary/25'
                    }`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-4 text-xs font-sans text-cyber-text max-w-sm leading-relaxed pr-6">
                    {alert.reason}
                  </td>
                  <td className="py-4 whitespace-nowrap">
                    <span className={`text-[10px] uppercase font-bold flex items-center gap-1.5 ${
                      alert.status === 'Active' ? 'text-cyber-danger' :
                      alert.status === 'Investigating' ? 'text-cyber-warning' :
                      'text-cyber-success'
                    }`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${
                        alert.status === 'Active' ? 'bg-cyber-danger animate-ping' :
                        alert.status === 'Investigating' ? 'bg-cyber-warning animate-pulse' :
                        'bg-cyber-success'
                      }`}></span>
                      {alert.status}
                    </span>
                  </td>
                  <td className="py-4 text-right pr-4 whitespace-nowrap">
                    <div className="flex justify-end gap-2">
                      {canAct && alert.status === 'Active' && (
                        <button
                          onClick={() => handleUpdateStatus(alert.id, 'Investigating')}
                          className="px-2 py-1 bg-cyber-warning/15 hover:bg-cyber-warning text-cyber-warning hover:text-cyber-bg rounded border border-cyber-warning/35 text-[10px] font-bold tracking-wider transition-all"
                        >
                          INVESTIGATE
                        </button>
                      )}
                      {canAct && alert.status !== 'Resolved' && (
                        <button
                          onClick={() => handleUpdateStatus(alert.id, 'Resolved')}
                          className="px-2 py-1 bg-cyber-success/15 hover:bg-cyber-success text-cyber-success hover:text-cyber-bg rounded border border-cyber-success/35 text-[10px] font-bold tracking-wider transition-all"
                        >
                          RESOLVE
                        </button>
                      )}
                      <button 
                        onClick={() => navigate(`/employees/${alert.employee.id}`)}
                        className="p-1.5 hover:bg-cyber-primary/20 text-cyber-muted hover:text-cyber-primary rounded transition-all"
                        title="View DNA profile"
                      >
                        <ChevronRight className="h-4.5 w-4.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}

              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-cyber-muted">
                    <CheckCircle2 className="h-8 w-8 text-cyber-success mx-auto mb-2" />
                    NO CORRELATED ALERTS MATCHING THE FILTERS
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
