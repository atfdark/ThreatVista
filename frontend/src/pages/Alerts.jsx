import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  AlertTriangle, 
  Filter, 
  Search, 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  ChevronRight, 
  ChevronLeft,
  RefreshCw,
  Radio,
  Wifi,
  Users
} from 'lucide-react';
import { api } from '../services/mockData';
import { useWebSocket } from '../services/websocket';
import { formatIST } from '../utils/time';

const PAGE_SIZE = 15;

export default function Alerts() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [endpoints, setEndpoints] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [onlineOnly, setOnlineOnly] = useState(true); // Default to online employees as requested
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [actionError, setActionError] = useState('');

  // Role gates the INVESTIGATE / RESOLVE actions (read-only auditor can't mutate).
  const role = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin'; }
    catch { return 'admin'; }
  })();
  const canAct = role === 'admin' || role === 'analyst';

  const loadData = async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const [alertsData, endpointsData] = await Promise.all([
        api.getAlerts(),
        api.getEndpoints().catch(() => [])
      ]);
      setAlerts(alertsData || []);
      setEndpoints(endpointsData || []);
    } catch (err) {
      console.error("Failed to load alerts", err);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Live WebSocket listener
  useWebSocket((msg) => {
    if (msg.type === 'new_alert' || msg.type === 'alert_updated' || msg.type === 'device_connected') {
      loadData(true);
    }
  });

  // Calculate online employee IDs set
  const onlineEmployeeIds = useMemo(() => {
    const ids = new Set();
    endpoints.forEach(ep => {
      if (ep.online && ep.employee_id) {
        ids.add(ep.employee_id);
      }
    });
    return ids;
  }, [endpoints]);

  const handleUpdateStatus = async (alertId, newStatus) => {
    setActionError('');
    const previous = alerts.map(a => ({ ...a }));
    setAlerts(prevAlerts =>
      prevAlerts.map(alert => (alert.id === alertId ? { ...alert, status: newStatus } : alert))
    );
    try {
      await api.updateAlertStatus(alertId, newStatus);
    } catch (err) {
      setAlerts(previous);
      setActionError(err?.response?.data?.detail || 'Failed to update alert status.');
    }
  };

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [severityFilter, statusFilter, onlineOnly, searchTerm]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter(alert => {
      const matchesSeverity = severityFilter === 'All' || alert.severity === severityFilter;
      const matchesStatus = statusFilter === 'All' || alert.status === statusFilter;
      const matchesOnline = !onlineOnly || onlineEmployeeIds.has(alert.employee?.id) || onlineEmployeeIds.has(alert.employee_id);
      const empName = alert.employee?.name || '';
      const reason = alert.reason || '';
      const matchesSearch = empName.toLowerCase().includes(searchTerm.toLowerCase()) ||
                            reason.toLowerCase().includes(searchTerm.toLowerCase());
      return matchesSeverity && matchesStatus && matchesOnline && matchesSearch;
    });
  }, [alerts, severityFilter, statusFilter, onlineOnly, onlineEmployeeIds, searchTerm]);

  const totalPages = Math.ceil(filteredAlerts.length / PAGE_SIZE) || 1;
  const paginatedAlerts = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE;
    return filteredAlerts.slice(start, start + PAGE_SIZE);
  }, [filteredAlerts, page]);

  if (loading && alerts.length === 0) {
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
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Security Alert Ledger</h2>
          <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
            CORRELATED BEHAVIOR ANOMALIES & EXCURSIONS ({filteredAlerts.length} total alerts)
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Online Filter Quick Toggle Button */}
          <button
            onClick={() => setOnlineOnly(!onlineOnly)}
            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono font-bold tracking-wider transition-all border cursor-pointer ${
              onlineOnly 
                ? 'bg-cyber-success/15 border-cyber-success text-cyber-success shadow-[0_0_12px_rgba(16,185,129,0.25)]' 
                : 'bg-cyber-card border-cyber-border text-cyber-muted hover:text-cyber-text'
            }`}
            title="Toggle between showing only currently connected online employees or all employees"
          >
            <Wifi className={`h-3.5 w-3.5 ${onlineOnly ? 'animate-pulse text-cyber-success' : 'text-cyber-muted'}`} />
            {onlineOnly ? 'SHOWING ONLINE EMPLOYEES' : 'SHOWING ALL EMPLOYEES'}
          </button>

          <button 
            onClick={() => loadData()}
            className="flex items-center gap-2 px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text hover:text-cyber-primary transition-colors focus:outline-none cursor-pointer"
          >
            <RefreshCw className="h-4 w-4" /> REFRESH
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

        <div className="flex flex-wrap sm:flex-nowrap gap-3">
          {/* Online Scope Filter */}
          <div className="relative min-w-[150px]">
            <select
              value={onlineOnly ? 'online' : 'all'}
              onChange={(e) => setOnlineOnly(e.target.value === 'online')}
              className="w-full px-3 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
            >
              <option value="online" className="bg-cyber-card">🟢 Online Only ({onlineEmployeeIds.size} active)</option>
              <option value="all" className="bg-cyber-card">👥 All Employees</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="relative min-w-[140px]">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
            >
              <option value="All" className="bg-cyber-card">All Severities</option>
              <option value="Critical" className="bg-cyber-card text-cyber-danger">Critical</option>
              <option value="High" className="bg-cyber-card text-cyber-danger">High</option>
              <option value="Medium" className="bg-cyber-card text-cyber-warning">Medium</option>
              <option value="Low" className="bg-cyber-card text-cyber-secondary">Low</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="relative min-w-[140px]">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
            >
              <option value="All" className="bg-cyber-card">All Statuses</option>
              <option value="Active" className="bg-cyber-card">Active</option>
              <option value="Acknowledged" className="bg-cyber-card">Acknowledged</option>
              <option value="Investigating" className="bg-cyber-card">Investigating</option>
              <option value="Resolved" className="bg-cyber-card">Resolved</option>
            </select>
          </div>
        </div>
      </div>

      {/* Alerts Ledger Table */}
      <div className="glass-panel overflow-hidden border border-cyber-border/80">
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
              {paginatedAlerts.map((alert) => {
                const empId = alert.employee?.id || alert.employee_id;
                const isEmpOnline = onlineEmployeeIds.has(empId);

                return (
                  <tr key={alert.id} className="hover:bg-cyber-border/10 transition-colors group">
                    <td className="py-4 pl-4 text-cyber-muted whitespace-nowrap text-[10px]">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5 text-cyber-muted" />
                        {formatIST(alert.timestamp, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </div>
                    </td>
                    <td className="py-4 font-semibold text-cyber-text whitespace-nowrap">
                      <button 
                        onClick={() => navigate(`/employees/${empId}`)}
                        className="hover:underline hover:text-cyber-primary transition-colors text-left flex flex-col"
                      >
                        <span className="flex items-center gap-1.5">
                          {alert.employee?.name || `Employee #${empId}`}
                          {isEmpOnline && (
                            <span className="h-2 w-2 rounded-full bg-cyber-success inline-block shadow-[0_0_6px_#10b981]" title="Device Online" />
                          )}
                        </span>
                        <span className="text-[10px] text-cyber-muted font-normal">{alert.employee?.department || 'General'}</span>
                      </button>
                    </td>
                    <td className="py-4 whitespace-nowrap">
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                        alert.severity === 'Critical' || alert.severity === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25 shadow-[0_0_8px_rgba(239,68,68,0.1)]' :
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
                        alert.status === 'Acknowledged' ? 'text-cyber-accent' :
                        alert.status === 'Investigating' ? 'text-cyber-warning' :
                        'text-cyber-success'
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${
                          alert.status === 'Active' ? 'bg-cyber-danger animate-ping' :
                          alert.status === 'Acknowledged' ? 'bg-cyber-accent animate-pulse' :
                          alert.status === 'Investigating' ? 'bg-cyber-warning animate-pulse' :
                          'bg-cyber-success'
                        }`}></span>
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-4 text-right pr-4 whitespace-nowrap">
                      <div className="flex justify-end items-center gap-1.5">
                        {canAct && alert.status === 'Active' && (
                          <button
                            onClick={() => handleUpdateStatus(alert.id, 'Acknowledged')}
                            className="px-2 py-1 bg-cyber-primary/15 hover:bg-cyber-primary text-cyber-primary hover:text-cyber-bg rounded border border-cyber-primary/35 text-[10px] font-bold tracking-wider transition-all cursor-pointer"
                            title="Acknowledge alert"
                          >
                            ACK
                          </button>
                        )}
                        {canAct && (alert.status === 'Active' || alert.status === 'Acknowledged') && (
                          <button
                            onClick={() => handleUpdateStatus(alert.id, 'Investigating')}
                            className="px-2 py-1 bg-cyber-warning/15 hover:bg-cyber-warning text-cyber-warning hover:text-cyber-bg rounded border border-cyber-warning/35 text-[10px] font-bold tracking-wider transition-all cursor-pointer"
                            title="Mark investigating"
                          >
                            INVESTIGATE
                          </button>
                        )}
                        {role === 'admin' && alert.status !== 'Resolved' && (alert.reason || '').toLowerCase().includes('usb') && (
                          <button
                            onClick={async () => {
                              try {
                                await api.blockUsbAlert(alert.id);
                                loadData(true);
                              } catch (e) {
                                setActionError('Failed to issue block USB command');
                              }
                            }}
                            className="px-2 py-1 bg-cyber-danger/20 hover:bg-cyber-danger text-cyber-danger hover:text-white rounded border border-cyber-danger/40 text-[10px] font-bold tracking-wider transition-all cursor-pointer"
                            title="Issue EDR command to disable USB"
                          >
                            BLOCK USB
                          </button>
                        )}
                        {canAct && alert.status !== 'Resolved' && (
                          <button
                            onClick={() => handleUpdateStatus(alert.id, 'Resolved')}
                            className="px-2 py-1 bg-cyber-success/15 hover:bg-cyber-success text-cyber-success hover:text-cyber-bg rounded border border-cyber-success/35 text-[10px] font-bold tracking-wider transition-all cursor-pointer"
                            title="Resolve alert"
                          >
                            RESOLVE
                          </button>
                        )}
                        <button 
                          onClick={() => navigate(`/employees/${empId}`)}
                          className="p-1.5 hover:bg-cyber-primary/20 text-cyber-muted hover:text-cyber-primary rounded transition-all cursor-pointer"
                          title="View DNA profile"
                        >
                          <ChevronRight className="h-4.5 w-4.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}

              {paginatedAlerts.length === 0 && (
                <tr>
                  <td colSpan="6" className="text-center py-12 text-cyber-muted">
                    <CheckCircle2 className="h-8 w-8 text-cyber-success mx-auto mb-2" />
                    {onlineOnly 
                      ? 'NO ALERTS RECORDED FOR CURRENTLY ONLINE EMPLOYEES' 
                      : 'NO CORRELATED ALERTS MATCHING THE FILTERS'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {filteredAlerts.length > PAGE_SIZE && (
          <div className="px-4 py-3 border-t border-cyber-border flex items-center justify-between text-xs font-mono text-cyber-muted bg-cyber-bg/40">
            <div>
              Showing <span className="text-cyber-text font-bold">{(page - 1) * PAGE_SIZE + 1}</span> - <span className="text-cyber-text font-bold">{Math.min(page * PAGE_SIZE, filteredAlerts.length)}</span> of <span className="text-cyber-text font-bold">{filteredAlerts.length}</span> alerts
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-2.5 py-1 rounded bg-cyber-card border border-cyber-border hover:border-cyber-primary text-cyber-text disabled:opacity-30 transition-all flex items-center gap-1 cursor-pointer"
              >
                <ChevronLeft className="h-3.5 w-3.5" /> Prev
              </button>
              <span className="px-2 text-cyber-text font-bold">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-2.5 py-1 rounded bg-cyber-card border border-cyber-border hover:border-cyber-primary text-cyber-text disabled:opacity-30 transition-all flex items-center gap-1 cursor-pointer"
              >
                Next <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
