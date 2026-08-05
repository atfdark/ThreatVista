import React, { useState, useEffect } from 'react';
import { Settings as SettingsIcon, Save, ShieldAlert, Cpu, Database, Bell, AlertCircle, CheckCircle2 } from 'lucide-react';
import { api } from '../services/mockData';

export default function Settings() {
  const [highRiskVal, setHighRiskVal] = useState(75);
  const [suspiciousVal, setSuspiciousVal] = useState(50);
  const [dnaWindow, setDnaWindow] = useState(14);
  const [endpointPoll, setEndpointPoll] = useState(60);
  const [monitoringToggles, setMonitoringToggles] = useState({
    files: true,
    usb: true,
    network: true,
    processes: true
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState('');

  // Read-Only Auditor role: settings are view-only, all controls disabled.
  const isAuditor = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role === 'auditor'; }
    catch { return false; }
  })();

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const cfg = await api.getSettings();
        if (!mounted) return;
        setHighRiskVal(cfg.high_risk_threshold ?? 75);
        setSuspiciousVal(cfg.suspicious_threshold ?? 50);
        setDnaWindow(cfg.dna_window_days ?? 14);
        setEndpointPoll(cfg.endpoint_poll_seconds ?? 60);
        setMonitoringToggles({
          files: cfg.monitor_files ?? true,
          usb: cfg.monitor_usb ?? true,
          network: cfg.monitor_network ?? true,
          processes: cfg.monitor_processes ?? true
        });
      } catch (err) {
        console.error("Failed to load settings", err);
      } finally {
        if (mounted) setLoading(false);
      }
    })();
    return () => { mounted = false; };
  }, []);

  const handleToggle = (key) => {
    setMonitoringToggles(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setSaved(false);
    setSaveError('');
    try {
      await api.saveSettings({
        high_risk_threshold: highRiskVal,
        suspicious_threshold: suspiciousVal,
        dna_window_days: dnaWindow,
        endpoint_poll_seconds: endpointPoll,
        monitor_files: monitoringToggles.files,
        monitor_usb: monitoringToggles.usb,
        monitor_network: monitoringToggles.network,
        monitor_processes: monitoringToggles.processes
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 4000);
    } catch (err) {
      setSaveError(err?.response?.data?.detail || 'Failed to save configuration.');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING ENGINE CONFIGURATION...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Settings</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">ADJUST THREAT ENGINE RATINGS & INGESTION PARAMETERS</p>
      </div>

      <form onSubmit={handleSave} className="space-y-6 max-w-3xl">
        <fieldset disabled={isAuditor} className="space-y-6">
        {/* Risk Threshold Panel */}
        <div className="p-6 glass-panel border border-cyber-border/80 space-y-6">
          <div className="flex items-center gap-3 border-b border-cyber-border/50 pb-4">
            <ShieldAlert className="h-5 w-5 text-cyber-primary" />
            <h3 className="text-sm font-bold uppercase font-mono">Risk Index Calibration</h3>
          </div>

          <div className="space-y-6">
            {/* High Risk Slider */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-cyber-text font-semibold">HIGH RISK CLASSIFICATION THRESHOLD</span>
                <span className="text-cyber-danger font-bold">{highRiskVal}%</span>
              </div>
              <input
                type="range"
                min="60"
                max="95"
                value={highRiskVal}
                onChange={(e) => setHighRiskVal(parseInt(e.target.value))}
                className="w-full h-1.5 bg-cyber-bg rounded-lg appearance-none cursor-pointer accent-cyber-danger border border-cyber-border"
              />
              <p className="text-[10px] text-cyber-muted">Risk index scores above this threshold classify the employee as 'High Risk' and trigger automatic mitigation policies.</p>
            </div>

            {/* Suspicious Slider */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-cyber-text font-semibold">SUSPICIOUS CLASSIFICATION THRESHOLD</span>
                <span className="text-cyber-warning font-bold">{suspiciousVal}%</span>
              </div>
              <input
                type="range"
                min="30"
                max="59"
                value={suspiciousVal}
                onChange={(e) => setSuspiciousVal(parseInt(e.target.value))}
                className="w-full h-1.5 bg-cyber-bg rounded-lg appearance-none cursor-pointer accent-cyber-warning border border-cyber-border"
              />
              <p className="text-[10px] text-cyber-muted">Risk index scores above this threshold classify the employee as 'Suspicious' and increase metadata audit rates.</p>
            </div>
          </div>
        </div>

        {/* Endpoint agent calibration */}
        <div className="p-6 glass-panel border border-cyber-border/80 space-y-6">
          <div className="flex items-center gap-3 border-b border-cyber-border/50 pb-4">
            <Cpu className="h-5 w-5 text-cyber-secondary" />
            <h3 className="text-sm font-bold uppercase font-mono">Endpoint Ingestion Calibration</h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="block text-xs font-mono uppercase text-cyber-muted">Behavior DNA Rolling Baseline (Days)</label>
              <select
                value={dnaWindow}
                onChange={(e) => setDnaWindow(parseInt(e.target.value))}
                className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
              >
                <option value="7">7 Days</option>
                <option value="14">14 Days (Recommended)</option>
                <option value="30">30 Days</option>
              </select>
              <p className="text-[9px] text-cyber-muted">The sliding time frame utilized to construct user-specific behavior baselines.</p>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-mono uppercase text-cyber-muted">Endpoint Heartbeat Rate (Seconds)</label>
              <select
                value={endpointPoll}
                onChange={(e) => setEndpointPoll(parseInt(e.target.value))}
                className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
              >
                <option value="30">30 Seconds</option>
                <option value="60">60 Seconds</option>
                <option value="300">5 Minutes</option>
              </select>
              <p className="text-[9px] text-cyber-muted">Interval frequency at which local agents synchronize logs to the server.</p>
            </div>
          </div>
        </div>

        {/* Security Module Toggles */}
        <div className="p-6 glass-panel border border-cyber-border/80 space-y-6">
          <div className="flex items-center gap-3 border-b border-cyber-border/50 pb-4">
            <Database className="h-5 w-5 text-cyber-accent" />
            <h3 className="text-sm font-bold uppercase font-mono">Telemetry Collection Modules</h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {[
              { key: 'files', label: 'File Operations', desc: 'Monitor creation, deletion, and mass renaming events.' },
              { key: 'usb', label: 'USB Connections', desc: 'Listen for Windows PNP mass storage drives insertions.' },
              { key: 'network', label: 'Outbound TCP Packets', desc: 'Monitor outbound sockets and upload byte volume.' },
              { key: 'processes', label: 'Process Executions', desc: 'Flag execution of console tools (cmd, powershell).' }
            ].map(mod => (
              <div key={mod.key} className="flex justify-between items-start p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg">
                <div className="space-y-0.5">
                  <span className="text-xs font-bold text-cyber-text block uppercase font-mono">{mod.label}</span>
                  <span className="text-[9px] text-cyber-muted block leading-relaxed">{mod.desc}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggle(mod.key)}
                  className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                    monitoringToggles[mod.key] ? 'bg-cyber-primary' : 'bg-cyber-border'
                  }`}
                >
                  <span
                    className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-cyber-bg shadow ring-0 transition duration-200 ease-in-out ${
                      monitoringToggles[mod.key] ? 'translate-x-4' : 'translate-x-0'
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        </div>

        {/* Save button */}
        <div className="flex items-center gap-4">
          <button
            type="submit"
            disabled={saving || isAuditor}
            className="flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-xs tracking-wider transition-all focus:outline-none hover:scale-[1.01] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Save className="h-4 w-4" /> {isAuditor ? 'READ-ONLY MODE' : saving ? 'SAVING...' : 'SAVE ENGINE CONFIGURATION'}
          </button>

          {saved && !isAuditor && (
            <div className="flex items-center gap-1.5 text-cyber-success font-mono text-xs uppercase animate-pulse">
              <CheckCircle2 className="h-4 w-4" /> Configuration saved to database
            </div>
          )}

          {saveError && (
            <div className="flex items-center gap-1.5 text-cyber-danger font-mono text-xs uppercase">
              <AlertCircle className="h-4 w-4" /> {saveError}
            </div>
          )}

          {isAuditor && (
            <div className="flex items-center gap-1.5 text-cyber-warning font-mono text-xs uppercase">
              <ShieldAlert className="h-4 w-4" /> Read-only auditor — changes are blocked
            </div>
          )}
        </div>
        </fieldset>
      </form>
    </div>
  );
}
