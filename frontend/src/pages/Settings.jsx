import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, Save, ShieldAlert, Cpu, Database, Bell, 
  AlertCircle, CheckCircle2, Key, Plus, Trash2, Edit2, Search, Tag, ShieldCheck, X
} from 'lucide-react';
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

  // Sensitive Keywords state
  const [keywords, setKeywords] = useState([]);
  const [keywordSearch, setKeywordSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [showAddModal, setShowAddModal] = useState(false);
  const [editingKeyword, setEditingKeyword] = useState(null);
  const [newKeyword, setNewKeyword] = useState({ keyword: '', category: 'Financial', risk_weight: 10 });
  const [keywordSaving, setKeywordSaving] = useState(false);
  const [keywordMsg, setKeywordMsg] = useState({ type: '', text: '' });

  // Read-Only Auditor role: settings are view-only, all controls disabled.
  const isAuditor = (() => {
    try { return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role === 'auditor'; }
    catch { return false; }
  })();

  const fetchKeywords = async () => {
    try {
      const data = await api.getSensitiveKeywords();
      setKeywords(data);
    } catch (err) {
      console.error("Failed to load sensitive keywords", err);
    }
  };

  useEffect(() => {
    let mounted = true;
    (async () => {
      try {
        const [cfg, kws] = await Promise.all([
          api.getSettings(),
          api.getSensitiveKeywords()
        ]);
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
        setKeywords(kws);
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

  const handleCreateKeyword = async (e) => {
    e.preventDefault();
    if (!newKeyword.keyword.trim()) return;
    setKeywordSaving(true);
    setKeywordMsg({ type: '', text: '' });
    try {
      await api.createSensitiveKeyword({
        keyword: newKeyword.keyword.trim().toLowerCase(),
        category: newKeyword.category,
        risk_weight: parseInt(newKeyword.risk_weight) || 10,
        is_active: true
      });
      setNewKeyword({ keyword: '', category: 'Financial', risk_weight: 10 });
      setShowAddModal(false);
      setKeywordMsg({ type: 'success', text: 'Keyword added successfully!' });
      await fetchKeywords();
      setTimeout(() => setKeywordMsg({ type: '', text: '' }), 4000);
    } catch (err) {
      setKeywordMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to add keyword.' });
    } finally {
      setKeywordSaving(false);
    }
  };

  const handleUpdateKeyword = async (e) => {
    e.preventDefault();
    if (!editingKeyword || !editingKeyword.keyword.trim()) return;
    setKeywordSaving(true);
    setKeywordMsg({ type: '', text: '' });
    try {
      await api.updateSensitiveKeyword(editingKeyword.id, {
        keyword: editingKeyword.keyword.trim().toLowerCase(),
        category: editingKeyword.category,
        risk_weight: parseInt(editingKeyword.risk_weight) || 10,
        is_active: editingKeyword.is_active
      });
      setEditingKeyword(null);
      setKeywordMsg({ type: 'success', text: 'Keyword updated successfully!' });
      await fetchKeywords();
      setTimeout(() => setKeywordMsg({ type: '', text: '' }), 4000);
    } catch (err) {
      setKeywordMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to update keyword.' });
    } finally {
      setKeywordSaving(false);
    }
  };

  const handleDeleteKeyword = async (id, keywordName) => {
    if (!window.confirm(`Delete sensitive keyword "${keywordName}"?`)) return;
    try {
      await api.deleteSensitiveKeyword(id);
      setKeywordMsg({ type: 'success', text: `Keyword "${keywordName}" removed.` });
      await fetchKeywords();
      setTimeout(() => setKeywordMsg({ type: '', text: '' }), 4000);
    } catch (err) {
      setKeywordMsg({ type: 'error', text: 'Failed to delete keyword.' });
    }
  };

  const filteredKeywords = keywords.filter(k => {
    const matchesSearch = k.keyword.toLowerCase().includes(keywordSearch.toLowerCase()) || 
                          k.category.toLowerCase().includes(keywordSearch.toLowerCase());
    const matchesCat = selectedCategory === 'ALL' || k.category.toUpperCase() === selectedCategory.toUpperCase();
    return matchesSearch && matchesCat;
  });

  const categories = ['ALL', 'Financial', 'HR', 'Intellectual Property', 'Strategic', 'Security', 'General'];

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
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Settings</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
          ADJUST THREAT ENGINE RATINGS, SENSITIVE ASSET KEYWORDS & INGESTION PARAMETERS
        </p>
      </div>

      {/* Sensitive Asset Keywords Management Section */}
      <div className="p-6 glass-panel border border-cyber-border/80 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border/50 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyber-primary/10 rounded-lg border border-cyber-primary/30">
              <Key className="h-5 w-5 text-cyber-primary" />
            </div>
            <div>
              <h3 className="text-sm font-bold uppercase font-mono text-cyber-text">Sensitive Company Asset Keywords</h3>
              <p className="text-[11px] text-cyber-muted">Define confidential keywords (salary, payroll, source_code, project_alpha) to detect unauthorized data movement.</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-cyber-muted bg-cyber-bg px-2.5 py-1 rounded border border-cyber-border">
              {keywords.length} KEYWORDS CONFIGURED
            </span>
            {!isAuditor && (
              <button
                type="button"
                onClick={() => setShowAddModal(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-primary/20 hover:bg-cyber-primary/30 text-cyber-primary border border-cyber-primary/40 rounded-lg text-xs font-mono font-bold transition-all"
              >
                <Plus className="h-4 w-4" /> ADD KEYWORD
              </button>
            )}
          </div>
        </div>

        {/* Feedback Message */}
        {keywordMsg.text && (
          <div className={`p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
            keywordMsg.type === 'success' 
              ? 'bg-cyber-success/10 border-cyber-success/30 text-cyber-success' 
              : 'bg-cyber-danger/10 border-cyber-danger/30 text-cyber-danger'
          }`}>
            {keywordMsg.type === 'success' ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
            {keywordMsg.text}
          </div>
        )}

        {/* Search and Category Filter */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search sensitive keywords (e.g. salary, confidential)..."
              value={keywordSearch}
              onChange={(e) => setKeywordSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text placeholder:text-cyber-muted/60 focus:outline-none focus:border-cyber-primary"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {categories.map(cat => (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1.5 rounded-lg text-[11px] font-mono transition-colors ${
                  selectedCategory === cat
                    ? 'bg-cyber-primary text-cyber-bg font-bold'
                    : 'bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-text'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Keywords Grid / Table */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 max-h-72 overflow-y-auto pr-1">
          {filteredKeywords.map(kw => (
            <div
              key={kw.id}
              className="p-3 bg-cyber-bg/70 border border-cyber-border hover:border-cyber-primary/50 rounded-lg flex flex-col justify-between transition-all group"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <Tag className="h-3.5 w-3.5 text-cyber-primary shrink-0" />
                  <span className="font-mono text-xs font-bold text-cyber-text truncate">{kw.keyword}</span>
                </div>
                {!isAuditor && (
                  <div className="flex items-center gap-1 opacity-60 group-hover:opacity-100 transition-opacity">
                    <button
                      type="button"
                      onClick={() => setEditingKeyword(kw)}
                      className="p-1 hover:text-cyber-primary transition-colors"
                      title="Edit keyword"
                    >
                      <Edit2 className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDeleteKeyword(kw.id, kw.keyword)}
                      className="p-1 hover:text-cyber-danger transition-colors"
                      title="Delete keyword"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                )}
              </div>
              <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-cyber-muted">
                <span className="px-1.5 py-0.5 rounded bg-cyber-border/40 text-cyber-secondary border border-cyber-border/60">
                  {kw.category}
                </span>
                <span className="text-cyber-warning font-bold">
                  +{kw.risk_weight || 10} Risk
                </span>
              </div>
            </div>
          ))}
          {filteredKeywords.length === 0 && (
            <div className="col-span-full py-8 text-center text-xs font-mono text-cyber-muted">
              No matching keywords found.
            </div>
          )}
        </div>
      </div>

      {/* Main Configuration Form */}
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
            className="flex items-center gap-2 px-5 py-3 bg-gradient-to-r from-cyber-primary to-cyber-secondary hover:from-cyber-primary/90 hover:to-cyber-secondary/90 text-cyber-bg font-bold rounded-lg text-xs tracking-wider transition-all focus:outline-none hover:scale-[1.01] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
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

      {/* Add Keyword Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-scale-up">
            <div className="flex items-center justify-between border-b border-cyber-border/50 pb-3">
              <h3 className="font-mono text-sm font-bold text-cyber-text uppercase flex items-center gap-2">
                <Key className="h-4 w-4 text-cyber-primary" /> Add Sensitive Keyword
              </h3>
              <button 
                onClick={() => setShowAddModal(false)}
                className="text-cyber-muted hover:text-cyber-text"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleCreateKeyword} className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Keyword / Asset Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. salary, project_alpha, patent"
                  value={newKeyword.keyword}
                  onChange={(e) => setNewKeyword({ ...newKeyword, keyword: e.target.value })}
                  className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Category</label>
                  <select
                    value={newKeyword.category}
                    onChange={(e) => setNewKeyword({ ...newKeyword, category: e.target.value })}
                    className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                  >
                    <option value="Financial">Financial</option>
                    <option value="HR">HR</option>
                    <option value="Intellectual Property">Intellectual Property</option>
                    <option value="Strategic">Strategic</option>
                    <option value="Security">Security</option>
                    <option value="General">General</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Risk Added</label>
                  <select
                    value={newKeyword.risk_weight}
                    onChange={(e) => setNewKeyword({ ...newKeyword, risk_weight: parseInt(e.target.value) })}
                    className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                  >
                    <option value="10">+10 Risk</option>
                    <option value="20">+20 Risk</option>
                    <option value="30">+30 Risk</option>
                    <option value="40">+40 Risk</option>
                    <option value="50">+50 Risk</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs font-mono hover:text-cyber-text"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={keywordSaving}
                  className="px-4 py-2 bg-cyber-primary text-cyber-bg font-bold rounded-lg text-xs font-mono hover:bg-cyber-primary/90 disabled:opacity-50"
                >
                  {keywordSaving ? 'SAVING...' : 'ADD KEYWORD'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Keyword Modal */}
      {editingKeyword && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4 animate-scale-up">
            <div className="flex items-center justify-between border-b border-cyber-border/50 pb-3">
              <h3 className="font-mono text-sm font-bold text-cyber-text uppercase flex items-center gap-2">
                <Edit2 className="h-4 w-4 text-cyber-primary" /> Edit Sensitive Keyword
              </h3>
              <button 
                onClick={() => setEditingKeyword(null)}
                className="text-cyber-muted hover:text-cyber-text"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handleUpdateKeyword} className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Keyword / Asset Name</label>
                <input
                  type="text"
                  required
                  value={editingKeyword.keyword}
                  onChange={(e) => setEditingKeyword({ ...editingKeyword, keyword: e.target.value })}
                  className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Category</label>
                  <select
                    value={editingKeyword.category}
                    onChange={(e) => setEditingKeyword({ ...editingKeyword, category: e.target.value })}
                    className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                  >
                    <option value="Financial">Financial</option>
                    <option value="HR">HR</option>
                    <option value="Intellectual Property">Intellectual Property</option>
                    <option value="Strategic">Strategic</option>
                    <option value="Security">Security</option>
                    <option value="General">General</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono uppercase text-cyber-muted mb-1">Risk Added</label>
                  <select
                    value={editingKeyword.risk_weight}
                    onChange={(e) => setEditingKeyword({ ...editingKeyword, risk_weight: parseInt(e.target.value) })}
                    className="w-full p-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
                  >
                    <option value="10">+10 Risk</option>
                    <option value="20">+20 Risk</option>
                    <option value="30">+30 Risk</option>
                    <option value="40">+40 Risk</option>
                    <option value="50">+50 Risk</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setEditingKeyword(null)}
                  className="px-4 py-2 bg-cyber-bg border border-cyber-border text-cyber-muted rounded-lg text-xs font-mono hover:text-cyber-text"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={keywordSaving}
                  className="px-4 py-2 bg-cyber-primary text-cyber-bg font-bold rounded-lg text-xs font-mono hover:bg-cyber-primary/90 disabled:opacity-50"
                >
                  {keywordSaving ? 'SAVING...' : 'SAVE CHANGES'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
