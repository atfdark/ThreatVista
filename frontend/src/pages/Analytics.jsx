import React, { useState, useEffect } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, AreaChart, Area, CartesianGrid, Legend } from 'recharts';
import { BarChart3, ShieldAlert, Cpu, HardDrive, Network, BrainCircuit, Activity } from 'lucide-react';
import { api } from '../services/mockData';

export default function Analytics() {
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const data = await api.getAnalytics();
        setAnalytics(data);
      } catch (err) {
        console.error("Failed to load analytics data", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">INGESTING GLOBAL ANALYTICS...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Analytics & Audits</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">AGGREGATED ANOMALOUS BEHAVIOR TELEMETRY LOGS</p>
      </div>

      {/* Metric Breakdown Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary rounded-lg shrink-0">
            <Cpu className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Telemetry Processors</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">Watchdog & psutil</span>
            <span className="text-[9px] text-cyber-muted font-mono">Real-time local event parsing</span>
          </div>
        </div>

        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-accent/10 border border-cyber-accent/20 text-cyber-accent rounded-lg shrink-0">
            <HardDrive className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Hardware Monitors</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">WMI PnP Device Listeners</span>
            <span className="text-[9px] text-cyber-muted font-mono">USB connection tracking</span>
          </div>
        </div>

        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-secondary/10 border border-cyber-secondary/20 text-cyber-secondary rounded-lg shrink-0">
            <Network className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Network Evaluators</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">TCP Socket Listeners</span>
            <span className="text-[9px] text-cyber-muted font-mono">Upload bandwidth tracking</span>
          </div>
        </div>
      </div>

      {/* AI Model Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-accent/10 border border-cyber-accent/20 text-cyber-accent rounded-lg shrink-0">
            <BrainCircuit className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Anomaly Detection Model</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">Isolation Forest</span>
            <span className="text-[9px] text-cyber-muted font-mono">Unsupervised behavioral analysis</span>
          </div>
        </div>

        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-primary/10 border border-cyber-primary/20 text-cyber-primary rounded-lg shrink-0">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">AI Alerts Generated</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">{analytics?.severity_distribution?.reduce((a,b)=>a+b.count,0) || 0}</span>
            <span className="text-[9px] text-cyber-muted font-mono">Rule + AI correlation</span>
          </div>
        </div>

        <div className="p-5 glass-panel flex items-center gap-4">
          <div className="p-3 bg-cyber-success/10 border border-cyber-success/20 text-cyber-success rounded-lg shrink-0">
            <Activity className="h-6 w-6" />
          </div>
          <div>
            <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Model Status</span>
            <span className="text-xl font-bold text-cyber-text block mt-0.5">Active</span>
            <span className="text-[9px] text-cyber-muted font-mono">Real-time inference</span>
          </div>
        </div>
      </div>

      {/* Main charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Chart */}
        <div className="p-6 glass-panel">
          <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-6">User Risk Score Distribution</h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics?.risk_distribution || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                <XAxis dataKey="range" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} name="Users Count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Count Chart */}
        <div className="p-6 glass-panel">
          <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-6">Security Alerts Severity Distribution</h4>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analytics?.severity_distribution || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                <XAxis dataKey="severity" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="count" fill="#a855f7" radius={[4, 4, 0, 0]} name="Alerts Count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Aggregate Telemetry area */}
      <div className="p-6 glass-panel">
        <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-6">Anomalous Weekly Telemetry Trends</h4>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={analytics?.device_activity || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
              <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
              <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                itemStyle={{ color: '#f8fafc' }}
              />
              <Legend wrapperStyle={{ fontSize: 11, color: '#f8fafc' }} />
              <Area type="monotone" dataKey="files" stackId="1" stroke="#a855f7" fill="#a855f7" fillOpacity={0.15} name="Total Copies (operations)" />
              <Area type="monotone" dataKey="network" stackId="2" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.15} name="Upload Load (MB)" />
              <Area type="monotone" dataKey="usb" stackId="3" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.25} name="USB Activity (inserts)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
