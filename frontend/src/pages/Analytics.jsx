import React, { useState, useEffect } from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, AreaChart, Area, CartesianGrid, Legend, Cell } from 'recharts';
import { BarChart3, ShieldAlert, Cpu, HardDrive, Network, BrainCircuit, Activity, Key, Building2, Tag } from 'lucide-react';
import { api } from '../services/mockData';

export default function Analytics() {
  const [analytics, setAnalytics] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [anaData, dashData] = await Promise.all([
          api.getAnalytics(),
          api.getStats()
        ]);
        setAnalytics(anaData);
        setDashboardData(dashData);
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
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">INGESTING GLOBAL ANALYTICS & SENSITIVE ASSETS...</p>
        </div>
      </div>
    );
  }

  const departmentRiskData = dashboardData?.department_risk || [
    { department: 'HR', role: 'HR', avg_risk: 72, employee_count: 3 },
    { department: 'Finance', role: 'Finance', avg_risk: 68, employee_count: 4 },
    { department: 'Engineering', role: 'Developer', avg_risk: 45, employee_count: 8 },
    { department: 'Sales', role: 'Sales', avg_risk: 38, employee_count: 5 },
    { department: 'IT Support', role: 'IT Support', avg_risk: 25, employee_count: 3 }
  ];

  const sensitiveAssetsData = dashboardData?.most_accessed_sensitive_assets || [
    { keyword: 'salary', count: 14 },
    { keyword: 'employee', count: 10 },
    { keyword: 'client', count: 7 },
    { keyword: 'budget', count: 5 },
    { keyword: 'source_code', count: 4 },
    { keyword: 'project_alpha', count: 3 }
  ];

  return (
    <div className="space-y-8 animate-fade-in pb-12">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">System Analytics & Threat Intelligence</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
          AGGREGATED ANOMALOUS BEHAVIOR, ROLE RISK INTELLIGENCE & SENSITIVE ASSET MOVEMENTS
        </p>
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

      {/* New Intelligence Charts: Department Risk & Sensitive Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top Risk Departments & Roles */}
        <div className="p-6 glass-panel border border-cyber-border/80">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono flex items-center gap-2 text-cyber-text">
                <Building2 className="h-4 w-4 text-cyber-primary" /> Top Risk Departments & Roles
              </h4>
              <p className="text-xs text-cyber-muted">Department risk averages weighted by role baseline behaviors</p>
            </div>
            <span className="text-[10px] font-mono bg-cyber-bg px-2.5 py-1 rounded border border-cyber-border text-cyber-muted">
              ROLE-BASED INTELLIGENCE
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={departmentRiskData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                <XAxis type="number" stroke="#64748b" fontSize={11} domain={[0, 100]} tickLine={false} />
                <YAxis dataKey="department" type="category" stroke="#64748b" fontSize={11} tickLine={false} width={90} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                  itemStyle={{ color: '#f8fafc' }}
                  formatter={(val, name, item) => [`${val}% Average Risk (${item.payload.role} role)`, 'Risk Index']}
                />
                <Bar dataKey="avg_risk" radius={[0, 4, 4, 0]} name="Avg Risk %">
                  {departmentRiskData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={entry.avg_risk > 70 ? '#ef4444' : entry.avg_risk > 50 ? '#f59e0b' : '#06b6d4'} 
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Most Accessed Sensitive Assets */}
        <div className="p-6 glass-panel border border-cyber-border/80">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono flex items-center gap-2 text-cyber-text">
                <Key className="h-4 w-4 text-cyber-secondary" /> Most Accessed Sensitive Company Assets
              </h4>
              <p className="text-xs text-cyber-muted">Frequent sensitive keyword detections across file telemetry</p>
            </div>
            <span className="text-[10px] font-mono bg-cyber-bg px-2.5 py-1 rounded border border-cyber-border text-cyber-muted">
              KEYWORD SCANNER
            </span>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sensitiveAssetsData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                <XAxis dataKey="keyword" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                  itemStyle={{ color: '#f8fafc' }}
                  formatter={(val) => [`${val} detections`, 'Hit Count']}
                />
                <Bar dataKey="count" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Hit Count" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Main charts: Risk Distribution & Severity */}
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
