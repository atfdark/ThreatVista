import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  ArrowLeft, 
  Search, 
  Filter, 
  Calendar, 
  FileCode, 
  Laptop, 
  Monitor, 
  HardDrive, 
  Activity, 
  BrainCircuit, 
  AlertOctagon, 
  CheckCircle,
  Database,
  ArrowRight
} from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { api } from '../services/mockData';

export default function EmployeeProfile() {
  const { id } = useParams();
  const navigate = useNavigate();
  
  // List Mode States
  const [employees, setEmployees] = useState([]);
  const [aiScores, setAiScores] = useState({});
  const [searchTerm, setSearchTerm] = useState('');
  const [deptFilter, setDeptFilter] = useState('All');
  
  // Detail Mode States
  const [employee, setEmployee] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);

  // Load appropriate data
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        if (id) {
          const detail = await api.getEmployeeDetail(parseInt(id));
          setEmployee(detail);
          setAiAnalysis(detail.ai_analysis || null);
        } else {
          const list = await api.getEmployees();
          setEmployees(list);
          const scores = {};
          for (const emp of list) {
            const ai = await api.getAIAnalysis(emp.id);
            if (ai) scores[emp.id] = ai;
          }
          setAiScores(scores);
        }
      } catch (err) {
        console.error("Failed to load employee data", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, [id]);

  if (loading) {
    return (
      <div className="flex h-[70vh] items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-10 w-10 border-4 border-cyber-primary border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs font-mono text-cyber-muted uppercase tracking-widest">LOADING TELEMETRY PORTAL...</p>
        </div>
      </div>
    );
  }

  // ==========================================
  // RENDER DETAILED PROFILE
  // ==========================================
  if (id && employee) {
    const dna = employee.behavior_profile || { working_hours_baseline: "09:00 - 17:00", avg_usb_inserts_per_day: 0, avg_file_copies_per_day: 0, avg_upload_mb_per_day: 0 };
    
    // Format chart date
    const chartData = (employee.risk_scores || []).map(score => ({
      date: new Date(score.recorded_at).toLocaleDateString([], { month: 'short', day: 'numeric' }),
      score: score.score
    }));

    // AI recommendation rules
    const getRecommendations = (score) => {
      if (score > 75) {
        return [
          { action: "Revoke USB Access", desc: "Instantly disable read/write USB mass storage access on the client machine via endpoint agent policy." },
          { action: "Trigger Audit Logs Extraction", desc: "Force endpoint agent to upload detailed process tree execution logs for the last 24 hours." },
          { action: "Flag with HR & Security", desc: "Coordinate immediate security audit meeting. Flag employee profile for restricted source code repository access." }
        ];
      } else if (score > 40) {
        return [
          { action: "Increase Baseline Frequency", desc: "Reduce Behavior DNA recalculation window from 14 days to 48 hours." },
          { action: "Enable Network Rate Limiting", desc: "Restrict outbound network speeds to external domains to prevent large-volume packet transfers." }
        ];
      }
      return [
        { action: "Standard Monitoring", desc: "Behavior matches baseline DNA bounds. Continue standard background metadata ingestion." }
      ];
    };

    return (
      <div className="space-y-8 animate-fade-in">
        {/* Back navigation */}
        <button 
          onClick={() => navigate('/employees')}
          className="flex items-center gap-2 text-xs font-mono font-bold text-cyber-primary uppercase hover:underline focus:outline-none"
        >
          <ArrowLeft className="h-4 w-4" /> BACK TO MONITORING DIRECTORY
        </button>

        {/* Employee Header Panel */}
        <div className="p-6 glass-panel border border-cyber-border/80 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div className="flex items-center gap-4">
            <div className="h-16 w-16 rounded-full bg-cyber-primary/10 border-2 border-cyber-primary/30 flex items-center justify-center font-mono font-bold text-cyber-primary text-xl shadow-cyber">
              {employee.name.split(' ').map(n => n[0]).join('')}
            </div>
            <div>
              <h2 className="text-2xl font-bold tracking-tight">{employee.name}</h2>
              <p className="text-xs font-mono text-cyber-muted mt-1 uppercase">{employee.email} • {employee.department}</p>
            </div>
          </div>

          <div className="flex items-center gap-6 bg-cyber-bg/50 border border-cyber-border px-5 py-3 rounded-lg">
            <div>
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Risk Assessment</span>
              <span className="text-3xl font-extrabold text-cyber-text font-mono">
                {aiAnalysis ? `${aiAnalysis.risk_score}%` : `${employee.risk_score}%`}
              </span>
            </div>
            <div className="h-10 w-px bg-cyber-border"></div>
            <div>
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Classification</span>
              <span className={`text-xs font-mono px-2 py-0.5 rounded border inline-block mt-1 font-semibold uppercase ${
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Critical' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                (aiAnalysis ? aiAnalysis.status : employee.status) === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
              }`}>
                {aiAnalysis ? aiAnalysis.status : employee.status}
              </span>
            </div>
          </div>
        </div>

        {/* Behavior DNA Profiling (Baseline) */}
        <div>
          <h3 className="text-sm font-bold font-mono uppercase text-cyber-muted tracking-wider mb-4 flex items-center gap-2">
            <BrainCircuit className="h-5 w-5 text-cyber-primary" /> Personalized Behavior DNA (Rolling Baseline)
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Baseline Shift Hours</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{dna.working_hours_baseline}</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Normal daily working boundary</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily USB Inserts</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{dna.avg_usb_inserts_per_day} insertions/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Plug & Play hardware interactions</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily Copies</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{dna.avg_file_copies_per_day} operations/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">File system read & copy transfers</span>
            </div>
            <div className="p-4 bg-cyber-card/60 border border-cyber-border rounded-lg">
              <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider block">Avg Daily Network Upload</span>
              <span className="text-lg font-bold text-cyber-text block mt-1">{dna.avg_upload_mb_per_day} MB/day</span>
              <span className="text-[9px] text-cyber-muted font-mono block mt-1">Outbound packet bandwidth baseline</span>
            </div>
          </div>
        </div>

        {/* Risk Trend & AI summary */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Risk Line Chart */}
          <div className="lg:col-span-2 p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-6">Historical Risk Progression</h4>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0.4}/>
                      <stop offset="95%" stopColor={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.3} />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 100]} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f1626', borderColor: '#1e293b', borderRadius: 8, fontSize: 11 }}
                    itemStyle={{ color: '#f8fafc' }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="score" 
                    stroke={employee.risk_score > 75 ? '#ef4444' : '#06b6d4'} 
                    strokeWidth={2}
                    fillOpacity={1} 
                    fill="url(#colorRisk)" 
                    name="Risk score %"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Explainable AI Recommendations */}
          <div className="p-6 glass-panel flex flex-col justify-between">
            <div>
              <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4 flex items-center gap-2">
                <BrainCircuit className="h-4.5 w-4.5 text-cyber-primary" /> Explainable AI (XAI) Recommendation
              </h4>
              {aiAnalysis ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <span className="text-3xl font-extrabold text-cyber-text font-mono">{aiAnalysis.risk_score}%</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                      aiAnalysis.status === 'Critical' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                      aiAnalysis.status === 'High' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      aiAnalysis.status === 'Medium' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                      'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                    }`}>
                      {aiAnalysis.status}
                    </span>
                    {aiAnalysis.model_anomaly && (
                      <span className="text-[9px] font-mono px-2 py-0.5 rounded border border-cyber-danger/25 text-cyber-danger bg-cyber-danger/10">
                        ISOLATION FOREST ANOMALY
                      </span>
                    )}
                  </div>
                  <div className="space-y-2">
                    <span className="text-[10px] text-cyber-muted font-mono uppercase tracking-wider">Detected Risk Factors</span>
                    {aiAnalysis.reasons.map((reason, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <CheckCircle className={`h-3.5 w-3.5 shrink-0 mt-0.5 ${aiAnalysis.risk_score > 75 ? 'text-cyber-danger' : 'text-cyber-primary'}`} />
                        <span className="text-[11px] text-cyber-text leading-relaxed">{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {getRecommendations(employee.risk_score).map((rec, i) => (
                    <div key={i} className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg space-y-1">
                      <div className="flex items-center gap-2">
                        <CheckCircle className={`h-4 w-4 shrink-0 ${employee.risk_score > 75 ? 'text-cyber-danger' : 'text-cyber-primary'}`} />
                        <span className="text-xs font-bold text-cyber-text uppercase font-mono">{rec.action}</span>
                      </div>
                      <p className="text-[10px] text-cyber-muted leading-relaxed">{rec.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {aiAnalysis && (
              <div className="text-[10.5px] text-cyber-muted font-mono leading-relaxed mt-4 p-3 bg-cyber-border/20 border border-cyber-border rounded">
                <span className="text-cyber-text font-bold uppercase block mb-1">AI Model Output</span>
                Isolation Forest raw score: {aiAnalysis.model_score.toFixed(4)} | Anomaly: {aiAnalysis.model_anomaly ? 'Yes' : 'No'}
                <br/>
                Recommended: {aiAnalysis.recommendations.slice(0, 2).join('; ')}
              </div>
            )}
          </div>
        </div>

        {/* Telemetry Event Streams */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Events Log */}
          <div className="lg:col-span-2 p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Raw Metadata Telemetry Stream</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-cyber-border text-cyber-muted font-mono uppercase text-[9px] tracking-wider">
                    <th className="pb-3 pl-3">Event Type</th>
                    <th className="pb-3">Telemetry Details</th>
                    <th className="pb-3 text-right pr-3">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/40 font-mono">
                  {employee.events.map((evt) => (
                    <tr key={evt.id} className="hover:bg-cyber-border/10">
                      <td className="py-2.5 pl-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase ${
                          evt.event_type === 'usb_insert' ? 'text-cyber-primary border-cyber-primary/20 bg-cyber-primary/5' :
                          evt.event_type === 'file_copy' ? 'text-cyber-accent border-cyber-accent/20 bg-cyber-accent/5' :
                          evt.event_type === 'network_upload' ? 'text-cyber-secondary border-cyber-secondary/20 bg-cyber-secondary/5' :
                          'text-cyber-muted border-cyber-border bg-cyber-bg/50'
                        }`}>
                          {evt.event_type.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="py-2.5 text-xs text-cyber-text">{evt.details}</td>
                      <td className="py-2.5 text-right pr-3 text-cyber-muted text-[10px]">
                        {new Date(evt.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Connected Alerts List */}
          <div className="p-6 glass-panel">
            <h4 className="text-sm font-bold tracking-wide uppercase font-mono mb-4">Correlated Security Alerts</h4>
            <div className="space-y-4">
              {employee.alerts.length === 0 ? (
                <div className="text-center py-8 text-cyber-muted text-xs font-mono">
                  NO ACTIVE CORRELATED ALERTS
                </div>
              ) : (
                employee.alerts.map((alert) => (
                  <div key={alert.id} className="p-3 bg-cyber-bg/50 border border-cyber-border rounded-lg space-y-1.5">
                    <div className="flex justify-between items-center">
                      <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border uppercase ${
                        alert.severity === 'High' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                        'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25'
                      }`}>
                        {alert.severity} Severity
                      </span>
                      <span className="text-[10px] text-cyber-muted font-mono">{alert.status}</span>
                    </div>
                    <p className="text-[11px] text-cyber-text leading-relaxed">{alert.reason}</p>
                    <p className="text-[9px] text-cyber-muted font-mono">
                      {new Date(alert.timestamp).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ==========================================
  // RENDER MONITORED EMPLOYEES DIRECTORY
  // ==========================================
  const filteredEmployees = employees.filter(emp => {
    const matchesSearch = emp.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          emp.email.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesDept = deptFilter === 'All' || emp.department === deptFilter;
    return matchesSearch && matchesDept;
  });

  const departments = ['All', ...new Set(employees.map(emp => emp.department))];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Monitored Employees Directory</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">SEARCH EMPLOYEES & VIEW BEHAVIOR DNA PROFILES</p>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-4">
        {/* Search Input */}
        <div className="relative flex-1">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted">
            <Search className="h-4 w-4" />
          </span>
          <input
            type="text"
            placeholder="Search employees by name or email..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-10 pr-4 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-muted focus:outline-none focus:border-cyber-primary transition-colors"
          />
        </div>

        {/* Department Filter Select */}
        <div className="relative min-w-[200px]">
          <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-muted pointer-events-none">
            <Filter className="h-4 w-4" />
          </span>
          <select
            value={deptFilter}
            onChange={(e) => setDeptFilter(e.target.value)}
            className="w-full pl-10 pr-8 py-2.5 bg-cyber-card border border-cyber-border rounded-lg text-sm text-cyber-text focus:outline-none focus:border-cyber-primary appearance-none cursor-pointer"
          >
            {departments.map(dept => (
              <option key={dept} value={dept} className="bg-cyber-card">{dept}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Grid of Employees Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filteredEmployees.map((emp) => {
          const ai = aiScores[emp.id];
          const riskScore = ai ? ai.risk_score : emp.risk_score;
          const status = ai ? ai.status : emp.status;
          return (
            <div key={emp.id} className="p-6 glass-panel border border-cyber-border/80 flex flex-col justify-between h-56">
              <div>
                {/* Header */}
                <div className="flex justify-between items-start gap-4 mb-4">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-full bg-cyber-primary/10 border border-cyber-primary/20 flex items-center justify-center font-mono font-bold text-cyber-primary">
                      {emp.name.split(' ').map(n => n[0]).join('')}
                    </div>
                    <div>
                      <h4 className="font-bold text-cyber-text text-sm">{emp.name}</h4>
                      <span className="text-[10px] text-cyber-muted font-mono">{emp.department}</span>
                    </div>
                  </div>
                  <span className={`text-[9px] font-mono px-2 py-0.5 rounded border uppercase font-medium ${
                    status === 'Critical' || status === 'High Risk' ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/25' :
                    status === 'Medium' || status === 'Suspicious' ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/25' :
                    'text-cyber-success bg-cyber-success/10 border-cyber-success/25'
                  }`}>
                    {status}
                  </span>
                </div>

                {/* Risk Score bar */}
                <div className="space-y-1">
                  <div className="flex justify-between text-[11px] font-mono">
                    <span className="text-cyber-muted">RISK INDEX</span>
                    <span className="font-bold text-cyber-text">{riskScore}%</span>
                  </div>
                  <div className="w-full bg-cyber-bg border border-cyber-border h-2 rounded-full overflow-hidden">
                    <div 
                      className={`h-full ${
                        riskScore > 75 ? 'bg-cyber-danger' : 
                        riskScore > 50 ? 'bg-cyber-warning' : 
                        'bg-cyber-success'
                      }`}
                      style={{ width: `${riskScore}%` }}
                    ></div>
                  </div>
                </div>
              </div>

              {/* Bottom Navigate button */}
              <button 
                onClick={() => navigate(`/employees/${emp.id}`)}
                className="w-full mt-4 py-2 bg-cyber-border/40 hover:bg-cyber-primary text-cyber-text hover:text-cyber-bg hover:border-cyber-primary rounded-lg text-xs font-mono font-bold flex items-center justify-center gap-1 border border-cyber-border transition-all"
              >
                ANALYZE BEHAVIOR DNA <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}

        {filteredEmployees.length === 0 && (
          <div className="col-span-full text-center py-16 glass-panel">
            <AlertOctagon className="h-10 w-10 text-cyber-warning mx-auto mb-3" />
            <p className="text-sm font-mono text-cyber-muted">NO MONITORED EMPLOYEES MATCHED SEARCH CRITERIA</p>
          </div>
        )}
      </div>
    </div>
  );
}
