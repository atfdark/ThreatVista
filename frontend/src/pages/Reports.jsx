import React, { useState } from 'react';
import { FileBarChart, Download, FileJson, FileCode, FileText, Calendar, AlertCircle } from 'lucide-react';
import { api } from '../services/mockData';

const REPORTS = [
  { id: 'daily_threat', label: 'Daily Threat Report', desc: 'Today\'s alerts, events, and overall risk posture.' },
  { id: 'weekly_activity', label: 'Weekly Activity Report', desc: '7-day per-employee activity and risk summary.' },
  { id: 'monthly_summary', label: 'Monthly Security Summary', desc: '30-day overview with risk distribution and trends.' },
  { id: 'high_risk_employees', label: 'High-Risk Employee Report', desc: 'Employees scored above the suspicious threshold, ranked.' },
  { id: 'usb_usage', label: 'USB Usage Report', desc: 'USB insertions and removals in the selected period.' },
  { id: 'file_activity', label: 'File Activity Report', desc: 'File copy / create / delete / modify operations.' },
  { id: 'network_activity', label: 'Network Activity Report', desc: 'Outbound upload volumes and counts per employee.' },
];

const FORMATS = [
  { id: 'csv', label: 'CSV', icon: FileText, hint: 'Spreadsheet' },
  { id: 'json', label: 'JSON', icon: FileJson, hint: 'Structured' },
  { id: 'html', label: 'HTML', icon: FileCode, hint: 'Printable / PDF' },
];

export default function Reports() {
  const [start, setStart] = useState('');
  const [end, setEnd] = useState('');
  const [downloading, setDownloading] = useState(null); // "<reportId>:<format>"
  const [error, setError] = useState('');

  const handleDownload = async (reportType, format) => {
    const key = `${reportType}:${format}`;
    setError('');
    setDownloading(key);
    try {
      const blob = await api.downloadReport(reportType, format, start, end);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threatvista_${reportType}_${format}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err?.response?.data?.detail || 'Report download failed.');
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Title Header */}
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Security Reports</h2>
        <p className="text-xs text-cyber-muted font-mono mt-1 uppercase tracking-wider">
          DOWNLOADABLE EXPORTS &middot; CSV &middot; JSON &middot; PRINTABLE HTML
        </p>
      </div>

      {/* Date Range Selector */}
      <div className="flex flex-col xl:flex-row xl:items-center gap-4 p-5 glass-panel border border-cyber-border/80">
        <div className="flex items-center gap-2 text-cyber-muted">
          <Calendar className="h-4 w-4 text-cyber-primary" />
          <span className="text-xs font-mono uppercase tracking-wider">Report Period</span>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="date"
            value={start}
            onChange={(e) => setStart(e.target.value)}
            className="px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
          />
          <span className="text-cyber-muted text-xs font-mono">to</span>
          <input
            type="date"
            value={end}
            onChange={(e) => setEnd(e.target.value)}
            className="px-3 py-2 bg-cyber-card border border-cyber-border rounded-lg text-xs font-mono text-cyber-text focus:outline-none focus:border-cyber-primary"
          />
          <span className="text-[9px] text-cyber-muted font-mono">Leave blank for the default window (1 / 7 / 30 days).</span>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 px-4 py-3 bg-cyber-danger/10 border border-cyber-danger/30 rounded-lg text-xs text-cyber-danger font-mono">
          <AlertCircle className="h-4 w-4" /> {error}
        </div>
      )}

      {/* Report Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {REPORTS.map((report) => (
          <div key={report.id} className="p-6 glass-panel border border-cyber-border/80 flex flex-col gap-4">
            <div className="flex items-start gap-3">
              <div className="h-9 w-9 rounded-lg bg-cyber-primary/10 border border-cyber-primary/25 flex items-center justify-center shrink-0">
                <FileBarChart className="h-4.5 w-4.5 text-cyber-primary" />
              </div>
              <div>
                <h3 className="text-sm font-bold uppercase font-mono tracking-wide">{report.label}</h3>
                <p className="text-[10px] text-cyber-muted font-sans leading-relaxed mt-1">{report.desc}</p>
              </div>
            </div>

            <div className="flex gap-2 mt-auto">
              {FORMATS.map((fmt) => {
                const Icon = fmt.icon;
                const isBusy = downloading === `${report.id}:${fmt.id}`;
                return (
                  <button
                    key={fmt.id}
                    onClick={() => handleDownload(report.id, fmt.id)}
                    disabled={!!downloading}
                    className="flex items-center gap-2 px-3 py-2 bg-cyber-card hover:bg-cyber-primary/10 border border-cyber-border hover:border-cyber-primary/50 rounded-lg text-[10px] font-mono uppercase tracking-wider text-cyber-text hover:text-cyber-primary transition-all disabled:opacity-40 disabled:cursor-wait"
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {isBusy ? 'GENERATING...' : fmt.label}
                    <Download className="h-3 w-3 text-cyber-muted" />
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
