import React, { useState, useEffect } from 'react';
import {
  Brain,
  Clock,
  HardDrive,
  FolderTree,
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  FileText,
  Activity,
  Layers,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { api } from '../services/mockData';
import { formatISTClock } from '../utils/time';

export default function EmployeeBehaviorPanel({ employeeId, compact = false }) {
  const [twin, setTwin] = useState(null);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(!compact);

  useEffect(() => {
    if (!employeeId) return;
    let isMounted = true;
    const loadBehaviorData = async () => {
      setLoading(true);
      try {
        const [twinData, anomData] = await Promise.all([
          api.getUserDigitalTwin(employeeId),
          api.getUserAnomalyHistory(employeeId, 3),
        ]);
        if (isMounted) {
          setTwin(twinData);
          setAnomalies(anomData || []);
        }
      } catch (err) {
        console.error('Failed to load employee behavioral profile', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };
    loadBehaviorData();
    return () => {
      isMounted = false;
    };
  }, [employeeId]);

  if (loading) {
    return (
      <div className="p-3 bg-cyber-bg/50 border border-cyber-border/40 rounded-lg text-xs font-mono text-cyber-muted flex items-center justify-center gap-2">
        <Activity className="h-3.5 w-3.5 animate-spin text-cyber-primary" /> Loading Digital Twin Intelligence...
      </div>
    );
  }

  if (!twin) return null;

  const latestAnomaly = anomalies.length > 0 ? anomalies[0] : null;
  const isHighAnomaly = latestAnomaly && (latestAnomaly.severity === 'HIGH' || latestAnomaly.anomaly_score >= 65);

  return (
    <div className="border border-cyber-primary/30 bg-cyber-bg/80 rounded-lg overflow-hidden font-mono shadow-sm">
      {/* Header bar */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="px-3.5 py-2 bg-cyber-card/90 border-b border-cyber-border/60 flex items-center justify-between cursor-pointer hover:bg-cyber-card transition-colors"
      >
        <div className="flex items-center gap-2">
          <Brain className="h-4 w-4 text-cyber-primary animate-pulse" />
          <span className="text-xs font-bold text-cyber-text tracking-wider uppercase">
            Employee Digital Twin & UBA Intelligence
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary font-bold">
            {twin.role} Baseline
          </span>
        </div>

        <div className="flex items-center gap-2">
          {latestAnomaly && (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase flex items-center gap-1 ${
              isHighAnomaly
                ? 'text-rose-400 bg-rose-500/10 border-rose-500/30 animate-pulse'
                : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
            }`}>
              <ShieldAlert className="h-3 w-3" />
              Anomaly: {latestAnomaly.anomaly_score}% ({latestAnomaly.severity})
            </span>
          )}
          {expanded ? <ChevronUp className="h-3.5 w-3.5 text-cyber-muted" /> : <ChevronDown className="h-3.5 w-3.5 text-cyber-muted" />}
        </div>
      </div>

      {/* Expanded Intelligence Grid */}
      {expanded && (
        <div className="p-3.5 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-xs">
            
            {/* 1. Working Hours & Time Anomaly Card */}
            <div className="p-2.5 rounded bg-cyber-card/60 border border-cyber-border/50 flex flex-col justify-between">
              <div>
                <div className="text-[10px] uppercase text-cyber-muted font-bold flex items-center gap-1">
                  <Clock className="h-3 w-3 text-cyan-400" /> Normal Operating Hours
                </div>
                <div className="text-sm font-extrabold text-cyber-text mt-1">
                  {twin.normal_hours || '09:00 - 18:00'}
                </div>
              </div>
              <div className="mt-2 text-[10.5px] text-cyber-muted border-t border-cyber-border/40 pt-1.5 flex items-center justify-between">
                <span>Current Clock:</span>
                <span className="text-cyan-300 font-bold">{formatISTClock(new Date(), { hour: '2-digit', minute: '2-digit' })}</span>
              </div>
            </div>

            {/* 2. File Velocity & Sensitivity Card */}
            <div className="p-2.5 rounded bg-cyber-card/60 border border-cyber-border/50 flex flex-col justify-between">
              <div>
                <div className="text-[10px] uppercase text-cyber-muted font-bold flex items-center gap-1">
                  <FileText className="h-3 w-3 text-indigo-400" /> Daily File Baseline
                </div>
                <div className="text-sm font-extrabold text-cyber-text mt-1">
                  {twin.avg_files_per_day} <span className="text-[10px] font-normal text-cyber-muted">files / day</span>
                </div>
              </div>
              <div className="mt-2 text-[10.5px] text-cyber-muted border-t border-cyber-border/40 pt-1.5 flex items-center justify-between">
                <span>Typical Tier:</span>
                <span className="text-indigo-300 font-bold uppercase">{twin.typical_sensitivity || 'INTERNAL'}</span>
              </div>
            </div>

            {/* 3. USB Attachment Habit Card */}
            <div className="p-2.5 rounded bg-cyber-card/60 border border-cyber-border/50 flex flex-col justify-between">
              <div>
                <div className="text-[10px] uppercase text-cyber-muted font-bold flex items-center gap-1">
                  <HardDrive className="h-3 w-3 text-amber-400" /> USB Usage Habit
                </div>
                <div className="text-sm font-extrabold text-cyber-text mt-1 flex items-center gap-1.5">
                  <span className={twin.usb_frequency === 'None' || twin.usb_frequency === 'Rare' ? 'text-emerald-400' : 'text-amber-400'}>
                    {twin.usb_frequency}
                  </span>
                  <span className="text-[10px] font-normal text-cyber-muted">({twin.usb_events_per_week} / wk)</span>
                </div>
              </div>
              <div className="mt-2 text-[10.5px] text-cyber-muted border-t border-cyber-border/40 pt-1.5 flex items-center justify-between">
                <span>Threat Baseline:</span>
                <span className="text-cyber-text font-bold">{twin.risk_profile} Risk</span>
              </div>
            </div>
          </div>

          {/* Common Directory Footprint */}
          {twin.common_directories && twin.common_directories.length > 0 && (
            <div className="p-2 rounded bg-cyber-card/40 border border-cyber-border/40 text-[11px] flex items-center gap-2">
              <FolderTree className="h-3.5 w-3.5 text-cyber-primary shrink-0" />
              <span className="text-cyber-muted text-[10px] uppercase font-bold shrink-0">Common Workspaces:</span>
              <div className="flex flex-wrap gap-1.5">
                {twin.common_directories.map((dir, idx) => (
                  <span key={idx} className="px-1.5 py-0.2 rounded bg-cyber-card border border-cyber-border text-[10px] text-cyber-text">
                    {dir}/
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Active Anomaly Diagnostic Indicators */}
          {latestAnomaly && latestAnomaly.indicators && latestAnomaly.indicators.length > 0 && (
            <div className="p-2.5 rounded bg-amber-950/20 border border-amber-500/30 text-xs">
              <div className="flex items-center justify-between text-[11px] font-bold text-amber-400 mb-1.5">
                <span className="flex items-center gap-1">
                  <AlertTriangle className="h-3.5 w-3.5" /> Active Behavioral Anomaly Indicators
                </span>
                <span className="text-[10px] text-cyber-muted">
                  Score: {latestAnomaly.anomaly_score}% ({latestAnomaly.severity})
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {latestAnomaly.indicators.map((ind, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/40 text-[10.5px] text-amber-200 font-medium">
                    • {ind}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
