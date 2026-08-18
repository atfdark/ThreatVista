import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  HardDrive,
  User,
  Laptop,
  Clock,
  CheckCircle,
  Shield,
  ShieldAlert,
  X,
  Volume2,
  VolumeX,
  ChevronRight,
  ChevronLeft,
  Activity,
  Layers,
  Cpu,
  CornerDownRight,
  Flame,
  Check,
  Search
} from 'lucide-react';
import { api } from '../services/mockData';
import { playAcknowledgeSound } from '../utils/sound';

export default function SecurityAlertPopup({
  alerts = [],
  onDismiss,
  onStatusChange,
  onAcknowledgeAll,
  soundEnabled = true,
  onToggleSound,
}) {
  const navigate = useNavigate();
  const [currentIndex, setCurrentIndex] = useState(0);
  const [isBusy, setIsBusy] = useState(false);
  const [actionMessage, setActionMessage] = useState('');

  // Get current logged in user role for RBAC
  const userRole = (() => {
    try {
      return JSON.parse(localStorage.getItem('threatvista_user') || '{}').role || 'admin';
    } catch {
      return 'admin';
    }
  })();

  const canAct = userRole === 'admin' || userRole === 'analyst';
  const isAdmin = userRole === 'admin';

  // Keep index within bounds if alerts change
  useEffect(() => {
    if (currentIndex >= alerts.length && alerts.length > 0) {
      setCurrentIndex(alerts.length - 1);
    }
  }, [alerts.length, currentIndex]);

  if (!alerts || alerts.length === 0) return null;

  const currentAlert = alerts[currentIndex] || alerts[0];
  const hasMultiple = alerts.length > 1;

  const handleAcknowledge = async () => {
    if (!currentAlert?.alert_id) {
      if (onStatusChange) onStatusChange(currentAlert, 'Acknowledged');
      return;
    }
    setIsBusy(true);
    try {
      await api.acknowledgeAlert(currentAlert.alert_id);
      playAcknowledgeSound();
      setActionMessage('Alert Acknowledged');
      if (onStatusChange) onStatusChange(currentAlert, 'Acknowledged');
      setTimeout(() => setActionMessage(''), 2500);
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    } finally {
      setIsBusy(false);
    }
  };

  const handleInvestigate = async () => {
    if (currentAlert?.alert_id) {
      try {
        await api.investigateAlert(currentAlert.alert_id);
        if (onStatusChange) onStatusChange(currentAlert, 'Investigating');
      } catch (err) {
        console.error('Failed to mark investigating:', err);
      }
    }
    if (currentAlert?.employee_id) {
      navigate(`/employees/${currentAlert.employee_id}`);
    } else {
      navigate('/alerts');
    }
  };

  const handleBlockUsb = async () => {
    if (!currentAlert?.alert_id) return;
    setIsBusy(true);
    try {
      await api.blockUsbAlert(currentAlert.alert_id);
      playAcknowledgeSound();
      setActionMessage('EDR Command Sent: USB Storage Disabled');
      if (onStatusChange) onStatusChange(currentAlert, 'Investigating');
      setTimeout(() => setActionMessage(''), 3000);
    } catch (err) {
      console.error('Failed to issue block USB command:', err);
    } finally {
      setIsBusy(false);
    }
  };

  const handleResolve = async () => {
    if (!currentAlert?.alert_id) return;
    setIsBusy(true);
    try {
      await api.resolveAlert(currentAlert.alert_id, 'Resolved via SOC Alert HUD');
      playAcknowledgeSound();
      setActionMessage('Alert Resolved');
      if (onStatusChange) onStatusChange(currentAlert, 'Resolved');
      setTimeout(() => {
        setActionMessage('');
        if (onDismiss) onDismiss(currentAlert);
      }, 1500);
    } catch (err) {
      console.error('Failed to resolve alert:', err);
    } finally {
      setIsBusy(false);
    }
  };

  // Severity color styles
  const severity = currentAlert.severity || 'Informational';
  const severityStyle =
    severity === 'Critical'
      ? 'border-cyber-danger text-cyber-danger bg-cyber-danger/15 shadow-[0_0_20px_rgba(239,68,68,0.3)]'
      : severity === 'High'
      ? 'border-cyber-danger/70 text-cyber-danger bg-cyber-danger/10 shadow-[0_0_15px_rgba(239,68,68,0.2)]'
      : severity === 'Medium'
      ? 'border-cyber-warning text-cyber-warning bg-cyber-warning/10 shadow-[0_0_15px_rgba(245,158,11,0.2)]'
      : 'border-cyber-primary text-cyber-primary bg-cyber-primary/10 shadow-[0_0_15px_rgba(0,240,255,0.2)]';

  const status = currentAlert.status || 'Active';
  const statusColor =
    status === 'Resolved'
      ? 'text-cyber-success bg-cyber-success/15 border-cyber-success/30'
      : status === 'Investigating'
      ? 'text-cyber-warning bg-cyber-warning/15 border-cyber-warning/30'
      : status === 'Acknowledged'
      ? 'text-cyber-accent bg-cyber-accent/15 border-cyber-accent/30'
      : 'text-cyber-danger bg-cyber-danger/15 border-cyber-danger/30 animate-pulse';

  return (
    <div className="fixed top-5 right-5 z-50 w-full max-w-lg animate-slide-in">
      <div
        className={`glass-panel border-2 rounded-xl bg-cyber-bg/95 backdrop-blur-md overflow-hidden transition-all duration-300 ${severityStyle}`}
      >
        {/* Top Glowing Status Bar */}
        <div className="flex items-center justify-between px-4 py-2.5 bg-cyber-card/80 border-b border-cyber-border/40">
          <div className="flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyber-danger opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-cyber-danger"></span>
            </span>
            <span className="text-xs font-mono font-bold tracking-widest text-cyber-danger uppercase">
              REAL-TIME SOC ALERT
            </span>
            {hasMultiple && (
              <span className="ml-2 text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyber-card border border-cyber-border text-cyber-muted">
                {currentIndex + 1} / {alerts.length}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Quick Acknowledge All */}
            {hasMultiple && canAct && onAcknowledgeAll && (
              <button
                onClick={onAcknowledgeAll}
                className="px-2 py-0.5 bg-cyber-primary/20 hover:bg-cyber-primary text-cyber-primary hover:text-cyber-bg border border-cyber-primary/40 rounded text-[9.5px] font-mono font-bold tracking-wider transition-all cursor-pointer"
                title="Acknowledge all alerts and stop beeping"
              >
                ACK ALL
              </button>
            )}

            {/* Audio Toggle button */}
            <button
              onClick={onToggleSound}
              className="p-1 rounded hover:bg-cyber-card text-cyber-muted hover:text-cyber-text transition-colors cursor-pointer"
              title={soundEnabled ? 'Alert Sound Enabled (Continuous Beep)' : 'Alert Sound Muted'}
            >
              {soundEnabled ? (
                <Volume2 className="h-4 w-4 text-cyber-primary" />
              ) : (
                <VolumeX className="h-4 w-4 text-cyber-muted" />
              )}
            </button>

            {/* Dismiss button */}
            <button
              onClick={() => onDismiss && onDismiss(currentAlert)}
              className="p-1 rounded hover:bg-cyber-danger/20 text-cyber-muted hover:text-cyber-danger transition-colors cursor-pointer"
              title="Dismiss Alert Pop-Up"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Main Alert Body */}
        <div className="p-5 space-y-4">
          {/* Header row: Title & Badges */}
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger shrink-0">
                <HardDrive className="h-6 w-6 animate-pulse" />
              </div>
              <div>
                <h3 className="text-base font-bold tracking-tight text-cyber-text flex items-center gap-2">
                  {currentAlert.title || '⚠️ USB DEVICE DETECTED'}
                </h3>
                <p className="text-xs text-cyber-muted font-mono mt-0.5">
                  {currentAlert.reason || 'USB Activity Detected on Monitored Endpoint'}
                </p>
              </div>
            </div>

            <div className="flex flex-col items-end gap-1.5 shrink-0">
              <span
                className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                  severity === 'Critical' || severity === 'High'
                    ? 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30'
                    : severity === 'Medium'
                    ? 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30'
                    : 'text-cyber-primary bg-cyber-primary/10 border-cyber-primary/30'
                }`}
              >
                {severity}
              </span>
              <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${statusColor}`}>
                {status}
              </span>
            </div>
          </div>

          {/* Action notification banner if any */}
          {actionMessage && (
            <div className="p-2 rounded bg-cyber-success/15 border border-cyber-success/40 text-cyber-success text-xs font-mono flex items-center gap-2 animate-fade-in">
              <CheckCircle className="h-4 w-4 shrink-0" />
              {actionMessage}
            </div>
          )}

          {/* Metadata Card */}
          <div className="grid grid-cols-2 gap-3 p-3.5 rounded-lg bg-cyber-card/60 border border-cyber-border/60 text-xs font-mono">
            <div className="space-y-1.5">
              <div className="text-[10px] text-cyber-muted uppercase tracking-wider flex items-center gap-1.5">
                <User className="h-3 w-3 text-cyber-primary" /> Employee
              </div>
              <div className="font-semibold text-cyber-text truncate">
                {currentAlert.employee_name || 'Rahul Sharma'}
              </div>
              <div className="text-[10px] text-cyber-muted truncate">
                Dept: {currentAlert.department || 'Engineering'}
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="text-[10px] text-cyber-muted uppercase tracking-wider flex items-center gap-1.5">
                <Laptop className="h-3 w-3 text-cyber-secondary" /> Endpoint
              </div>
              <div className="font-semibold text-cyber-text truncate">
                {currentAlert.hostname || 'DEV-LAPTOP-01'}
              </div>
              <div className="text-[10px] text-cyber-muted truncate">
                ID: {currentAlert.device_id || 'DEV-0001'}
              </div>
            </div>

            <div className="space-y-1.5 col-span-2 pt-2 border-t border-cyber-border/40">
              <div className="text-[10px] text-cyber-muted uppercase tracking-wider flex items-center gap-1.5">
                <HardDrive className="h-3 w-3 text-cyber-warning" /> Device Details
              </div>
              <div className="text-xs text-cyber-text font-bold flex items-center justify-between">
                <span>{currentAlert.device_name || 'USB Storage Device'}</span>
                {currentAlert.drive_letter && (
                  <span className="px-1.5 py-0.5 rounded bg-cyber-primary/10 border border-cyber-primary/30 text-cyber-primary text-[10px]">
                    Drive {currentAlert.drive_letter}
                  </span>
                )}
              </div>
            </div>

            {/* Hardware Specs Grid */}
            <div className="col-span-2 grid grid-cols-3 gap-2 pt-2 border-t border-cyber-border/30 text-[10px] text-cyber-muted">
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-cyber-muted/80">Vendor / PID</span>
                <span className="text-cyber-text font-bold">
                  {currentAlert.vendor_id || 'N/A'} : {currentAlert.product_id || 'N/A'}
                </span>
              </div>
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-cyber-muted/80">Capacity</span>
                <span className="text-cyber-text font-bold">{currentAlert.total_size || '16.0GB'}</span>
              </div>
              <div>
                <span className="block text-[9px] uppercase tracking-wider text-cyber-muted/80">File System</span>
                <span className="text-cyber-text font-bold">{currentAlert.file_system || 'FAT32'}</span>
              </div>
            </div>

            {currentAlert.serial_number && currentAlert.serial_number !== 'N/A' && (
              <div className="col-span-2 text-[10px] text-cyber-muted flex items-center justify-between pt-1">
                <span>Hardware Serial:</span>
                <span className="font-mono text-cyber-accent text-[9px] truncate max-w-[240px]">
                  {currentAlert.serial_number}
                </span>
              </div>
            )}
          </div>

          {/* Time & Alert Footer Details */}
          <div className="flex items-center justify-between text-[10px] font-mono text-cyber-muted px-1">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {currentAlert.timestamp ? new Date(currentAlert.timestamp).toLocaleTimeString() : 'Just now'}
            </span>
            <span className="text-cyber-muted/70">
              Risk: <span className="text-cyber-warning font-bold">Under AI Correlation</span>
            </span>
          </div>

          {/* Action Button Bar */}
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-cyber-border/50">
            {/* Acknowledge Button */}
            {canAct && status !== 'Acknowledged' && status !== 'Resolved' && (
              <button
                disabled={isBusy}
                onClick={handleAcknowledge}
                className="flex-1 min-w-[110px] px-3 py-2 bg-cyber-primary/20 hover:bg-cyber-primary text-cyber-primary hover:text-cyber-bg border border-cyber-primary/50 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-1.5 shadow-cyber cursor-pointer active:scale-95"
                title="Acknowledge alert and stop alarm beep"
              >
                <Check className="h-3.5 w-3.5" /> ACKNOWLEDGE (STOP BEEP)
              </button>
            )}

            {/* Investigate Button */}
            {canAct && (
              <button
                disabled={isBusy}
                onClick={handleInvestigate}
                className="flex-1 min-w-[110px] px-3 py-2 bg-cyber-warning/15 hover:bg-cyber-warning text-cyber-warning hover:text-cyber-bg border border-cyber-warning/40 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Search className="h-3.5 w-3.5" /> INVESTIGATE
              </button>
            )}

            {/* EDR Block USB Button (Admin only) */}
            {isAdmin && status !== 'Resolved' && (
              <button
                disabled={isBusy}
                onClick={handleBlockUsb}
                className="px-3 py-2 bg-cyber-danger/20 hover:bg-cyber-danger text-cyber-danger hover:text-white border border-cyber-danger/50 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-1.5 shadow-sm"
                title="Issue EDR command to disable USB mass storage on employee device"
              >
                <ShieldAlert className="h-3.5 w-3.5" /> BLOCK USB
              </button>
            )}

            {/* Resolve Button */}
            {isAdmin && status !== 'Resolved' && (
              <button
                disabled={isBusy}
                onClick={handleResolve}
                className="px-3 py-2 bg-cyber-success/15 hover:bg-cyber-success text-cyber-success hover:text-cyber-bg border border-cyber-success/40 rounded-lg text-xs font-mono font-bold tracking-wider transition-all flex items-center justify-center gap-1.5 shadow-sm"
              >
                <CheckCircle className="h-3.5 w-3.5" /> RESOLVE
              </button>
            )}
          </div>

          {/* Multiple alerts navigation controls */}
          {hasMultiple && (
            <div className="flex items-center justify-between pt-1 text-xs font-mono text-cyber-muted border-t border-cyber-border/30">
              <button
                onClick={() => setCurrentIndex((prev) => Math.max(0, prev - 1))}
                disabled={currentIndex === 0}
                className="px-2 py-1 hover:text-cyber-primary disabled:opacity-30 transition-colors flex items-center gap-1"
              >
                <ChevronLeft className="h-3.5 w-3.5" /> Prev Alert
              </button>
              <span>
                Alert {currentIndex + 1} of {alerts.length}
              </span>
              <button
                onClick={() => setCurrentIndex((prev) => Math.min(alerts.length - 1, prev + 1))}
                disabled={currentIndex === alerts.length - 1}
                className="px-2 py-1 hover:text-cyber-primary disabled:opacity-30 transition-colors flex items-center gap-1"
              >
                Next Alert <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
