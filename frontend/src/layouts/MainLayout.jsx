import React, { useEffect, useState, useCallback } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { UserCheck, Volume2, VolumeX, Bell, Wifi, WifiOff, RefreshCw } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import SecurityAlertPopup from '../components/SecurityAlertPopup';
import { useWebSocket } from '../services/websocket';
import { formatIST } from '../utils/time';
import { playSecurityAlertSound, startAlertBeepLoop, stopAlertBeepLoop, playAcknowledgeSound, isSoundEnabled, setSoundEnabled, testAlertSound } from '../utils/sound';

export default function MainLayout() {
  const navigate = useNavigate();
  const [toast, setToast] = useState(null);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [soundActive, setSoundActive] = useState(() => isSoundEnabled());

  useEffect(() => {
    const token = localStorage.getItem('threatvista_token');
    if (!token) {
      navigate('/login');
      return;
    }
    // Employees belong on their own profile page, not the SOC command center.
    try {
      const user = JSON.parse(localStorage.getItem('threatvista_user') || '{}');
      if (user.role === 'employee') {
        navigate('/me');
      }
    } catch {
      /* ignore malformed stored user */
    }
  }, [navigate]);

  // Continuous beeping until all active alerts are acknowledged/resolved
  useEffect(() => {
    const hasUnacknowledged = securityAlerts.some(
      (a) => a.status !== 'Acknowledged' && a.status !== 'Resolved'
    );
    if (hasUnacknowledged && soundActive) {
      startAlertBeepLoop();
    } else {
      stopAlertBeepLoop();
    }
    return () => {
      stopAlertBeepLoop();
    };
  }, [securityAlerts, soundActive]);

  const handleToggleSound = () => {
    const next = !soundActive;
    setSoundEnabled(next);
    setSoundActive(next);
  };

  const handleTestSound = () => {
    testAlertSound();
  };

  const handleDismissAlert = (alertToDismiss) => {
    setSecurityAlerts((prev) => prev.filter((a) => a !== alertToDismiss && a.alert_id !== alertToDismiss.alert_id));
  };

  const handleAlertStatusChange = (alert, newStatus) => {
    setSecurityAlerts((prev) =>
      prev.map((a) => (a.alert_id === alert.alert_id || a === alert ? { ...a, status: newStatus } : a))
    );
  };

  const handleAcknowledgeAll = () => {
    setSecurityAlerts((prev) =>
      prev.map((a) => ({ ...a, status: 'Acknowledged' }))
    );
    stopAlertBeepLoop();
    playAcknowledgeSound();
  };

  // Live WebSocket message handler with auto-reconnect
  const handleWsMessage = useCallback((msg) => {
    if (msg.type === 'new_login') {
      const d = msg.data || {};
      setToast({
        username: d.username,
        role: d.role,
        ip: d.ip,
        at: d.at,
      });
      window.setTimeout(() => setToast(null), 6000);
    } else if (msg.type === 'security_alert') {
      const alertData = msg.data || {};
      // Start continuous beep loop
      startAlertBeepLoop();
      // Add to active alerts stack (deduping by alert_id or timestamp/device)
      setSecurityAlerts((prev) => {
        const filtered = prev.filter(
          (a) => (alertData.alert_id && a.alert_id !== alertData.alert_id) || a.drive_letter !== alertData.drive_letter
        );
        return [alertData, ...filtered].slice(0, 10);
      });
    } else if (msg.type === 'alert_updated') {
      const updated = msg.data || {};
      setSecurityAlerts((prev) =>
        prev.map((a) =>
          a.alert_id === updated.id ? { ...a, status: updated.status, severity: updated.severity || a.severity } : a
        )
      );
    }
  }, []);

  const { isConnected, connectionStatus } = useWebSocket(handleWsMessage);

  return (
    <div className="flex h-screen bg-cyber-bg text-cyber-text cyber-grid">
      {/* Real-time Security Alert Pop-up Modal (HUD) */}
      <SecurityAlertPopup
        alerts={securityAlerts}
        onDismiss={handleDismissAlert}
        onStatusChange={handleAlertStatusChange}
        onAcknowledgeAll={handleAcknowledgeAll}
        soundEnabled={soundActive}
        onToggleSound={handleToggleSound}
      />

      {/* Live sign-in notification */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 p-4 glass-panel border border-cyber-success/40 bg-cyber-card/95 shadow-cyber rounded-lg max-w-xs animate-slide-in">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-cyber-success/10 border border-cyber-success/30 rounded-lg shrink-0">
              <UserCheck className="h-4 w-4 text-cyber-success" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-mono uppercase tracking-wider text-cyber-success mb-0.5">
                EMPLOYEE SIGNED IN
              </div>
              <div className="text-sm font-bold text-cyber-text truncate">{toast.username}</div>
              <div className="text-[10px] font-mono text-cyber-muted mt-0.5">
                {toast.role} · {toast.ip || 'unknown IP'} ·{' '}
                {toast.at ? formatIST(toast.at, { hour: '2-digit', minute: '2-digit' }) : ''}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Sidebar */}
      <Sidebar />

      {/* Main Command Center Body — this element is the scroll container */}
      <main className="flex-1 pl-64 overflow-y-auto relative scanline-overlay">
        {/* Top Control Ribbon & Live Status Bar */}
        <div className="sticky top-0 z-30 bg-cyber-card/90 backdrop-blur-md border-b border-cyber-border/40 px-8 py-2.5 flex items-center justify-between">
          <div className="flex items-center gap-4 text-xs font-mono">
            {/* Live WebSocket Connection Indicator */}
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${isConnected ? 'bg-cyber-success animate-pulse' : 'bg-cyber-danger'}`}></span>
              <span className="text-[11px] font-bold text-cyber-muted uppercase tracking-wider">
                {isConnected ? 'SOC CHANNEL ONLINE' : connectionStatus === 'reconnecting' ? 'RECONNECTING...' : 'DISCONNECTED'}
              </span>
            </div>
          </div>

          {/* Quick Header Controls */}
          <div className="flex items-center gap-3">
            {/* Audio Alert Controls */}
            <div className="flex items-center gap-1.5 bg-cyber-card/80 border border-cyber-border/60 rounded-lg px-2 py-1">
              <button
                onClick={handleToggleSound}
                className="flex items-center gap-1.5 text-xs font-mono text-cyber-muted hover:text-cyber-primary transition-colors"
                title={soundActive ? 'Sound Alerts: Enabled' : 'Sound Alerts: Muted'}
              >
                {soundActive ? (
                  <Volume2 className="h-3.5 w-3.5 text-cyber-primary" />
                ) : (
                  <VolumeX className="h-3.5 w-3.5 text-cyber-muted" />
                )}
                <span className="text-[10px] font-bold uppercase">{soundActive ? 'AUDIO ON' : 'MUTED'}</span>
              </button>

              <div className="h-3 w-px bg-cyber-border/60 mx-1"></div>

              <button
                onClick={handleTestSound}
                className="text-[9px] font-mono text-cyber-muted hover:text-cyber-accent transition-colors px-1 uppercase tracking-wider"
                title="Test Alert Chime"
              >
                TEST
              </button>
            </div>
          </div>
        </div>

        {/* Top Accent Gradient Bar */}
        <div className="h-1 bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent sticky top-[45px] z-20"></div>

        {/* Page Content */}
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

