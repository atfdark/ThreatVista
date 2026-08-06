import React, { useEffect, useState } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import { UserCheck } from 'lucide-react';
import Sidebar from '../components/Sidebar';
import { useWebSocket } from '../services/websocket';

export default function MainLayout() {
  const navigate = useNavigate();
  const [toast, setToast] = useState(null);

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

  // Live sign-in toasts: the SOC console sees every employee login instantly.
  useWebSocket((msg) => {
    if (msg.type === 'new_login') {
      const d = msg.data || {};
      setToast({
        username: d.username,
        role: d.role,
        ip: d.ip,
        at: d.at,
      });
      window.setTimeout(() => setToast(null), 6000);
    }
  });

  return (
    <div className="flex h-screen bg-cyber-bg text-cyber-text cyber-grid">
      {/* Live sign-in notification */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 p-4 glass-panel border border-cyber-success/40 bg-cyber-card/95 shadow-cyber rounded-lg max-w-xs">
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
                {toast.at ? new Date(toast.at).toLocaleTimeString() : ''}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Navigation Sidebar */}
      <Sidebar />

      {/* Main Command Center Body — this element is the scroll container */}
      <main className="flex-1 pl-64 overflow-y-auto relative scanline-overlay">
        {/* Subtle top banner decoration */}
        <div className="h-1 bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent sticky top-0 z-10"></div>
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
