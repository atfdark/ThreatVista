import React, { useState, useEffect } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Users, 
  AlertTriangle, 
  BarChart3, 
  Settings, 
  LogOut, 
  ShieldCheck, 
  Database,
  RefreshCw
} from 'lucide-react';
import { api } from '../services/mockData';

export default function Sidebar() {
  const navigate = useNavigate();
  const [dbConnected, setDbConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('threatvista_user') || '{}');
    } catch {
      return {};
    }
  });

  const checkConnection = async () => {
    setLoading(true);
    const status = await api.isBackendConnected();
    setDbConnected(status);
    setLoading(false);
  };

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 10000); // Poll every 10s
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('threatvista_token');
    localStorage.removeItem('threatvista_user');
    navigate('/login');
  };

  const displayName = user.username ? user.username.charAt(0).toUpperCase() + user.username.slice(1) : 'Administrator';
  const initials = (user.username || 'AD').slice(0, 2).toUpperCase();
  const roleLabel = user.role === 'analyst' ? 'Security Analyst' : 'SOC Administrator';

  const navItems = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/employees', label: 'Employees', icon: Users },
    { to: '/alerts', label: 'Alerts', icon: AlertTriangle, badge: true },
    { to: '/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-cyber-card/90 border-r border-cyber-border flex flex-col h-screen fixed left-0 top-0 z-20 backdrop-blur-md">
      {/* Brand Header */}
      <div className="p-6 border-b border-cyber-border flex items-center gap-3">
        <ShieldCheck className="h-8 w-8 text-cyber-primary animate-cyber-pulse" />
        <div>
          <h1 className="font-bold text-lg tracking-wider text-transparent bg-clip-text bg-gradient-to-r from-cyber-primary to-cyber-secondary">
            THREATVISTA
          </h1>
          <p className="text-[10px] text-cyber-muted tracking-widest font-mono">INSIDER DETECTION</p>
        </div>
      </div>

      {/* Nav Menu */}
      <nav className="flex-1 p-4 space-y-2 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) => `
                flex items-center justify-between px-4 py-3 rounded-lg text-sm transition-all duration-200 group
                ${isActive 
                  ? 'bg-cyber-primary/10 text-cyber-primary border border-cyber-primary/20 shadow-cyber' 
                  : 'text-cyber-muted hover:text-cyber-text hover:bg-cyber-border/30 border border-transparent'
                }
              `}
            >
              <div className="flex items-center gap-3">
                <Icon className="h-5 w-5 transition-transform group-hover:scale-110" />
                <span className="font-medium">{item.label}</span>
              </div>
            </NavLink>
          );
        })}
      </nav>

      {/* Connection & User Status */}
      <div className="p-4 border-t border-cyber-border space-y-4">
        {/* Backend Heartbeat */}
        <div className="bg-cyber-bg/60 rounded-lg p-3 border border-cyber-border/80 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-cyber-muted" />
            <span className="text-xs font-mono">SQLite API</span>
          </div>
          <button 
            onClick={checkConnection} 
            disabled={loading}
            className="flex items-center gap-1.5 focus:outline-none"
            title="Refresh database connection status"
          >
            <span className={`h-2.5 w-2.5 rounded-full inline-block ${dbConnected ? 'bg-cyber-success shadow-[0_0_8px_#10b981]' : 'bg-cyber-danger shadow-[0_0_8px_#ef4444]'}`}></span>
            <span className="text-[10px] font-mono text-cyber-muted uppercase">
              {dbConnected ? 'online' : 'offline'}
            </span>
            <RefreshCw className={`h-3 w-3 text-cyber-muted ${loading ? 'animate-spin' : 'hover:text-cyber-primary transition-colors'}`} />
          </button>
        </div>

        {/* User Card */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-full bg-cyber-primary/10 border border-cyber-primary/30 flex items-center justify-center font-mono font-bold text-cyber-primary text-sm">
              {initials}
            </div>
            <div>
              <p className="text-xs font-semibold text-cyber-text">{displayName}</p>
              <p className="text-[10px] text-cyber-muted font-mono">{roleLabel}</p>
            </div>
          </div>
          <button 
            onClick={handleLogout}
            className="text-cyber-muted hover:text-cyber-danger p-2 rounded-lg hover:bg-cyber-danger/10 transition-colors"
            title="Sign Out"
          >
            <LogOut className="h-5 w-5" />
          </button>
        </div>
      </div>
    </aside>
  );
}
