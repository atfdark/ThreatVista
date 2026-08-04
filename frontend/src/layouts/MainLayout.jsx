import React, { useEffect } from 'react';
import { Outlet, useNavigate } from 'react-router-dom';
import Sidebar from '../components/Sidebar';

export default function MainLayout() {
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('threatvista_token');
    if (!token) {
      navigate('/login');
    }
  }, [navigate]);

  return (
    <div className="flex h-screen bg-cyber-bg text-cyber-text cyber-grid min-h-screen">
      {/* Navigation Sidebar */}
      <Sidebar />

      {/* Main Command Center Body */}
      <main className="flex-1 pl-64 overflow-y-auto flex flex-col min-h-screen relative scanline-overlay">
        {/* Subtle top banner decoration */}
        <div className="h-1 bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent"></div>
        <div className="p-8 flex-1">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
