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
    <div className="flex h-screen bg-cyber-bg text-cyber-text cyber-grid">
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
