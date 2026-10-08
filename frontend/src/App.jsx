import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './layouts/MainLayout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import EmployeeProfile from './pages/EmployeeProfile';
import Incidents from './pages/Incidents';
import Alerts from './pages/Alerts';
import Analytics from './pages/Analytics';
import Settings from './pages/Settings';
import Reports from './pages/Reports';
import Audit from './pages/Audit';
import ActiveSessions from './pages/ActiveSessions';
import MyProfile from './pages/MyProfile';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/me" element={<MyProfile />} />
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="sessions" element={<ActiveSessions />} />
          <Route path="employees" element={<Dashboard />} />
          <Route path="employees/:id" element={<EmployeeProfile />} />
          <Route path="incidents" element={<Incidents />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="settings" element={<Settings />} />
          <Route path="reports" element={<Reports />} />
          <Route path="audit" element={<Audit />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
