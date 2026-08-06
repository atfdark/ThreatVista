import axios from 'axios';

// Backend API root. Set VITE_API_BASE_URL (e.g. http://192.168.1.100:8000/api)
// in frontend/.env when the dashboard must talk to a SOC server on the LAN.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api';

// Authenticated axios instance: attaches the JWT from localStorage to every
// request and redirects to /login when the token is rejected by the backend.
const http = axios.create({ baseURL: API_BASE_URL, timeout: 3000 });

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('threatvista_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

http.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401 && !window.location.pathname.includes('/login')) {
      localStorage.removeItem('threatvista_token');
      localStorage.removeItem('threatvista_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

export const MOCK_STATS = {
  total_employees: 156,
  high_risk: 2,
  active_alerts: 6,
  average_risk: 18
};

export const MOCK_EMPLOYEES = [
  { id: 1, name: "Rahul Sharma", email: "rahul.sharma@threatvista.com", department: "Engineering", risk_score: 92, status: "High Risk", photo_url: null },
  { id: 2, name: "Amit Verma", email: "amit.verma@threatvista.com", department: "Sales", risk_score: 63, status: "Suspicious", photo_url: null },
  { id: 3, name: "Priya Patel", email: "priya.patel@threatvista.com", department: "Human Resources", risk_score: 15, status: "Normal", photo_url: null },
  { id: 4, name: "Ananya Rao", email: "ananya.rao@threatvista.com", department: "Finance", risk_score: 28, status: "Normal", photo_url: null },
  { id: 5, name: "Vikram Singh", email: "vikram.singh@threatvista.com", department: "Marketing", risk_score: 41, status: "Normal", photo_url: null }
];

export const MOCK_ALERTS = [
  {
    id: 1,
    severity: "High",
    reason: "Correlation: Mass file copying of patent data (120 files) following external network upload (1.2GB) and USB insertion.",
    status: "Active",
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    employee: { id: 1, name: "Rahul Sharma", email: "rahul.sharma@threatvista.com", department: "Engineering", risk_score: 92, status: "High Risk" }
  },
  {
    id: 2,
    severity: "Medium",
    reason: "Unusual network upload volume (1.2 GB, baseline: 15 MB/day)",
    status: "Active",
    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
    employee: { id: 1, name: "Rahul Sharma", email: "rahul.sharma@threatvista.com", department: "Engineering", risk_score: 92, status: "High Risk" }
  },
  {
    id: 3,
    severity: "High",
    reason: "Late night login at 02:45 AM followed by access to restricted sales and employee contact spreadsheets.",
    status: "Investigating",
    timestamp: new Date(Date.now() - 17.5 * 60 * 60 * 1000).toISOString(),
    employee: { id: 2, name: "Amit Verma", email: "amit.verma@threatvista.com", department: "Sales", risk_score: 63, status: "Suspicious" }
  },
  {
    id: 4,
    severity: "Low",
    reason: "Unusual process spawned: cmd.exe executed file attribute edits.",
    status: "Resolved",
    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    employee: { id: 1, name: "Rahul Sharma", email: "rahul.sharma@threatvista.com", department: "Engineering", risk_score: 92, status: "High Risk" }
  }
];

export const MOCK_EMPLOYEE_DETAILS = {
  1: {
    id: 1,
    name: "Rahul Sharma",
    email: "rahul.sharma@threatvista.com",
    department: "Engineering",
    risk_score: 92,
    status: "High Risk",
    photo_url: null,
    behavior_profile: {
      working_hours_baseline: "09:00 - 18:00",
      avg_usb_inserts_per_day: 0.2,
      avg_file_copies_per_day: 4.5,
      avg_upload_mb_per_day: 15.0
    },
    events: [
      { id: 101, event_type: "file_copy", details: "Copied 120 files containing keyword 'patent_design' to USB", timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
      { id: 102, event_type: "usb_insert", details: "Mass Storage Device (Kingston 64GB) connected", timestamp: new Date(Date.now() - 2.5 * 60 * 60 * 1000).toISOString() },
      { id: 103, event_type: "network_upload", details: "Uploaded 1.2 GB of ZIP data to unknown external IP", timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString() },
      { id: 104, event_type: "process_start", details: "Ran cmd.exe to edit file attributes", timestamp: new Date(Date.now() - 4.5 * 60 * 60 * 1000).toISOString() }
    ],
    alerts: [
      { id: 1, severity: "High", reason: "Correlation: Mass file copying of patent data (120 files) following external network upload (1.2GB) and USB insertion.", status: "Active", timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
      { id: 2, severity: "Medium", reason: "Unusual network upload volume (1.2 GB, baseline: 15 MB/day)", status: "Active", timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString() }
    ],
    risk_scores: [
      { score: 40, recorded_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 48, recorded_at: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 56, recorded_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 64, recorded_at: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 72, recorded_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 85, recorded_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 92, recorded_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString() }
    ]
  },
  2: {
    id: 2,
    name: "Amit Verma",
    email: "amit.verma@threatvista.com",
    department: "Sales",
    risk_score: 63,
    status: "Suspicious",
    photo_url: null,
    behavior_profile: {
      working_hours_baseline: "10:00 - 19:00",
      avg_usb_inserts_per_day: 0.5,
      avg_file_copies_per_day: 12.2,
      avg_upload_mb_per_day: 45.0
    },
    events: [
      { id: 201, event_type: "login", details: "System access detected at 02:45 AM (Out-of-office hours)", timestamp: new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString() },
      { id: 202, event_type: "file_access", details: "Accessed employee_contacts_confidential.xlsx", timestamp: new Date(Date.now() - 17.5 * 60 * 60 * 1000).toISOString() },
      { id: 203, event_type: "usb_insert", details: "Unrecognized USB Device (Generic Flash) connected", timestamp: new Date(Date.now() - 17.2 * 60 * 60 * 1000).toISOString() }
    ],
    alerts: [
      { id: 3, severity: "High", reason: "Late night login at 02:45 AM followed by access to restricted sales and employee contact spreadsheets.", status: "Investigating", timestamp: new Date(Date.now() - 17.5 * 60 * 60 * 1000).toISOString() }
    ],
    risk_scores: [
      { score: 55, recorded_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 59, recorded_at: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 55, recorded_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 59, recorded_at: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 55, recorded_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 60, recorded_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 63, recorded_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString() }
    ]
  },
  3: {
    id: 3,
    name: "Priya Patel",
    email: "priya.patel@threatvista.com",
    department: "Human Resources",
    risk_score: 15,
    status: "Normal",
    photo_url: null,
    behavior_profile: {
      working_hours_baseline: "09:00 - 17:30",
      avg_usb_inserts_per_day: 0.05,
      avg_file_copies_per_day: 2.0,
      avg_upload_mb_per_day: 5.0
    },
    events: [
      { id: 301, event_type: "file_access", details: "Modified performance_evaluation_Q2.docx", timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString() },
      { id: 302, event_type: "login", details: "Logged in at 09:02 AM", timestamp: new Date(Date.now() - 10 * 60 * 60 * 1000).toISOString() }
    ],
    alerts: [],
    risk_scores: [
      { score: 12, recorded_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 15, recorded_at: new Date(Date.now() - 6 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 12, recorded_at: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 15, recorded_at: new Date(Date.now() - 4 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 12, recorded_at: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 15, recorded_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString() },
      { score: 15, recorded_at: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString() }
    ]
  }
};

export const MOCK_ANALYTICS = {
  summary: MOCK_STATS,
  risk_distribution: [
    { range: "Low (0-30)", count: 120 },
    { range: "Medium (31-60)", count: 28 },
    { range: "High (61-80)", count: 6 },
    { range: "Critical (81-100)", count: 2 }
  ],
  severity_distribution: [
    { severity: "High", count: 2 },
    { severity: "Medium", count: 3 },
    { severity: "Low", count: 1 }
  ],
  device_activity: [
    { name: "Mon", usb: 4, network: 120, files: 400 },
    { name: "Tue", usb: 8, network: 240, files: 820 },
    { name: "Wed", usb: 15, network: 1800, files: 1950 },
    { name: "Thu", usb: 5, network: 320, files: 610 },
    { name: "Fri", usb: 3, network: 290, files: 530 }
  ]
};

export const MOCK_SETTINGS = {
  high_risk_threshold: 75,
  suspicious_threshold: 50,
  dna_window_days: 14,
  endpoint_poll_seconds: 60,
  monitor_files: true,
  monitor_usb: true,
  monitor_network: true,
  monitor_processes: true
};

export const MOCK_ENDPOINTS = [
  {
    employee: { ...MOCK_EMPLOYEES[0] },
    device: {
      device_id: 'DEV-0001',
      hostname: 'RAHUL-PC',
      os_version: 'Windows 10',
      cpu_cores: 8,
      ram_gb: 16,
      ip_address: '192.168.1.102',
      agent_version: '1.0.0',
      online: true,
      last_seen_at: new Date(Date.now() - 3000).toISOString(),
      last_cpu_usage: 15,
      last_ram_usage: 42,
      last_disk_usage: 63
    },
    recent_event_count: 12
  },
  {
    employee: { ...MOCK_EMPLOYEES[2] },
    device: {
      device_id: 'DEV-0003',
      hostname: 'PRIYA-PC',
      os_version: 'Windows 11',
      cpu_cores: 8,
      ram_gb: 32,
      ip_address: '192.168.1.105',
      agent_version: '1.0.0',
      online: true,
      last_seen_at: new Date(Date.now() - 8000).toISOString(),
      last_cpu_usage: 8,
      last_ram_usage: 31,
      last_disk_usage: 48
    },
    recent_event_count: 3
  },
  {
    employee: { ...MOCK_EMPLOYEES[1] },
    device: {
      device_id: 'DEV-0002',
      hostname: 'AMIT-PC',
      os_version: 'Windows 10',
      cpu_cores: 4,
      ram_gb: 8,
      ip_address: '192.168.1.104',
      agent_version: '1.0.0',
      online: false,
      last_seen_at: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      last_cpu_usage: null,
      last_ram_usage: null,
      last_disk_usage: null
    },
    recent_event_count: 0
  }
];

export const api = {
  isBackendConnected: async () => {
    try {
      const res = await http.get(`/status`, { timeout: 2000 });
      return res.status === 200;
    } catch {
      return false;
    }
  },

  getStats: async () => {
    try {
      const res = await http.get(`/dashboard`);
      return res.data;
    } catch {
      return MOCK_STATS;
    }
  },

  getEmployees: async () => {
    try {
      const res = await http.get(`/employees`);
      return res.data;
    } catch {
      return MOCK_EMPLOYEES;
    }
  },

  getEmployeeDetail: async (id) => {
    try {
      const res = await http.get(`/employees/${id}`);
      return res.data;
    } catch {
      return MOCK_EMPLOYEE_DETAILS[id] || {
        id,
        name: "Unknown Employee",
        email: "unknown@threatvista.com",
        department: "Unknown",
        risk_score: 0,
        status: "Normal",
        photo_url: null,
        behavior_profile: { working_hours_baseline: "09:00 - 17:00", avg_usb_inserts_per_day: 0, avg_file_copies_per_day: 0, avg_upload_mb_per_day: 0 },
        events: [],
        alerts: [],
        risk_scores: []
      };
    }
  },

  getAlerts: async () => {
    try {
      const res = await http.get(`/alerts`);
      return res.data;
    } catch {
      return MOCK_ALERTS;
    }
  },

  getAnalytics: async () => {
    try {
      const res = await http.get(`/dashboard`);
      return {
        ...MOCK_ANALYTICS,
        summary: res.data.summary || res.data,
        risk_distribution: res.data.risk_distribution.length ? res.data.risk_distribution : MOCK_ANALYTICS.risk_distribution,
        severity_distribution: res.data.severity_distribution.length ? res.data.severity_distribution : MOCK_ANALYTICS.severity_distribution
      };
    } catch {
      return MOCK_ANALYTICS;
    }
  },

  getEvents: async (employeeId = null, limit = 20) => {
    try {
      const url = employeeId ? `/events?employee_id=${employeeId}&limit=${limit}` : `/events?limit=${limit}`;
      const res = await http.get(url);
      return res.data;
    } catch {
      return [];
    }
  },

  getAIAnalysis: async (employeeId) => {
    try {
      const res = await http.get(`/ai/analysis/${employeeId}`);
      return res.data;
    } catch {
      return null;
    }
  },

  analyzeEmployee: async (employeeId) => {
    try {
      const res = await http.post(`/ai/analyze/${employeeId}`);
      return res.data;
    } catch {
      return null;
    }
  },

  // --- Settings (persisted to backend) ---
  getSettings: async () => {
    try {
      const res = await http.get(`/settings`);
      return res.data;
    } catch {
      return MOCK_SETTINGS;
    }
  },

  saveSettings: async (settings) => {
    const res = await http.put(`/settings`, settings);
    return res.data;
  },

  // --- Alert status transitions (persisted to backend) ---
  updateAlertStatus: async (alertId, status) => {
    const res = await http.patch(`/alerts/${alertId}`, { status });
    return res.data;
  },

  // --- Auth / sessions (backend-revoked logout) ---
  logout: async () => {
    try {
      await http.post(`/auth/logout`);
    } catch {
      /* best-effort: still clear local state even if the backend is down */
    }
  },

  getSessions: async (userId) => {
    const params = userId ? { user_id: userId } : {};
    const res = await http.get(`/auth/sessions`, { params });
    return res.data;
  },

  revokeSession: async (sessionId) => {
    const res = await http.delete(`/auth/sessions/${sessionId}`);
    return res.data;
  },

  // --- Audit trail (admin only) ---
  getAuditLogs: async (params = {}) => {
    const res = await http.get(`/audit-logs`, { params });
    return res.data;
  },

  // --- Report downloads (blob; supports csv | json | html) ---
  downloadReport: async (reportType, format = 'json', start = '', end = '') => {
    const params = { format };
    if (start) params.start = start;
    if (end) params.end = end;
    const res = await http.get(`/reports/${reportType}`, { params, responseType: 'blob' });
    return res.data;
  },

  // --- EDR: remote commands (simulated) ---
  requestCommand: async (employeeId, command) => {
    const res = await http.post(`/employees/${employeeId}/commands`, { command });
    return res.data;
  },

  getCommands: async (employeeId) => {
    try {
      const res = await http.get(`/employees/${employeeId}/commands`);
      return res.data;
    } catch {
      return [];
    }
  },

  // --- EDR: connected endpoints (Active Sessions page) ---
  getEndpoints: async () => {
    try {
      const res = await http.get(`/endpoints`);
      return res.data;
    } catch {
      return MOCK_ENDPOINTS;
    }
  },

  // --- EDR: agent registration + heartbeat (used by the endpoint agent) ---
  registerAgent: async (employeeEmail, deviceInfo) => {
    const res = await http.post(`/agent/register`, { employee_email: employeeEmail, ...deviceInfo });
    return res.data;
  },

  sendHeartbeat: async (deviceId, metrics) => {
    const res = await http.post(`/agent/heartbeat`, { device_id: deviceId, ...metrics });
    return res.data;
  },

  login: async (username, password) => {
    try {
      const res = await http.post(`/auth/login`, { username, password });
      return res.data;
    } catch (err) {
      if (err.response && err.response.status === 401) {
        throw new Error("Invalid username or password");
      }
      if (err.response && err.response.status === 429) {
        throw new Error(err.response.data?.detail || "Too many attempts. Try again later.");
      }
      // Offline fallback so the demo can still be shown without a backend.
      const OFFLINE_USERS = {
        admin: { password: "admin123", role: "admin" },
        analyst: { password: "analyst123", role: "analyst" },
        auditor: { password: "auditor123", role: "auditor" },
      };
      const match = OFFLINE_USERS[username];
      if (match && match.password === password) {
        return {
          access_token: `mock_jwt_token_threatvista_${username}`,
          token_type: "bearer",
          username: username,
          role: match.role
        };
      }
      throw new Error("Connection failed. Use admin / admin123 (or analyst / auditor accounts).");
    }
  },

  register: async (name, email, password) => {
    const res = await http.post(`/auth/register`, { username: email, password, name });
    return res.data;
  }
};
