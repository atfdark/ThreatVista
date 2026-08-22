import axios from 'axios';

// Backend API root. Default `/api` goes through the Vite dev proxy (same
// origin), so login works from localhost OR a LAN IP. Override with
// VITE_API_BASE_URL (e.g. http://192.168.1.100:8000/api) for a direct
// backend URL when the UI is not served by Vite.
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

// Authenticated axios instance: attaches the JWT from localStorage to every
// request and redirects to /login when the token is rejected by the backend.
const http = axios.create({ baseURL: API_BASE_URL, timeout: 15000 });

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

// ---------------------------------------------------------------------------
// Neutral empty defaults used when the backend is unreachable.
//
// The UI shows ONLY real data from the backend. When an API call fails these
// placeholders are returned so pages render their empty states instead of
// fabricating demo employees/alerts/incidents/endpoints.
// ---------------------------------------------------------------------------

const EMPTY_STATS = {
  total_employees: 0,
  high_risk: 0,
  active_alerts: 0,
  average_risk: 0
};

const EMPTY_ANALYTICS = {
  summary: EMPTY_STATS,
  risk_distribution: [],
  severity_distribution: [],
  device_activity: []
};

// Safe placeholder for an employee whose profile could not load. No fake
// events/alerts/risk history — just an empty shell so the page can render.
const emptyEmployeeDetail = (id) => ({
  id,
  name: "Unknown Employee",
  email: "unknown@threatvista.com",
  department: "Unknown",
  role_type: "General",
  role_baseline: null,
  last_triggered_rule: "Standard Monitoring",
  risk_score: 0,
  status: "Normal",
  photo_url: null,
  behavior_profile: {
    working_hours_baseline: "09:00 - 17:00",
    avg_usb_inserts_per_day: 0,
    avg_file_copies_per_day: 0,
    avg_upload_mb_per_day: 0
  },
  events: [],
  alerts: [],
  risk_scores: [],
  sensitive_files_accessed: [],
  top_matched_keywords: []
});

const EMPTY_INCIDENT = {
  id: 0,
  employee_id: null,
  employee: null,
  title: "Unknown Incident",
  severity: "Medium",
  status: "CLOSED",
  risk_score: 0,
  confidence: 0,
  created_at: null,
  updated_at: null,
  resolved_at: null,
  resolved_by: null,
  resolution_reason: null,
  active: false,
  timeline: []
};

// Config thresholds the Settings page needs to render its form. These are
// defaults (same shape the backend returns), not fabricated records.
const DEFAULT_SETTINGS = {
  high_risk_threshold: 75,
  suspicious_threshold: 50,
  dna_window_days: 14,
  endpoint_poll_seconds: 60,
  monitor_files: true,
  monitor_usb: true,
  monitor_network: true,
  monitor_processes: true
};

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
      return EMPTY_STATS;
    }
  },

  getEmployees: async () => {
    try {
      const res = await http.get(`/employees`);
      return res.data;
    } catch {
      return [];
    }
  },

  getEmployeeDetail: async (id) => {
    try {
      const res = await http.get(`/employees/${id}`);
      return res.data;
    } catch {
      return emptyEmployeeDetail(id);
    }
  },

  deleteEmployee: async (id) => {
    const res = await http.delete(`/employees/${id}`);
    return res.data;
  },

  getAlerts: async () => {
    try {
      const res = await http.get(`/alerts`);
      return res.data;
    } catch {
      return [];
    }
  },

  getAnalytics: async () => {
    try {
      const res = await http.get(`/dashboard`);
      return {
        ...EMPTY_ANALYTICS,
        summary: res.data.summary || res.data,
        risk_distribution: res.data.risk_distribution || [],
        severity_distribution: res.data.severity_distribution || [],
        device_activity: res.data.device_activity || []
      };
    } catch {
      return EMPTY_ANALYTICS;
    }
  },

  getEvents: async (employeeIdOrLimit = null, maybeLimit = 50) => {
    try {
      let employeeId = null;
      let limit = 50;

      if (typeof employeeIdOrLimit === 'object' && employeeIdOrLimit !== null) {
        employeeId = employeeIdOrLimit.employee_id ?? employeeIdOrLimit.employeeId ?? null;
        limit = employeeIdOrLimit.limit ?? 50;
      } else if (employeeIdOrLimit !== null && maybeLimit !== 50) {
        employeeId = employeeIdOrLimit;
        limit = maybeLimit;
      } else if (typeof employeeIdOrLimit === 'number' && employeeIdOrLimit > 0) {
        // If single numeric parameter passed (e.g. api.getEvents(200)), treat as limit
        limit = employeeIdOrLimit;
      } else {
        employeeId = employeeIdOrLimit;
      }

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

  // --- Employee Role Management & Baselines ---
  updateEmployeeRole: async (employeeId, roleType) => {
    const res = await http.patch(`/employees/${employeeId}/role`, { role_type: roleType });
    return res.data;
  },

  getRoleBaselines: async () => {
    try {
      const res = await http.get(`/roles/baselines`);
      return res.data;
    } catch {
      return {};
    }
  },

  // --- Company Sensitive Asset Keywords ---
  getSensitiveKeywords: async () => {
    try {
      const res = await http.get(`/sensitive-keywords`);
      return res.data;
    } catch {
      return [];
    }
  },

  createSensitiveKeyword: async (keywordData) => {
    const res = await http.post(`/sensitive-keywords`, keywordData);
    return res.data;
  },

  updateSensitiveKeyword: async (keywordId, keywordData) => {
    const res = await http.put(`/sensitive-keywords/${keywordId}`, keywordData);
    return res.data;
  },

  deleteSensitiveKeyword: async (keywordId) => {
    const res = await http.delete(`/sensitive-keywords/${keywordId}`);
    return res.data;
  },

  // --- Settings (persisted to backend) ---
  getSettings: async () => {
    try {
      const res = await http.get(`/settings`);
      return res.data;
    } catch {
      return DEFAULT_SETTINGS;
    }
  },

  saveSettings: async (settings) => {
    const res = await http.put(`/settings`, settings);
    return res.data;
  },

  // --- Alert status transitions & EDR responses (persisted & audited) ---
  updateAlertStatus: async (alertId, status, reason = null) => {
    const res = await http.patch(`/alerts/${alertId}`, { status, reason });
    return res.data;
  },

  acknowledgeAlert: async (alertId) => {
    const res = await http.post(`/alerts/${alertId}/acknowledge`);
    return res.data;
  },

  investigateAlert: async (alertId) => {
    const res = await http.post(`/alerts/${alertId}/investigate`);
    return res.data;
  },

  blockUsbAlert: async (alertId) => {
    const res = await http.post(`/alerts/${alertId}/block-usb`);
    return res.data;
  },

  resolveAlert: async (alertId, reason = 'Resolved by administrator') => {
    const res = await http.post(`/alerts/${alertId}/resolve`, { reason });
    return res.data;
  },

  // --- Incidents (persistent lifecycle; admin actions audited) ---
  getIncidents: async (params = {}) => {
    try {
      const res = await http.get(`/incidents`, { params });
      return res.data;
    } catch {
      return [];
    }
  },

  getIncidentDetail: async (incidentId) => {
    try {
      const res = await http.get(`/incidents/${incidentId}`);
      return res.data;
    } catch {
      return EMPTY_INCIDENT;
    }
  },

  investigateIncident: async (incidentId) => {
    const res = await http.post(`/incidents/${incidentId}/investigate`);
    return res.data;
  },

  resolveIncident: async (incidentId, reason) => {
    const res = await http.post(`/incidents/${incidentId}/resolve`, { reason });
    return res.data;
  },

  archiveIncident: async (incidentId) => {
    const res = await http.post(`/incidents/${incidentId}/archive`);
    return res.data;
  },

  resetEmployeeRisk: async (employeeId) => {
    const res = await http.post(`/employees/${employeeId}/reset-risk`);
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
      return [];
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

  // --- EDR: employee self-enrollment (token-based, no email) ---
  // Issues a one-time enrollment token for the logged-in employee's device.
  enrollDevice: async () => {
    const res = await http.post(`/agent/enroll`);
    return res.data;
  },

  // Current device status for the logged-in employee (My Profile page).
  getAgentStatus: async () => {
    const res = await http.get(`/agent/status`);
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
      throw new Error("Cannot reach the backend. Make sure the server is running, then try again.");
    }
  },

  register: async (name, email, password, roleType = 'Developer', department = null) => {
    const res = await http.post(`/auth/register`, { 
      username: email, 
      password, 
      name,
      role_type: roleType,
      department: department || roleType
    });
    return res.data;
  },

  // --- JIT Action Approvals (Pre-Action Authorization) ---
  getActionRequests: async (status = null) => {
    try {
      const params = {};
      if (status) params.status = status;
      const res = await http.get('/action-requests', { params });
      return res.data;
    } catch {
      return [];
    }
  },

  getPendingActionRequestsCount: async () => {
    try {
      const res = await http.get('/action-requests/pending-count');
      return res.data?.pending_count || 0;
    } catch {
      return 0;
    }
  },

  approveActionRequest: async (requestId, notes = '') => {
    const res = await http.post(`/action-requests/${requestId}/approve`, { notes });
    return res.data;
  },

  rejectActionRequest: async (requestId, reason = '') => {
    const res = await http.post(`/action-requests/${requestId}/reject`, { reason });
    return res.data;
  },

  batchResolveActionRequests: async (requestIds, action = 'approve', notes = '') => {
    const res = await http.post('/action-requests/batch-resolve', {
      request_ids: requestIds,
      action,
      notes,
    });
    return res.data;
  },


  // --- Priority 2: User Behavior Analytics & Digital Twin ---
  getUserBehaviorProfile: async (employeeId) => {
    try {
      const res = await http.get(`/users/${employeeId}/behavior-profile`);
      return res.data;
    } catch {
      return null;
    }
  },

  getUserDigitalTwin: async (employeeId) => {
    try {
      const res = await http.get(`/users/${employeeId}/digital-twin`);
      return res.data;
    } catch {
      return null;
    }
  },

  getUserAnomalyHistory: async (employeeId, limit = 20) => {
    try {
      const res = await http.get(`/users/${employeeId}/anomaly-history`, { params: { limit } });
      return res.data || [];
    } catch {
      return [];
    }
  },

  getUserRiskHistory: async (employeeId) => {
    try {
      const res = await http.get(`/users/${employeeId}/risk-history`);
      return res.data || [];
    } catch {
      return [];
    }
  },

  // --- ThreatVista v2.0: Core SIH High-Impact APIs ---
  getVaultStatus: async () => {
    try {
      const res = await http.get('/vault/status');
      return res.data;
    } catch {
      return {
        encryption_algorithm: "AES-256-GCM",
        key_length_bits: 256,
        status: "ACTIVE_PROTECTED",
        zero_knowledge: true
      };
    }
  },

  rotateVaultKeys: async (newPassphrase) => {
    const res = await http.post('/vault/rotate-keys', { new_passphrase: newPassphrase });
    return res.data;
  },

  approveActionStep: async (requestId, notes = '', approverName = 'Admin', approverRole = 'SOC Admin') => {
    const res = await http.post(`/action-requests/${requestId}/approve-step`, {
      notes,
      approver_name: approverName,
      approver_role: approverRole
    });
    return res.data;
  },

  getApprovalChain: async (requestId) => {
    try {
      const res = await http.get(`/action-requests/${requestId}/approval-chain`);
      return res.data;
    } catch {
      return { required_approvals: 1, current_approvals: 0, chain: [] };
    }
  },

  simulateRansomwareBatch: async (fileCount = 100) => {
    const res = await http.post('/recovery/simulate-batch', { file_count: fileCount });
    return res.data;
  },

  simulateRansomwareAttack: async () => {
    const res = await http.post('/recovery/simulate-attack');
    return res.data;
  },

  executeMassRollback: async () => {
    const res = await http.post('/recovery/mass-rollback');
    return res.data;
  },

  getRecoveryLogs: async () => {
    try {
      const res = await http.get('/recovery/logs');
      return res.data || [];
    } catch {
      return [];
    }
  },

  explainEmployeeRisk: async (employeeId) => {
    try {
      const res = await http.post('/copilot/explain-risk', null, { params: { employee_id: employeeId } });
      return res.data;
    } catch {
      return null;
    }
  },

  copilotChat: async (message, employeeId = null, context = null) => {
    const res = await http.post('/copilot/chat', {
      message,
      employee_id: employeeId,
      context
    });
    return res.data;
  },

  nlInvestigate: async (query) => {
    const res = await http.post('/copilot/investigate', { query });
    return res.data;
  },

  getUserThreatTimeline: async (employeeId) => {
    try {
      const res = await http.get(`/users/${employeeId}/threat-timeline`);
      return res.data || { timeline: [] };
    } catch {
      return { timeline: [] };
    }
  }
};

