import { useEffect, useMemo, useRef, useState } from "react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import StatCard from "./components/StatCard";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const TOKEN_KEY = "dpi_token";
const ROLE_KEY = "dpi_role";
const USERNAME_KEY = "dpi_username";

const emptyRules = {
  blocked_ips: [],
  blocked_apps: [],
  blocked_domains: [],
  blocked_ports: [],
};

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function safeFileLabel(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "-";
  }
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : text;
}

function isStrongPassword(value) {
  const password = String(value || "");
  return (
    password.length >= 8 &&
    /[A-Z]/.test(password) &&
    /[a-z]/.test(password) &&
    /\d/.test(password) &&
    /[^A-Za-z0-9]/.test(password)
  );
}

function getPasswordChecks(value) {
  const password = String(value || "");
  return [
    { key: "len", label: "At least 8 characters", ok: password.length >= 8 },
    { key: "upper", label: "One uppercase letter", ok: /[A-Z]/.test(password) },
    { key: "lower", label: "One lowercase letter", ok: /[a-z]/.test(password) },
    { key: "digit", label: "One number", ok: /\d/.test(password) },
    { key: "special", label: "One special character", ok: /[^A-Za-z0-9]/.test(password) },
  ];
}

function isPcapFile(file) {
  if (!file) {
    return false;
  }
  const name = String(file.name || "").toLowerCase();
  return name.endsWith(".pcap");
}

async function parseJsonResponse(res, contextLabel) {
  const contentType = String(res.headers.get("content-type") || "").toLowerCase();
  if (contentType.includes("application/json")) {
    return res.json();
  }

  const text = await res.text();
  const preview = String(text || "").replace(/\s+/g, " ").slice(0, 120);
  throw new Error(
    `${contextLabel} returned non-JSON response (status ${res.status}). Check VITE_API_URL/API backend. Preview: ${preview || "<empty>"}`
  );
}

export default function App() {
  const toastTimerRef = useRef(null);
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY) || "");
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({ username: "", password: "" });
  const [currentUser, setCurrentUser] = useState(() => localStorage.getItem(USERNAME_KEY) || "");
  const [currentRole, setCurrentRole] = useState(() => localStorage.getItem(ROLE_KEY) || "viewer");

  const [health, setHealth] = useState("checking");
  const [apps, setApps] = useState([]);
  const [rules, setRules] = useState(emptyRules);
  const [ruleForm, setRuleForm] = useState({ ip: "", domain: "", port: "", app: "YouTube" });
  const [job, setJob] = useState({ input_file: "test_dpi.pcap", output_file: "output_python.pcap" });

  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [streamLoading, setStreamLoading] = useState(false);
  const [error, setError] = useState("");
  const [authError, setAuthError] = useState({ text: "", mode: null });
  const [authNotice, setAuthNotice] = useState({ text: "", mode: null });
  const [dashboardToast, setDashboardToast] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [users, setUsers] = useState([]);
  const [usersLoading, setUsersLoading] = useState(false);
  const [pendingRequests, setPendingRequests] = useState([]);
  const [requestAccessSent, setRequestAccessSent] = useState(false);
  const [streamConfig, setStreamConfig] = useState({
    interface: "Ethernet",
    output_path: "node_backend/outputs/live_stream.pcap",
    interval_seconds: 2,
  });
  const [streamStatus, setStreamStatus] = useState({
    running: false,
    started_at: null,
    stopped_at: null,
    interface: null,
    output_file: null,
    last_error: null,
    stats: {
      total_packets: 0,
      forwarded_packets: 0,
      dropped_packets: 0,
      drop_rate: 0,
      tcp_packets: 0,
      udp_packets: 0,
      app_counts: {},
      block_reasons: {},
    },
    ticks: [],
  });
  const [streamCapability, setStreamCapability] = useState({
    ok: true,
    interfaces: [],
    reason: null,
    suggestion: null,
  });

  const isAdmin = currentRole === "admin";
  const isViewer = currentRole === "viewer";

  const tabs = [
    { key: "overview", label: "Overview", roles: ["admin", "viewer"] },
    { key: "analysis", label: "My Analysis", roles: ["viewer"] },
    { key: "testing", label: "DPI Testing", roles: ["admin"] },
    { key: "streaming", label: "Streaming", roles: ["admin"] },
    { key: "report", label: "Report", roles: ["admin", "viewer"] },
    { key: "users", label: "Users", roles: ["admin"] },
  ];

  useEffect(() => {
    boot();
  }, [token, currentRole]);

  useEffect(() => {
    const allowedTabs = tabs.filter((tab) => tab.roles.includes(currentRole)).map((tab) => tab.key);
    if (!allowedTabs.includes(activeTab)) {
      setActiveTab("overview");
    }
  }, [activeTab, currentRole]);

  useEffect(() => {
    if (!token || !isAdmin || activeTab !== "streaming") {
      return;
    }

    fetchStreamCapability();
    fetchStreamStatus();
    const id = setInterval(fetchStreamStatus, 2000);
    return () => clearInterval(id);
  }, [token, activeTab, isAdmin]);

  useEffect(() => {
    if (!token || !isAdmin || activeTab !== "users") {
      return;
    }
    fetchUsers();
  }, [token, activeTab, isAdmin]);

  useEffect(() => {
    if (!token || !isAdmin) {
      return;
    }

    fetchPendingRequestsCount();
    const id = setInterval(fetchPendingRequestsCount, 10000);
    return () => clearInterval(id);
  }, [token, isAdmin]);

  function authHeaders() {
    const headers = { "Content-Type": "application/json" };
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    return headers;
  }

  function showDashboardToast(message, durationMs = 3500) {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
      toastTimerRef.current = null;
    }
    setDashboardToast(message);
    toastTimerRef.current = setTimeout(() => {
      setDashboardToast("");
      toastTimerRef.current = null;
    }, durationMs);
  }

  async function boot() {
    setError("");
    try {
      const [healthRes, appsRes] = await Promise.all([fetch(`${API_BASE}/api/health`), fetch(`${API_BASE}/api/apps`)]);
      if (healthRes.ok) {
        const healthBody = await parseJsonResponse(healthRes, "Health API");
        setHealth(healthBody?.ok ? "online" : "offline");
      } else {
        setHealth("offline");
      }

      if (appsRes.ok) {
        const appsData = await parseJsonResponse(appsRes, "Apps API");
        const filtered = (appsData.apps || []).filter((x) => x !== "Unknown");
        setApps(filtered);
        if (filtered.length) {
          setRuleForm((prev) => ({ ...prev, app: filtered[0] }));
        }
      }

      if (token) {
        const requests = [fetch(`${API_BASE}/api/history`, { headers: authHeaders() })];
        if (isAdmin) {
          requests.push(fetch(`${API_BASE}/api/dpi/rules`, { headers: authHeaders() }));
          requests.push(fetch(`${API_BASE}/api/auth/access-requests`, { headers: authHeaders() }));
        }
        const [historyRes, rulesRes, pendingRes] = await Promise.all(requests);

        if (historyRes.ok) {
          setHistory(await parseJsonResponse(historyRes, "History API"));
        }
        if (isAdmin && rulesRes && rulesRes.ok) {
          setRules(await parseJsonResponse(rulesRes, "Rules API"));
        }
        if (isAdmin && pendingRes && pendingRes.ok) {
          const pendingPayload = await parseJsonResponse(pendingRes, "Access Requests API");
          setPendingRequests(Array.isArray(pendingPayload) ? pendingPayload : []);
        }
      }
    } catch (e) {
      setHealth("offline");
      setError(`Cannot reach backend: ${e.message}`);
    }
  }

  async function refreshHistory() {
    if (!token) {
      return;
    }
    const historyRes = await fetch(`${API_BASE}/api/history`, { headers: authHeaders() });
    if (!historyRes.ok) {
      const payload = await parseJsonResponse(historyRes, "History API");
      throw new Error(payload.error || "Failed to load history");
    }
    const rows = await parseJsonResponse(historyRes, "History API");
    setHistory(Array.isArray(rows) ? rows : []);
  }

  function saveSession(nextToken, username, role) {
    localStorage.setItem(TOKEN_KEY, nextToken);
    localStorage.setItem(USERNAME_KEY, username || "");
    localStorage.setItem(ROLE_KEY, role || "viewer");
    setToken(nextToken);
    setCurrentUser(username || "");
    setCurrentRole(role || "viewer");
    setRequestAccessSent(false);
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(ROLE_KEY);
    setToken("");
    setCurrentUser("");
    setCurrentRole("viewer");
    setHistory([]);
    setRules(emptyRules);
    setUsers([]);
    setPendingRequests([]);
    setResult(null);
    setAuthError({ text: "", mode: null });
    setAuthNotice({ text: "", mode: null });
    setDashboardToast("");
    setRequestAccessSent(false);
    setActiveTab("overview");
  }

  function switchAuthMode(nextMode) {
    setAuthMode(nextMode);
    setAuthError({ text: "", mode: null });
    setAuthNotice({ text: "", mode: null });
    setAuthForm({ username: "", password: "" });
    setRequestAccessSent(false);
  }

  async function submitAuth() {
    setAuthError({ text: "", mode: null });
    setAuthNotice({ text: "", mode: null });
    setLoading(true);

    try {
      const identity = authForm.username.trim();
      if (authMode === "register") {
        if (!EMAIL_REGEX.test(identity)) {
          throw new Error("Enter a valid email address for account creation.");
        }
        if (!isStrongPassword(authForm.password)) {
          throw new Error("Password must be strong: 8+ chars with upper, lower, number, and special character.");
        }
      }

      const endpoint = authMode === "login" ? "/api/auth/login" : "/api/auth/register";
      const payload = { username: identity, password: authForm.password };

      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const body = await parseJsonResponse(res, authMode === "login" ? "Login API" : "Register API");
      if (!res.ok) {
        throw new Error(body.error || "Authentication failed");
      }

      if (authMode === "register") {
        const registeredIdentity = identity;
        setAuthMode("login");
        setAuthNotice({
          text: "Registration complete. Please log in with your new account.",
          mode: "login",
        });
        setAuthForm({ username: registeredIdentity, password: "" });
        return;
      }

      saveSession(body.token, body.username, body.role || "viewer");
    } catch (e) {
      setAuthError({ text: e.message, mode: authMode });
    } finally {
      setLoading(false);
    }
  }

  function addToList(key, value) {
    const clean = String(value || "").trim();
    if (!clean) {
      return;
    }
    setRules((prev) => {
      if (prev[key].includes(clean)) {
        return prev;
      }
      return { ...prev, [key]: [...prev[key], clean] };
    });
  }

  function addPort(value) {
    const num = Number(value);
    if (!Number.isInteger(num) || num < 1 || num > 65535) {
      return;
    }
    setRules((prev) => {
      if (prev.blocked_ports.includes(num)) {
        return prev;
      }
      return { ...prev, blocked_ports: [...prev.blocked_ports, num] };
    });
  }

  function removeRuleItem(key, value) {
    setRules((prev) => ({ ...prev, [key]: prev[key].filter((item) => item !== value) }));
  }

  async function saveRules() {
    if (!token) {
      setError("Login required");
      return;
    }
    if (!isAdmin) {
      setError("Only admins can save rules.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/dpi/rules`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(rules),
      });
      if (!res.ok) {
        const payload = await res.json();
        throw new Error(payload.detail || payload.error || "Failed to save rules");
      }
      showDashboardToast("Rules saved successfully.");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function runProcess() {
    if (!token) {
      setError("Login required");
      return;
    }
    if (!isAdmin) {
      setError("Only admins can run DPI.");
      return;
    }

    setError("");
    setLoading(true);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/dpi/run`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ input_path: job.input_file, output_path: job.output_file, rules }),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.detail || payload.error || "Processing failed");
      }

      setResult({
        output_file: payload.output_file,
        stats: {
          total_packets: payload.total,
          forwarded_packets: payload.forwarded,
          dropped_packets: payload.dropped,
          drop_rate: (payload.drop_rate || 0) / 100,
          app_counts: payload.top_apps || {},
          block_reasons: payload.block_reasons || {},
        },
      });
      showDashboardToast("DPI run completed.");

      await refreshHistory();
      setActiveTab("report");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function uploadAdminPcap(file) {
    if (!file) {
      return;
    }
    if (!isPcapFile(file)) {
      setError("Only .pcap files are allowed.");
      return;
    }
    if (!token) {
      setError("Login required");
      return;
    }
    if (!isAdmin) {
      setError("Only admins can upload DPI test files.");
      return;
    }

    setError("");
    setLoading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/api/dpi/upload`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const payload = await parseJsonResponse(res, "Upload API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to upload file");
      }

      setJob((prev) => ({
        ...prev,
        input_file: payload.filepath || prev.input_file,
      }));
      showDashboardToast(`Uploaded ${safeFileLabel(payload.filename || file.name)} for DPI testing.`);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function fetchStreamStatus() {
    if (!token) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/dpi/stream/status`, { headers: authHeaders() });
      if (!res.ok) {
        return;
      }
      const payload = await res.json();
      setStreamStatus(payload);
    } catch (_error) {
      // keep previous stream status if polling fails temporarily
    }
  }

  async function fetchStreamCapability() {
    if (!token) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/dpi/stream/capabilities`, { headers: authHeaders() });
      if (!res.ok) {
        return;
      }
      const payload = await res.json();
      setStreamCapability(payload);

      if (payload.ok && Array.isArray(payload.interfaces) && payload.interfaces.length && !streamConfig.interface) {
        setStreamConfig((prev) => ({ ...prev, interface: payload.interfaces[0] }));
      }
    } catch (_error) {
      // Keep last known capability state.
    }
  }

  async function startStreaming() {
    if (!token) {
      setError("Login required");
      return;
    }
    if (!isAdmin) {
      setError("Only admins can start live streaming.");
      return;
    }

    setError("");
    setStreamLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/dpi/stream/start`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify(streamConfig),
      });
      const payload = await res.json();
      if (!res.ok) {
        if (payload.capability && payload.capability.reason) {
          setStreamCapability(payload.capability);
        }
        throw new Error(payload.error || "Failed to start live stream");
      }
      showDashboardToast("Live stream started.");
      await fetchStreamStatus();
    } catch (e) {
      setError(e.message);
    } finally {
      setStreamLoading(false);
    }
  }

  async function stopStreaming() {
    if (!token) {
      return;
    }
    if (!isAdmin) {
      setError("Only admins can stop live streaming.");
      return;
    }

    setError("");
    setStreamLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/dpi/stream/stop`, {
        method: "POST",
        headers: authHeaders(),
      });
      const payload = await res.json();
      if (!res.ok) {
        throw new Error(payload.error || "Failed to stop live stream");
      }
      showDashboardToast("Stop requested for live stream.");
      await fetchStreamStatus();
    } catch (e) {
      setError(e.message);
    } finally {
      setStreamLoading(false);
    }
  }

  const topApps = useMemo(() => {
    if (!result?.stats?.app_counts) {
      return [];
    }
    return Object.entries(result.stats.app_counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6);
  }, [result]);

  const historySummary = useMemo(() => {
    const recent = history.slice(0, 7).reverse();
    const points = recent.map((run, index) => ({
      x: index,
      y: Number(run.dropped ?? run.dropped_packets ?? 0),
      label: new Date(run.timestamp).toLocaleDateString(),
    }));

    const totalProcessed = history.reduce((sum, run) => sum + Number(run.total_packets ?? 0), 0);
    const totalDropped = history.reduce((sum, run) => sum + Number(run.dropped ?? run.dropped_packets ?? 0), 0);
    const avgDropRate = totalProcessed ? (totalDropped / totalProcessed) * 100 : 0;

    return {
      points,
      totalProcessed,
      totalDropped,
      avgDropRate,
      recentCount: history.length,
    };
  }, [history]);

  const appMix = useMemo(() => {
    const source = result?.stats?.app_counts || {};
    const rows = Object.entries(source)
      .map(([name, count]) => ({ name, count: Number(count || 0) }))
      .filter((item) => item.count > 0)
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
    const total = rows.reduce((sum, item) => sum + item.count, 0);
    return { rows, total };
  }, [result]);

  const streamPoints = useMemo(() => {
    const ticks = streamStatus.ticks || [];
    return ticks.slice(-20).map((tick, index) => ({
      x: index,
      y: Number(tick.dropped_packets || 0),
      label: new Date(tick.ts).toLocaleTimeString(),
    }));
  }, [streamStatus]);

  const streamTopApps = useMemo(() => {
    return Object.entries(streamStatus?.stats?.app_counts || {})
      .sort((a, b) => Number(b[1]) - Number(a[1]))
      .slice(0, 6)
      .map(([name, count]) => ({ name, count: Number(count || 0) }));
  }, [streamStatus]);

  async function fetchUsers() {
    if (!token || !isAdmin) {
      return;
    }
    setUsersLoading(true);
    try {
      const [usersRes, pendingRes] = await Promise.all([
        fetch(`${API_BASE}/api/auth/users`, { headers: authHeaders() }),
        fetch(`${API_BASE}/api/auth/access-requests`, { headers: authHeaders() }),
      ]);

      const usersPayload = await parseJsonResponse(usersRes, "Users API");
      if (!usersRes.ok) {
        throw new Error(usersPayload.error || "Failed to load users");
      }

      const pendingPayload = await parseJsonResponse(pendingRes, "Access Requests API");
      if (!pendingRes.ok) {
        throw new Error(pendingPayload.error || "Failed to load access requests");
      }

      setUsers(usersPayload);
      setPendingRequests(Array.isArray(pendingPayload) ? pendingPayload : []);
    } catch (e) {
      setError(e.message);
    } finally {
      setUsersLoading(false);
    }
  }

  async function fetchPendingRequestsCount() {
    if (!token || !isAdmin) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/auth/access-requests`, { headers: authHeaders() });
      const payload = await parseJsonResponse(res, "Access Requests API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to load access requests");
      }
      setPendingRequests(Array.isArray(payload) ? payload : []);
    } catch (_e) {
      // Keep last known badge count if transient polling fails.
    }
  }

  async function promoteUser(username) {
    if (!token || !isAdmin) {
      return;
    }
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/promote/${encodeURIComponent(username)}`, {
        method: "PATCH",
        headers: authHeaders(),
      });
      const payload = await parseJsonResponse(res, "Promote User API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to promote user");
      }
      showDashboardToast(payload.message || `${username} promoted to admin`);
      await fetchUsers();
    } catch (e) {
      setError(e.message);
    }
  }

  async function demoteUser(username) {
    if (!token || !isAdmin) {
      return;
    }
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/demote/${encodeURIComponent(username)}`, {
        method: "PATCH",
        headers: authHeaders(),
      });
      const payload = await parseJsonResponse(res, "Demote User API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to demote user");
      }
      showDashboardToast(payload.message || `${username} demoted to viewer`);
      await fetchUsers();
    } catch (e) {
      setError(e.message);
    }
  }

  async function requestAdminAccess() {
    if (!token || !isViewer) {
      return;
    }
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/request-access`, {
        method: "POST",
        headers: authHeaders(),
      });
      const payload = await parseJsonResponse(res, "Request Access API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to request access");
      }
      setRequestAccessSent(true);
      showDashboardToast(payload.message || "Access request sent to admin");
    } catch (e) {
      setError(e.message);
    }
  }

  async function approveRequest(requestId) {
    if (!token || !isAdmin) {
      return;
    }
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/access-requests/${encodeURIComponent(requestId)}/approve`, {
        method: "PATCH",
        headers: authHeaders(),
      });
      const payload = await parseJsonResponse(res, "Approve Request API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to approve request");
      }
      showDashboardToast(payload.message || "Access request approved");
      await fetchUsers();
    } catch (e) {
      setError(e.message);
    }
  }

  async function rejectRequest(requestId) {
    if (!token || !isAdmin) {
      return;
    }
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/auth/access-requests/${encodeURIComponent(requestId)}/reject`, {
        method: "PATCH",
        headers: authHeaders(),
      });
      const payload = await parseJsonResponse(res, "Reject Request API");
      if (!res.ok) {
        throw new Error(payload.error || "Failed to reject request");
      }
      showDashboardToast(payload.message || "Access request rejected");
      await fetchUsers();
    } catch (e) {
      setError(e.message);
    }
  }

  function applyAnalysisResult(payload) {
    setResult({
      output_file: payload.output_filename || payload.output_file || "analysis_output.pcap",
      stats: {
        total_packets: Number(payload.total || 0),
        forwarded_packets: Number(payload.forwarded || 0),
        dropped_packets: Number(payload.dropped || 0),
        drop_rate: Number(payload.drop_rate || 0) / 100,
        app_counts: payload.top_apps || {},
        block_reasons: payload.block_reasons || {},
      },
    });
  }

  async function downloadRunPdf(runId) {
    if (!token) {
      setError("Login required");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/dpi/report/pdf/${encodeURIComponent(runId)}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const payload = await parseJsonResponse(res, "Report PDF API");
        throw new Error(payload.error || "Failed to download PDF report");
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `DPI_Report_${runId}.pdf`;
      anchor.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      setError(e.message);
    }
  }

  function exportLatestReport() {
    if (!result) {
      return;
    }
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const generatedAt = new Date().toLocaleString();

    doc.setFontSize(18);
    doc.text("DPI Run Report", 40, 48);
    doc.setFontSize(11);
    doc.text(`Generated: ${generatedAt}`, 40, 70);
    doc.text(`User: ${currentUser || "session"}`, 40, 86);

    const summaryRows = [
      ["Output File", safeFileLabel(result.output_file)],
      ["Total Packets", String(result.stats.total_packets ?? 0)],
      ["Forwarded Packets", String(result.stats.forwarded_packets ?? 0)],
      ["Dropped Packets", String(result.stats.dropped_packets ?? 0)],
      ["Drop Rate", `${((result.stats.drop_rate || 0) * 100).toFixed(2)}%`],
    ];

    autoTable(doc, {
      startY: 104,
      head: [["Metric", "Value"]],
      body: summaryRows,
      styles: { fontSize: 10 },
      headStyles: { fillColor: [17, 63, 103] },
    });

    const appCounts = Object.entries(result.stats.app_counts || {})
      .sort((a, b) => Number(b[1]) - Number(a[1]))
      .slice(0, 10)
      .map(([app, count]) => [app, String(count)]);

    autoTable(doc, {
      startY: doc.lastAutoTable.finalY + 18,
      head: [["Top Classified App", "Packets"]],
      body: appCounts.length ? appCounts : [["No data", "0"]],
      styles: { fontSize: 10 },
      headStyles: { fillColor: [63, 142, 252] },
    });

    const reportRows = history.slice(0, 15).map((entry) => {
      const total = Number(entry.total_packets ?? 0);
      const dropped = Number(entry.dropped ?? entry.dropped_packets ?? 0);
      const forwarded = Number(entry.forwarded ?? entry.forwarded_packets ?? 0);
      const dropRate = total ? `${((dropped / total) * 100).toFixed(2)}%` : "0.00%";
      return [
        new Date(entry.timestamp).toLocaleString(),
        safeFileLabel(entry.input_file),
        safeFileLabel(entry.output_file),
        String(total),
        String(forwarded),
        String(dropped),
        dropRate,
      ];
    });

    autoTable(doc, {
      startY: doc.lastAutoTable.finalY + 18,
      head: [["Timestamp", "Input", "Output", "Total", "Forwarded", "Dropped", "Drop %"]],
      body: reportRows.length ? reportRows : [["No runs", "-", "-", "0", "0", "0", "0.00%"]],
      styles: { fontSize: 8, cellWidth: "wrap" },
      columnStyles: {
        0: { cellWidth: 90 },
        1: { cellWidth: 95 },
        2: { cellWidth: 95 },
        3: { cellWidth: 45 },
        4: { cellWidth: 55 },
        5: { cellWidth: 45 },
        6: { cellWidth: 45 },
      },
      headStyles: { fillColor: [45, 106, 79] },
    });

    doc.save(`dpi_report_${Date.now()}.pdf`);
  }

  if (!token) {
    return (
      <AuthPage
        authMode={authMode}
        switchAuthMode={switchAuthMode}
        authForm={authForm}
        setAuthForm={setAuthForm}
        health={health}
        loading={loading}
        authError={authError}
        authNotice={authNotice}
        submitAuth={submitAuth}
      />
    );
  }

  return (
    <div className="page-shell">
      <header className="hero dashboard-hero">
        <div>
          <h1>DPI Operations Dashboard</h1>
          <p>Real-time job trigger dashboard with reporting, charts, and DPI test controls.</p>
        </div>
        <div className="hero-actions">
          <span className={`status ${health}`}>Backend: {health}</span>
          <span className="user-tag">User: {currentUser || "session"}</span>
          <span className={`role-badge ${isAdmin ? "admin" : "viewer"}`}>{isAdmin ? "Admin" : "Viewer"}</span>
          {isAdmin && (
            <span className={`pending-badge ${pendingRequests.length > 0 ? "attention" : ""}`}>
              Pending Requests: {pendingRequests.length}
            </span>
          )}
          <button onClick={logout}>Logout</button>
        </div>
      </header>

      {error && <div className="error-box">{error}</div>}
      {dashboardToast && <div className="notice-box toast-banner">{dashboardToast}</div>}

      <nav className="tab-row">
        {tabs
          .filter((tab) => tab.roles.includes(currentRole))
          .map((tab) => (
            <button key={tab.key} className={activeTab === tab.key ? "tab active" : "tab"} onClick={() => setActiveTab(tab.key)}>{tab.label}</button>
          ))}
      </nav>

      {activeTab === "overview" && (
        <section className="panel-grid overview-grid">
          <section className="panel">
            <h2>Run KPIs</h2>
            <div className="stats-grid">
              <StatCard label="Runs Logged" value={historySummary.recentCount} accent="var(--c1)" />
              <StatCard label="Packets Processed" value={historySummary.totalProcessed} accent="var(--c2)" />
              <StatCard label="Dropped Packets" value={historySummary.totalDropped} accent="var(--c3)" />
              <StatCard label="Avg Drop Rate" value={`${historySummary.avgDropRate.toFixed(2)}%`} accent="var(--c4)" />
            </div>
          </section>

          <section className="panel chart-panel">
            <h2>Drop Trend</h2>
            <p className="hint">Dropped packets over latest runs.</p>
            <SparkChart points={historySummary.points} />
          </section>

          <section className="panel chart-panel">
            <h2>Application Mix</h2>
            <p className="hint">From latest DPI run classification results.</p>
            <DonutChart rows={appMix.rows} total={appMix.total} isAdmin={isAdmin} onGoTesting={() => setActiveTab("testing")} />
          </section>

          <section className="panel chart-panel">
            <h2>Top Apps</h2>
            <p className="hint">Most frequent classified applications in current run.</p>
            <BarChart rows={topApps.map(([name, count]) => ({ name, count }))} />
          </section>

          {isViewer && (
            <section className="panel viewer-lock-panel">
              <h2>Restricted Controls</h2>
              <p>DPI testing, live capture, rule changes, and output downloads are limited to admins.</p>
              {!requestAccessSent ? (
                <button className="request-admin-btn" onClick={requestAdminAccess}>Request Admin Access</button>
              ) : (
                <p className="request-sent">Request sent. Admin will review your request.</p>
              )}
            </section>
          )}
        </section>
      )}

      {activeTab === "analysis" && isViewer && (
        <MyAnalysisTab
          token={token}
          onAnalysisResult={applyAnalysisResult}
          onRefreshHistory={refreshHistory}
          onDownloadPdf={downloadRunPdf}
          history={history}
          setError={setError}
          showDashboardToast={showDashboardToast}
        />
      )}

      {activeTab === "testing" && (
        <section className="panel-grid">
          <section className="panel">
            <h2>Rules</h2>
            <p className="hint">Define and save the blocking policy used by test runs.</p>

            <div className="row-input">
              <input value={ruleForm.ip} placeholder="IP e.g. 192.168.1.50" onChange={(e) => setRuleForm((p) => ({ ...p, ip: e.target.value }))} />
              <button onClick={() => { addToList("blocked_ips", ruleForm.ip); setRuleForm((p) => ({ ...p, ip: "" })); }}>Add IP</button>
            </div>

            <div className="row-input">
              <input value={ruleForm.domain} placeholder="Domain pattern e.g. *.facebook.com" onChange={(e) => setRuleForm((p) => ({ ...p, domain: e.target.value }))} />
              <button onClick={() => { addToList("blocked_domains", ruleForm.domain); setRuleForm((p) => ({ ...p, domain: "" })); }}>Add Domain</button>
            </div>

            <div className="row-input">
              <input value={ruleForm.port} placeholder="Port e.g. 22" onChange={(e) => setRuleForm((p) => ({ ...p, port: e.target.value }))} />
              <button onClick={() => { addPort(ruleForm.port); setRuleForm((p) => ({ ...p, port: "" })); }}>Add Port</button>
            </div>

            <div className="row-input">
              <select value={ruleForm.app} onChange={(e) => setRuleForm((p) => ({ ...p, app: e.target.value }))}>
                {apps.map((app) => (
                  <option key={app} value={app}>{app}</option>
                ))}
              </select>
              <button onClick={() => addToList("blocked_apps", ruleForm.app)}>Add App</button>
            </div>

            <div className="chips-wrap">
              <RuleGroup title="Blocked IPs" items={rules.blocked_ips} onRemove={(item) => removeRuleItem("blocked_ips", item)} />
              <RuleGroup title="Blocked Domains" items={rules.blocked_domains} onRemove={(item) => removeRuleItem("blocked_domains", item)} />
              <RuleGroup title="Blocked Ports" items={rules.blocked_ports} onRemove={(item) => removeRuleItem("blocked_ports", item)} />
              <RuleGroup title="Blocked Apps" items={rules.blocked_apps} onRemove={(item) => removeRuleItem("blocked_apps", item)} />
            </div>

            <button className="primary" disabled={loading} onClick={saveRules}>Save Rules</button>
          </section>

          <section className="panel">
            <h2>Run DPI Test</h2>
            <p className="hint">Execute a processing run and generate output + report data.</p>

            <label>Upload PCAP file</label>
            <input
              type="file"
              accept=".pcap"
              onChange={(e) => uploadAdminPcap(e.target.files?.[0] || null)}
            />

            <label>Input PCAP path</label>
            <input value={job.input_file} onChange={(e) => setJob((p) => ({ ...p, input_file: e.target.value }))} />

            <label>Output PCAP path</label>
            <input value={job.output_file} onChange={(e) => setJob((p) => ({ ...p, output_file: e.target.value }))} />

            <button className="primary" disabled={loading} onClick={runProcess}>{loading ? "Running..." : "Run DPI"}</button>

            {result && (
              <div className="result-box">
                <h3>Latest Run Summary</h3>
                <p>Output file: {safeFileLabel(result.output_file)}</p>
                <div className="stats-grid">
                  <StatCard label="Total" value={result.stats.total_packets} accent="var(--c1)" />
                  <StatCard label="Forwarded" value={result.stats.forwarded_packets} accent="var(--c2)" />
                  <StatCard label="Dropped" value={result.stats.dropped_packets} accent="var(--c3)" />
                  <StatCard label="Drop rate" value={`${(result.stats.drop_rate * 100).toFixed(2)}%`} accent="var(--c4)" />
                </div>
              </div>
            )}
          </section>
        </section>
      )}

      {activeTab === "streaming" && (
        <section className="panel-grid">
          <section className="panel">
            <h2>Live Capture Control</h2>
            <p className="hint">Capture traffic from a network interface, apply DPI rules continuously, and write rolling output.</p>

            {!streamCapability.ok && (
              <div className="stream-warning">
                <b>Live capture is unavailable on this host.</b>
                <p>{streamCapability.reason || "Missing packet capture dependency."}</p>
                <p>{streamCapability.suggestion || "Install the required capture provider and restart backend."}</p>
                <p>Fallback: use the DPI Testing tab for file-based packet processing.</p>
              </div>
            )}

            {streamCapability.ok && Array.isArray(streamCapability.interfaces) && streamCapability.interfaces.length > 0 && (
              <div className="stream-hint">
                Detected interfaces: {streamCapability.interfaces.slice(0, 4).join(", ")}
              </div>
            )}

            <label>Interface Name</label>
            <input
              value={streamConfig.interface}
              onChange={(e) => setStreamConfig((p) => ({ ...p, interface: e.target.value }))}
              placeholder="Ethernet"
            />

            <label>Rolling Output PCAP</label>
            <input
              value={streamConfig.output_path}
              onChange={(e) => setStreamConfig((p) => ({ ...p, output_path: e.target.value }))}
              placeholder="node_backend/outputs/live_stream.pcap"
            />

            <label>Status Update Interval (seconds)</label>
            <input
              type="number"
              min="1"
              step="1"
              value={streamConfig.interval_seconds}
              onChange={(e) => setStreamConfig((p) => ({ ...p, interval_seconds: Number(e.target.value || 2) }))}
            />

            <div className="stream-actions">
              <button className="primary" disabled={streamLoading || streamStatus.running || !streamCapability.ok} onClick={startStreaming}>Start Live Stream</button>
              <button disabled={streamLoading || !streamStatus.running} onClick={stopStreaming}>Stop Stream</button>
            </div>

            <div className="stream-meta">
              <p><b>Running:</b> {streamStatus.running ? "Yes" : "No"}</p>
              <p><b>Interface:</b> {streamStatus.interface || "-"}</p>
              <p><b>Output:</b> {streamStatus.output_file || "-"}</p>
              <p><b>Started:</b> {streamStatus.started_at ? new Date(streamStatus.started_at).toLocaleString() : "-"}</p>
              {streamStatus.last_error && <p className="stream-error"><b>Last Error:</b> {streamStatus.last_error}</p>}
            </div>
          </section>

          <section className="panel">
            <h2>Streaming Telemetry</h2>
            <div className="stats-grid">
              <StatCard label="Total" value={streamStatus.stats?.total_packets || 0} accent="var(--c1)" />
              <StatCard label="Forwarded" value={streamStatus.stats?.forwarded_packets || 0} accent="var(--c2)" />
              <StatCard label="Dropped" value={streamStatus.stats?.dropped_packets || 0} accent="var(--c3)" />
              <StatCard label="Drop Rate" value={`${((streamStatus.stats?.drop_rate || 0) * 100).toFixed(2)}%`} accent="var(--c4)" />
            </div>

            <h3>Live Drop Trend</h3>
            <SparkChart points={streamPoints} />

            <h3>Top Apps In Stream</h3>
            <BarChart rows={streamTopApps} />
          </section>
        </section>
      )}

      {activeTab === "report" && (
        <section className="panel">
          <h2>Run Report Section</h2>
          <p className="hint">Inspect historical runs and download run-level PDF reports.</p>
          <div className="report-actions">
            <button onClick={exportLatestReport} disabled={!result}>Export Latest Snapshot (PDF)</button>
          </div>

          <div className="table-wrap">
            <table className="report-table">
              <thead>
                <tr>
                  {isAdmin && <th>User</th>}
                  <th>Timestamp</th>
                  <th>Run Type</th>
                  <th>Input</th>
                  <th>Output</th>
                  <th>Total</th>
                  <th>Forwarded</th>
                  <th>Dropped</th>
                  <th>Drop %</th>
                  <th>PDF</th>
                </tr>
              </thead>
              <tbody>
                {history.length === 0 && (
                  <tr>
                    <td colSpan={isAdmin ? 10 : 9}>No runs yet.</td>
                  </tr>
                )}
                {history.map((entry) => {
                  const total = Number(entry.total_packets ?? 0);
                  const dropped = Number(entry.dropped ?? entry.dropped_packets ?? 0);
                  const dropRate = total ? (dropped / total) * 100 : 0;
                  return (
                    <tr key={entry.id}>
                      {isAdmin && <td>{entry.user_id || "-"}</td>}
                      <td>{new Date(entry.timestamp).toLocaleString()}</td>
                      <td>{entry.run_type || "full"}</td>
                      <td>{safeFileLabel(entry.input_file)}</td>
                      <td>{safeFileLabel(entry.output_file)}</td>
                      <td>{total}</td>
                      <td>{Number(entry.forwarded ?? entry.forwarded_packets ?? 0)}</td>
                      <td>{dropped}</td>
                      <td>{dropRate.toFixed(2)}%</td>
                      <td>
                        <button onClick={() => downloadRunPdf(entry.id)}>PDF</button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === "users" && isAdmin && (
        <section className="panel">
          <div className="users-head">
            <h2>User Management</h2>
            <button onClick={fetchUsers} disabled={usersLoading}>{usersLoading ? "Refreshing..." : "Refresh"}</button>
          </div>
          <p className="hint">Manage roles, approve access requests, and keep least-privilege controls.</p>

          {pendingRequests.length > 0 && (
            <div className="pending-requests-box">
              <h3>Pending Access Requests ({pendingRequests.length})</h3>
              <div className="pending-list">
                {pendingRequests.map((request) => (
                  <div key={request.id} className="pending-row">
                    <span><b>{request.username}</b> requested admin access</span>
                    <div className="pending-actions">
                      <button className="approve-btn" onClick={() => approveRequest(request.id)}>Approve</button>
                      <button className="reject-btn" onClick={() => rejectRequest(request.id)}>Reject</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="table-wrap">
            <table className="report-table users-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Joined</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 && (
                  <tr>
                    <td colSpan={4}>{usersLoading ? "Loading users..." : "No users found."}</td>
                  </tr>
                )}
                {users.map((user) => (
                  <tr key={user.id || user.username}>
                    <td>{user.username}</td>
                    <td>
                      <span className={`role-badge ${user.role === "admin" ? "admin" : "viewer"}`}>{user.role === "admin" ? "Admin" : "Viewer"}</span>
                    </td>
                    <td>{user.created_at ? new Date(user.created_at).toLocaleDateString() : "-"}</td>
                    <td>
                      {user.username === currentUser ? (
                        <span className="hint">(You)</span>
                      ) : user.role === "viewer" ? (
                        <button onClick={() => promoteUser(user.username)}>Promote to Admin</button>
                      ) : (
                        <button className="demote-btn" onClick={() => demoteUser(user.username)}>Demote to Viewer</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}

function AuthPage({ authMode, switchAuthMode, authForm, setAuthForm, health, loading, authError, authNotice, submitAuth }) {
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const passwordChecks = getPasswordChecks(authForm.password);

  useEffect(() => {
    if (showAuthModal) {
      document.body.classList.add("wp-lock-scroll");
    } else {
      document.body.classList.remove("wp-lock-scroll");
    }

    return () => {
      document.body.classList.remove("wp-lock-scroll");
    };
  }, [showAuthModal]);
 
  return (
    <div className="welcome-page">
      <div className="wp-grid-bg" aria-hidden="true" />
 
      <div className="wp-nodes" aria-hidden="true">
        {[...Array(7)].map((_, i) => (
          <span key={i} className={`wp-node wp-node-${i + 1}`} />
        ))}
        <svg className="wp-connections" viewBox="0 0 1200 700" preserveAspectRatio="none">
          <line x1="18%" y1="28%" x2="52%" y2="60%" stroke="#3f8efc18" strokeWidth="1" strokeDasharray="5 4"/>
          <line x1="52%" y1="60%" x2="78%" y2="32%" stroke="#3f8efc18" strokeWidth="1" strokeDasharray="5 4"/>
          <line x1="18%" y1="28%" x2="78%" y2="32%" stroke="#f08a4b12" strokeWidth="1" strokeDasharray="6 5"/>
        </svg>
      </div>
 
      <div className="wp-stage">
        {/* LEFT — branding */}
        <div className="wp-brand">
          <div className="wp-eyebrow">
            <span className={`wp-status-dot ${health === "online" ? "dot-online" : "dot-offline"}`} />
            <span className="wp-eyebrow-text">PACKET INTELLIGENCE PLATFORM</span>
          </div>
 
          <h1 className="wp-title">
            <span className="wp-title-line1">DPI</span>
            <span className="wp-title-line2">Control Plane</span>
          </h1>
 
          <p className="wp-desc">
            Deep packet inspection, live traffic analysis, and real-time
            threat classification — all from one unified dashboard.
          </p>
 
          <div className="wp-feature-list">
            {[
              { icon: "📦", label: "PCAP analysis & filtering" },
              { icon: "📡", label: "Live stream capture" },
              { icon: "🔐", label: "Role-based access control" },
              { icon: "📄", label: "PDF report generation" },
            ].map((f) => (
              <div key={f.label} className="wp-feature-row">
                <span className="wp-feature-icon">{f.icon}</span>
                <span>{f.label}</span>
              </div>
            ))}
          </div>
 
          <button className="wp-cta" onClick={() => setShowAuthModal(true)}>
            <span>Access Dashboard</span>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M5 12h14M12 5l7 7-7 7" />
            </svg>
          </button>
 
          <div className="wp-backend-pill">
            <span className={`wp-status-dot ${health === "online" ? "dot-online" : "dot-offline"}`} />
            Backend: {health}
          </div>
        </div>
 
        {/* RIGHT — visual panel */}
        <div className="wp-visual" aria-hidden="true">
          <div className="wp-vis-card">
            <div className="wp-vis-header">
              <span className="wp-vis-dot red" />
              <span className="wp-vis-dot yellow" />
              <span className="wp-vis-dot green" />
              <span className="wp-vis-title">live_stream.pcap — DPI Engine</span>
            </div>
 
            <div className="wp-vis-body">
              {/* KPIs */}
              <div className="wp-vis-kpi-row">
                {[
                  { label: "TOTAL",   val: "1,247", cls: "blue"  },
                  { label: "PASSED",  val: "1,190", cls: "green" },
                  { label: "BLOCKED", val: "57",    cls: "red"   },
                ].map((k) => (
                  <div key={k.label} className="wp-vis-kpi">
                    <span className={`wp-vis-kpi-val ${k.cls}`}>{k.val}</span>
                    <span className="wp-vis-kpi-label">{k.label}</span>
                  </div>
                ))}
              </div>
 
              {/* Bars */}
              <div className="wp-vis-bars">
                {[
                  { app: "HTTPS",    pct: 72, count: 898 },
                  { app: "DNS",      pct: 11, count: 137 },
                  { app: "HTTP",     pct: 8,  count: 100 },
                  { app: "Twitter",  pct: 5,  count: 62  },
                  { app: "YouTube",  pct: 4,  count: 50  },
                ].map((b) => (
                  <div key={b.app} className="wp-vis-bar-row">
                    <span className="wp-vis-bar-label">{b.app}</span>
                    <div className="wp-vis-bar-track">
                      <div className="wp-vis-bar-fill" style={{ width: `${b.pct}%` }} />
                    </div>
                    <span className="wp-vis-bar-count">{b.count}</span>
                  </div>
                ))}
              </div>
 
              {/* Log */}
              <div className="wp-vis-log">
                {[
                  { t: "11:42:07", msg: "BLOCKED  192.168.1.50 → facebook.com", color: "#d64545" },
                  { t: "11:42:08", msg: "PASS     10.0.0.4 → google.com:443",   color: "#1f7a48" },
                  { t: "11:42:08", msg: "BLOCKED  port:22 SSH attempt",          color: "#d64545" },
                  { t: "11:42:09", msg: "PASS     10.0.0.7 → cdn.jsdelivr.net",  color: "#1f7a48" },
                ].map((l, i) => (
                  <div key={i} className="wp-vis-log-row">
                    <span className="wp-vis-log-time">{l.t}</span>
                    <span style={{ color: l.color, fontWeight: 600 }}>{l.msg}</span>
                  </div>
                ))}
                <div className="wp-vis-cursor" />
              </div>
            </div>
          </div>
        </div>
      </div>
 
      {/* Auth Modal */}
      {showAuthModal && (
        <div className="wp-modal-overlay" onClick={() => setShowAuthModal(false)}>
          <div className="wp-modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
            <button className="wp-modal-close" onClick={() => setShowAuthModal(false)} aria-label="Close">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <path d="M18 6L6 18M6 6l12 12" />
              </svg>
            </button>
 
            <div className="wp-modal-brand">
              <span className="wp-modal-logo">◈</span>
              <span>DPI Control Plane</span>
            </div>
 
            <h2 className="wp-modal-title">
              {authMode === "login" ? "Sign in to continue" : "Create your account"}
            </h2>
 
            <div className="wp-modal-tabs">
              <button className={`wp-modal-tab ${authMode === "login" ? "active" : ""}`} onClick={() => switchAuthMode("login")}>Login</button>
              <button className={`wp-modal-tab ${authMode === "register" ? "active" : ""}`} onClick={() => switchAuthMode("register")}>Register</button>
            </div>
 
            {authError.mode === authMode && authError.text && <div className="wp-modal-error">{authError.text}</div>}
            {authNotice.mode === authMode && authNotice.text && <div className="wp-modal-notice">{authNotice.text}</div>}
 
            <div className="wp-modal-form">
              <div className="wp-field">
                <label>{authMode === "register" ? "Email address" : "Username or email"}</label>
                <input
                  value={authForm.username}
                  placeholder={authMode === "register" ? "you@example.com" : "Username or email"}
                  onChange={(e) => setAuthForm((p) => ({ ...p, username: e.target.value }))}
                  onKeyDown={(e) => e.key === "Enter" && submitAuth()}
                />
              </div>
 
              <div className="wp-field">
                <label>Password</label>
                <div className="wp-field-row">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={authForm.password}
                    placeholder="Password"
                    onChange={(e) => setAuthForm((p) => ({ ...p, password: e.target.value }))}
                    onKeyDown={(e) => e.key === "Enter" && submitAuth()}
                  />
                  <button type="button" className="wp-show-btn" onClick={() => setShowPassword((v) => !v)}>
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </div>
 
              {authMode === "register" && (
                <>
                  <p className="wp-modal-hint">
                    New accounts start as <strong>Viewer</strong>. Request admin access from the dashboard.
                  </p>
                  <ul className="wp-pw-rules">
                    {passwordChecks.map((rule) => (
                      <li key={rule.key} className={rule.ok ? "ok" : ""}>
                        <span className="wp-pw-check">{rule.ok ? "✓" : "○"}</span>
                        {rule.label}
                      </li>
                    ))}
                  </ul>
                </>
              )}
 
              <button className="wp-submit" disabled={loading} onClick={submitAuth}>
                {loading ? <span className="wp-spinner" /> : authMode === "login" ? "Sign In" : "Create Account"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


function MyAnalysisTab({ token, onAnalysisResult, onRefreshHistory, onDownloadPdf, history, setError, showDashboardToast }) {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [analysis, setAnalysis] = useState(null);

  async function handleAnalyze() {
    if (!file) {
      setError("Select a .pcap file first.");
      return;
    }
    if (!isPcapFile(file)) {
      setError("Only .pcap files are allowed.");
      return;
    }

    setError("");
    setLoading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/api/dpi/analyze`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });

      const payload = await parseJsonResponse(res, "Analyze API");
      if (!res.ok) {
        throw new Error(payload.error || "Analysis failed");
      }

      setAnalysis(payload);
      onAnalysisResult(payload);
      await onRefreshHistory();
      showDashboardToast("Analysis complete. Report added to your history.");
    } catch (e) {
      setError(e.message || "Analysis failed. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel-grid analysis-grid">
      <section className="panel">
        <h2>My Analysis</h2>
        <p className="hint">Upload your .pcap file for read-only DPI analysis. No blocking rules are applied.</p>

        <div
          className={`upload-dropzone ${file ? "selected" : ""}`}
          onClick={() => document.getElementById("viewer-upload-input")?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              e.preventDefault();
              document.getElementById("viewer-upload-input")?.click();
            }
          }}
        >
          <input
            id="viewer-upload-input"
            type="file"
            accept=".pcap"
            style={{ display: "none" }}
            onChange={(e) => {
              const nextFile = e.target.files?.[0] || null;
              if (nextFile && !isPcapFile(nextFile)) {
                setError("Only .pcap files are allowed.");
                setFile(null);
                return;
              }
              setError("");
              setFile(nextFile);
            }}
          />
          {!file && (
            <div>
              <b>Click to upload .pcap file</b>
              <p className="hint">Only .pcap files are supported.</p>
            </div>
          )}
          {!!file && (
            <div>
              <b>{safeFileLabel(file.name)}</b>
              <p className="hint">{(Number(file.size || 0) / 1024).toFixed(1)} KB selected</p>
            </div>
          )}
        </div>

        <button className="primary" onClick={handleAnalyze} disabled={!file || loading}>
          {loading ? "Analyzing..." : "Analyze My PCAP"}
        </button>
      </section>

      <section className="panel">
        <h2>Latest Analysis Result</h2>
        {!analysis && <div className="empty-state">Upload and analyze a file to view metrics.</div>}

        {analysis && (
          <>
            <div className="stats-grid">
              <StatCard label="Total Packets" value={Number(analysis.total || 0)} accent="var(--c1)" />
              <StatCard label="Forwarded" value={Number(analysis.forwarded || 0)} accent="var(--c2)" />
              <StatCard label="Dropped" value={Number(analysis.dropped || 0)} accent="var(--c3)" />
              <StatCard label="Drop Rate" value={`${Number(analysis.drop_rate || 0).toFixed(2)}%`} accent="var(--c4)" />
            </div>

            <h3>Top Classified Apps</h3>
            <BarChart
              rows={Object.entries(analysis.top_apps || {}).map(([name, count]) => ({
                name,
                count: Number(count || 0),
              }))}
            />
          </>
        )}
      </section>

      <section className="panel analysis-history-panel">
        <h2>My Upload History</h2>
        <p className="hint">Only your own runs are shown here.</p>

        <div className="table-wrap">
          <table className="report-table analysis-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>File</th>
                <th>Total</th>
                <th>Dropped</th>
                <th>Drop %</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 && (
                <tr>
                  <td colSpan={6}>No uploads yet.</td>
                </tr>
              )}
              {history.map((run) => {
                const total = Number(run.total_packets ?? 0);
                const dropped = Number(run.dropped ?? run.dropped_packets ?? 0);
                const dropRate = total ? (dropped / total) * 100 : Number(run.drop_rate || 0);
                return (
                  <tr key={run.id}>
                    <td>{new Date(run.timestamp).toLocaleString()}</td>
                    <td>{safeFileLabel(run.input_file)}</td>
                    <td>{total}</td>
                    <td>{dropped}</td>
                    <td>{dropRate.toFixed(2)}%</td>
                    <td>
                      <button onClick={() => onDownloadPdf(run.id)}>PDF</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

function RuleGroup({ title, items, onRemove }) {
  return (
    <div className="rule-group">
      <h4>{title}</h4>
      <div className="chip-list">
        {items.length === 0 && <span className="chip muted">none</span>}
        {items.map((item) => (
          <button key={`${title}-${item}`} className="chip" onClick={() => onRemove(item)}>{String(item)} x</button>
        ))}
      </div>
    </div>
  );
}

function BarChart({ rows }) {
  if (!rows.length) {
    return <div className="empty-state">Run DPI once to see app bars.</div>;
  }
  const max = Math.max(...rows.map((r) => Number(r.count || 0)), 1);
  return (
    <div className="bars">
      {rows.map((row) => (
        <div key={row.name} className="bar-row">
          <span>{row.name}</span>
          <div className="bar"><i style={{ width: `${(Number(row.count || 0) / max) * 100}%` }} /></div>
          <b>{row.count}</b>
        </div>
      ))}
    </div>
  );
}

function SparkChart({ points }) {
  if (!points.length) {
    return <div className="empty-state">No history yet.</div>;
  }

  const width = 520;
  const height = 160;
  const padding = 16;
  const maxY = Math.max(...points.map((p) => p.y), 1);
  const stepX = points.length > 1 ? (width - padding * 2) / (points.length - 1) : 0;

  const coords = points.map((point, index) => {
    const x = padding + index * stepX;
    const y = height - padding - (point.y / maxY) * (height - padding * 2);
    return { x, y, label: point.label, value: point.y };
  });

  const line = coords.map((c) => `${c.x},${c.y}`).join(" ");
  return (
    <svg className="spark" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Drop trend chart">
      <polyline points={line} fill="none" stroke="#2f73d8" strokeWidth="3" />
      {coords.map((c) => (
        <g key={`${c.label}-${c.value}`}>
          <circle cx={c.x} cy={c.y} r="4" fill="#f08a4b" />
        </g>
      ))}
    </svg>
  );
}

function DonutChart({ rows, total, isAdmin, onGoTesting }) {
  if (!rows.length || !total) {
    return (
      <div className="empty-state empty-state-rich">
        <div className="empty-icon">No data yet</div>
        {isAdmin ? <button onClick={onGoTesting}>Run your first DPI</button> : <p>Ask your admin to run a DPI analysis.</p>}
      </div>
    );
  }
  const palette = ["#3f8efc", "#f08a4b", "#2d6a4f", "#d64545", "#9467bd"];
  let cumulative = 0;
  const slices = rows
    .map((row, index) => {
      const size = (row.count / total) * 100;
      const from = cumulative;
      cumulative += size;
      return `${palette[index % palette.length]} ${from}% ${cumulative}%`;
    })
    .join(", ");

  return (
    <div className="donut-wrap">
      <div className="donut" style={{ background: `conic-gradient(${slices})` }}>
        <div className="donut-hole">
          <b>{total}</b>
          <span>packets</span>
        </div>
      </div>
      <div className="legend">
        {rows.map((row, idx) => (
          <div key={row.name} className="legend-row">
            <i style={{ background: palette[idx % palette.length] }} />
            <span>{row.name}</span>
            <b>{((row.count / total) * 100).toFixed(1)}%</b>
          </div>
        ))}
      </div>
    </div>
  );
}
