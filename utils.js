/* ============================================================
   Cable TV CMS — Shared Utilities
   ============================================================ */

const API = "http://localhost:5000/api";

// ── Token Management ──────────────────────────────────────────
const Auth = {
  getToken:    () => localStorage.getItem("ctv_token"),
  setToken:    (t) => localStorage.setItem("ctv_token", t),
  removeToken: () => localStorage.removeItem("ctv_token"),
  getUser:     () => JSON.parse(localStorage.getItem("ctv_user") || "{}"),
  setUser:     (u) => localStorage.setItem("ctv_user", JSON.stringify(u)),
  isAdmin:     () => Auth.getUser().is_admin === true,
  isLoggedIn:  () => !!Auth.getToken(),
  logout() {
    localStorage.removeItem("ctv_token");
    localStorage.removeItem("ctv_user");
    window.location.href = "../pages/login.html";
  },
};

// ── API Client ────────────────────────────────────────────────
async function apiFetch(endpoint, options = {}) {
  const token = Auth.getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers || {}),
  };
  try {
    const res = await fetch(`${API}${endpoint}`, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  } catch (err) {
    throw err;
  }
}

// ── Toast Notifications ───────────────────────────────────────
function ensureToastContainer() {
  let c = document.getElementById("toast-container");
  if (!c) {
    c = document.createElement("div");
    c.id = "toast-container";
    document.body.appendChild(c);
  }
  return c;
}

function showToast(message, type = "info", duration = 3500) {
  const icons = { success: "✓", error: "✕", info: "ℹ" };
  const container = ensureToastContainer();
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${icons[type] || "ℹ"}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = "slideOut .3s ease forwards";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Guard: redirect if not logged in ─────────────────────────
function requireAuth(adminOnly = false) {
  if (!Auth.isLoggedIn()) {
    window.location.href = "../pages/login.html";
    return false;
  }
  if (adminOnly && !Auth.isAdmin()) {
    window.location.href = "../pages/dashboard.html";
    return false;
  }
  return true;
}

// ── Helpers ───────────────────────────────────────────────────
function formatCurrency(amount) {
  return "₹" + parseFloat(amount).toLocaleString("en-IN", { minimumFractionDigits: 0 });
}

function formatDate(dateStr) {
  if (!dateStr) return "—";
  return new Date(dateStr).toLocaleDateString("en-IN", {
    day: "2-digit", month: "short", year: "numeric",
  });
}

function badgeHtml(status) {
  const cls = {
    "Active":   "badge-active",
    "Inactive": "badge-inactive",
    "Success":  "badge-success",
    "Pending":  "badge-pending",
    "Failed":   "badge-failed",
  }[status] || "badge-pending";
  const dot = { "Active": "●", "Inactive": "●", "Success": "✓", "Pending": "◐", "Failed": "✕" }[status] || "●";
  return `<span class="badge ${cls}">${dot} ${status}</span>`;
}

function setLoading(btn, loading, label = "Loading...") {
  if (!btn) return;
  btn.disabled = loading;
  btn._origText = btn._origText || btn.innerHTML;
  btn.innerHTML = loading
    ? `<span class="spinner"></span>${label}`
    : btn._origText;
}

// ── Navbar Renderer ───────────────────────────────────────────
function renderNavbar(activeTab) {
  const user = Auth.getUser();
  const isAdmin = Auth.isAdmin();
  const links = isAdmin
    ? [
        { href: "../pages/admin.html",     label: "Customers",     key: "customers" },
        { href: "../pages/admin.html#payments", label: "Payments", key: "payments" },
      ]
    : [
        { href: "../pages/dashboard.html", label: "Dashboard",     key: "dashboard" },
        { href: "../pages/plans.html",     label: "Plans",         key: "plans" },
        { href: "../pages/history.html",   label: "History",       key: "history" },
      ];

  const nav = document.getElementById("main-navbar");
  if (!nav) return;
  nav.innerHTML = `
    <a class="navbar-brand" href="${isAdmin ? "../pages/admin.html" : "../pages/dashboard.html"}">
      <span class="logo-dot"></span>CableCMS
    </a>
    <div style="display:flex;gap:.5rem;align-items:center;flex-wrap:wrap">
      ${links.map(l => `
        <a href="${l.href}" class="btn btn-sm ${activeTab === l.key ? "btn-primary" : "btn-secondary"}" style="${activeTab === l.key ? "" : "border:none;color:var(--text-muted)"}">
          ${l.label}
        </a>
      `).join("")}
      <div class="navbar-user">${user.name || "User"}</div>
      <button class="btn btn-sm btn-danger" onclick="Auth.logout()">Logout</button>
    </div>
  `;
}
