/* VAPT Platform — Global JavaScript */

// ── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
  const el = document.getElementById("topbarTime");
  if (el) {
    el.textContent = new Date().toLocaleTimeString("en-US", {
      hour12: true, hour: "2-digit", minute: "2-digit", second: "2-digit"
    });
  }
}
setInterval(updateClock, 1000);
updateClock();

// ── Sidebar toggle ─────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb = document.getElementById("sidebar");
  const overlay = document.getElementById("sidebarOverlay");
  sb.classList.toggle("open");
  overlay.classList.toggle("active");
}

// ── Disclaimer modal ───────────────────────────────────────────────────────
const DISCLAIMER_KEY = "vapt_disclaimer_accepted";

window.addEventListener("DOMContentLoaded", function () {
  const modal = document.getElementById("disclaimerModal");
  if (modal && !localStorage.getItem(DISCLAIMER_KEY)) {
    modal.style.display = "flex";
  }
});

function closeDisclaimer() {
  localStorage.setItem(DISCLAIMER_KEY, "1");
  const modal = document.getElementById("disclaimerModal");
  if (modal) modal.style.display = "none";
}

function toggleDisclaimer() {
  const modal = document.getElementById("disclaimerModal");
  if (modal) {
    modal.style.display = modal.style.display === "flex" ? "none" : "flex";
  }
}

// Close modal on overlay click
document.addEventListener("click", function (e) {
  const modal = document.getElementById("disclaimerModal");
  if (modal && e.target === modal) {
    modal.style.display = "none";
  }
});

// ── Notifications ──────────────────────────────────────────────────────────
function showNotification(message, type = "info") {
  let container = document.getElementById("notificationContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "notificationContainer";
    document.body.appendChild(container);
  }

  const icons = { success: "fa-circle-check", error: "fa-circle-xmark", info: "fa-circle-info" };
  const notif = document.createElement("div");
  notif.className = `notification ${type}`;
  notif.innerHTML = `
    <i class="fas ${icons[type] || icons.info}" style="color:var(--${type === 'success' ? 'accent-green' : type === 'error' ? 'sev-critical' : 'primary'})"></i>
    <span>${message}</span>`;

  container.appendChild(notif);
  setTimeout(() => {
    notif.style.animation = "notifOut 0.3s ease forwards";
    setTimeout(() => notif.remove(), 300);
  }, 3500);
}

// ── Keyboard shortcuts ─────────────────────────────────────────────────────
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") {
    const modal = document.getElementById("disclaimerModal");
    const detailModal = document.getElementById("detailModal");
    if (modal && modal.style.display === "flex") modal.style.display = "none";
    if (detailModal && detailModal.style.display === "flex") detailModal.style.display = "none";
  }
});

// ── Active nav highlight ───────────────────────────────────────────────────
document.querySelectorAll(".nav-item[href]").forEach(item => {
  if (item.getAttribute("href") === window.location.pathname) {
    item.classList.add("active");
  }
});
