// main.js

// Generate fingerprint
function getFingerprint() {
  let fp = localStorage.getItem('scanhealth_fp');
  if (!fp) {
    fp = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
      (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
    );
    localStorage.setItem('scanhealth_fp', fp);
  }
  return fp;
}

// single shared refresh promise
let refreshPromise = null;
let refreshFailed = false;

// perform a single refresh, share across callers
function attemptRefresh() {
  if (refreshFailed) return Promise.resolve({ ok: false });
  if (!refreshPromise) {
    refreshPromise = (async () => {
      try {
        const fp = getFingerprint();
        const r = await fetch('/refresh', {
          method: 'POST',
          credentials: 'include',
          headers: { 'X-Client-Fingerprint': fp }
        });
        if (!r.ok) {
          refreshFailed = true;
          return { ok: false };
        }
        return { ok: true };
      } catch (err) {
        refreshFailed = true;
        return { ok: false };
      } finally {
        refreshPromise = null;
      }
    })();
  }
  return refreshPromise;
}

async function apiFetch(url, opts = {}) {
  if (refreshFailed) return new Response(null, { status: 401 });

  const fp = getFingerprint();
  opts.headers = { ...(opts.headers || {}), 'X-Client-Fingerprint': fp };

  let res;
  try {
    res = await fetch(url, { ...opts, credentials: 'include' });
  } catch (err) {
    return new Response(null, { status: 0, statusText: 'Network Error' });
  }

  if (res.status === 401) {
    const refreshed = await attemptRefresh();
    if (refreshed.ok) {
      try {
        res = await fetch(url, { ...opts, credentials: 'include', headers: { 'X-Client-Fingerprint': fp } });
      } catch (err) {
        return new Response(null, { status: 0, statusText: 'Network Error' });
      }
    } else {
      refreshFailed = true;
      return new Response(null, { status: 401 });
    }
  }

  return res;
}

// Boot: schedule auth check on idle or after load to avoid blocking initial render
function scheduleAuthCheck() {
  const path = window.location.pathname;
  if (path === "/login" || path === "/signup") return;

  const doCheck = async () => {
    try {
      const r = await apiFetch('/api/auth/check');
      if (r.status === 401) {
        // do nothing — user may choose to login later
      }
    } catch (e) { /* swallow */ }
  };

  if ('requestIdleCallback' in window) {
    requestIdleCallback(doCheck, { timeout: 2000 });
  } else {
    window.addEventListener('load', () => setTimeout(doCheck, 800));
  }
}

// Call scheduleAuthCheck (non-blocking)
scheduleAuthCheck();

// hide loader
window.addEventListener('load', function () {
  const myDiv = document.getElementById('loading_page');
  if (myDiv) myDiv.style.display = 'none';
});

// Navbar render (unchanged)
(function renderNavbar() {
  const existingLink = document.querySelector("link[data-navbar-style]");
  if (!existingLink) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "./css/styles.css";
    link.setAttribute("data-navbar-style", "true");
    document.head.appendChild(link);
  }

  const navbarHTML = `
    <nav class="navbar">
      <div class="logo">Scan Health</div>
      <input type="checkbox" id="menu-toggle">
      <label for="menu-toggle" class="menu-btn"></label>
      <ul class="nav-links">
        <li><a href="/">Home</a></li>
        <li><a href="#About">About</a></li>
        <li><a href="/scanner">Scanner</a></li>
        <li><a href="#">Contact</a></li>
        <li><a href="/login">Login</a></li>
        <li><a href="/signup">Signup</a></li>
      </ul>
    </nav>
  `;
  const root = document.getElementById("nav-root");
  if (root) {
    root.innerHTML = navbarHTML;
    const links = root.querySelectorAll(".nav-links a");
    const toggle = root.querySelector("#menu-toggle");
    links.forEach(link =>
      link.addEventListener("click", () => { if (toggle) toggle.checked = false; })
    );
  }
})();

async function updateNavbarAuthState() {
  try {
    const res = await apiFetch('/api/auth/check');
    const navLinks = document.querySelector(".nav-links");
    if (!navLinks) return;

    if (res.ok) {
      // logged in
      const data = await res.json();
      navLinks.innerHTML = `
        <li><a href="/profile" id="profile-link">
          <img src="/Imgs/profile-icon.png" alt="Profile"
               style="width:24px;height:24px;border-radius:50%;vertical-align:middle;">
        </a></li>
        <li><a href="/">Home</a></li>
        <li><a href="#About">About</a></li>
        <li><a href="/scanner">Scanner</a></li>
        <li><a href="#">Contact</a></li>
        <li><a href="#" id="logout-link">Logout</a></li>
      `;

      // attach logout handler
      const logoutLink = document.getElementById("logout-link");
      if (logoutLink) {
        logoutLink.addEventListener("click", async (e) => {
          e.preventDefault();
          await apiFetch("/api/auth/logout", { method: "POST" });
          localStorage.removeItem("access_token");
          location.href = "/login";
        });
      }
    } else {
      // not logged in
      navLinks.innerHTML = `
        <li><a href="/">Home</a></li>
        <li><a href="#About">About</a></li>
        <li><a href="/scanner">Scanner</a></li>
        <li><a href="#">Contact</a></li>
        <li><a href="/login">Login</a></li>
        <li><a href="/signup">Signup</a></li>
      `;
    }
  } catch {
    // on error just show default
  }
}

// Call it after navbar is rendered
updateNavbarAuthState();

