// Server-side session support for the dashboard.
//
// With OIDC configured the page never receives a token: sign-in is a redirect to the identity provider, the browser
// keeps only an HttpOnly session cookie, and /api/chat is authorised by that cookie on the server. This script adapts the
// demo dashboard to that model without changing it when OIDC is not configured (the demo persona login still works then).
(function () {
  let sessionMode = false;

  function el(id) { return document.getElementById(id); }

  // ---- Azure (Entra) connection banner ----
  function showBanner(text, href, label) {
    let banner = el('entra-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'entra-banner';
      banner.setAttribute('role', 'status');
      banner.style.cssText = 'margin:12px 0;padding:10px 14px;border:1px solid #f59e0b;border-radius:8px;background:rgba(245,158,11,0.12);font-size:13px;';
      const dash = el('dashboard-screen');
      if (dash) dash.insertBefore(banner, dash.firstChild);
    }
    banner.textContent = '';
    banner.appendChild(document.createTextNode(text + ' '));
    const link = document.createElement('a');
    link.href = href;
    link.textContent = label;
    link.style.fontWeight = '600';
    banner.appendChild(link);
    banner.style.display = 'block';
  }

  function hideBanner() {
    const banner = el('entra-banner');
    if (banner) banner.style.display = 'none';
  }

  // Looks at a chat result: Azure not connected, or Entra wants more proof (MFA / Conditional Access)
  function inspectChatResult(data) {
    if (!data || typeof data !== 'object') return;
    if (data.stepUp && data.stepUp.required) {
      const q = data.stepUp.claims ? '?claims=' + encodeURIComponent(data.stepUp.claims) : '';
      showBanner('Azure needs additional verification (for example MFA) before this action.', '/auth/entra/login' + q, 'Verify and retry');
    } else if (data.code === 'USER_ASSERTION_REQUIRED' || (data.mcpResponse && data.mcpResponse.audit && data.mcpResponse.audit.code === 'USER_ASSERTION_REQUIRED')) {
      showBanner('Connect your Azure account to use Azure tools.', '/auth/entra/login', 'Connect Azure');
    }
  }

  function showSignIn() {
    const grid = document.querySelector('.persona-grid');
    if (grid) grid.style.display = 'none';
    document.querySelectorAll('#login-screen form, #login-screen .manual-login').forEach(n => { n.style.display = 'none'; });
    const hero = document.querySelector('#login-screen .login-hero');
    if (hero) {
      hero.innerHTML = '<h2>🔐 Sign in</h2>' +
        '<p>Sign in with your organisation account. You will be asked which actions the assistant may take on your behalf.</p>' +
        '<p><a class="btn" style="display:inline-block;padding:10px 18px;" href="/auth/login">Sign in</a></p>';
    }
  }

  function enterDashboard(user) {
    sessionMode = true;
    // currentUser / currentToken are top-level `let` bindings of the dashboard script: shared by name, not via window
    currentUser = user; // eslint-disable-line no-undef
    currentToken = 'session'; // eslint-disable-line no-undef -- placeholder only: the real token never reaches the browser
    el('login-screen').style.display = 'none';
    el('dashboard-screen').style.display = 'block';
    el('header-user-status').style.display = 'flex';
    window.updateDashboardUserView();
  }

  // ---- adapt the dashboard when running in session mode ----
  const originalUpdate = window.updateDashboardUserView;
  window.updateDashboardUserView = function () {
    if (!sessionMode) return originalUpdate.apply(this, arguments);
    const u = currentUser; // eslint-disable-line no-undef
    el('header-user-badge').textContent = 'Signed in as ' + (u.displayName || u.email);
    document.querySelectorAll('#dash-btn-alice, #dash-btn-bob, #dash-btn-charlie').forEach(b => { b.style.display = 'none'; });
    const badge = el('active-user-badge');
    if (badge) { badge.className = 'role-badge role-regular'; badge.textContent = 'Signed in via your organisation account'; }
    el('user-name').textContent = u.displayName || '';
    el('user-email').textContent = u.email || '';
    el('user-scopes').textContent = (u.scopes || []).join(', ') || '(none consented)';
    el('user-azure-role').textContent = 'Determined by your cloud roles';
    const note = 'Held on the server; tokens are never sent to the browser.';
    ['kc-raw', 'entra-raw', 'google-raw'].forEach(id => { if (el(id)) el(id).textContent = note; });
  };

  const originalLogout = window.logout;
  window.logout = function () {
    if (!sessionMode) return originalLogout.apply(this, arguments);
    fetch('/auth/logout', { method: 'POST', headers: { 'X-Requested-With': 'fetch' } })
      .then(r => r.json())
      .then(d => { window.location.href = d.redirect || '/'; })
      .catch(() => { window.location.href = '/'; });
  };

  // Strip any token material from chat requests in session mode (the server uses the session instead).
  const originalFetch = window.fetch.bind(window);
  window.fetch = function (url, options) {
    if (sessionMode && String(url).startsWith('/api/chat') && options) {
      const headers = Object.assign({}, options.headers);
      delete headers['Authorization'];
      delete headers['X-User-Entra-Token'];
      headers['X-Requested-With'] = 'fetch';
      let body = options.body;
      try {
        const parsed = JSON.parse(body);
        delete parsed.token;
        delete parsed.userEntraToken;
        body = JSON.stringify(parsed);
      } catch (e) { /* leave body as is */ }
      return originalFetch(url, Object.assign({}, options, { headers, body, credentials: 'same-origin' })).then(res => {
        res.clone().json().then(inspectChatResult).catch(() => { /* not JSON */ });
        return res;
      });
    }
    return originalFetch(url, options);
  };

  fetch('/api/session', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(s => {
      if (s.mode !== 'oidc') return; // demo persona login stays as it is
      if (s.authenticated) {
        enterDashboard(s.user);
        if (s.entra && s.entra.configured && !s.entra.connected) {
          showBanner('Azure is not connected yet.', s.entra.signInUrl || '/auth/entra/login', 'Connect Azure');
        } else {
          hideBanner();
        }
      } else {
        showSignIn();
      }
    })
    .catch(() => { /* leave the page as is */ });
})();
