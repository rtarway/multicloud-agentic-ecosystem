// Browser smoke test of the BFF login: fake IdP + stub orchestrator + real frontend + real Chromium.
// Not part of test-all.sh (needs a browser). Run: npm i --no-save playwright-core && node scripts/smoke-bff-login.js
// Set CHROMIUM_PATH if your Chromium is not at the default location.
const http = require('http');
const crypto = require('crypto');
const path = require('path');
const ROOT = path.resolve(__dirname, '..');
const { createIdp } = require(`${ROOT}/shared/test/helpers`);
const { chromium } = require('playwright-core');

const IDP_PORT = 18080, FE_PORT = 3000, ORCH_PORT = 13001;
const issuer = `http://127.0.0.1:${IDP_PORT}/realms/poc`;
const idp = createIdp({ issuer });
const codes = new Map();
const entraIdp = createIdp({ issuer: 'https://login.microsoftonline.com/tenant-1/v2.0', kid: 'entra-key' });
const entraCodes = new Map();
const orchestratorCalls = [];

const idpServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${IDP_PORT}`);
  const json = (obj, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  if (url.pathname === '/realms/poc/.well-known/openid-configuration') return json({ issuer, jwks_uri: `${issuer}/protocol/openid-connect/certs` });
  if (url.pathname === '/realms/poc/protocol/openid-connect/certs') return json(idp.jwks());
  if (url.pathname === '/realms/poc/protocol/openid-connect/auth') {
    const code = crypto.randomBytes(8).toString('hex');
    codes.set(code, { nonce: url.searchParams.get('nonce'), challenge: url.searchParams.get('code_challenge') });
    res.writeHead(302, { location: `${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}` });
    return res.end();
  }
  if (url.pathname === '/realms/poc/protocol/openid-connect/token') {
    let body = ''; req.on('data', c => (body += c)); req.on('end', () => {
      const p = Object.fromEntries(new URLSearchParams(body));
      const tx = codes.get(p.code);
      if (!tx || crypto.createHash('sha256').update(p.code_verifier).digest('base64url') !== tx.challenge) return json({ error: 'invalid_grant' }, 400);
      const user = { sub: 'kc-bob', email: 'bob@rtarwaygmail.onmicrosoft.com', email_verified: true, name: 'Bob POC', preferred_username: 'bob' };
      json({
        id_token: idp.sign({ ...user, aud: 'web-frontend', azp: 'web-frontend', nonce: tx.nonce }),
        access_token: idp.sign({ ...user, aud: 'agent-orchestrator-client', azp: 'web-frontend', scope: 'openid profile email mcp:tool1 mcp:bigquery:query' }),
        refresh_token: 'r1', expires_in: 300
      });
    });
    return;
  }
  if (url.pathname === '/realms/poc/protocol/openid-connect/logout') { res.writeHead(302, { location: url.searchParams.get('post_logout_redirect_uri') }); return res.end(); }
  if (url.pathname === '/entra/authorize') {
    const code = crypto.randomBytes(8).toString('hex');
    entraCodes.set(code, { nonce: url.searchParams.get('nonce'), challenge: url.searchParams.get('code_challenge') });
    res.writeHead(302, { location: `${url.searchParams.get('redirect_uri')}?code=${code}&state=${url.searchParams.get('state')}` });
    return res.end();
  }
  if (url.pathname === '/entra/keys') return json(entraIdp.jwks());
  if (url.pathname === '/entra/token') {
    let body = ''; req.on('data', c => (body += c)); req.on('end', () => {
      const p = Object.fromEntries(new URLSearchParams(body));
      const tx = entraCodes.get(p.code);
      if (!tx || crypto.createHash('sha256').update(p.code_verifier).digest('base64url') !== tx.challenge) return json({ error: 'invalid_grant' }, 400);
      json({
        id_token: entraIdp.sign({ aud: 'bff-client', tid: 'tenant-1', preferred_username: 'bob@rtarwaygmail.onmicrosoft.com', nonce: tx.nonce }),
        access_token: 'entra-access-token-for-orchestrator', refresh_token: 'er1', expires_in: 3600
      });
    });
    return;
  }
  res.writeHead(404); res.end();
});

const orch = http.createServer((req, res) => {
  let body = ''; req.on('data', c => (body += c)); req.on('end', () => {
    const call = { authorization: req.headers.authorization, entra: req.headers['x-user-entra-token'], body: JSON.parse(body) };
    orchestratorCalls.push(call);
    res.writeHead(200, { 'content-type': 'application/json' });
    if (/app2/.test(call.body.prompt) && !call.entra) {
      return res.end(JSON.stringify({ status: 'FAILED_POLICY_CHECK', code: 'USER_ASSERTION_REQUIRED', mcpResponse: { isError: true, content: [{ type: 'text', text: 'Azure sign-in required' }] }, hopToHop: {} }));
    }
    res.end(JSON.stringify({ status: 'COMPLETED_SUCCESSFULLY', mcpResponse: { isError: false, content: [{ type: 'text', text: 'stub ok' }] }, hopToHop: {} }));
  });
});

(async () => {
  await new Promise(r => idpServer.listen(IDP_PORT, '127.0.0.1', r));
  await new Promise(r => orch.listen(ORCH_PORT, '127.0.0.1', r));
  Object.assign(process.env, {
    OIDC_ISSUER: issuer, OIDC_CLIENT_ID: 'web-frontend', OIDC_REDIRECT_URI: `http://localhost:${FE_PORT}/auth/callback`,
    AGENT_ORCHESTRATOR_URL: `http://127.0.0.1:${ORCH_PORT}`, PORT: String(FE_PORT), ALLOW_SIMULATION: 'false',
    IDENTITY_MAP_PATH: path.join(ROOT, 'identity', 'identity-map.json'),
    ENTRA_TENANT_ID: 'tenant-1', ENTRA_BFF_CLIENT_ID: 'bff-client', ENTRA_ORCHESTRATOR_APP_ID: 'orch-app',
    ENTRA_AUTHORIZATION_ENDPOINT: `http://127.0.0.1:${IDP_PORT}/entra/authorize`,
    ENTRA_TOKEN_ENDPOINT: `http://127.0.0.1:${IDP_PORT}/entra/token`,
    ENTRA_JWKS_URI: `http://127.0.0.1:${IDP_PORT}/entra/keys`
  });
  const app = require(`${ROOT}/app/web-frontend/src/index`);
  const fe = app.listen(FE_PORT);

  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox'] });
  const page = await browser.newPage();
  const results = [];
  const check = (name, ok, detail = '') => { results.push(ok); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ' - ' + detail : ''}`); };

  await page.goto(`http://localhost:${FE_PORT}/`);
  await page.waitForSelector('a[href="/auth/login"]', { timeout: 5000 });
  check('signed-out page shows a Sign in link and hides the demo persona cards', await page.isVisible('a[href="/auth/login"]') && !(await page.isVisible('.persona-grid')));

  await page.click('a[href="/auth/login"]');
  await page.waitForSelector('#dashboard-screen', { state: 'visible', timeout: 8000 });
  check('after the redirect round trip the dashboard is shown', await page.isVisible('#dashboard-screen'));
  check('user identity is displayed', (await page.textContent('#user-email')).includes('bob@rtarwaygmail.onmicrosoft.com'));
  check('consented scopes are displayed', (await page.textContent('#user-scopes')).includes('mcp:tool1'));

  const pageState = await page.evaluate(() => JSON.stringify({
    html: document.documentElement.outerHTML.slice(0, 2_000_000), cookie: document.cookie,
    local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage)
  }));
  check('no JWT anywhere in the page, cookies visible to JS, or storage', !/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\./.test(pageState));
  check('the session cookie is HttpOnly (invisible to JS)', !/sid=/.test(JSON.parse(pageState).cookie));
  const cookies = await page.context().cookies();
  check('sid cookie exists with HttpOnly + SameSite=Lax', cookies.some(c => c.name === 'sid' && c.httpOnly && c.sameSite === 'Lax'));

  await page.fill('#prompt-input', 'Query BigQuery sales in north-america');
  await page.evaluate(() => submitPrompt());
  await page.waitForFunction(() => document.querySelector('#results-container') && getComputedStyle(document.querySelector('#results-container')).display !== 'none');
  await new Promise(r => setTimeout(r, 500));
  const call = orchestratorCalls[0];
  check('orchestrator received the call with the server-held bearer token', call && /^Bearer eyJ/.test(call.authorization));
  check('the page-side placeholder token was never forwarded', call && !call.authorization.includes('session') && !(call.body && 'token' in call.body));

  // Azure leg: an Azure prompt asks for the Entra sign-in; connecting it makes the next call carry the server-held token
  await page.fill('#prompt-input', 'Read the customer metrics from app2');
  await page.evaluate(() => submitPrompt());
  await page.waitForSelector('#entra-banner a', { timeout: 5000 });
  check('an Azure prompt without an Entra sign-in shows a "Connect Azure" link', (await page.textContent('#entra-banner')).includes('Connect your Azure account'));
  await page.click('#entra-banner a');
  await page.waitForSelector('#dashboard-screen', { state: 'visible', timeout: 8000 });
  await page.waitForTimeout(500);
  const sess = await page.evaluate(() => fetch('/api/session').then(r => r.json()));
  check('after the Entra round trip Azure is connected for the same user', sess.entra && sess.entra.connected === true && sess.entra.upn === 'bob@rtarwaygmail.onmicrosoft.com');
  check('the Entra token never reaches the page', !JSON.stringify(sess).includes('entra-access-token'));
  await page.fill('#prompt-input', 'Read the customer metrics from app2'); // the page reloaded after the redirect
  await page.evaluate(() => submitPrompt());
  await new Promise(r => setTimeout(r, 700));
  check('the next Azure call carries the Entra token held on the server', orchestratorCalls.at(-1).entra === 'entra-access-token-for-orchestrator');

  await page.evaluate(() => logout());
  await page.waitForSelector('a[href="/auth/login"]', { timeout: 8000 });
  check('logout returns to the signed-out page', await page.isVisible('a[href="/auth/login"]'));
  const after = await fetch(`http://localhost:${FE_PORT}/api/session`, { headers: { cookie: cookies.map(c => `${c.name}=${c.value}`).join('; ') } }).then(r => r.json());
  check('the old session cookie no longer works', after.authenticated === false);

  await browser.close();
  fe.close(); idpServer.close(); orch.close();
  process.exit(results.every(Boolean) ? 0 : 1);
})().catch(err => { console.error(err); process.exit(2); });
