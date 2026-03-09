import crypto from 'crypto';
import express, { Request, Response, NextFunction, Application } from 'express';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function getServerUrl(): string {
  const url = process.env.MCP_SERVER_URL;
  if (!url) throw new Error('MCP_SERVER_URL environment variable is required');
  return url.replace(/\/+$/, '');
}

function getAuthSecret(): string {
  const secret = process.env.MCP_AUTH_SECRET;
  if (!secret) throw new Error('MCP_AUTH_SECRET environment variable is required');
  return secret;
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

interface OAuthClient {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  client_name?: string;
  created_at: number;
}

interface AuthCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
}

interface AccessToken {
  token: string;
  client_id: string;
  expires_at: number;
}

const clients = new Map<string, OAuthClient>();
const authCodes = new Map<string, AuthCode>();
const accessTokens = new Map<string, AccessToken>();

const AUTH_CODE_TTL = 10 * 60 * 1000;   // 10 minutes
const ACCESS_TOKEN_TTL = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL = 5 * 60 * 1000;  // 5 minutes

// ---------------------------------------------------------------------------
// Cleanup expired entries
// ---------------------------------------------------------------------------

setInterval(() => {
  const now = Date.now();
  for (const [key, code] of authCodes) {
    if (code.expires_at < now) authCodes.delete(key);
  }
  for (const [key, token] of accessTokens) {
    if (token.expires_at < now) accessTokens.delete(key);
  }
}, CLEANUP_INTERVAL);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function generateId(): string {
  return crypto.randomBytes(32).toString('hex');
}

function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to keep constant time, then return false
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function verifyPkceS256(codeVerifier: string, codeChallenge: string): boolean {
  const hash = crypto.createHash('sha256').update(codeVerifier).digest();
  const computed = hash.toString('base64url');
  return timingSafeEqual(computed, codeChallenge);
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

function handleProtectedResourceMetadata(_req: Request, res: Response): void {
  const serverUrl = getServerUrl();
  res.json({
    resource: serverUrl,
    authorization_servers: [serverUrl],
    bearer_methods_supported: ['header'],
  });
}

function handleAuthServerMetadata(_req: Request, res: Response): void {
  const serverUrl = getServerUrl();
  res.json({
    issuer: serverUrl,
    authorization_endpoint: `${serverUrl}/authorize`,
    token_endpoint: `${serverUrl}/token`,
    registration_endpoint: `${serverUrl}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    code_challenge_methods_supported: ['S256'],
  });
}

function handleClientRegistration(req: Request, res: Response): void {
  const { redirect_uris, client_name } = req.body;

  if (!redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    res.status(400).json({ error: 'invalid_request', error_description: 'redirect_uris required' });
    return;
  }

  const client: OAuthClient = {
    client_id: generateId(),
    client_secret: generateId(),
    redirect_uris,
    client_name: client_name || undefined,
    created_at: Date.now(),
  };

  clients.set(client.client_id, client);

  res.status(201).json({
    client_id: client.client_id,
    client_secret: client.client_secret,
    redirect_uris: client.redirect_uris,
    client_name: client.client_name,
  });
}

function handleAuthorizeGet(req: Request, res: Response): void {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, response_type } = req.query as Record<string, string>;

  if (response_type !== 'code') {
    res.status(400).send('Invalid response_type');
    return;
  }

  const client = clients.get(client_id);
  if (!client) {
    res.status(400).send('Unknown client');
    return;
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    res.status(400).send('Invalid redirect_uri');
    return;
  }

  const displayName = client.client_name ? escapeHtml(client.client_name) : 'MCP Client';

  res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize ${displayName}</title>
<style>
  body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
  .card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:400px;width:100%}
  h1{margin:0 0 .5rem;font-size:1.25rem}
  p{color:#666;margin:0 0 1.5rem;font-size:.9rem}
  input[type=password]{width:100%;padding:.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;box-sizing:border-box;margin-bottom:1rem}
  button{width:100%;padding:.75rem;background:#000;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer}
  button:hover{background:#333}
  .error{color:#e00;font-size:.85rem;margin-bottom:1rem;display:none}
</style></head><body>
<div class="card">
  <h1>Authorize ${displayName}</h1>
  <p>Enter the server secret to authorize access.</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="${escapeHtml(client_id)}">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirect_uri)}">
    <input type="hidden" name="state" value="${escapeHtml(state || '')}">
    <input type="hidden" name="code_challenge" value="${escapeHtml(code_challenge || '')}">
    <input type="hidden" name="code_challenge_method" value="${escapeHtml(code_challenge_method || '')}">
    <input type="hidden" name="response_type" value="code">
    <input type="password" name="secret" placeholder="Server secret" required autofocus>
    <button type="submit">Authorize</button>
  </form>
</div></body></html>`);
}

function handleAuthorizePost(req: Request, res: Response): void {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method, secret } = req.body;

  const client = clients.get(client_id);
  if (!client) {
    res.status(400).send('Unknown client');
    return;
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    res.status(400).send('Invalid redirect_uri');
    return;
  }

  if (!timingSafeEqual(secret || '', getAuthSecret())) {
    res.type('html').send(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorization Failed</title>
<style>
  body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#f5f5f5}
  .card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:400px;width:100%;text-align:center}
  h1{color:#e00;margin:0 0 .5rem;font-size:1.25rem}
  p{color:#666;margin:0 0 1.5rem;font-size:.9rem}
  a{color:#000;text-decoration:underline}
</style></head><body>
<div class="card"><h1>Invalid Secret</h1><p>The secret you entered is incorrect.</p><p><a href="javascript:history.back()">Try again</a></p></div></body></html>`);
    return;
  }

  const code = generateId();
  authCodes.set(code, {
    code,
    client_id,
    redirect_uri,
    code_challenge: code_challenge || '',
    code_challenge_method: code_challenge_method || 'S256',
    expires_at: Date.now() + AUTH_CODE_TTL,
  });

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) redirectUrl.searchParams.set('state', state);

  res.redirect(302, redirectUrl.toString());
}

function handleTokenExchange(req: Request, res: Response): void {
  const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

  if (grant_type !== 'authorization_code') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  const authCode = authCodes.get(code);
  if (!authCode) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' });
    return;
  }

  // Delete code immediately (single use)
  authCodes.delete(code);

  if (authCode.expires_at < Date.now()) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code expired' });
    return;
  }

  if (authCode.client_id !== client_id) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'Client mismatch' });
    return;
  }

  if (authCode.redirect_uri !== redirect_uri) {
    res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
    return;
  }

  // Verify client secret
  const client = clients.get(client_id);
  if (!client || !timingSafeEqual(client_secret || '', client.client_secret)) {
    res.status(401).json({ error: 'invalid_client' });
    return;
  }

  // Verify PKCE
  if (authCode.code_challenge && code_verifier) {
    if (!verifyPkceS256(code_verifier, authCode.code_challenge)) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
      return;
    }
  }

  const token = generateId();
  const expiresIn = ACCESS_TOKEN_TTL / 1000;

  accessTokens.set(token, {
    token,
    client_id,
    expires_at: Date.now() + ACCESS_TOKEN_TTL,
  });

  res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: expiresIn,
  });
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export function bearerAuthMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).set('WWW-Authenticate', 'Bearer').json({
      error: 'unauthorized',
      error_description: 'Bearer token required',
    });
    return;
  }

  const token = authHeader.slice(7);
  const stored = accessTokens.get(token);

  if (!stored || stored.expires_at < Date.now()) {
    if (stored) accessTokens.delete(token);
    res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({
      error: 'invalid_token',
      error_description: 'Token is invalid or expired',
    });
    return;
  }

  next();
}

// ---------------------------------------------------------------------------
// Mount all routes
// ---------------------------------------------------------------------------

export function mountOAuthRoutes(app: Application): void {
  // Express 5 needs urlencoded for form POST from authorize page
  app.use('/authorize', express.urlencoded({ extended: false }));

  app.get('/.well-known/oauth-protected-resource', handleProtectedResourceMetadata);
  app.get('/.well-known/oauth-authorization-server', handleAuthServerMetadata);
  app.post('/register', handleClientRegistration);
  app.get('/authorize', handleAuthorizeGet);
  app.post('/authorize', handleAuthorizePost);
  app.post('/token', handleTokenExchange);
}
