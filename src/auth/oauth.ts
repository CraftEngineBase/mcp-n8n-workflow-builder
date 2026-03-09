import crypto from 'crypto';
import { Response } from 'express';
import { OAuthServerProvider, AuthorizationParams } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import { OAuthClientInformationFull, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function getAuthSecret(): string {
  const secret = process.env.MCP_AUTH_SECRET;
  if (!secret) throw new Error('MCP_AUTH_SECRET environment variable is required');
  return secret;
}

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------

interface StoredAuthCode {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
}

interface StoredAccessToken {
  clientId: string;
  expiresAt: number;
}

const registeredClients = new Map<string, OAuthClientInformationFull>();
const authCodes = new Map<string, StoredAuthCode>();
const accessTokens = new Map<string, StoredAccessToken>();

const ACCESS_TOKEN_TTL = 60 * 60 * 1000; // 1 hour
const CLEANUP_INTERVAL = 5 * 60 * 1000;  // 5 minutes

// Cleanup expired tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, token] of accessTokens) {
    if (token.expiresAt < now) accessTokens.delete(key);
  }
}, CLEANUP_INTERVAL);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// ---------------------------------------------------------------------------
// OAuthRegisteredClientsStore implementation
// ---------------------------------------------------------------------------

class InMemoryClientsStore implements OAuthRegisteredClientsStore {
  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return registeredClients.get(clientId);
  }

  async registerClient(client: any): Promise<OAuthClientInformationFull> {
    const clientId = client.client_id ?? crypto.randomUUID();
    const fullClient = { ...client, client_id: clientId };
    registeredClients.set(clientId, fullClient);
    return fullClient;
  }
}

// ---------------------------------------------------------------------------
// OAuthServerProvider implementation
// ---------------------------------------------------------------------------

class SecretOAuthProvider implements OAuthServerProvider {
  readonly clientsStore = new InMemoryClientsStore();

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const displayName = client.client_name ? escapeHtml(client.client_name) : 'MCP Client';
    const { state, codeChallenge, redirectUri } = params;

    // Render the authorize form
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
</style></head><body>
<div class="card">
  <h1>Authorize ${displayName}</h1>
  <p>Enter the server secret to authorize access.</p>
  <form method="POST" action="/authorize">
    <input type="hidden" name="client_id" value="${escapeHtml(client.client_id)}">
    <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
    <input type="hidden" name="state" value="${escapeHtml(state || '')}">
    <input type="hidden" name="code_challenge" value="${escapeHtml(codeChallenge)}">
    <input type="hidden" name="response_type" value="code">
    <input type="password" name="secret" placeholder="Server secret" required autofocus>
    <button type="submit">Authorize</button>
  </form>
</div></body></html>`);
  }

  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const stored = authCodes.get(authorizationCode);
    if (!stored) throw new Error('Invalid authorization code');
    return stored.codeChallenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string, _codeVerifier?: string, _redirectUri?: string): Promise<OAuthTokens> {
    const stored = authCodes.get(authorizationCode);
    if (!stored) throw new Error('Invalid authorization code');

    // Single-use: delete immediately
    authCodes.delete(authorizationCode);

    if (stored.clientId !== client.client_id) {
      throw new Error('Client mismatch');
    }

    const token = generateToken();
    const expiresIn = ACCESS_TOKEN_TTL / 1000;

    accessTokens.set(token, {
      clientId: client.client_id,
      expiresAt: Date.now() + ACCESS_TOKEN_TTL,
    });

    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
    };
  }

  async exchangeRefreshToken(): Promise<OAuthTokens> {
    throw new Error('Refresh tokens not supported');
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const stored = accessTokens.get(token);
    if (!stored || stored.expiresAt < Date.now()) {
      if (stored) accessTokens.delete(token);
      throw new Error('Invalid or expired token');
    }

    return {
      token,
      clientId: stored.clientId,
      scopes: [],
      expiresAt: Math.floor(stored.expiresAt / 1000),
    };
  }
}

// ---------------------------------------------------------------------------
// Authorize POST handler (called by SDK's auth router for form submission)
// ---------------------------------------------------------------------------

/**
 * The SDK's mcpAuthRouter handles GET /authorize by calling provider.authorize().
 * But the POST /authorize (form submission) needs a custom handler because
 * the SDK doesn't know about our secret-based auth flow.
 *
 * This middleware should be mounted BEFORE mcpAuthRouter so it intercepts
 * POST /authorize with the secret form data.
 */
export function createAuthorizePostHandler(provider: SecretOAuthProvider) {
  return async (req: any, res: Response): Promise<void> => {
    const { client_id, redirect_uri, state, code_challenge, secret } = req.body;

    const client = await provider.clientsStore.getClient(client_id);
    if (!client) {
      res.status(400).send('Unknown client');
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

    // Generate auth code and store it
    const code = generateToken();
    authCodes.set(code, {
      clientId: client_id,
      codeChallenge: code_challenge || '',
      redirectUri: redirect_uri,
    });

    // Redirect back to client with code
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) redirectUrl.searchParams.set('state', state);

    res.redirect(302, redirectUrl.toString());
  };
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

export const oauthProvider = new SecretOAuthProvider();
