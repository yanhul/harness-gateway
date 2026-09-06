const STATES = {
  OBSERVED: new Set(['DIAGNOSED', 'BLOCKED']),
  DIAGNOSED: new Set(['AWAITING_HUMAN', 'BLOCKED']),
  AWAITING_HUMAN: new Set(['AUTHORIZED', 'REJECTED', 'EXPIRED', 'REVOKED', 'BLOCKED']),
  AUTHORIZED: new Set(['ACTING', 'REVOKED', 'BLOCKED']),
  ACTING: new Set(['VERIFYING', 'BLOCKED', 'REVOKED']),
  VERIFYING: new Set(['PERSISTED', 'BLOCKED']),
  PERSISTED: new Set(['RESUMED']),
  RESUMED: new Set(),
  REJECTED: new Set(),
  EXPIRED: new Set(),
  REVOKED: new Set(),
  BLOCKED: new Set(),
};

const LIFECYCLE = new Set(['VERIFYING', 'PERSISTED', 'RESUMED']);

function hex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

async function hmac(secret, body) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const value = (body.startsWith('sha256=') ? body.slice(7) : body).trim();
  if (!/^[0-9a-f]{64}$/i.test(value)) return false;
  return crypto.subtle.verify('HMAC', key, Uint8Array.from(value.match(/../g), x => parseInt(x, 16)), new TextEncoder().encode(body.raw));
}

async function verifyGithubSignature(secret, signature, raw) {
  if (!secret || !signature || !signature.startsWith('sha256=')) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw)));
  const expected = 'sha256=' + hex(digest);
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });
}

export class GatewayDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
  }

  async init() {
    await this.state.blockConcurrencyWhile(async () => {
      this.sql.exec(`CREATE TABLE IF NOT EXISTS tickets (
        ticket TEXT PRIMARY KEY, repo TEXT NOT NULL, target_sha TEXT NOT NULL,
        governance_digest TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, nonce_hash TEXT, nonce_expires_at TEXT,
        nonce_consumed INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS authorizations (
        token_hash TEXT PRIMARY KEY, ticket TEXT NOT NULL, repo TEXT NOT NULL,
        target_sha TEXT NOT NULL, governance_digest TEXT NOT NULL, issued_at TEXT NOT NULL,
        expires_at TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY(ticket) REFERENCES tickets(ticket)
      );
      CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT NOT NULL, event_type TEXT NOT NULL,
        actor TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL,
        prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL
      );`);
    });
  }

  async event(ticket, eventType, actor, payload) {
    const created = new Date().toISOString();
    const prev = this.sql.exec('SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1').one()?.event_hash || '';
    const canonical = [prev, ticket, eventType, actor, payload, created].join('|');
    const hash = await sha256(canonical);
    this.sql.exec('INSERT INTO events(ticket,event_type,actor,payload,created_at,prev_hash,event_hash) VALUES(?,?,?,?,?,?,?)', ticket, eventType, actor, payload, created, prev, hash);
  }

  transition(ticket, next) {
    const row = this.sql.exec('SELECT status FROM tickets WHERE ticket=?', ticket).one();
    if (!row || !STATES[row.status]?.has(next)) throw new Error('illegal transition');
    this.sql.exec('UPDATE tickets SET status=?,updated_at=? WHERE ticket=?', next, new Date().toISOString(), ticket);
  }

  async webhook(request) {
    const raw = await request.text();
    if (!await verifyGithubSignature(this.env.GITHUB_WEBHOOK_SECRET, request.headers.get('X-Hub-Signature-256'), raw)) return json({ error: 'invalid signature' }, 401);
    const body = JSON.parse(raw);
    const repo = body?.repository?.full_name;
    const allow = (this.env.REPO_ALLOWLIST || '').split(',').map(x => x.trim()).filter(Boolean);
    if (!repo || !allow.includes(repo)) return json({ error: 'repository not allowed' }, 403);
    const run = body?.workflow_run;
    const sha = run?.head_sha;
    const runUrl = run?.html_url;
    if (!sha || !runUrl) return json({ error: 'invalid workflow_run' }, 400);
    const ticket = await sha256([repo, sha, runUrl, Date.now(), crypto.randomUUID()].join('|'));
    const governance = body?.workflow_run?.governance_digest;
    if (!/^[0-9a-f]{64}$/i.test(governance || '')) return json({ error: 'missing governance digest' }, 400);
    const now = new Date().toISOString();
    this.sql.exec('INSERT INTO tickets(ticket,repo,target_sha,governance_digest,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)', ticket, repo, sha, governance, 'OBSERVED', now, now);
    await this.event(ticket, 'OBSERVED', 'github', JSON.stringify({ repo, sha, runUrl }));
    return json({ ticket, status: 'OBSERVED' }, 201);
  }

  async sms(request) {
    if (request.headers.get('X-SMS-Bridge-Token') !== this.env.SMS_BRIDGE_TOKEN) return json({ error: 'unauthorized' }, 401);
    const sender = request.headers.get('X-SMS-Sender');
    const text = String((await request.json()).text || '').trim();
    const m = text.match(/^SUA\s+(\S+)\s+(\S+)$/);
    if (!m || !sender) return json({ error: 'invalid command' }, 400);
    const row = this.sql.exec('SELECT * FROM tickets WHERE ticket=?', m[1]).one();
    if (!row || row.status !== 'AWAITING_HUMAN') return json({ error: 'ticket not awaiting human' }, 409);
    if (row.nonce_consumed || !row.nonce_hash || !row.nonce_expires_at || Date.parse(row.nonce_expires_at) < Date.now()) return json({ error: 'nonce invalid or expired' }, 403);
    const supplied = await sha256(m[2]);
    if (supplied !== row.nonce_hash) return json({ error: 'nonce mismatch' }, 403);
    const result = this.sql.exec('UPDATE tickets SET nonce_consumed=1,status=?,updated_at=? WHERE ticket=? AND status=? AND nonce_consumed=0 AND nonce_hash=?', 'AUTHORIZED', new Date().toISOString(), m[1], 'AWAITING_HUMAN', supplied);
    if (result.rowsWritten !== 1) return json({ error: 'replay rejected' }, 409);
    await this.event(m[1], 'AUTHORIZED', sender, JSON.stringify({ repo: row.repo, sha: row.target_sha, governance_digest: row.governance_digest }));
    return json({ status: 'AUTHORIZED', ticket: m[1], governance_digest: row.governance_digest });
  }

  async lifecycle(request) {
    if (request.headers.get('X-Repair-Worker-Token') !== this.env.REPAIR_WORKER_TOKEN) return json({ error: 'unauthorized' }, 401);
    const p = await request.json();
    if (!LIFECYCLE.has(p.status)) return json({ error: 'invalid lifecycle status' }, 400);
    const row = this.sql.exec('SELECT * FROM tickets WHERE ticket=?', p.ticket).one();
    if (!row || row.repo !== p.repo || row.target_sha !== p.target_sha || row.governance_digest !== p.governance_digest) return json({ error: 'binding mismatch' }, 403);
    if (row.status !== 'ACTING' && !(row.status === 'VERIFYING' && p.status === 'PERSISTED') && !(row.status === 'PERSISTED' && p.status === 'RESUMED')) return json({ error: 'illegal lifecycle order' }, 409);
    const tokenHash = await sha256(p.authorization_token || '');
    const auth = this.sql.exec('SELECT * FROM authorizations WHERE token_hash=? AND ticket=?', tokenHash, p.ticket).one();
    if (!auth || !auth.consumed || Date.parse(auth.expires_at) < Date.now()) return json({ error: 'worker authorization not consumed or expired' }, 403);
    this.transition(p.ticket, p.status);
    await this.event(p.ticket, p.status, 'repair-worker', JSON.stringify({ repo: p.repo, sha: p.target_sha, governance_digest: p.governance_digest }));
    return json({ status: p.status, ticket: p.ticket });
  }

  async fetch(request) {
    await this.init();
    const u = new URL(request.url);
    if (u.pathname === '/github/webhook' && request.method === 'POST') return this.webhook(request);
    if (u.pathname === '/sms/command' && request.method === 'POST') return this.sms(request);
    if (u.pathname === '/repair/lifecycle' && request.method === 'POST') return this.lifecycle(request);
    return json({ error: 'not found' }, 404);
  }
}

export default {
  async fetch(request, env) {
    const id = env.GATEWAY.idFromName('primary');
    return env.GATEWAY.get(id).fetch(request);
  }
};
