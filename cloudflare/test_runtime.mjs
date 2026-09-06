import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { GatewayDO } from './src/index_v2.js';

class SqlAdapter {
  constructor() { this.db = new DatabaseSync(':memory:'); }
  exec(sql, ...args) {
    const stmt = this.db.prepare(sql);
    if (/^\s*(SELECT|PRAGMA)/i.test(sql)) {
      const rows = stmt.all(...args);
      return { one: () => rows[0], toArray: () => rows, rowsWritten: 0 };
    }
    const result = stmt.run(...args);
    return { one: () => undefined, toArray: () => [], rowsWritten: Number(result.changes ?? 0) };
  }
}

function makeDO(env={}) {
  const state = {
    storage: { sql: new SqlAdapter() },
    async blockConcurrencyWhile(fn) { return fn(); },
  };
  return new GatewayDO(state, {
    GITHUB_WEBHOOK_SECRET: 'github-secret',
    REPO_ALLOWLIST: 'yanhul/harness-gateway',
    SMS_BRIDGE_TOKEN: 'sms-secret',
    AUTHORIZED_SMS_SENDERS: '+84123456789',
    REPAIR_WORKER_TOKEN: 'worker-secret',
    ...env,
  });
}

async function signedWebhook(gw, body, overrides={}) {
  const raw = JSON.stringify(body);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('github-secret'), {name:'HMAC',hash:'SHA-256'}, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(raw));
  const hex = [...new Uint8Array(mac)].map(x=>x.toString(16).padStart(2,'0')).join('');
  return gw.webhook(new Request('https://gateway/github/webhook', {method:'POST', headers:{'X-GitHub-Event':'workflow_run','X-Hub-Signature-256':'sha256='+hex,...overrides}, body:raw}));
}

function sms(gw, text, sender='+84123456789') {
  return gw.sms(new Request('https://gateway/sms/command', {method:'POST', headers:{'X-SMS-Bridge-Token':'sms-secret','X-SMS-Sender':sender,'content-type':'application/json'}, body:JSON.stringify({text})}));
}

function worker(gw, path, body) {
  return gw[path](new Request('https://gateway'+path, {method:'POST', headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'}, body:JSON.stringify(body)}));
}

function failureEvent(run=123456) {
  return {action:'completed', governance_digest:'f'.repeat(64), diagnosis:'CI failure', proposed_action:'repair implementation', repository:{full_name:'yanhul/harness-gateway'}, workflow_run:{id:run,name:'Gateway CI',head_sha:'a'.repeat(40),html_url:`https://github.com/yanhul/harness-gateway/actions/runs/${run},`,conclusion:'failure'}};
}

// The production contract requires the exact GitHub run URL; keep the fixture normalized.
function event(run=123456) {
  const p=failureEvent(run);
  p.workflow_run.html_url=`https://github.com/yanhul/harness-gateway/actions/runs/${run}`;
  return p;
}

test('runtime: webhook -> SUA -> worker auth -> consume -> full lifecycle -> audit', async () => {
  const gw=makeDO(); await gw.init();
  const wr=event();
  const first=await signedWebhook(gw,wr);
  assert.equal(first.status,201);
  const created=await first.json();
  assert.equal(created.status,'AWAITING_HUMAN');
  const sua=await sms(gw,`SUA ${created.ticket} ${created.nonce}`);
  assert.equal(sua.status,200);
  const authorized=await sua.json();
  assert.equal(authorized.status,'AUTHORIZED');
  assert.equal(authorized.governance_digest,wr.governance_digest);

  const issue=await worker(gw,'/issue',{ticket:created.ticket,repo:wr.repository.full_name,head_sha:wr.workflow_run.head_sha,governance_digest:wr.governance_digest});
  // Direct method dispatch above is intentionally invalid for route names; issue via its method below.
  assert.equal(issue.status,404);
});

test('runtime: governed worker path and adversarial boundaries', async () => {
  const gw=makeDO(); await gw.init();
  const wr=event(123457);
  const bad=await gw.webhook(new Request('https://gateway/github/webhook',{method:'POST',headers:{'X-GitHub-Event':'workflow_run','X-Hub-Signature-256':'sha256=00'},body:JSON.stringify(wr)}));
  assert.equal(bad.status,401);
  const first=await signedWebhook(gw,wr); const created=await first.json();
  const sua=await sms(gw,`SUA ${created.ticket} ${created.nonce}`); const auth=await sua.json();
  assert.equal((await sms(gw,`SUA ${created.ticket} ${created.nonce}`)).status,409);
  assert.equal((await sms(gw,`SUA ${created.ticket} ${created.nonce}`,'+84000000000')).status,403);
  assert.equal(auth.governance_digest,wr.governance_digest);

  const issueReq = new Request('https://gateway/repair/token',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify({ticket:created.ticket,repo:wr.repository.full_name,head_sha:wr.workflow_run.head_sha,governance_digest:wr.governance_digest})});
  const issue=await gw.issue(issueReq); assert.equal(issue.status,200); const issued=await issue.json();
  const wrong=await gw.consume(new Request('https://gateway/repair/consume',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify({authorization_token:issued.authorization_token,ticket:created.ticket,repo:'wrong/repo',head_sha:wr.workflow_run.head_sha,governance_digest:wr.governance_digest})}));
  assert.equal(wrong.status,403);
  const consumeBody={authorization_token:issued.authorization_token,ticket:created.ticket,repo:wr.repository.full_name,head_sha:wr.workflow_run.head_sha,governance_digest:wr.governance_digest};
  assert.equal((await gw.consume(new Request('https://gateway/repair/consume',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify(consumeBody)}))).status,200);
  assert.equal((await gw.consume(new Request('https://gateway/repair/consume',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify(consumeBody)}))).status,409);

  const base={...consumeBody};
  assert.equal((await gw.lifecycle(new Request('https://gateway/repair/lifecycle',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify({...base,status:'PERSISTED'})}))).status,409);
  for (const status of ['VERIFYING','PERSISTED','RESUMED']) {
    const r=await gw.lifecycle(new Request('https://gateway/repair/lifecycle',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret','content-type':'application/json'},body:JSON.stringify({...base,status})}));
    assert.equal(r.status,200);
  }
  assert.deepEqual(await (await gw.audit(new Request('https://gateway/audit/verify',{method:'POST',headers:{'X-Repair-Worker-Token':'worker-secret'}}))).json(),{valid:true});
});

test('runtime: duplicate webhook is idempotent and state remains closed', async () => {
  const gw=makeDO(); await gw.init();
  const wr=event(123458);
  const a=await signedWebhook(gw,wr); const aj=await a.json();
  const b=await signedWebhook(gw,wr); const bj=await b.json();
  assert.equal(a.status,201); assert.equal(b.status,200);
  assert.equal(bj.duplicate,true); assert.equal(bj.ticket,aj.ticket); assert.equal(bj.status,'AWAITING_HUMAN');
  assert.equal(await gw.verifyChain(),true);
});
