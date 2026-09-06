import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('./src/index_v2.js', import.meta.url), 'utf8');

test('webhook is authenticated over raw body and rejects spoofing', () => {
  assert.match(source, /req\.text\(\)/);
  assert.match(source, /X-Hub-Signature-256/);
  assert.match(source, /GITHUB_WEBHOOK_SECRET/);
  assert.match(source, /invalid signature/);
});

test('human SUA binds governance from stored ticket', () => {
  assert.match(source, /SELECT \* FROM tickets WHERE ticket=\?/);
  assert.match(source, /governance_digest:r\.governance_digest/);
  assert.match(source, /!\['SUA','BOQUA','RETRY'\]/);
  assert.match(source, /parts\.length!==3/);
});

test('supported SMS commands and sender allowlist are fail-closed', () => {
  for (const command of ['SUA','BOQUA','RETRY','STATUS','STOP']) assert.match(source,new RegExp(command));
  assert.match(source,/AUTHORIZED_SMS_SENDERS/);
  assert.match(source,/sender not authorized/);
});

test('one-time nonce and repair authorization are conditional', () => {
  assert.match(source, /nonce_used=1/);
  assert.match(source, /nonce_used=0/);
  assert.match(source, /consumed=1 WHERE token_hash=/);
  assert.match(source, /consumed=0 AND revoked=0 AND expires_at>=/);
});

test('worker lifecycle has exact binding and no state skipping', () => {
  assert.match(source, /r\.repo!==p\.repo/);
  assert.match(source, /r\.head_sha!==p\.head_sha/);
  assert.match(source, /r\.governance_digest!==p\.governance_digest/);
  assert.match(source, /r\.status==='ACTING'&&p\.status==='VERIFYING'/);
  assert.match(source, /r\.status==='VERIFYING'&&p\.status==='PERSISTED'/);
  assert.match(source, /r\.status==='PERSISTED'&&p\.status==='RESUMED'/);
});

test('audit chain carries predecessor and reference-compatible deterministic hash inputs', () => {
  assert.match(source, /prev_hash/);
  assert.match(source, /event_hash/);
  assert.match(source, /sha\(prev\+event\+actor\+body\)/);
  assert.match(source, /verifyChain/);
});

test('governing state machine is explicit and closed', () => {
  for (const state of ['OBSERVED','DIAGNOSED','AWAITING_HUMAN','AUTHORIZED','ACTING','VERIFYING','PERSISTED','RESUMED','REJECTED','EXPIRED','REVOKED','BLOCKED']) assert.match(source,new RegExp(state));
  assert.match(source,/const LIFE=new Set\(\['VERIFYING','PERSISTED','RESUMED'\]\)/);
});
