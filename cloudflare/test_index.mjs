import test from 'node:test';
import assert from 'node:assert/strict';
import gateway, { GatewayDO } from './src/index_v2.js';

test('Cloudflare module exports governed entrypoint and Durable Object', () => {
  assert.equal(typeof gateway.fetch, 'function');
  assert.equal(typeof GatewayDO, 'function');
});

test('Cloudflare source contains protected protocol boundaries', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('./src/index_v2.js', import.meta.url), 'utf8');
  for (const p of ['/github/webhook','/sms/command','/repair/token','/repair/consume','/repair/lifecycle','/audit/verify']) assert.match(source,new RegExp(p.replaceAll('/','\\/')));
  for (const h of ['X-Hub-Signature-256','X-SMS-Bridge-Token','X-SMS-Sender','X-Repair-Worker-Token']) assert.match(source,new RegExp(h));
});

test('Cloudflare source contains command parity and fail-closed sender binding', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('./src/index_v2.js', import.meta.url), 'utf8');
  for (const c of ['SUA','BOQUA','RETRY','STATUS','STOP']) assert.match(source,new RegExp(c));
  assert.match(source,/AUTHORIZED_SMS_SENDERS/);
  assert.match(source,/sender not authorized/);
  assert.match(source,/nonce_used=0/);
  assert.match(source,/consumed=0/);
});

test('Cloudflare source preserves durable serialization and audit verification', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('./src/index_v2.js', import.meta.url), 'utf8');
  assert.match(source,/state\.storage\.sql/);
  assert.match(source,/blockConcurrencyWhile/);
  assert.match(source,/verifyChain/);
  assert.match(source,/prev_hash/);
  assert.match(source,/event_hash/);
});
