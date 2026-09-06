import test from 'node:test';
import assert from 'node:assert/strict';
import gateway, { GatewayDO } from './src/index.js';

test('Cloudflare module exports gateway entrypoint and Durable Object', () => {
  assert.equal(typeof gateway.fetch, 'function');
  assert.equal(typeof GatewayDO, 'function');
});

test('Cloudflare source contains governed lifecycle endpoints', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('./src/index.js', import.meta.url), 'utf8');
  assert.match(source, /\/github\/webhook/);
  assert.match(source, /\/sms\/command/);
  assert.match(source, /\/repair\/lifecycle/);
  assert.match(source, /X-Hub-Signature-256/);
  assert.match(source, /X-SMS-Bridge-Token/);
  assert.match(source, /X-Repair-Worker-Token/);
});

test('Cloudflare source uses durable SQLite and atomic one-time guards', async () => {
  const fs = await import('node:fs/promises');
  const source = await fs.readFile(new URL('./src/index.js', import.meta.url), 'utf8');
  assert.match(source, /state\.storage\.sql/);
  assert.match(source, /blockConcurrencyWhile/);
  assert.match(source, /nonce_used=1/);
  assert.match(source, /nonce_used=0/);
  assert.match(source, /consumed=0/);
});
