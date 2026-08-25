'use strict';

/**
 * End-to-end API test: full backend (in-memory mode, dead Mongo URI) +
 * a fake engine speaking NDJSON over the real Unix socket + a real
 * WebSocket client. Exercises the entire path the production stack uses.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sx-api-'));
process.env.RULES_DIR = path.join(tmpDir, 'rules');
process.env.ENGINE_SOCKET = path.join(tmpDir, 'engine.sock');
process.env.MONGO_URI = 'mongodb://127.0.0.1:59999/unreachable'; // dead port

const { createServer } = require('../src/app');
const { WebSocket } = require('ws');

let parts; // { server, store, ingestion, stream }
let base;
let port;

test.before(async () => {
  fs.mkdirSync(process.env.RULES_DIR, { recursive: true });
  parts = await createServer();
  await new Promise((r) => parts.server.listen(0, '127.0.0.1', r));
  port = parts.server.address().port;
  base = `http://127.0.0.1:${port}`;
});

test.after(async () => {
  if (parts.ingestion) parts.ingestion.stop();
  if (parts.stream.wss) parts.stream.close();
  await new Promise((r) => parts.server.close(r));
});

async function postEngineAlerts(alerts) {
  const sock = await new Promise((resolve, reject) => {
    const s = net.connect(process.env.ENGINE_SOCKET, () => resolve(s));
    s.once('error', reject);
  });
  for (const a of alerts) sock.write(JSON.stringify(a) + '\n');
  await new Promise((r) => setTimeout(r, 200));
  sock.end();
}

function sampleAlert(over = {}) {
  return {
    alert_id: `api-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: '2026-08-25T12:00:00.000Z',
    severity: 'HIGH',
    type: 'PORT_SCAN',
    src_ip: '203.0.113.50',
    dst_ip: '192.168.1.10',
    src_port: 44000,
    dst_port: 3389,
    protocol: 'TCP',
    tcp_flags: 2,
    mitre: {
      technique_id: 'T1046',
      technique_name: 'Network Service Discovery',
      tactic: 'Discovery',
      kill_chain_phase: 'Reconnaissance',
    },
    evidence: { scan_type: 'SYN', ports_contacted: [22, 80, 3389] },
    description: 'api test alert',
    yara_match: null,
    raw_payload_hash: null,
    false_positive: false,
    reviewed: false,
    ...over,
  };
}

test('GET /api/health reports in-memory mode and engine stats', async () => {
  const res = await fetch(`${base}/api/health`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.db, 'in-memory');
  assert.equal(body.engine.connected, false);
  assert.equal(body.ws.clients, 0);
});

test('REST round-trip: ingest via engine socket, query, triage, delete', async () => {
  const a1 = sampleAlert({ severity: 'HIGH', type: 'PORT_SCAN' });
  const a2 = sampleAlert({ severity: 'CRITICAL', type: 'SYN_FLOOD', src_ip: '203.0.113.99' });
  const a3 = sampleAlert({ severity: 'LOW', type: 'HTTP_ANOMALY' });
  await postEngineAlerts([a1, a2, a3]);

  // Health should now show the engine connected stats.
  const health = await (await fetch(`${base}/api/health`)).json();
  assert.equal(health.engine.alerts, 3);

  // List all
  const list = await (await fetch(`${base}/api/alerts`)).json();
  assert.equal(list.total, 3);

  // Filters
  const crit = await (
    await fetch(`${base}/api/alerts?severity=CRITICAL`)
  ).json();
  assert.equal(crit.total, 1);
  assert.equal(crit.items[0].alert_id, a2.alert_id);

  const byIp = await (
    await fetch(`${base}/api/alerts?src_ip=203.0.113.99`)
  ).json();
  assert.equal(byIp.total, 1);

  const byTechnique = await (
    await fetch(`${base}/api/alerts?technique=T1046`)
  ).json();
  assert.equal(byTechnique.total, 3);

  // Get one
  const one = await (await fetch(`${base}/api/alerts/${a1.alert_id}`)).json();
  assert.equal(one.severity, 'HIGH');
  assert.equal(one.mitre.technique_id, 'T1046');
  assert.deepEqual(one.evidence.ports_contacted, [22, 80, 3389]);

  // 404 for unknown
  const missing = await fetch(`${base}/api/alerts/does-not-exist`);
  assert.equal(missing.status, 404);

  // Triage update
  const put = await fetch(`${base}/api/alerts/${a1.alert_id}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ false_positive: true, reviewed: true }),
  });
  assert.equal(put.status, 200);
  const updated = await put.json();
  assert.equal(updated.false_positive, true);
  assert.equal(updated.reviewed, true);

  const reviewed = await (
    await fetch(`${base}/api/alerts?reviewed=true`)
  ).json();
  assert.equal(reviewed.total, 1);
  assert.equal(reviewed.items[0].alert_id, a1.alert_id);

  // PUT with no fields → 400
  const bad = await fetch(`${base}/api/alerts/${a1.alert_id}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(bad.status, 400);

  // Stats summary
  const sum = await (await fetch(`${base}/api/stats/summary`)).json();
  assert.equal(sum.total, 3);
  assert.equal(sum.by_severity.CRITICAL, 1);
  assert.equal(sum.by_type.PORT_SCAN, 1);
  assert.equal(sum.by_type.SYN_FLOOD, 1);
  assert.equal(sum.by_type.HTTP_ANOMALY, 1);
  assert.equal(sum.db_mode, 'in-memory');
  assert.ok(Array.isArray(sum.top_src_ips));

  // Delete
  const del = await fetch(`${base}/api/alerts/${a3.alert_id}`, {
    method: 'DELETE',
  });
  assert.equal(del.status, 204);
  const after = await (await fetch(`${base}/api/alerts`)).json();
  assert.equal(after.total, 2);
});

test('rules CRUD over a temp rules dir', async () => {
  const dir = process.env.RULES_DIR;

  // Empty dir → empty list
  let list = await (await fetch(`${base}/api/rules`)).json();
  assert.equal(list.rules.length, 0);

  // Create
  const rule = `rule test_api_rule {
    meta:
        severity = "HIGH"
        mitre = "T1059"
        description = "API test rule"
    strings:
        $a = { 90 90 90 }
    condition:
        $a
}`;
  const post = await fetch(`${base}/api/rules`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filename: 'api_test.yar', content: rule }),
  });
  assert.equal(post.status, 201);
  const created = await post.json();
  assert.equal(created.rules.length, 1);
  assert.equal(created.rules[0].name, 'test_api_rule');
  assert.equal(created.rules[0].meta.severity, 'HIGH');
  assert.equal(created.rules[0].meta.mitre, 'T1059');

  // Duplicate → 409
  const dup = await fetch(`${base}/api/rules`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filename: 'api_test.yar', content: rule }),
  });
  assert.equal(dup.status, 409);

  // Bad filename → 400
  const badName = await fetch(`${base}/api/rules`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ filename: '../evil.yar', content: rule }),
  });
  assert.equal(badName.status, 400);

  // List now shows the rule
  list = await (await fetch(`${base}/api/rules`)).json();
  assert.equal(list.rules.length, 1);
  assert.equal(list.rules[0].file, 'api_test.yar');

  // Get
  const one = await (await fetch(`${base}/api/rules/api_test`)).json();
  assert.ok(one.content.includes('test_api_rule'));

  // Update
  const put = await fetch(`${base}/api/rules/api_test`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ content: rule + '\n// updated\n' }),
  });
  assert.equal(put.status, 200);
  const updatedFile = fs.readFileSync(path.join(dir, 'api_test.yar'), 'utf8');
  assert.ok(updatedFile.includes('// updated'));

  // Reload (no pid file → reloaded:false with detail)
  const reload = await (await fetch(`${base}/api/rules/reload`, { method: 'POST' })).json();
  assert.equal(reload.reloaded, false);

  // Delete
  const del = await fetch(`${base}/api/rules/api_test`, { method: 'DELETE' });
  assert.equal(del.status, 204);
  assert.equal(fs.existsSync(path.join(dir, 'api_test.yar')), false);
  const gone = await fetch(`${base}/api/rules/api_test`);
  assert.equal(gone.status, 404);
});

test('WebSocket: hello + history on connect, live alert on broadcast', async () => {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`);
  const messages = [];
  const done = new Promise((resolve, reject) => {
    ws.on('message', (raw) => {
      messages.push(JSON.parse(raw.toString()));
      if (messages.some((m) => m.type === 'alert')) resolve();
    });
    ws.on('error', reject);
    setTimeout(() => reject(new Error('ws timeout waiting for live alert')), 5000);
  });

  ws.on('open', async () => {
    // Send a fresh alert through the real engine socket path.
    await postEngineAlerts([
      sampleAlert({ severity: 'CRITICAL', type: 'HONEYPOT_HIT', alert_id: 'ws-live-1' }),
    ]);
  });

  await done;
  ws.close();

  const types = messages.map((m) => m.type);
  assert.ok(types.includes('hello'), 'expected hello first');
  assert.ok(types.includes('history'), 'expected history replay');
  assert.equal(messages[0].type, 'hello');

  const hist = messages.find((m) => m.type === 'history');
  assert.ok(Array.isArray(hist.data));
  assert.ok(hist.data.length >= 1, 'history should include prior alerts');

  const live = messages.find((m) => m.type === 'alert');
  assert.equal(live.data.alert_id, 'ws-live-1');
  assert.equal(live.data.severity, 'CRITICAL');
});

test('unknown /api route returns JSON 404', async () => {
  const res = await fetch(`${base}/api/nope`);
  assert.equal(res.status, 404);
  const body = await res.json();
  assert.equal(typeof body.error, 'string');
});
