'use strict';

const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { AlertStore } = require('../src/services/AlertStore');
const { EngineIngestion } = require('../src/services/EngineIngestion');

function alertJson(over = {}) {
  return {
    alert_id: `ing-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: new Date().toISOString(),
    severity: 'HIGH',
    type: 'PORT_SCAN',
    src_ip: '10.0.0.1',
    dst_ip: '10.0.0.2',
    src_port: 1,
    dst_port: 22,
    protocol: 'TCP',
    tcp_flags: 2,
    mitre: { technique_id: 'T1046' },
    evidence: {},
    description: 'ingestion test',
    yara_match: null,
    raw_payload_hash: null,
    false_positive: false,
    reviewed: false,
    ...over,
  };
}

/** Connect a fake engine and write raw bytes to the socket. */
function connectEngine(socketPath) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socketPath, () => resolve(sock));
    sock.once('error', reject);
  });
}

async function withIngestion(t, fn) {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  const socketPath = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), 'sx-ing-')),
    'alerts.sock'
  );
  const ingestion = new EngineIngestion({ socketPath, store });
  await ingestion.start();
  try {
    await fn(ingestion, store, socketPath);
  } finally {
    ingestion.stop();
  }
}

test('ingestion: accepts engine connection and stores NDJSON alerts', async (t) => {
  await withIngestion(t, async (ingestion, store, socketPath) => {
    const sock = await connectEngine(socketPath);
    assert.equal(ingestion.stats.connected, true);
    assert.equal(ingestion.stats.connections, 1);

    const a1 = alertJson({ alert_id: 'in-1' });
    const a2 = alertJson({ alert_id: 'in-2', type: 'SYN_FLOOD' });
    sock.write(JSON.stringify(a1) + '\n' + JSON.stringify(a2) + '\n');

    await new Promise((r) => setTimeout(r, 150));
    sock.end();

    const { items, total } = await store.list({});
    assert.equal(total, 2);
    const ids = items.map((a) => a.alert_id).sort();
    assert.deepEqual(ids, ['in-1', 'in-2']);
    assert.equal(ingestion.stats.alerts, 2);
    assert.equal(ingestion.stats.malformed, 0);
  });
});

test('ingestion: handles split frames and malformed lines', async (t) => {
  await withIngestion(t, async (ingestion, store, socketPath) => {
    const sock = await connectEngine(socketPath);
    const a = alertJson({ alert_id: 'split-1' });
    const line = JSON.stringify(a) + '\n';
    const mid = Math.floor(line.length / 2);

    // 1) A complete malformed line (its own frame).
    sock.write('this is not json\n');
    await new Promise((r) => setTimeout(r, 50));
    // 2) A valid alert whose frame arrives split across two writes.
    sock.write(line.slice(0, mid));
    await new Promise((r) => setTimeout(r, 50));
    sock.write(line.slice(mid));

    await new Promise((r) => setTimeout(r, 150));
    sock.end();

    const { total } = await store.list({});
    assert.equal(total, 1);
    assert.equal(ingestion.stats.malformed, 1);
    assert.equal(ingestion.stats.alerts, 1);
  });
});

test('ingestion: duplicate alert_id is not re-stored', async (t) => {
  await withIngestion(t, async (ingestion, store, socketPath) => {
    const sock = await connectEngine(socketPath);
    const a = alertJson({ alert_id: 'dup-77' });
    sock.write(JSON.stringify(a) + '\n' + JSON.stringify(a) + '\n');
    await new Promise((r) => setTimeout(r, 150));
    sock.end();

    const { total } = await store.list({});
    assert.equal(total, 1);
    assert.equal(ingestion.stats.duplicates, 1);
  });
});

test('ingestion: engine restart replaces the connection', async (t) => {
  await withIngestion(t, async (ingestion, store, socketPath) => {
    const s1 = await connectEngine(socketPath);
    s1.write(JSON.stringify(alertJson({ alert_id: 'gen-1' })) + '\n');
    await new Promise((r) => setTimeout(r, 100));
    s1.destroy();
    await new Promise((r) => setTimeout(r, 100));

    // Engine "restarts" — a second connection.
    const s2 = await connectEngine(socketPath);
    assert.equal(ingestion.stats.connections, 2);
    assert.equal(ingestion.stats.connected, true);
    s2.write(JSON.stringify(alertJson({ alert_id: 'gen-2' })) + '\n');
    await new Promise((r) => setTimeout(r, 100));
    s2.end();

    const { total } = await store.list({});
    assert.equal(total, 2);
  });
});
