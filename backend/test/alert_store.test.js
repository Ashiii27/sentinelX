'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { AlertStore } = require('../src/services/AlertStore');

function makeAlert(over = {}) {
  return {
    alert_id: `id-${Math.random().toString(36).slice(2, 10)}`,
    timestamp: '2026-08-25T10:00:00.000Z',
    severity: 'HIGH',
    type: 'PORT_SCAN',
    src_ip: '203.0.113.5',
    dst_ip: '192.168.1.10',
    src_port: 41000,
    dst_port: 22,
    protocol: 'TCP',
    tcp_flags: 2,
    mitre: { technique_id: 'T1046', tactic: 'Discovery' },
    evidence: { scan_type: 'SYN' },
    description: 'test alert',
    false_positive: false,
    reviewed: false,
    ...over,
  };
}

test('AlertStore (memory): add is deduped on alert_id', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  const a = makeAlert({ alert_id: 'dup-1' });

  const r1 = await store.add(a);
  const r2 = await store.add(a);
  assert.equal(r1.isNew, true);
  assert.equal(r2.isNew, false);

  const { total } = await store.list({});
  assert.equal(total, 1);
});

test('AlertStore (memory): list filters + pagination + sort', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  await store.add(makeAlert({ severity: 'HIGH', src_ip: '1.1.1.1' }));
  await store.add(makeAlert({ severity: 'CRITICAL', type: 'SYN_FLOOD', src_ip: '2.2.2.2' }));
  await store.add(makeAlert({ severity: 'LOW', type: 'HTTP_ANOMALY', src_ip: '1.1.1.1' }));
  await store.add(makeAlert({ severity: 'HIGH', src_ip: '3.3.3.3', reviewed: true }));

  const all = await store.list({});
  assert.equal(all.total, 4);

  const crit = await store.list({ severity: 'CRITICAL' });
  assert.equal(crit.total, 1);
  assert.equal(crit.items[0].type, 'SYN_FLOOD');

  const sri = await store.list({ src_ip: '1.1.1.1' });
  assert.equal(sri.total, 2);

  const typeF = await store.list({ type: 'HTTP_ANOMALY' });
  assert.equal(typeF.total, 1);

  const reviewed = await store.list({ reviewed: 'true' });
  assert.equal(reviewed.total, 1);
  assert.equal(reviewed.items[0].src_ip, '3.3.3.3');

  const p1 = await store.list({ limit: 2, page: 1, sort: 'oldest' });
  assert.equal(p1.items.length, 2);
  const p2 = await store.list({ limit: 2, page: 2, sort: 'oldest' });
  assert.equal(p2.items.length, 2);
  assert.notDeepEqual(p1.items[0].alert_id, p2.items[0].alert_id);
});

test('AlertStore (memory): time-range filter', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  await store.add(makeAlert({ timestamp: '2026-08-25T09:00:00Z' }));
  await store.add(makeAlert({ timestamp: '2026-08-25T11:00:00Z' }));
  await store.add(makeAlert({ timestamp: '2026-08-26T11:00:00Z' }));

  const inRange = await store.list({
    from: '2026-08-25T10:00:00Z',
    to: '2026-08-25T12:00:00Z',
  });
  assert.equal(inRange.total, 1);
  assert.equal(inRange.items[0].timestamp, '2026-08-25T11:00:00Z');
});

test('AlertStore (memory): get / updateTriage / remove', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  const a = makeAlert({ alert_id: 'triage-1' });
  await store.add(a);

  const got = await store.get('triage-1');
  assert.equal(got.severity, 'HIGH');
  assert.equal(got.reviewed, false);

  const updated = await store.updateTriage('triage-1', {
    false_positive: true,
    reviewed: true,
  });
  assert.equal(updated.false_positive, true);
  assert.equal(updated.reviewed, true);

  assert.equal(await store.updateTriage('missing-id', { reviewed: true }), null);

  assert.equal(await store.remove('triage-1'), true);
  assert.equal(await store.remove('triage-1'), false);
  assert.equal(await store.get('triage-1'), null);
});

test('AlertStore (memory): cap evicts oldest first', async () => {
  const store = new AlertStore({ useMongo: false, cap: 3 });
  for (let i = 0; i < 5; i++) {
    await store.add(makeAlert({ alert_id: `evict-${i}` }));
  }
  const { total } = await store.list({});
  assert.equal(total, 3);
  assert.equal(await store.get('evict-0'), null);
  assert.ok(await store.get('evict-4'));
});

test('AlertStore (memory): recent() returns newest first', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  await store.add(makeAlert({ alert_id: 'r1', timestamp: '2026-08-25T08:00:00Z' }));
  await store.add(makeAlert({ alert_id: 'r2', timestamp: '2026-08-25T09:00:00Z' }));
  await store.add(makeAlert({ alert_id: 'r3', timestamp: '2026-08-25T10:00:00Z' }));

  const rec = await store.recent(2);
  assert.equal(rec.length, 2);
  assert.equal(rec[0].alert_id, 'r3');
  assert.equal(rec[1].alert_id, 'r2');
});

test('AlertStore (memory): summary aggregates', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  await store.add(makeAlert({ severity: 'HIGH', type: 'PORT_SCAN' }));
  await store.add(makeAlert({ severity: 'HIGH', type: 'PORT_SCAN' }));
  await store.add(makeAlert({ severity: 'CRITICAL', type: 'SYN_FLOOD' }));
  await store.add(
    makeAlert({
      severity: 'LOW',
      type: 'HONEYPOT_HIT',
      mitre: { technique_id: 'T1046' },
      src_ip: '9.9.9.9',
    })
  );

  const s = await store.summary();
  assert.equal(s.total, 4);
  assert.equal(s.by_severity.HIGH, 2);
  assert.equal(s.by_severity.CRITICAL, 1);
  assert.equal(s.by_severity.LOW, 1);
  assert.equal(s.by_severity.MEDIUM, 0);
  assert.equal(s.by_type.PORT_SCAN, 2);
  assert.equal(s.by_type.SYN_FLOOD, 1);
  assert.equal(s.by_mitre.length, 1);
  assert.equal(s.by_mitre[0].technique_id, 'T1046');
  assert.equal(s.by_mitre[0].count, 4);
  assert.ok(s.top_src_ips.some((t) => t.ip === '203.0.113.5'));
});

test('AlertStore (memory): summary on empty store', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  const s = await store.summary();
  assert.equal(s.total, 0);
  assert.deepEqual(s.by_severity, { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
});
