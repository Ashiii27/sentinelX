/**
 * Tests for the optional GeoLite2 enrichment service.
 *
 * No real .mmdb is needed: the reader factory is injectable, so these
 * tests verify enable/disable logic, record mapping, and failure
 * tolerance. The real mmdb-lib path is exercised by the factory default
 * (covered by the missing-file test, which never reaches mmdb-lib).
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const os = require('os');
const fs = require('fs');

const { createGeoIPEnricher } = require('../src/services/geoip');
const { AlertStore } = require('../src/services/AlertStore');
const { EngineIngestion } = require('../src/services/EngineIngestion');

const GEO_RECORD = {
  city: { geoname_id: 470, names: { en: 'Ashburn' } },
  country: { iso_code: 'US', names: { en: 'United States' } },
  location: { latitude: 39.0438, longitude: -77.4874 },
  asn: 'AS15169',
};

test('disabled when no mmdb path is configured', async () => {
  const e = await createGeoIPEnricher({ mmdbPath: '' });
  assert.strictEqual(e.enabled, false);
  assert.strictEqual(await e.lookup('203.0.113.1'), null);
});

test('disabled when the file is missing (never throws)', async () => {
  const missing = path.join(os.tmpdir(), `no-such-${Date.now()}.mmdb`);
  const e = await createGeoIPEnricher({ mmdbPath: missing });
  assert.strictEqual(e.enabled, false);
  assert.strictEqual(await e.lookup('203.0.113.1'), null);
});

test('maps a GeoLite2 record to the geo shape', async () => {
  const tmp = path.join(os.tmpdir(), `fake-${Date.now()}.mmdb`);
  fs.writeFileSync(tmp, 'fake');
  try {
    const e = await createGeoIPEnricher({
      mmdbPath: tmp,
      readerFactory: () => ({
        get: async (ip) => (ip === '203.0.113.7' ? GEO_RECORD : undefined),
      }),
    });
    assert.strictEqual(e.enabled, true);

    const geo = await e.lookup('203.0.113.7');
    assert.deepStrictEqual(geo, {
      country: 'US',
      city: 'Ashburn',
      lat: 39.0438,
      lon: -77.4874,
      asn: 'AS15169',
    });

    // Unknown IP (reader returns undefined) → null
    assert.strictEqual(await e.lookup('198.51.100.99'), null);
  } finally {
    fs.unlinkSync(tmp);
  }
});

test('lookup failures are swallowed (never reject)', async () => {
  const tmp = path.join(os.tmpdir(), `fake2-${Date.now()}.mmdb`);
  fs.writeFileSync(tmp, 'fake');
  try {
    const e = await createGeoIPEnricher({
      mmdbPath: tmp,
      readerFactory: () => ({
        get: async () => {
          throw new Error('boom');
        },
      }),
    });
    assert.strictEqual(e.enabled, true);
    assert.strictEqual(await e.lookup('203.0.113.1'), null);
  } finally {
    fs.unlinkSync(tmp);
  }
});

test('enriched geo lands on alerts through ingestion', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sx-geo-'));
  const socketPath = path.join(dir, 'alerts.sock');
  const net = require('net');

  const store = new AlertStore({ useMongo: false, cap: 100 });
  const enricher = {
    enabled: true,
    lookup: async (ip) =>
      ip === '203.0.113.77'
        ? { country: 'RU', city: null, lat: 55.7, lon: 37.6, asn: 'AS13238' }
        : null,
  };
  const ingestion = new EngineIngestion({
    socketPath,
    store,
    stream: null,
    enricher,
  });
  await ingestion.start();

  const client = net.connect(socketPath);
  await new Promise((r) => client.once('connect', r));
  client.write(
    JSON.stringify({
      alert_id: 'geo-1',
      timestamp: new Date().toISOString(),
      severity: 'HIGH',
      type: 'PORT_SCAN',
      src_ip: '203.0.113.77',
      dst_ip: '192.168.1.100',
      src_port: 1,
      dst_port: 22,
      protocol: 'TCP',
      tcp_flags: 2,
      mitre: {
        technique_id: 'T1046',
        tactic: 'Discovery',
        kill_chain_phase: 'Reconnaissance',
      },
      evidence: {},
      yara_match: null,
      raw_payload_hash: null,
      description: 'geo test',
      false_positive: false,
      reviewed: false,
    }) + '\n'
  );
  await new Promise((r) => setTimeout(r, 150));
  client.destroy();
  ingestion.stop();

  const alert = await store.get('geo-1');
  assert.ok(alert, 'alert stored');
  assert.deepStrictEqual(alert.geo, {
    country: 'RU',
    city: null,
    lat: 55.7,
    lon: 37.6,
    asn: 'AS13238',
  });
});

test('summary exposes by_kill_chain counts', async () => {
  const store = new AlertStore({ useMongo: false, cap: 100 });
  const base = {
    severity: 'HIGH',
    type: 'PORT_SCAN',
    src_ip: '203.0.113.1',
    dst_ip: '192.168.1.100',
    src_port: 1,
    dst_port: 22,
    protocol: 'TCP',
    tcp_flags: 2,
    yara_match: null,
    raw_payload_hash: null,
    description: '',
    false_positive: false,
    reviewed: false,
    timestamp: new Date().toISOString(),
  };
  await store.add({ ...base, alert_id: 'kc-1', mitre: { technique_id: 'T1046', tactic: 'Discovery', kill_chain_phase: 'Reconnaissance' } });
  await store.add({ ...base, alert_id: 'kc-2', mitre: { technique_id: 'T1046', tactic: 'Discovery', kill_chain_phase: 'Reconnaissance' } });
  await store.add({ ...base, alert_id: 'kc-3', mitre: { technique_id: 'T1498.001', tactic: 'Impact', kill_chain_phase: 'Impact' } });

  const s = await store.summary();
  assert.deepStrictEqual(s.by_kill_chain, { Reconnaissance: 2, Impact: 1 });
});
