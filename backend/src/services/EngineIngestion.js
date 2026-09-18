/**
 * EngineIngestion — reads alerts from the C++ engine over its Unix
 * socket and fans them out to the store + live WebSocket stream.
 *
 * The engine is a CLIENT of this socket (it connects to the path the
 * backend listens on). The engine may start after the backend, restart,
 * or drop, so this service:
 *   - listens on the configured socket path (creates/removes the file)
 *   - accepts an engine connection, then keeps the listener alive
 *   - accumulates partial frames and parses NDJSON line by line
 *   - stores each alert (deduped on alert_id) and broadcasts it live
 *
 * Malformed lines are counted and skipped — one corrupt frame must
 * never wedge ingestion.
 */
'use strict';

const net = require('net');
const fs = require('fs');
const { EventEmitter } = require('events');

const MAX_FRAME_BYTES = 1024 * 1024;
const SEVERITIES = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
const ALERT_TYPES = new Set([
  'PORT_SCAN',
  'SYN_FLOOD',
  'HTTP_ANOMALY',
  'YARA_MATCH',
  'HONEYPOT_HIT',
]);
const PROTOCOLS = new Set(['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'UNKNOWN']);

/**
 * Validate the engine-to-backend contract before any enrichment or storage.
 * JSON.parse only proves that a frame is syntactically JSON; accepting a
 * partial object would make bad input look like a real detection in the
 * dashboard and, with MongoDB enabled, can also fail asynchronously.
 *
 * @returns {{valid: boolean, error?: string}}
 */
function validateAlert(alert) {
  if (!alert || typeof alert !== 'object' || Array.isArray(alert)) {
    return { valid: false, error: 'alert must be a JSON object' };
  }

  const requiredStrings = [
    ['alert_id', 256],
    ['timestamp', 64],
    ['src_ip', 64],
    ['dst_ip', 64],
  ];
  for (const [field, max] of requiredStrings) {
    if (typeof alert[field] !== 'string' || alert[field].length === 0) {
      return { valid: false, error: `${field} must be a non-empty string` };
    }
    if (alert[field].length > max) {
      return { valid: false, error: `${field} exceeds ${max} characters` };
    }
  }

  if (!Number.isFinite(Date.parse(alert.timestamp))) {
    return { valid: false, error: 'timestamp must be an ISO-compatible date' };
  }
  if (net.isIP(alert.src_ip) === 0 || net.isIP(alert.dst_ip) === 0) {
    return { valid: false, error: 'src_ip and dst_ip must be valid IP addresses' };
  }
  if (!SEVERITIES.has(alert.severity)) {
    return { valid: false, error: 'severity is invalid' };
  }
  if (!ALERT_TYPES.has(alert.type)) {
    return { valid: false, error: 'type is invalid' };
  }
  if (!PROTOCOLS.has(alert.protocol)) {
    return { valid: false, error: 'protocol is invalid' };
  }

  for (const field of ['src_port', 'dst_port']) {
    if (!Number.isInteger(alert[field]) || alert[field] < 0 || alert[field] > 65535) {
      return { valid: false, error: `${field} must be an integer from 0 to 65535` };
    }
  }
  if (alert.protocol === 'TCP' && !Number.isInteger(alert.tcp_flags)) {
    return { valid: false, error: 'tcp_flags must be an integer for TCP alerts' };
  }
  if (alert.tcp_flags !== undefined &&
      (!Number.isInteger(alert.tcp_flags) || alert.tcp_flags < 0 || alert.tcp_flags > 255)) {
    return { valid: false, error: 'tcp_flags must be an integer from 0 to 255' };
  }
  if (!alert.mitre || typeof alert.mitre !== 'object' || Array.isArray(alert.mitre) ||
      typeof alert.mitre.technique_id !== 'string' || alert.mitre.technique_id.length === 0) {
    return { valid: false, error: 'mitre.technique_id is required' };
  }
  if (alert.evidence !== undefined &&
      (!alert.evidence || typeof alert.evidence !== 'object' || Array.isArray(alert.evidence))) {
    return { valid: false, error: 'evidence must be a JSON object' };
  }
  if (alert.description !== undefined &&
      (typeof alert.description !== 'string' || alert.description.length > 4096)) {
    return { valid: false, error: 'description must be a string of at most 4096 characters' };
  }
  for (const field of ['false_positive', 'reviewed']) {
    if (alert[field] !== undefined && typeof alert[field] !== 'boolean') {
      return { valid: false, error: `${field} must be boolean` };
    }
  }
  if (alert.yara_match !== undefined && alert.yara_match !== null &&
      (typeof alert.yara_match !== 'object' || Array.isArray(alert.yara_match))) {
    return { valid: false, error: 'yara_match must be an object or null' };
  }
  if (alert.raw_payload_hash !== undefined && alert.raw_payload_hash !== null &&
      typeof alert.raw_payload_hash !== 'string') {
    return { valid: false, error: 'raw_payload_hash must be a string or null' };
  }

  return { valid: true };
}

class EngineIngestion extends EventEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.socketPath  Unix socket path to listen on
   * @param {object} opts.store       AlertStore
   * @param {object} [opts.stream]    AlertStream (broadcasts live alerts)
   * @param {object} [opts.enricher]  GeoIP enricher ({ enabled, lookup })
   */
  constructor({ socketPath, store, stream = null, enricher = null }) {
    super();
    this.socketPath = socketPath;
    this.store = store;
    this.stream = stream;
    this.enricher = enricher || { enabled: false, lookup: async () => null };

    this.server = null;
    this.client = null;        // active engine connection (one at a time)
    this.running = false;
    this.buffer = '';
    // Keep frames in wire order. Geo-IP lookups and Mongo writes are async;
    // without a queue, a slow lookup could make the live feed reorder alerts.
    this.processing = Promise.resolve();

    this.stats = {
      connected: false,
      connections: 0,
      alerts: 0,
      duplicates: 0,
      malformed: 0,
      invalid: 0,
      failures: 0,
      last_alert_at: null,
    };
  }

  /** Start listening. Resolves when the socket is bound. */
  async start() {
    if (this.running) return;
    this.running = true;

    // Ensure the parent directory exists (e.g. /run/sentinelx on first
    // boot, /tmp in dev) and remove a stale socket file left by a
    // crashed backend — bind() would fail with EADDRINUSE on a dead
    // endpoint.
    fs.mkdirSync(require('path').dirname(this.socketPath), { recursive: true });
    try {
      fs.unlinkSync(this.socketPath);
    } catch {
      /* no stale file — fine */
    }

    await new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this._onEngineConnect(socket));
      this.server.once('error', reject);
      this.server.listen(this.socketPath, () => {
        this.server.removeListener('error', reject);
        this.server.on('error', (err) => {
          console.error('[ingestion] listener error:', err.message);
        });
        resolve();
      });
    });

    console.log(`[ingestion] listening on ${this.socketPath} (engine socket)`);
  }

  _onEngineConnect(socket) {
    // The engine connects as a client. Only one engine at a time — a
    // second connection replaces the first (an engine restart).
    if (this.client) {
      this.client.destroy();
      this.client = null;
    }
    this.client = socket;
    this.buffer = '';
    this.stats.connected = true;
    this.stats.connections += 1;
    this.emit('engine-connected');
    console.log(`[ingestion] engine connected (${socket.remoteAddress || 'unix'})`);

    socket.setEncoding('utf8');

    socket.on('data', (chunk) => this._onData(chunk));

    socket.on('close', () => {
      this.stats.connected = false;
      if (this.client === socket) this.client = null;
      this.emit('engine-disconnected');
      console.log('[ingestion] engine disconnected (waiting for reconnect)');
    });

    socket.on('error', (err) => {
      // ECONNRESET during engine shutdown is normal; log only if loud.
      if (err.code !== 'ECONNRESET') {
        console.error('[ingestion] engine socket error:', err.message);
      }
    });
  }

  _onData(chunk) {
    this.buffer += chunk;

    let nl;
    while ((nl = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, nl).trim();
      this.buffer = this.buffer.slice(nl + 1);
      if (!line) continue;

      if (Buffer.byteLength(line, 'utf8') > MAX_FRAME_BYTES) {
        this.stats.malformed += 1;
        continue;
      }

      let alert;
      try {
        alert = JSON.parse(line);
      } catch (err) {
        this.stats.malformed += 1;
        if (this.stats.malformed <= 3) {
          console.warn(
            `[ingestion] malformed line skipped: ${line.slice(0, 120)}`
          );
        }
        continue;
      }

      const validation = validateAlert(alert);
      if (!validation.valid) {
        this.stats.invalid += 1;
        this.stats.malformed += 1;
        if (this.stats.invalid <= 3) {
          console.warn(`[ingestion] invalid alert skipped: ${validation.error}`);
        }
        continue;
      }

      // Preserve NDJSON order and make storage failures observable instead
      // of creating unhandled promise rejections in the socket callback.
      this.processing = this.processing
        .then(() => this._handleAlert(alert))
        .catch((err) => {
          this.stats.failures += 1;
          console.error('[ingestion] alert handling failed:', err.message);
        });
    }

    // Guard against a runaway buffer (no newlines at all — protocol
    // violation or binary garbage).
    if (Buffer.byteLength(this.buffer, 'utf8') > MAX_FRAME_BYTES) {
      this.stats.malformed += 1;
      this.buffer = '';
    }
  }

  /** Store + broadcast one parsed alert. */
  async _handleAlert(alert) {
    // Optional GeoLite2 enrichment for the Threat Map. Never blocks
    // alert flow — any failure leaves `geo` as null.
    if (this.enricher && this.enricher.enabled) {
      try {
        alert.geo = (await this.enricher.lookup(alert.src_ip)) || null;
      } catch {
        alert.geo = null;
      }
    }

    const res = await this.store.add(alert);
    this.stats.last_alert_at = new Date().toISOString();
    if (res.isNew) {
      this.stats.alerts += 1;
      if (this.stream) this.stream.broadcast(alert);
      this.emit('alert', alert);
    } else {
      this.stats.duplicates += 1;
    }
  }

  /** Stop listening and close the engine connection. */
  stop() {
    this.running = false;
    if (this.client) {
      this.client.destroy();
      this.client = null;
    }
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    try {
      fs.unlinkSync(this.socketPath);
    } catch {
      /* already gone */
    }
    this.stats.connected = false;
  }
}

module.exports = { EngineIngestion, validateAlert };
