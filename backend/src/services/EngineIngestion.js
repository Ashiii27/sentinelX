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

    this.stats = {
      connected: false,
      connections: 0,
      alerts: 0,
      duplicates: 0,
      malformed: 0,
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

      this._handleAlert(alert);
    }

    // Guard against a runaway buffer (no newlines at all — protocol
    // violation or binary garbage).
    if (this.buffer.length > 1024 * 1024) {
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

module.exports = { EngineIngestion };
