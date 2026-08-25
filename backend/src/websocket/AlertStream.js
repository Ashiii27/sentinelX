/**
 * AlertStream — the real-time layer: one WebSocket per dashboard client
 * receiving live alert broadcasts (plus a history replay on connect so
 * a refreshed tab doesn't lose the last few minutes).
 *
 * Wire protocol (all messages JSON, one per WS frame):
 *
 *   server → client:
 *     { "type": "hello",   "data": { "clients": 3, "time": "..." } }
 *     { "type": "history", "data": [ alert, alert, ... ] }   // ≤ N recent
 *     { "type": "alert",   "data": { ...alert json... } }    // live alert
 *     { "type": "stats",   "data": { "clients": 3 } }        // on join/leave
 *
 *   client → server:
 *     (v1 is read-only; ping/pong keepalive is handled by ws)
 */
'use strict';

const { WebSocketServer } = require('ws');

class AlertStream {
  /**
   * @param {object} opts
   * @param {number} [opts.historyCount] alerts to replay on connect
   * @param {object} [opts.store] AlertStore (source of history)
   */
  constructor({ historyCount = 50, store = null }) {
    this.historyCount = historyCount;
    this.store = store;
    this.wss = null;
    this.clients = new Set();
    this.sessionId = 0;
  }

  /** Attach to the HTTP server and start handling upgrades on /ws. */
  attach(server, path = '/ws') {
    this.wss = new WebSocketServer({ server, path });

    this.wss.on('connection', (ws, req) => {
      this.sessionId += 1;
      const id = `ws-${Date.now().toString(36)}-${this.sessionId}`;
      ws.sentinelxSession = {
        id,
        ip: req.socket.remoteAddress || '',
        user_agent: req.headers['user-agent'] || '',
        connected_at: new Date(),
      };
      ws.isAlive = true;
      this.clients.add(ws);

      // hello + history (history is async via the store).
      this._send(ws, 'hello', {
        clients: this.clients.size,
        time: new Date().toISOString(),
      });
      if (this.store) {
        this.store
          .recent(this.historyCount)
          .then((items) => this._send(ws, 'history', items))
          .catch((err) => console.error('[ws] history fetch failed:', err.message));
      }

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('close', () => {
        this.clients.delete(ws);
        this._announce();
      });

      ws.on('error', (err) => {
        this.clients.delete(ws);
        if (err.code !== 'ECONNRESET') {
          console.error('[ws] client error:', err.message);
        }
      });

      this._announce();
    });

    // Periodic liveness sweep: drop dead clients (hung tabs, NAT
    // timeouts) so `clients` stays honest.
    this.pingTimer = setInterval(() => {
      for (const ws of this.clients) {
        if (!ws.isAlive) {
          ws.terminate();
          this.clients.delete(ws);
          continue;
        }
        ws.isAlive = false;
        try {
          ws.ping();
        } catch {
          /* socket already closing */
        }
      }
    }, 30000);
    this.pingTimer.unref();

    console.log(`[ws] WebSocket server attached at ${path}`);
  }

  /**
   * Broadcast a live alert to all connected clients.
   * No-op (and safe) when no clients are connected.
   */
  broadcast(alert) {
    if (!this.wss || this.clients.size === 0) return 0;
    let n = 0;
    const payload = JSON.stringify({ type: 'alert', data: alert });
    for (const ws of this.clients) {
      if (ws.readyState === ws.OPEN) {
        ws.send(payload);
        n += 1;
      }
    }
    return n;
  }

  /** Tell clients the connection count changed (they render a badge). */
  _announce() {
    if (this.clients.size === 0) return;
    const payload = JSON.stringify({
      type: 'stats',
      data: { clients: this.clients.size },
    });
    for (const ws of this.clients) {
      if (ws.readyState === ws.OPEN) ws.send(payload);
    }
  }

  _send(ws, type, data) {
    if (ws.readyState !== ws.OPEN) return;
    ws.send(JSON.stringify({ type, data }));
  }

  /** @returns {{clients: number, wss: boolean}} */
  stats() {
    return { clients: this.clients.size, attached: !!this.wss };
  }

  close() {
    if (this.pingTimer) clearInterval(this.pingTimer);
    for (const ws of this.clients) {
      try {
        ws.close(1001, 'server shutting down');
      } catch {
        /* already closed */
      }
    }
    this.clients.clear();
    if (this.wss) {
      this.wss.close();
      this.wss = null;
    }
  }
}

module.exports = { AlertStream };
