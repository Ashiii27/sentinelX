/**
 * LiveSocket — WebSocket client for the SentinelX real-time stream.
 *
 * Protocol (server → client):
 *   { type: 'hello',   data: { service, clients } }
 *   { type: 'history', data: [alert, ...] }        // on connect
 *   { type: 'alert',   data: { alert, clients } }  // live alerts
 *   { type: 'clients', data: { clients } }
 *
 * Auto-reconnects with capped exponential backoff. The browser code
 * always connects to its OWN origin (/ws on location.host) — the dev
 * proxy (Vite) or production proxy (nginx) forwards it to the backend.
 */
import { EventEmitter } from './events.js';

export class LiveSocket extends EventEmitter {
  constructor(path = '/ws') {
    super();
    this.path = path;
    this.closedByUser = false;
    this.attempts = 0;
    this.ws = null;
    this._reconnectTimer = null;
  }

  get url() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${window.location.host}${this.path}`;
  }

  get isOpen() {
    return !!this.ws && this.ws.readyState === WebSocket.OPEN;
  }

  connect() {
    this.closedByUser = false;
    this._open();
    return this;
  }

  _open() {
    this.emit('connecting');
    let ws;
    try {
      ws = new WebSocket(this.url);
    } catch (err) {
      this._scheduleReconnect();
      return;
    }
    this.ws = ws;

    ws.onopen = () => {
      this.attempts = 0;
      this.emit('open');
    };

    ws.onmessage = (ev) => {
      let msg;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return; // non-JSON frame — ignore
      }
      this.emit('message', msg);
      this.emit(msg.type, msg.data);
    };

    ws.onclose = () => {
      this.ws = null;
      this.emit('close');
      if (!this.closedByUser) this._scheduleReconnect();
    };

    ws.onerror = () => {
      // onclose follows; nothing to do here.
    };
  }

  _scheduleReconnect() {
    if (this.closedByUser) return;
    this.attempts += 1;
    const delay = Math.min(15000, 1000 * 2 ** Math.min(this.attempts, 4));
    this.emit('reconnecting', { attempt: this.attempts, delay });
    clearTimeout(this._reconnectTimer);
    this._reconnectTimer = setTimeout(() => this._open(), delay);
  }

  close() {
    this.closedByUser = true;
    clearTimeout(this._reconnectTimer);
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.close();
      this.ws = null;
    }
  }
}

let shared = null;

/**
 * One shared socket per page (the backend caps per-client history;
 * many components should not each open their own connection).
 */
export function getLiveSocket() {
  if (!shared) {
    shared = new LiveSocket().connect();
  }
  return shared;
}
