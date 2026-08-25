/**
 * Tiny dependency-free EventEmitter (subset of Node's API) so the
 * socket client stays framework-agnostic.
 */
export class EventEmitter {
  constructor() {
    this._handlers = new Map();
  }

  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, new Set());
    this._handlers.get(event).add(fn);
    return () => this.off(event, fn);
  }

  off(event, fn) {
    this._handlers.get(event)?.delete(fn);
  }

  emit(event, ...args) {
    this._handlers.get(event)?.forEach((fn) => {
      try {
        fn(...args);
      } catch (err) {
        console.error(`[events] handler for "${event}" threw:`, err);
      }
    });
  }

  removeAllListeners(event) {
    if (event) this._handlers.delete(event);
    else this._handlers.clear();
  }
}
