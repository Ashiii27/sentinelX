/**
 * Alert persistence layer with a single interface over two backends:
 *
 *   - MongoDB (Mongoose)        — primary, when reachable
 *   - In-memory ring buffer     — degraded fallback, when Mongo is down
 *
 * The rest of the backend only talks to this store, so "is Mongo up?"
 * never leaks into route handlers.
 *
 * In-memory semantics:
 *   - capped at `cap` alerts (oldest by timestamp evicted first)
 *   - dedupe on alert_id (engine replays may deliver duplicates)
 *   - add() resolves { stored, isNew }; isNew=false means duplicate
 */
'use strict';

/** Build a Mongo query filter from API query params (shared with summary). */
function mongoFilterFromParams(params) {
  const f = {};
  if (params.severity) {
    f.severity = String(params.severity).toUpperCase();
  }
  if (params.type) {
    f.type = String(params.type).toUpperCase();
  }
  if (params.src_ip) f.src_ip = params.src_ip;
  if (params.dst_ip) f.dst_ip = params.dst_ip;
  if (params.technique) f['mitre.technique_id'] = params.technique;
  if (params.reviewed !== undefined) {
    f.reviewed = params.reviewed === 'true' || params.reviewed === '1';
  }
  if (params.false_positive !== undefined) {
    f.false_positive =
      params.false_positive === 'true' || params.false_positive === '1';
  }
  const time = {};
  if (params.from) time.$gte = new Date(params.from);
  if (params.to) time.$lte = new Date(params.to);
  if (Object.keys(time).length) f.timestamp = time;
  return f;
}

function memFilterFromParams(items, params) {
  const f = mongoFilterFromParams(params);
  return items.filter((a) => {
    if (f.severity && a.severity !== f.severity) return false;
    if (f.type && a.type !== f.type) return false;
    if (f.src_ip && a.src_ip !== f.src_ip) return false;
    if (f.dst_ip && a.dst_ip !== f.dst_ip) return false;
    if (f['mitre.technique_id'] &&
        a.mitre.technique_id !== f['mitre.technique_id']) return false;
    if (f.reviewed !== undefined && a.reviewed !== f.reviewed) return false;
    if (f.false_positive !== undefined &&
        a.false_positive !== f.false_positive) return false;
    if (f.timestamp) {
      const t = new Date(a.timestamp).getTime();
      if (f.timestamp.$gte && t < new Date(f.timestamp.$gte).getTime()) return false;
      if (f.timestamp.$lte && t > new Date(f.timestamp.$lte).getTime()) return false;
    }
    return true;
  });
}

class AlertStore {
  /**
   * @param {object} opts
   * @param {boolean} opts.useMongo  whether Mongo is connected
   * @param {object}  opts.mongoModel  Mongoose Alert model
   * @param {number}  [opts.cap]  in-memory capacity
   */
  constructor({ useMongo, mongoModel, cap = 20000 }) {
    this.useMongo = useMongo;
    this.Model = mongoModel;
    this.cap = cap;

    // In-memory state: Map<alert_id, doc> + array in insertion order.
    this.mem = new Map();
    this.memOrder = [];
  }

  /**
   * Persist one alert (engine NDJSON object, snake_case).
   * @returns {Promise<{stored: boolean, isNew: boolean}>}
   */
  async add(alert) {
    if (!alert || !alert.alert_id) {
      return { stored: false, isNew: false };
    }

    if (this.useMongo) {
      // $setOnInsert keeps the FIRST occurrence authoritative; duplicate
      // alert_ids (replay of the same capture) are no-ops.
      const res = await this.Model.updateOne(
        { alert_id: alert.alert_id },
        { $setOnInsert: this._mongoDoc(alert) },
        { upsert: true }
      );
      const isNew = res.upsertedCount === 1;
      return { stored: true, isNew };
    }

    if (this.mem.has(alert.alert_id)) {
      return { stored: true, isNew: false };
    }
    const doc = { ...alert, created_at: new Date() };
    this.mem.set(alert.alert_id, doc);
    this.memOrder.push(alert.alert_id);
    if (this.mem.size > this.cap) {
      // Evict oldest (insertion order ≈ arrival order).
      const old = this.memOrder.shift();
      this.mem.delete(old);
    }
    return { stored: true, isNew: true };
  }

  /**
   * Query alerts with filters + pagination.
   * @returns {Promise<{items: object[], total: number, page: number, limit: number}>}
   */
  async list(params = {}) {
    const page = Math.max(1, parseInt(params.page || '1', 10) || 1);
    const limit = Math.min(
      500,
      Math.max(1, parseInt(params.limit || '50', 10) || 50)
    );

    if (this.useMongo) {
      const filter = mongoFilterFromParams(params);
      const sort =
        params.sort === 'oldest'
          ? { timestamp: 1 }
          : { timestamp: -1 };
      const [items, total] = await Promise.all([
        this.Model.find(filter)
          .sort(sort)
          .skip((page - 1) * limit)
          .limit(limit),
        this.Model.countDocuments(filter),
      ]);
      return { items: items.map((d) => d.toObject()), total, page, limit };
    }

    const all = memFilterFromParams(this.memOrder.map((id) => this.mem.get(id)), params);
    all.sort((a, b) =>
      params.sort === 'oldest'
        ? new Date(a.timestamp) - new Date(b.timestamp)
        : new Date(b.timestamp) - new Date(a.timestamp)
    );
    const total = all.length;
    const items = all.slice((page - 1) * limit, page * limit);
    return { items, total, page, limit };
  }

  /** Fetch a single alert by its alert_id. */
  async get(alertId) {
    if (this.useMongo) {
      const doc = await this.Model.findOne({ alert_id: alertId });
      return doc ? doc.toObject() : null;
    }
    const doc = this.mem.get(alertId);
    return doc ? { ...doc } : null;
  }

  /**
   * Update triage fields.
   * @param {object} patch { false_positive?, reviewed? }
   * @returns {Promise<object|null>} the updated alert (null if missing)
   */
  async updateTriage(alertId, patch) {
    if (this.useMongo) {
      const set = {};
      if (patch.false_positive !== undefined) set.false_positive = !!patch.false_positive;
      if (patch.reviewed !== undefined) set.reviewed = !!patch.reviewed;
      const doc = await this.Model.findOneAndUpdate(
        { alert_id: alertId },
        { $set: set },
        { new: true }
      );
      return doc ? doc.toObject() : null;
    }
    const doc = this.mem.get(alertId);
    if (!doc) return null;
    if (patch.false_positive !== undefined) doc.false_positive = !!patch.false_positive;
    if (patch.reviewed !== undefined) doc.reviewed = !!patch.reviewed;
    doc.updated_at = new Date();
    return { ...doc };
  }

  /** Delete an alert (analyst cleanup). @returns {Promise<boolean>} */
  async remove(alertId) {
    if (this.useMongo) {
      const res = await this.Model.deleteOne({ alert_id: alertId });
      return res.deletedCount === 1;
    }
    if (!this.mem.has(alertId)) return false;
    this.mem.delete(alertId);
    const i = this.memOrder.indexOf(alertId);
    if (i !== -1) this.memOrder.splice(i, 1);
    return true;
  }

  /** Most recent N alerts, newest first (for WS history on connect). */
  async recent(n = 50) {
    if (this.useMongo) {
      const docs = await this.Model.find().sort({ timestamp: -1 }).limit(n);
      return docs.map((d) => d.toObject());
    }
    const ids = [...this.memOrder];
    const items = ids.map((id) => this.mem.get(id));
    items.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return items.slice(0, n);
  }

  /**
   * Dashboard summary (all computed, no filters).
   */
  async summary() {
    if (this.useMongo) {
      const now = Date.now();
      const dayAgo = new Date(now - 24 * 3600 * 1000);

      const [bySeverity, byType, byMitre, byKc, byHour, total, topIps] =
        await Promise.all([
          this.Model.aggregate([
            { $group: { _id: '$severity', count: { $sum: 1 } } },
          ]),
          this.Model.aggregate([
            { $group: { _id: '$type', count: { $sum: 1 } } },
          ]),
          this.Model.aggregate([
            { $group: { _id: '$mitre.technique_id', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ]),
          this.Model.aggregate([
            { $group: { _id: '$mitre.kill_chain_phase', count: { $sum: 1 } } },
          ]),
          this.Model.aggregate([
            { $match: { timestamp: { $gte: dayAgo } } },
            {
              $group: {
                _id: { $dateTrunc: { date: '$timestamp', unit: 'hour' } },
                count: { $sum: 1 },
              },
            },
            { $sort: { _id: 1 } },
          ]),
          this.Model.countDocuments({}),
          this.Model.aggregate([
            { $group: { _id: '$src_ip', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ]),
        ]);

      return this._shapeSummary(
        bySeverity, byType, byMitre, byKc, byHour, total, topIps
      );
    }

    // ── In-memory aggregation ────────────────────────────────────────────
    const items = this.memOrder.map((id) => this.mem.get(id));
    const bySeverity = {};
    const byType = {};
    const byMitre = {};
    const byKc = {};
    const byHourMap = new Map();
    const byIp = {};
    const now = Date.now();

    for (const a of items) {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      byType[a.type] = (byType[a.type] || 0) + 1;
      const tech = a.mitre && a.mitre.technique_id;
      if (tech) byMitre[tech] = (byMitre[tech] || 0) + 1;
      const kc = a.mitre && a.mitre.kill_chain_phase;
      if (kc) byKc[kc] = (byKc[kc] || 0) + 1;
      byIp[a.src_ip] = (byIp[a.src_ip] || 0) + 1;

      const t = new Date(a.timestamp).getTime();
      if (t >= now - 24 * 3600 * 1000) {
        const hour = new Date(t);
        hour.setMinutes(0, 0, 0);
        byHourMap.set(hour.toISOString(), (byHourMap.get(hour.toISOString()) || 0) + 1);
      }
    }

    return this._shapeSummary(
      Object.entries(bySeverity).map(([k, v]) => ({ _id: k, count: v })),
      Object.entries(byType).map(([k, v]) => ({ _id: k, count: v })),
      Object.entries(byMitre)
        .map(([k, v]) => ({ _id: k, count: v }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10),
      Object.entries(byKc).map(([k, v]) => ({ _id: k, count: v })),
      [...byHourMap.entries()].map(([h, c]) => ({ _id: h, count: c })),
      items.length,
      Object.entries(byIp)
        .map(([k, v]) => ({ _id: k, count: v }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
    );
  }

  /** Convert raw aggregate results into the stable API shape. */
  _shapeSummary(bySeverity, byType, byMitre, byKillChain, byHour, total, topIps) {
    const severity = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const row of bySeverity || []) {
      if (row._id in severity) severity[row._id] = row.count;
    }
    const type = {};
    for (const row of byType || []) type[row._id] = row.count;
    const killChain = {};
    for (const row of byKillChain || []) {
      if (row._id) killChain[row._id] = row.count;
    }
    return {
      total,
      by_severity: severity,
      by_type: type,
      by_kill_chain: killChain,
      by_mitre: (byMitre || []).map((r) => ({
        technique_id: r._id,
        count: r.count,
      })),
      hourly_24h: (byHour || []).map((r) => ({
        hour: new Date(r._id).toISOString(),
        count: r.count,
      })),
      top_src_ips: (topIps || []).map((r) => ({
        ip: r._id,
        count: r.count,
      })),
    };
  }

  /** Mongo document shape from an engine alert object. */
  _mongoDoc(alert) {
    return {
      alert_id: alert.alert_id,
      timestamp: new Date(alert.timestamp),
      severity: alert.severity,
      type: alert.type,
      src_ip: alert.src_ip,
      dst_ip: alert.dst_ip,
      src_port: alert.src_port ?? 0,
      dst_port: alert.dst_port ?? 0,
      protocol: alert.protocol,
      tcp_flags: alert.tcp_flags ?? 0,
      mitre: alert.mitre ?? {},
      evidence: alert.evidence ?? {},
      yara_match: alert.yara_match ?? null,
      raw_payload_hash: alert.raw_payload_hash ?? null,
      description: alert.description ?? '',
      false_positive: !!alert.false_positive,
      reviewed: !!alert.reviewed,
    };
  }
}

module.exports = { AlertStore, mongoFilterFromParams };
