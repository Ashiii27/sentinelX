/**
 * Mongoose model for persisted SentinelX alerts.
 *
 * Mirrors the engine's NDJSON alert schema 1:1 (see engine/README.md
 * "Alert JSON"). The engine is the source of truth for the shape; the
 * backend only persists, queries, and updates triage fields
 * (false_positive / reviewed).
 */
'use strict';

const mongoose = require('mongoose');

const { Schema } = mongoose;

const yaraMatchSchema = new Schema(
  {
    rule_name: { type: String, default: '' },
    rule_file: { type: String, default: '' },
    matched_strings: { type: [String], default: [] },
    payload_hash: { type: String, default: '' },
  },
  { _id: false }
);

const mitreSchema = new Schema(
  {
    technique_id: { type: String, default: '' },
    technique_name: { type: String, default: '' },
    tactic: { type: String, default: '' },
    kill_chain_phase: { type: String, default: '' },
    reference_url: { type: String, default: '' },
  },
  { _id: false }
);

const alertSchema = new Schema(
  {
    // ── Identity ────────────────────────────────────────────────────────
    alert_id: { type: String, required: true, unique: true },
    timestamp: { type: Date, required: true },

    // ── Classification ──────────────────────────────────────────────────
    severity: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      index: true,
    },
    type: {
      type: String,
      enum: ['PORT_SCAN', 'SYN_FLOOD', 'HTTP_ANOMALY', 'YARA_MATCH', 'HONEYPOT_HIT'],
      index: true,
    },

    // ── Network context (flattened, matching the engine schema) ─────────
    src_ip: { type: String, index: true },
    dst_ip: { type: String, index: true },
    src_port: { type: Number, default: 0 },
    dst_port: { type: Number, default: 0 },
    protocol: { type: String, default: '' },
    tcp_flags: { type: Number, default: 0 },

    // ── MITRE ATT&CK ────────────────────────────────────────────────────
    mitre: {
      type: mitreSchema,
      default: () => ({}),
    },

    // ── Evidence (detector-specific; shape varies by type) ──────────────
    evidence: { type: Schema.Types.Mixed, default: () => ({}) },

    // ── Signature match (null for non-YARA alerts) ──────────────────────
    yara_match: { type: yaraMatchSchema, default: null },
    raw_payload_hash: { type: String, default: null },

    // ── Summary ─────────────────────────────────────────────────────────
    description: { type: String, default: '' },

    // ── Triage (updated by analysts via the dashboard) ──────────────────
    false_positive: { type: Boolean, default: false, index: true },
    reviewed: { type: Boolean, default: false, index: true },
  },
  { timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' } }
);

// Useful compound + single-field indexes for the common dashboard queries.
alertSchema.index({ 'mitre.technique_id': 1 });
alertSchema.index({ timestamp: -1 });
alertSchema.index({ src_ip: 1, timestamp: -1 });
alertSchema.index({ severity: 1, timestamp: -1 });
alertSchema.index({ type: 1, timestamp: -1 });
// TTL: keep hot data, drop alerts older than 30 days (tune as needed).
alertSchema.index({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });

module.exports = mongoose.model('Alert', alertSchema);
