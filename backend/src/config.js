/**
 * Centralized environment configuration for the SentinelX backend.
 *
 * Every tunable lives here so the rest of the codebase never reads
 * process.env directly — easier to test and to audit.
 */
'use strict';

const path = require('path');

require('dotenv').config({
  path: path.join(__dirname, '..', '.env'),
});

function intFromEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

const config = {
  /** REST + WebSocket listen port */
  port: intFromEnv('PORT', 4000),

  /** CORS: "*" or comma-separated origin list */
  corsOrigin: process.env.CORS_ORIGIN || '*',

  /** MongoDB connection string (in-memory fallback when unreachable) */
  mongoUri: process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/sentinelx',

  /** Unix socket path the C++ engine connects to for alert delivery */
  engineSocket: process.env.ENGINE_SOCKET || '/run/sentinelx/alerts.sock',

  /** YARA rules directory (file-based rule management + engine source) */
  rulesDir:
    process.env.RULES_DIR ||
    path.join(__dirname, '..', '..', 'engine', 'rules'),

  /** Engine PID file, used by the rules hot-reload endpoint */
  enginePidFile:
    process.env.ENGINE_PID_FILE || '/run/sentinelx/sentinelx.pid',

  /** In-memory alert ring buffer capacity (degraded mode) */
  memoryAlertCap: intFromEnv('MEMORY_ALERT_CAP', 20000),

  /** How many recent alerts new WebSocket clients receive on connect */
  wsHistoryCount: intFromEnv('WS_HISTORY_COUNT', 50),

  /** Optional GeoLite2-City .mmdb path for Threat Map geo-IP enrichment.
   *  Empty = enrichment disabled (alerts flow through untouched). */
  geoipMmdb: process.env.GEOIP_MMDB || '',
};

module.exports = config;
