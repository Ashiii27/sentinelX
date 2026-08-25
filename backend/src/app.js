/**
 * SentinelX backend — entry point.
 *
 * Wires together:
 *   - MongoDB (Mongoose) or in-memory fallback      (src/db.js)
 *   - Alert store abstraction                        (services/AlertStore)
 *   - Engine ingestion over the Unix socket          (services/EngineIngestion)
 *   - REST API                                       (routes/*)
 *   - WebSocket live alert stream                    (websocket/AlertStream)
 *
 * Run:  npm start            (uses .env)
 * Test: npm test             (in-memory mode, ephemeral ports)
 */
'use strict';

const http = require('http');
const express = require('express');
const cors = require('cors');

const config = require('./config');
const { connectDB, disconnectDB } = require('./db');
const AlertModel = require('./models/Alert');
const SessionModel = require('./models/Session');
const { AlertStore } = require('./services/AlertStore');
const { EngineIngestion } = require('./services/EngineIngestion');
const { createGeoIPEnricher } = require('./services/geoip');
const { AlertStream } = require('./websocket/AlertStream');

/**
 * Build the full application.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.startIngestion=true] listen on the engine socket
 * @param {string}  [opts.mongoUri]            override config
 * @param {string}  [opts.engineSocket]        override config
 * @param {string}  [opts.geoipMmdb]           override config ("" = disabled)
 * @returns {Promise<{app, server, store, ingestion, stream, dbConnected, enricher}>}
 */
async function createServer(opts = {}) {
  const mongoUri = opts.mongoUri ?? config.mongoUri;
  const engineSocket = opts.engineSocket ?? config.engineSocket;
  const startIngestion = opts.startIngestion !== false;
  const geoipMmdb = opts.geoipMmdb ?? config.geoipMmdb;

  // Optional GeoLite2 enrichment — disabled (no-op) unless a .mmdb is
  // configured and readable.
  const enricher = await createGeoIPEnricher({ mmdbPath: geoipMmdb });

  // ── Database (with graceful in-memory fallback) ───────────────────────
  const dbConnected = await connectDB(mongoUri);
  const store = new AlertStore({
    useMongo: dbConnected,
    mongoModel: AlertModel,
    cap: config.memoryAlertCap,
  });

  // ── Live stream ───────────────────────────────────────────────────────
  const stream = new AlertStream({
    historyCount: config.wsHistoryCount,
    store,
  });

  // ── Express app ───────────────────────────────────────────────────────
  const app = express();
  app.disable('x-powered-by');
  app.use(
    cors({
      origin:
        config.corsOrigin === '*' ? true : config.corsOrigin.split(','),
    })
  );
  app.use(express.json({ limit: '1mb' }));

  // Minimal request logging (method, path, status, ms) — useful in a
  // security product, deliberately dependency-free.
  app.use((req, res, next) => {
    const t0 = Date.now();
    res.on('finish', () => {
      if (req.path.startsWith('/api/')) {
        console.log(
          `[http] ${req.method} ${req.originalUrl} → ${res.statusCode} (${Date.now() - t0}ms)`
        );
      }
    });
    next();
  });

  // Shared services, reachable from controllers via req.app.locals.
  app.locals.store = store;
  app.locals.stream = stream;
  app.locals.rulesDir = config.rulesDir;
  app.locals.enginePidFile = config.enginePidFile;
  app.locals.dbConnected = dbConnected;

  // ── REST API ──────────────────────────────────────────────────────────
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'sentinelx-backend',
      version: '1.0.0',
      db: dbConnected ? 'mongodb' : 'in-memory',
      engine: app.locals.ingestion ? app.locals.ingestion.stats : null,
      geoip: { enabled: enricher.enabled },
      ws: stream.stats(),
      uptime_seconds: Math.round(process.uptime()),
    });
  });

  app.use('/api/alerts', require('./routes/alerts'));
  app.use('/api/stats', require('./routes/stats'));
  app.use('/api/rules', require('./routes/rules'));

  // 404 for unknown /api routes (JSON, not HTML)
  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'not found', path: req.originalUrl });
  });

  // Central error handler — keeps the stack off the client, JSON shape.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status || 500;
    if (status >= 500) {
      console.error('[http] error:', err);
    }
    if (res.headersSent) return;
    res.status(status).json({
      error: status >= 500 ? 'internal server error' : err.message,
    });
  });

  // ── HTTP server + WebSocket attach ────────────────────────────────────
  const server = http.createServer(app);
  stream.attach(server);

  // ── Engine ingestion ──────────────────────────────────────────────────
  let ingestion = null;
  if (startIngestion) {
    ingestion = new EngineIngestion({
      socketPath: engineSocket,
      store,
      stream,
      enricher,
    });
    await ingestion.start();
    app.locals.ingestion = ingestion;
  }

  return { app, server, store, ingestion, stream, dbConnected, enricher };
}

// ── Direct execution: npm start ─────────────────────────────────────────
if (require.main === module) {
  let shuttingDown = false;

  async function gracefulShutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n[server] ${signal} received — shutting down`);
    try {
      const { server, store, ingestion, stream, dbConnected } = state;
      if (ingestion) ingestion.stop();
      stream.close();
      await new Promise((resolve) => server.close(resolve));
      if (dbConnected) await disconnectDB();
      console.log('[server] shutdown complete');
      process.exit(0);
    } catch (err) {
      console.error('[server] shutdown error:', err.message);
      process.exit(1);
    }
  }

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

  const state = {};

  (async () => {
    try {
      const parts = await createServer();
      Object.assign(state, parts);
      parts.server.listen(config.port, () => {
        console.log('');
        console.log('  SentinelX backend');
        console.log('  ─────────────────────────────────────────────');
        console.log(`  REST API     http://localhost:${config.port}/api`);
        console.log(`  WebSocket    ws://localhost:${config.port}/ws`);
        console.log(`  Engine socket ${config.engineSocket}`);
        console.log(`  Database     ${parts.dbConnected ? 'MongoDB' : 'in-memory (fallback)'}`);
        console.log(`  Geo-IP       ${parts.enricher.enabled ? 'enabled (GeoLite2)' : 'disabled (set GEOIP_MMDB)'}`);
        console.log(`  Rules dir    ${config.rulesDir}`);
        console.log('  ─────────────────────────────────────────────');
        console.log('');
      });
    } catch (err) {
      console.error('[server] fatal startup error:', err);
      process.exit(1);
    }
  })();
}

module.exports = { createServer };
