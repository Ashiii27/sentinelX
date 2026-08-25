/**
 * MongoDB connection with graceful degradation.
 *
 * SentinelX must stay useful even when no database is running (a first
 * install, a demo machine, CI). When Mongo is unreachable the backend
 * logs a clear warning and continues in in-memory mode: alerts are kept
 * in a bounded ring buffer, all REST endpoints keep working, and live
 * WebSocket streaming is unaffected. Persistence across restarts is the
 * only thing you lose.
 */
'use strict';

const mongoose = require('mongoose');

mongoose.set('strictQuery', true);

/**
 * @param {string} uri  MongoDB connection string
 * @returns {Promise<boolean>} true if connected, false if degraded
 */
async function connectDB(uri) {
  try {
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 3000,
      maxPoolSize: 10,
    });
    console.log(`[db] connected to MongoDB (${mongoose.connection.host})`);
    mongoose.connection.on('error', (err) => {
      console.error('[db] MongoDB error:', err.message);
    });
    mongoose.connection.on('disconnected', () => {
      console.warn('[db] MongoDB disconnected — queries will fail until reconnect');
    });
    return true;
  } catch (err) {
    console.warn(
      `[db] MongoDB unreachable at ${uri} (${err.codeName || err.code || err.message}) — ` +
        'running in IN-MEMORY mode (alerts will not survive a restart)'
    );
    return false;
  }
}

/** Disconnect cleanly on shutdown. */
async function disconnectDB() {
  if (mongoose.connection.readyState !== 0) {
    try {
      await mongoose.disconnect();
    } catch {
      /* already gone */
    }
  }
}

module.exports = { connectDB, disconnectDB, mongoose };
