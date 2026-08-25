/**
 * Stats API controllers.
 */
'use strict';

async function summary(req, res, next) {
  try {
    const data = await req.app.locals.store.summary();
    data.engine = req.app.locals.ingestion
      ? req.app.locals.ingestion.stats
      : null;
    data.ws = req.app.locals.stream ? req.app.locals.stream.stats() : null;
    data.db_mode = req.app.locals.store.useMongo ? 'mongodb' : 'in-memory';
    data.uptime_seconds = Math.round(process.uptime());
    res.json(data);
  } catch (err) {
    next(err);
  }
}

module.exports = { summary };
