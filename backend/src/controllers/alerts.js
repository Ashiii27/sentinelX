/**
 * Alert API controllers — thin wrappers over the AlertStore that
 * translate HTTP results (status codes, error shapes).
 */
'use strict';

async function listAlerts(req, res, next) {
  try {
    const query = { ...req.query };
    for (const field of ['from', 'to']) {
      if (query[field] !== undefined && !Number.isFinite(Date.parse(query[field]))) {
        return res.status(400).json({ error: `${field} must be a valid date` });
      }
    }
    if (query.from && query.to && Date.parse(query.from) > Date.parse(query.to)) {
      return res.status(400).json({ error: 'from must be before or equal to to' });
    }
    for (const field of ['reviewed', 'false_positive']) {
      if (query[field] !== undefined && !['true', 'false', '1', '0'].includes(query[field])) {
        return res.status(400).json({ error: `${field} must be true or false` });
      }
    }
    const { items, total, page, limit } = await req.app.locals.store.list(query);
    res.json({ items, total, page, limit });
  } catch (err) {
    next(err);
  }
}

async function getAlert(req, res, next) {
  try {
    const alert = await req.app.locals.store.get(req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'alert not found', id: req.params.id });
    }
    res.json(alert);
  } catch (err) {
    next(err);
  }
}

async function updateAlertTriage(req, res, next) {
  try {
    const body = req.body || {};
    const patch = {};
    for (const field of ['false_positive', 'reviewed']) {
      if (body[field] !== undefined && typeof body[field] !== 'boolean') {
        return res.status(400).json({ error: `${field} must be boolean` });
      }
    }
    if (body.false_positive !== undefined) {
      patch.false_positive = body.false_positive;
    }
    if (body.reviewed !== undefined) {
      patch.reviewed = body.reviewed;
    }
    if (Object.keys(patch).length === 0) {
      return res
        .status(400)
        .json({ error: 'nothing to update — send false_positive and/or reviewed' });
    }
    const alert = await req.app.locals.store.updateTriage(req.params.id, patch);
    if (!alert) {
      return res.status(404).json({ error: 'alert not found', id: req.params.id });
    }
    res.json(alert);
  } catch (err) {
    next(err);
  }
}

async function deleteAlert(req, res, next) {
  try {
    const ok = await req.app.locals.store.remove(req.params.id);
    if (!ok) {
      return res.status(404).json({ error: 'alert not found', id: req.params.id });
    }
    res.status(204).end();
  } catch (err) {
    next(err);
  }
}

module.exports = { listAlerts, getAlert, updateAlertTriage, deleteAlert };
