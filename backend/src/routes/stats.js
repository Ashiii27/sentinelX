/**
 * /api/stats — dashboard aggregates.
 */
'use strict';

const express = require('express');
const ctrl = require('../controllers/stats');

const router = express.Router();

// GET /api/stats/summary
router.get('/summary', ctrl.summary);

module.exports = router;
