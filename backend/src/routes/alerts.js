/**
 * /api/alerts — alert query + triage endpoints.
 */
'use strict';

const express = require('express');
const ctrl = require('../controllers/alerts');

const router = express.Router();

// GET /api/alerts?severity=&type=&src_ip=&dst_ip=&technique=&reviewed=
//                    &false_positive=&from=&to=&page=&limit=&sort=
router.get('/', ctrl.listAlerts);

// GET /api/alerts/:id
router.get('/:id', ctrl.getAlert);

// PUT /api/alerts/:id   { "false_positive": bool, "reviewed": bool }
router.put('/:id', ctrl.updateAlertTriage);

// DELETE /api/alerts/:id
router.delete('/:id', ctrl.deleteAlert);

module.exports = router;
