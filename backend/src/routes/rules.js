/**
 * /api/rules — YARA rule file CRUD + hot reload.
 */
'use strict';

const express = require('express');
const ctrl = require('../controllers/rules');

const router = express.Router();

// NOTE: /reload must be registered before /:name or "reload" would be
// treated as a rule name.
router.post('/reload', ctrl.reloadRules);

router.get('/', ctrl.listRules);
router.get('/:name', ctrl.getRule);
router.post('/', ctrl.createRule);
router.put('/:name', ctrl.updateRule);
router.delete('/:name', ctrl.deleteRule);

module.exports = router;
