/**
 * YARA rule management controllers.
 *
 * Rules are FILES in the engine's rules directory (single source of
 * truth — the engine loads exactly what's on disk). The backend
 * provides CRUD over those files plus a hot-reload trigger:
 *
 *   GET    /api/rules            list rules (name, file, parsed meta)
 *   GET    /api/rules/:name      one rule's file content
 *   POST   /api/rules            create a rule file  { filename, content }
 *   PUT    /api/rules/:name      update rule content
 *   DELETE /api/rules/:name      remove rule file
 *   POST   /api/rules/reload     send SIGUSR1 to the engine (hot reload)
 *
 * File writes are atomic (write to .tmp then rename) so the engine can
 * never read a half-written rule during a reload.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { parseRules } = require('../services/yaraRulesParser');

const FILENAME_RE = /^[a-z0-9][a-z0-9_\-]*\.(yar|yara)$/i;
const MAX_RULE_SIZE = 1024 * 1024; // 1 MB is plenty for a YARA file

function rulesDir(req) {
  return req.app.locals.rulesDir;
}

function ruleFilePath(req, name) {
  // Accept "shellcode_patterns" or "shellcode_patterns.yar".
  let base = String(name);
  if (!base.endsWith('.yar') && !base.endsWith('.yara')) base += '.yar';
  const resolved = path.resolve(rulesDir(req), base);
  if (!resolved.startsWith(path.resolve(rulesDir(req)) + path.sep)) {
    throw Object.assign(new Error('invalid rule name'), { status: 400 });
  }
  return resolved;
}

async function listRules(req, res, next) {
  try {
    const dir = rulesDir(req);
    if (!fs.existsSync(dir)) {
      return res.json({
        directory: dir,
        rules: [],
        note: 'rules directory does not exist yet',
      });
    }
    const files = fs
      .readdirSync(dir)
      .filter((f) => f.endsWith('.yar') || f.endsWith('.yara'))
      .sort();

    const rules = [];
    for (const file of files) {
      const content = fs.readFileSync(path.join(dir, file), 'utf8');
      for (const rule of parseRules(content, file)) {
        rules.push(rule);
      }
    }
    res.json({ directory: dir, rules });
  } catch (err) {
    next(err);
  }
}

async function getRule(req, res, next) {
  try {
    const file = ruleFilePath(req, req.params.name);
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: 'rule not found', name: req.params.name });
    }
    const content = fs.readFileSync(file, 'utf8');
    const parsed = parseRules(content, path.basename(file));
    res.json({
      name: path.basename(file),
      content,
      rules: parsed,
    });
  } catch (err) {
    next(err);
  }
}

async function createRule(req, res, next) {
  try {
    const { filename, content } = req.body || {};
    if (!filename || !FILENAME_RE.test(filename)) {
      return res
        .status(400)
        .json({ error: 'filename must match ^[a-z0-9_-]+.(yar|yara)$' });
    }
    if (typeof content !== 'string' || content.length === 0) {
      return res.status(400).json({ error: 'content must be a non-empty string' });
    }
    if (Buffer.byteLength(content, 'utf8') > MAX_RULE_SIZE) {
      return res.status(400).json({ error: 'rule file too large (max 1 MB)' });
    }
    const dir = rulesDir(req);
    const target = path.resolve(dir, filename);
    if (!target.startsWith(path.resolve(dir) + path.sep)) {
      return res.status(400).json({ error: 'invalid path' });
    }
    if (fs.existsSync(target)) {
      return res.status(409).json({ error: 'rule file already exists', filename });
    }
    fs.mkdirSync(dir, { recursive: true });
    atomicWrite(target, content);
    res.status(201).json({
      filename,
      rules: parseRules(content, filename),
      note: 'saved — POST /api/rules/reload to load it into the running engine',
    });
  } catch (err) {
    next(err);
  }
}

async function updateRule(req, res, next) {
  try {
    const file = ruleFilePath(req, req.params.name);
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: 'rule not found', name: req.params.name });
    }
    const { content } = req.body || {};
    if (typeof content !== 'string' || content.length === 0) {
      return res.status(400).json({ error: 'content must be a non-empty string' });
    }
    if (Buffer.byteLength(content, 'utf8') > MAX_RULE_SIZE) {
      return res.status(400).json({ error: 'rule file too large (max 1 MB)' });
    }
    atomicWrite(file, content);
    res.json({
      filename: path.basename(file),
      rules: parseRules(content, path.basename(file)),
      note: 'saved — POST /api/rules/reload to load it into the running engine',
    });
  } catch (err) {
    next(err);
  }
}

async function deleteRule(req, res, next) {
  try {
    const file = ruleFilePath(req, req.params.name);
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: 'rule not found', name: req.params.name });
    }
    fs.unlinkSync(file);
    res.status(204).end();
  } catch (err) {
    next(err);
  }
}

/**
 * Ask the running engine to hot-reload its YARA rules (SIGUSR1).
 * Requires the engine to write a PID file (deployment/sentinelx.service
 * does; the dev run of `sentinelx` does not).
 */
async function reloadRules(req, res, next) {
  try {
    const pidFile = req.app.locals.enginePidFile;
    if (!fs.existsSync(pidFile)) {
      return res.json({
        reloaded: false,
        detail: `no engine pid file at ${pidFile} — restart the engine to pick up rule changes`,
      });
    }
    const pid = parseInt(fs.readFileSync(pidFile, 'utf8').trim(), 10);
    if (!Number.isFinite(pid) || pid <= 0) {
      return res.json({ reloaded: false, detail: 'invalid pid file contents' });
    }
    try {
      process.kill(pid, 'SIGUSR1');
    } catch (err) {
      if (err.code === 'ESRCH') {
        return res.json({
          reloaded: false,
          detail: `engine pid ${pid} not running`,
        });
      }
      throw err;
    }
    res.json({
      reloaded: true,
      detail: `SIGUSR1 sent to engine pid ${pid} — rules reload in place`,
    });
  } catch (err) {
    next(err);
  }
}

/** Write atomically: tmp file in same dir + rename (no partial reads). */
function atomicWrite(target, content) {
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, target);
}

module.exports = {
  listRules,
  getRule,
  createRule,
  updateRule,
  deleteRule,
  reloadRules,
};
