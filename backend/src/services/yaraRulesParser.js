/**
 * Minimal YARA rule file parser for the dashboard's rule manager.
 *
 * This is NOT a YARA compiler — it extracts just what the UI needs:
 * rule name, meta fields (severity/mitre/description/...), and a rough
 * string count. Full validation happens in the engine at load time
 * (which skips broken files and reports why — see engine logs).
 *
 * Handles the rule shape used by SentinelX rules:
 *
 *   rule my_rule {
 *       meta:
 *           severity = "HIGH"
 *           mitre    = "T1059"
 *       strings:
 *           $a = { 90 90 }
 *           $b = "text"
 *       condition:
 *           $a
 *   }
 */
'use strict';

/**
 * @param {string} content  .yar file text
 * @param {string} filename
 * @returns {Array<{name, meta, string_count, line}>}
 */
function parseRules(content, filename) {
  const rules = [];
  const lines = content.split('\n');

  let current = null;
  let section = null; // 'meta' | 'strings' | 'condition' | null

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // ── Rule start: "rule NAME {  (tags supported: rule tag NAME {) ──
    const start = trimmed.match(/^rule\s+([\w$]+)/);
    if (start) {
      current = {
        name: start[1],
        file: filename,
        meta: {},
        string_count: 0,
        line: i + 1,
      };
      rules.push(current);
      section = null;
      continue;
    }

    // ── Rule end: first standalone "}" closes the current rule ────────
    if (trimmed === '}' && current) {
      current = null;
      section = null;
      continue;
    }
    if (!current) continue;

    // ── Section headers ─────────────────────────────────────────────────
    if (/^(meta|strings|condition)\s*:\s*$/.test(trimmed)) {
      section = trimmed.replace(':', '').trim();
      continue;
    }

    // ── Meta key = value ────────────────────────────────────────────────
    if (section === 'meta') {
      const m = trimmed.match(/^([\w$]+)\s*=\s*(.+)$/);
      if (m) {
        current.meta[m[1]] = unquote(m[2]);
      }
      continue;
    }

    // ── String identifiers ($name = ...) — count them ──────────────────
    if (section === 'strings') {
      if (/^\$[\w]+\s*(=|$)/.test(trimmed)) current.string_count += 1;
    }
  }

  return rules;
}

function unquote(v) {
  const t = v.trim().replace(/;.*$/, '').trim(); // strip trailing comments
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1);
  }
  return t;
}

module.exports = { parseRules };
