/**
 * YARARules — rule manager UI.
 *
 * The backend lists rules FLAT (one entry per rule, each tagged with
 * its source file); this component groups them by file so an analyst
 * sees the on-disk layout. Supports creating a new rule file, deleting
 * a file, and triggering an engine hot-reload (SIGUSR1 via
 * POST /api/rules/reload).
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import api, { apiError } from '../../services/api.js';
import { SeverityBadge } from '../common.jsx';

export default function YARARules() {
  const [directory, setDirectory] = useState('');
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  const [creating, setCreating] = useState(false);
  const [newFile, setNewFile] = useState('');
  const [newContent, setNewContent] = useState('');
  const [reloading, setReloading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.rules();
      setRules(data.rules || []);
      setDirectory(data.directory || '');
      setError(null);
    } catch (err) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Group flat rule list by source file (stable file order).
  const files = useMemo(() => {
    const map = new Map();
    for (const r of rules) {
      if (!map.has(r.file)) map.set(r.file, []);
      map.get(r.file).push(r);
    }
    return [...map.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([file, frules]) => ({ file, rules: frules }));
  }, [rules]);

  function flash(kind, text) {
    setNotice({ kind, text });
    setTimeout(() => setNotice(null), 5000);
  }

  async function handleCreate(e) {
    e.preventDefault();
    try {
      await api.createRule(newFile, newContent);
      flash('ok', `Rule file "${newFile}" created — hot-reload the engine to load it.`);
      setCreating(false);
      setNewFile('');
      setNewContent('');
      load();
    } catch (err) {
      flash('err', apiError(err));
    }
  }

  async function handleDelete(file) {
    if (!window.confirm(`Delete rule file ${file}?`)) return;
    try {
      await api.deleteRule(file);
      flash('ok', `Deleted ${file}.`);
      load();
    } catch (err) {
      flash('err', apiError(err));
    }
  }

  async function handleReload() {
    setReloading(true);
    try {
      const res = await api.reloadRules();
      flash(
        res.reloaded ? 'ok' : 'info',
        res.reloaded
          ? 'Engine signaled (SIGUSR1) — rules reloading.'
          : res.detail || 'No engine pid file found.'
      );
    } catch (err) {
      flash('err', apiError(err));
    } finally {
      setReloading(false);
    }
  }

  if (loading) return <div className="empty"><span className="spin" /> Loading rules…</div>;
  if (error) return <div className="msg err">{error}</div>;

  const totalRules = rules.length;

  return (
    <div>
      {notice && <div className={`msg ${notice.kind}`}>{notice.text}</div>}
      <div className="controls">
        <span className="muted" style={{ fontSize: 12 }}>
          {files.length} file(s), {totalRules} rule(s) — <span className="mono" title={directory}>{directory || '?'}</span>
        </span>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={() => setCreating((v) => !v)}>
          {creating ? 'Cancel' : '+ New rule file'}
        </button>
        <button className="btn primary" onClick={handleReload} disabled={reloading}>
          {reloading ? <span className="spin" /> : '⟳'} Hot-reload engine
        </button>
      </div>

      {creating && (
        <form onSubmit={handleCreate} style={{ marginBottom: 14 }}>
          <div className="controls">
            <label>File name (.yar)</label>
            <input
              type="text"
              value={newFile}
              onChange={(e) => setNewFile(e.target.value)}
              placeholder="my_rules.yar"
              required
              pattern="[a-zA-Z0-9._-]+\.ya?ra"
            />
          </div>
          <textarea
            value={newContent}
            onChange={(e) => setNewContent(e.target.value)}
            placeholder={'rule my_detection\n{\n  meta:\n    severity = "HIGH"\n    mitre = "T1059"\n  strings:\n    $a = "malicious string"\n  condition:\n    any of them\n}'}
            required
          />
          <div className="controls" style={{ marginTop: 8 }}>
            <button type="submit" className="btn primary">Save rule file</button>
            <span className="muted" style={{ fontSize: 11 }}>
              YARA syntax is validated by the engine at load time, not by the API.
            </span>
          </div>
        </form>
      )}

      {files.map((f) => (
        <div key={f.file} className="rule-file">
          <div style={{ minWidth: 0 }}>
            <div className="fname">{f.file}</div>
            <div className="meta">
              {f.rules.length} rule(s)
              {f.rules.map((r) => (
                <span key={r.name} title={`${r.name}${r.meta && r.meta.mitre ? ' → ' + r.meta.mitre : ''}`} style={{ marginLeft: 6 }}>
                  <span className="chip">{r.name}</span>
                </span>
              ))}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <SeverityBadge severity={highestSeverity(f.rules)} />
            <button className="btn danger" onClick={() => handleDelete(f.file)}>Delete</button>
          </div>
        </div>
      ))}
      {!files.length && <div className="empty">No rule files found.</div>}
    </div>
  );
}

function highestSeverity(rules) {
  const rank = { CRITICAL: 3, HIGH: 2, MEDIUM: 1, LOW: 0 };
  let worst = 'LOW';
  for (const r of rules) {
    const s = ((r.meta && r.meta.severity) || 'LOW').toUpperCase();
    if ((rank[s] || 0) > (rank[worst] || 0)) worst = s;
  }
  return worst;
}
