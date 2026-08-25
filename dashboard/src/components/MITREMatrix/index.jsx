/**
 * MITREMatrix — ATT&CK tactic heatmap.
 *
 * Instead of hardcoding thousands of techniques, the matrix is built
 * from what the engine has actually flagged: each alert carries
 * `mitre.technique_id` + `mitre.tactic`, so tactics light up as
 * detections of that tactic occur, with the observed techniques
 * listed as chips. Unseen tactics stay dimmed.
 */
import React, { useMemo } from 'react';
import { MITRE_TACTICS } from '../common.jsx';

export default function MITREMatrix({ alerts = [], byMitre = [], emptyText = 'No MITRE ATT&CK activity yet.' }) {
  const byTactic = useMemo(() => {
    const map = new Map();
    for (const a of alerts) {
      const tactic = a.mitre && a.mitre.tactic;
      const tech = a.mitre && a.mitre.technique_id;
      if (!tactic || !tech) continue;
      if (!map.has(tactic)) map.set(tactic, new Map());
      const techs = map.get(tactic);
      techs.set(tech, (techs.get(tech) || 0) + 1);
    }
    return map;
  }, [alerts]);

  const total = alerts.filter((a) => a.mitre && a.mitre.technique_id).length;
  if (!total) return <div className="empty">{emptyText}</div>;

  return (
    <div className="matrix">
      {MITRE_TACTICS.map((tactic) => {
        const techs = byTactic.get(tactic);
        const count = techs ? [...techs.values()].reduce((a, b) => a + b, 0) : 0;
        return (
          <div key={tactic} className={`tactic${count ? ' active' : ''}`}>
            <div className="name">
              <span>{tactic}</span>
              {count > 0 && <span className="count">{count}</span>}
            </div>
            <div className="techs">
              {techs
                ? [...techs.entries()]
                    .sort((a, b) => b[1] - a[1])
                    .map(([tech, n]) => (
                      <span key={tech} className="chip" title={`${tech} — ${n} alert(s)`}>
                        {tech} <span className="n">×{n}</span>
                      </span>
                    ))
                : <span className="muted" style={{ fontSize: 10 }}>—</span>}
            </div>
          </div>
        );
      })}
    </div>
  );
}
