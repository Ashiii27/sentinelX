/**
 * KillChain — Cyber Kill Chain activity view.
 *
 * Counts come from the backend summary's `by_kill_chain` aggregation
 * (alerts carry `mitre.kill_chain_phase`). Stages with no activity
 * render dim; active stages are highlighted.
 */
import React from 'react';
import { KILL_CHAIN_PHASES } from '../common.jsx';

export default function KillChain({ byKillChain = {}, emptyText = 'No kill chain activity recorded yet.' }) {
  const counts = KILL_CHAIN_PHASES.map(
    (phase) => byKillChain[phase] || 0
  );
  const total = counts.reduce((a, b) => a + b, 0);

  if (!total) return <div className="empty">{emptyText}</div>;

  return (
    <div className="killchain">
      {KILL_CHAIN_PHASES.map((phase, i) => (
        <React.Fragment key={phase}>
          {i > 0 && <span className="kc-arrow">▸</span>}
          <div className={`kc-stage${counts[i] ? ' active' : ''}`} title={`${phase}: ${counts[i]}`}>
            <div className="phase">{phase}</div>
            <div className={`count ${counts[i] ? 'hit' : 'zero'}`}>{counts[i] || '·'}</div>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}
