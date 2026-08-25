/**
 * Small shared UI primitives (severity colors, panels, formatters)
 * used across dashboard components.
 */
import React from 'react';

export const SEVERITY_COLORS = {
  LOW: '#3fb950',
  MEDIUM: '#d29922',
  HIGH: '#f0883e',
  CRITICAL: '#f85149',
};

export const KILL_CHAIN_PHASES = [
  'Reconnaissance',
  'Weaponization',
  'Delivery',
  'Exploitation',
  'Installation',
  'Command & Control',
  'Actions on Objectives',
];

export const MITRE_TACTICS = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

export function SeverityBadge({ severity }) {
  const sev = String(severity || 'LOW').toUpperCase();
  return (
    <span className={`badge badge-${sev.toLowerCase()}`}>{sev}</span>
  );
}

export function Panel({ title, subtitle, right, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <header className="panel-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p className="panel-sub">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}

export function formatTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function formatDateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

export function flowText(alert) {
  if (!alert) return '';
  const port = `${alert.src_ip || '?'}:${alert.src_port ?? '?'}`;
  const to = `${alert.dst_ip || '?'}:${alert.dst_port ?? '?'}`;
  return `${port} → ${to} (${alert.protocol || '?'})`;
}
