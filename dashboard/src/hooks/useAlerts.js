/**
 * useAlerts — merged view of the alert store:
 *
 *   - initial + refetchable REST page (GET /alerts with filters)
 *   - live WebSocket alerts spliced in as they arrive
 *   - history replay on (re)connect
 *
 * Returns { alerts, total, loading, error, wsStatus, refresh }.
 * The local list is capped at `cap` (newest first, deduped by alert_id)
 * so a SYN flood can't grow memory without bound — pagination is the
 * way to reach older alerts.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import api from '../services/api.js';
import { apiError } from '../services/api.js';
import { useWebSocket } from './useWebSocket.js';

const DEFAULT_CAP = 500;

export function useAlerts(params = {}, { cap = DEFAULT_CAP } = {}) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const seen = useRef(new Set());

  const upsert = useCallback(
    (alert, { prepend = true } = {}) => {
      if (!alert || !alert.alert_id) return;
      if (seen.current.has(alert.alert_id)) return;
      seen.current.add(alert.alert_id);
      setAlerts((prev) =>
        prepend
          ? [alert, ...prev].slice(0, cap)
          : prev
      );
    },
    [cap]
  );

  const { status: wsStatus } = useWebSocket({
    onAlert: (alert) => upsert(alert),
    onHistory: (hist) =>
      hist
        .slice()
        .reverse()
        .forEach((a) => upsert(a, { prepend: false })),
  });

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    seen.current = new Set();
    try {
      const data = await api.alerts(params);
      setAlerts(data.items || []);
      setTotal(data.total || 0);
      (data.items || []).forEach((a) => seen.current.add(a.alert_id));
      setLastUpdated(new Date());
    } catch (err) {
      setError(apiError(err));
    } finally {
      setLoading(false);
    }
  }, [params]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return {
    alerts,
    total,
    loading,
    error,
    wsStatus,
    lastUpdated,
    refresh,
    upsert,
  };
}

export default useAlerts;
