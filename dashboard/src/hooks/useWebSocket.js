/**
 * useWebSocket — subscribes a component to the live alert stream.
 *
 *   const { status } = useWebSocket({
 *     onAlert: (alert) => setFeed(...),
 *     onHistory: (alerts) => setFeed(...),
 *   });
 *
 * `status` ∈ 'connecting' | 'open' | 'reconnecting'
 * Callbacks are kept in refs so re-renders never drop the subscription.
 */
import { useEffect, useRef, useState } from 'react';
import { getLiveSocket } from '../services/socket.js';

export function useWebSocket({ onAlert = null, onHistory = null } = {}) {
  const [status, setStatus] = useState('connecting');

  const socket = useRef(null);
  const onAlertRef = useRef(onAlert);
  const onHistoryRef = useRef(onHistory);
  onAlertRef.current = onAlert;
  onHistoryRef.current = onHistory;

  useEffect(() => {
    if (!socket.current) socket.current = getLiveSocket();
    const s = socket.current;

    const offs = [
      s.on('connecting', () => setStatus('connecting')),
      s.on('open', () => setStatus('open')),
      s.on('reconnecting', () => setStatus('reconnecting')),
      s.on('message', (msg) => {
        if (msg.type === 'history' && onHistoryRef.current) {
          onHistoryRef.current(msg.data || []);
        } else if (msg.type === 'alert' && onAlertRef.current) {
          // The server sends { alert, clients } for live messages.
          onAlertRef.current(msg.data && msg.data.alert ? msg.data.alert : msg.data);
        }
      }),
    ];

    return () => offs.forEach((off) => off());
  }, []);

  return { status };
}

export default useWebSocket;
