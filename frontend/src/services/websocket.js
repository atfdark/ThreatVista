import { useEffect, useRef, useState } from 'react';

// Live feed URL. Prefer VITE_API_BASE_URL when set; otherwise use the current
// page host so Vite's /ws proxy works on localhost and LAN IPs alike.
function resolveWsUrl() {
  const envBase = import.meta.env.VITE_API_BASE_URL;
  if (envBase) {
    // Relative API bases (the normal Vite `/api` proxy) need the current
    // page origin; absolute bases are converted directly to ws/wss.
    if (envBase.startsWith('/')) {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${proto}//${window.location.host}${envBase.replace(/\/api$/, '')}/ws`;
    }
    return envBase.replace(/\/api$/, '').replace(/^http/, 'ws') + '/ws';
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${window.location.host}/ws`;
}

const WS_URL = resolveWsUrl();

/**
 * Connects to the ThreatVista WebSocket once and stays connected for the
 * lifetime of the component.
 *
 * The message handler is kept in a ref so a new inline-arrow callback on every
 * render does NOT tear down and reopen the socket (which previously leaked a
 * flood of connections to the backend).
 */
export function useWebSocket(onMessage) {
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef(null);
  const onMessageRef = useRef(onMessage);

  // Always point at the latest handler without reconnecting.
  onMessageRef.current = onMessage;

  useEffect(() => {
    let socket = null;
    try {
      socket = new WebSocket(WS_URL);
      wsRef.current = socket;

      socket.onopen = () => {
        setIsConnected(true);
        console.log('[WS] Connected to ThreatVista backend');
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onMessageRef.current) onMessageRef.current(data);
        } catch (e) {
          console.error('[WS] Failed to parse message', e);
        }
      };

      socket.onclose = () => {
        setIsConnected(false);
        console.log('[WS] Disconnected');
      };

      socket.onerror = (error) => {
        console.error('[WS] Error', error);
        setIsConnected(false);
      };
    } catch (e) {
      console.error('[WS] Failed to connect', e);
    }

    return () => {
      if (socket) {
        socket.close();
      }
      if (wsRef.current === socket) {
        wsRef.current = null;
      }
    };
  }, []); // connect once on mount

  return { isConnected, ws: wsRef.current };
}
