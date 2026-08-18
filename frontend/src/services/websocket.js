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
export function useWebSocket(onMessage, onReconnect = null) {
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('connecting'); // 'connected' | 'reconnecting' | 'disconnected'
  const wsRef = useRef(null);
  const onMessageRef = useRef(onMessage);
  const onReconnectRef = useRef(onReconnect);
  const reconnectTimeoutRef = useRef(null);
  const retryCountRef = useRef(0);
  const isUnmountedRef = useRef(false);

  // Always point at the latest handlers without reconnecting.
  onMessageRef.current = onMessage;
  onReconnectRef.current = onReconnect;

  useEffect(() => {
    isUnmountedRef.current = false;

    function connect() {
      if (isUnmountedRef.current) return;

      let socket = null;
      try {
        setConnectionStatus(retryCountRef.current === 0 ? 'connecting' : 'reconnecting');
        socket = new WebSocket(WS_URL);
        wsRef.current = socket;

        socket.onopen = () => {
          if (isUnmountedRef.current) return;
          setIsConnected(true);
          setConnectionStatus('connected');
          const wasReconnected = retryCountRef.current > 0;
          retryCountRef.current = 0;
          console.log('[WS] Connected to ThreatVista backend');

          if (wasReconnected && onReconnectRef.current) {
            try {
              onReconnectRef.current();
            } catch (err) {
              console.error('[WS] Reconnect sync error:', err);
            }
          }
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
          if (isUnmountedRef.current) return;
          setIsConnected(false);
          setConnectionStatus('reconnecting');
          scheduleReconnect();
        };

        socket.onerror = (error) => {
          if (isUnmountedRef.current) return;
          console.warn('[WS] Socket error, retrying...');
          setIsConnected(false);
          setConnectionStatus('reconnecting');
          if (socket) {
            socket.close();
          }
        };
      } catch (e) {
        if (!isUnmountedRef.current) {
          setIsConnected(false);
          setConnectionStatus('reconnecting');
          scheduleReconnect();
        }
      }
    }

    function scheduleReconnect() {
      if (isUnmountedRef.current) return;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }

      // Exponential backoff: 1s, 2s, 4s, up to max 8s
      const delay = Math.min(1000 * Math.pow(1.8, retryCountRef.current), 8000);
      retryCountRef.current += 1;

      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, delay);
    }

    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, []); // connect on mount and auto-manage lifecycle

  return { isConnected, connectionStatus, ws: wsRef.current };
}

