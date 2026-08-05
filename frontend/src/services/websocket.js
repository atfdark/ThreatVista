import { useEffect, useRef, useState } from 'react';

const WS_URL = 'ws://127.0.0.1:8000/ws';

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
