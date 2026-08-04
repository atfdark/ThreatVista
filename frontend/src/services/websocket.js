import { useEffect, useRef, useState } from 'react';

const WS_URL = 'ws://127.0.0.1:8000/ws';

export function useWebSocket(onMessage) {
  const [isConnected, setIsConnected] = useState(false);
  const ws = useRef(null);

  useEffect(() => {
    try {
      ws.current = new WebSocket(WS_URL);

      ws.current.onopen = () => {
        setIsConnected(true);
        console.log('[WS] Connected to ThreatVista backend');
      };

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (onMessage) onMessage(data);
        } catch (e) {
          console.error('[WS] Failed to parse message', e);
        }
      };

      ws.current.onclose = () => {
        setIsConnected(false);
        console.log('[WS] Disconnected');
      };

      ws.current.onerror = (error) => {
        console.error('[WS] Error', error);
        setIsConnected(false);
      };
    } catch (e) {
      console.error('[WS] Failed to connect', e);
    }

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [onMessage]);

  return { isConnected, ws: ws.current };
}
