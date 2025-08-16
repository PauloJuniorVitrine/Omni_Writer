import { useEffect, useRef } from 'react';

/**
 * Hook para integração com Server-Sent Events (SSE).
 * @param url URL do endpoint SSE
 * @param onMessage Callback para cada mensagem recebida
 * @example
 * useSSE('/api/status', (msg) => { ... });
 */
export function useSSE(url: string, onMessage: (data: any) => void) {
  const eventSourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    eventSourceRef.current = new EventSource(url);
    eventSourceRef.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onMessage(data);
      } catch {
        onMessage(event.data);
      }
    };
    return () => {
      eventSourceRef.current?.close();
    };
  }, [url, onMessage]);
} 