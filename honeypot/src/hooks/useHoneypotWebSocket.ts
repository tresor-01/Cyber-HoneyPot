import { useEffect, useRef, useCallback, useState } from "react";
import type { ActivityLog, Threat, ServiceStat, FullStats } from "@/lib/api";

const WS_URL = (import.meta.env.VITE_API_URL ?? "http://localhost:8000")
  .replace(/^http/, "ws") + "/ws";

export type WsStatus = "connecting" | "connected" | "disconnected";

export interface HoneypotState {
  active: boolean;
  logs: ActivityLog[];
  threats: Threat[];
  services: ServiceStat[];
  stats: FullStats | null;
  wsStatus: WsStatus;
}

interface UseHoneypotWebSocket {
  state: HoneypotState;
  toggleActive: (next: boolean) => void;
}

const MAX_LOGS    = 50;
const MAX_THREATS = 30;

export function useHoneypotWebSocket(): UseHoneypotWebSocket {
  const [state, setState] = useState<HoneypotState>({
    active:   true,
    logs:     [],
    threats:  [],
    services: [],
    stats:    null,
    wsStatus: "connecting",
  });

  const wsRef        = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    setState(s => ({ ...s, wsStatus: "connecting" }));
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      setState(s => ({ ...s, wsStatus: "connected" }));
    };

    ws.onclose = () => {
      setState(s => ({ ...s, wsStatus: "disconnected" }));
      // Reconnect after 3 seconds
      reconnectRef.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws.close();
    };

    ws.onmessage = (ev: MessageEvent) => {
      try {
        const msg = JSON.parse(ev.data as string);
        handleMessage(msg);
      } catch {/* ignore parse errors */}
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function handleMessage(msg: Record<string, unknown>) {
    switch (msg.event) {
      case "initial_state":
        setState(s => ({
          ...s,
          active:   (msg.active as boolean) ?? s.active,
          logs:     (msg.logs as ActivityLog[])     ?? [],
          threats:  (msg.threats as Threat[])       ?? [],
          services: (msg.services as ServiceStat[]) ?? [],
        }));
        break;

      case "activity_log":
        setState(s => ({
          ...s,
          logs: [msg.data as ActivityLog, ...s.logs].slice(0, MAX_LOGS),
        }));
        break;

      case "threat":
        setState(s => ({
          ...s,
          threats: [msg.data as Threat, ...s.threats].slice(0, MAX_THREATS),
        }));
        break;

      case "service_update":
        setState(s => ({
          ...s,
          services: s.services.map(sv =>
            sv.service_id === (msg.data as ServiceStat).service_id
              ? (msg.data as ServiceStat)
              : sv
          ),
        }));
        break;

      case "stats":
        setState(s => ({ ...s, stats: msg.data as FullStats }));
        break;

      case "honeypot_toggle":
        setState(s => ({ ...s, active: msg.active as boolean }));
        break;
    }
  }

  useEffect(() => {
    connect();
    return () => {
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  // Ping every 20s to keep connection alive
  useEffect(() => {
    const id = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send("ping");
      }
    }, 20_000);
    return () => clearInterval(id);
  }, []);

  const toggleActive = useCallback(async (next: boolean) => {
    const { api } = await import("@/lib/api");
    try {
      if (next) {
        await api.startHoneypot();
      } else {
        await api.stopHoneypot();
      }
      setState(s => ({ ...s, active: next }));
    } catch {
      // WebSocket event will update state anyway
    }
  }, []);

  return { state, toggleActive };
}
