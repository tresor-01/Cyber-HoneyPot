/**
 * REST API client for the honeypot backend.
 */

const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export interface ActivityLog {
  id: number;
  timestamp: string;
  event_type: "connection" | "authentication" | "command" | "file_access" | "disconnection";
  service: string;
  source_ip: string;
  source_port: number | null;
  details: string;
  success: boolean;
  raw_data: string | null;
}

export interface Threat {
  id: number;
  timestamp: string;
  type: "brute_force" | "port_scan" | "malware" | "ddos" | "injection";
  source_ip: string;
  target_service: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  details: string | null;
}

export interface ServiceStat {
  service_id: string;
  total_connections: number;
  failed_auths: number;
  commands_captured: number;
  last_activity: string | null;
  status: "active" | "inactive" | "compromised";
  port: number;
}

export interface HoneypotStats {
  total_connections: number;
  blocked_attacks: number;
  active_threats: number;
  services_running: number;
}

export interface SystemStats {
  cpu_percent: number;
  memory_percent: number;
  network_bytes_sent: number;
  network_bytes_recv: number;
}

export interface FullStats {
  honeypot: HoneypotStats;
  system: SystemStats;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  getStats:         ()     => request<FullStats>("/api/stats"),
  getLogs:          (limit = 50, offset = 0) =>
    request<ActivityLog[]>(`/api/logs?limit=${limit}&offset=${offset}`),
  getThreats:       (limit = 50, offset = 0) =>
    request<Threat[]>(`/api/threats?limit=${limit}&offset=${offset}`),
  getServices:      ()     => request<ServiceStat[]>("/api/services"),
  getStatus:        ()     => request<{ active: boolean }>("/api/honeypot/status"),
  startHoneypot:    ()     => request<{ active: boolean }>("/api/honeypot/start", { method: "POST" }),
  stopHoneypot:     ()     => request<{ active: boolean }>("/api/honeypot/stop", { method: "POST" }),
};
