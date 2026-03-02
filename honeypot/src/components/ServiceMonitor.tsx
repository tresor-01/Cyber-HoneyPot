import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Server, Wifi, Database, Globe, Lock, HardDrive, Monitor, Eye, Layers, Cpu } from "lucide-react";
import type { ServiceStat } from "@/lib/api";

const SERVICE_META: Record<string, { name: string; icon: React.ElementType; standardPort: number }> = {
  ssh:        { name: "SSH Server",     icon: Lock,      standardPort: 22   },
  http:       { name: "HTTP Server",    icon: Globe,     standardPort: 80   },
  ftp:        { name: "FTP Server",     icon: HardDrive, standardPort: 21   },
  telnet:     { name: "Telnet",         icon: Server,    standardPort: 23   },
  mysql:      { name: "MySQL",          icon: Database,  standardPort: 3306 },
  smtp:       { name: "SMTP",           icon: Wifi,      standardPort: 25   },
  rdp:        { name: "RDP",            icon: Monitor,   standardPort: 3389 },
  vnc:        { name: "VNC",            icon: Eye,       standardPort: 5900 },
  redis:      { name: "Redis",          icon: Layers,    standardPort: 6379 },
  postgresql: { name: "PostgreSQL",     icon: Cpu,       standardPort: 5432 },
};

interface ServiceMonitorProps {
  services: ServiceStat[];
  isActive: boolean;
}

const formatLastActivity = (ts: string | null): string => {
  if (!ts) return "Never";
  const diff = Date.now() - new Date(ts + "Z").getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins} min ago`;
  return `${Math.floor(mins / 60)}h ago`;
};

export const ServiceMonitor = ({ services, isActive }: ServiceMonitorProps) => {
  const getStatusVariant = (status: string) => {
    switch (status) {
      case "active":      return "active";
      case "compromised": return "threat";
      default:            return "secondary";
    }
  };

  // If we have no services yet, show placeholders
  const rows: ServiceStat[] = services.length > 0
    ? services
    : Object.keys(SERVICE_META).map(id => ({
        service_id: id,
        total_connections: 0,
        failed_auths: 0,
        commands_captured: 0,
        last_activity: null,
        status: isActive ? "active" : "inactive",
        port: SERVICE_META[id].standardPort,
      }));

  return (
    <Card className="neon-border">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-5 w-5 text-primary" />
          Service Monitor
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.map((service) => {
          const meta        = SERVICE_META[service.service_id];
          const IconComponent = meta?.icon ?? Server;
          const displayPort = meta?.standardPort ?? service.port;
          const status      = isActive ? service.status : "inactive";
          return (
            <div key={service.service_id} className="flex items-center justify-between p-3 rounded border border-border bg-muted/20">
              <div className="flex items-center gap-3">
                <IconComponent className={`h-4 w-4 ${status === "compromised" ? "text-destructive" : status === "inactive" ? "text-muted-foreground" : "text-primary"}`} />
                <div>
                  <div className="terminal-text font-medium text-sm">{meta?.name ?? service.service_id}</div>
                  <div className="terminal-text text-xs text-muted-foreground">Port {displayPort}</div>
                </div>
              </div>
              <div className="text-right space-y-1">
                <Badge variant={getStatusVariant(status) as "active" | "threat" | "secondary"} className="text-xs">
                  {status.toUpperCase()}
                </Badge>
                <div className="terminal-text text-xs text-muted-foreground">
                  {service.total_connections} total · {formatLastActivity(service.last_activity)}
                </div>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};