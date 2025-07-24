import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Server, Wifi, Database, Globe, Lock, HardDrive } from "lucide-react";

interface Service {
  id: string;
  name: string;
  port: number;
  status: "active" | "inactive" | "compromised";
  icon: any;
  connections: number;
  lastActivity: string;
}

interface ServiceMonitorProps {
  isActive: boolean;
}

export const ServiceMonitor = ({ isActive }: ServiceMonitorProps) => {
  const [services, setServices] = useState<Service[]>([
    {
      id: "ssh",
      name: "SSH Server",
      port: 22,
      status: "active",
      icon: Lock,
      connections: 0,
      lastActivity: "2 min ago"
    },
    {
      id: "http",
      name: "HTTP Server",
      port: 80,
      status: "active",
      icon: Globe,
      connections: 0,
      lastActivity: "1 min ago"
    },
    {
      id: "ftp",
      name: "FTP Server",
      port: 21,
      status: "active",
      icon: HardDrive,
      connections: 0,
      lastActivity: "5 min ago"
    },
    {
      id: "telnet",
      name: "Telnet",
      port: 23,
      status: "active",
      icon: Server,
      connections: 0,
      lastActivity: "3 min ago"
    },
    {
      id: "mysql",
      name: "MySQL",
      port: 3306,
      status: "active",
      icon: Database,
      connections: 0,
      lastActivity: "7 min ago"
    },
    {
      id: "smtp",
      name: "SMTP",
      port: 25,
      status: "active",
      icon: Wifi,
      connections: 0,
      lastActivity: "4 min ago"
    }
  ]);

  // Simulate random activity
  useEffect(() => {
    if (!isActive) return;

    const interval = setInterval(() => {
      setServices(prev => prev.map(service => {
        const shouldUpdate = Math.random() > 0.7;
        if (shouldUpdate) {
          const newConnections = Math.floor(Math.random() * 5);
          const statuses: Service["status"][] = ["active", "active", "active", "compromised"];
          const newStatus = statuses[Math.floor(Math.random() * statuses.length)];
          
          return {
            ...service,
            connections: newConnections,
            status: newConnections > 3 ? "compromised" : newStatus,
            lastActivity: "Just now"
          };
        }
        return service;
      }));
    }, 4000);

    return () => clearInterval(interval);
  }, [isActive]);

  const getStatusVariant = (status: Service["status"]) => {
    switch (status) {
      case "active": return "active";
      case "compromised": return "threat";
      case "inactive": return "secondary";
      default: return "secondary";
    }
  };

  return (
    <Card className="neon-border">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-5 w-5 text-primary" />
          Service Monitor
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {services.map((service) => {
          const IconComponent = service.icon;
          return (
            <div key={service.id} className="flex items-center justify-between p-3 rounded border border-border bg-muted/20">
              <div className="flex items-center gap-3">
                <IconComponent className={`h-4 w-4 ${service.status === 'compromised' ? 'text-destructive' : 'text-primary'}`} />
                <div>
                  <div className="terminal-text font-medium text-sm">{service.name}</div>
                  <div className="terminal-text text-xs text-muted-foreground">Port {service.port}</div>
                </div>
              </div>
              <div className="text-right space-y-1">
                <Badge variant={getStatusVariant(service.status)} className="text-xs">
                  {service.status.toUpperCase()}
                </Badge>
                <div className="terminal-text text-xs text-muted-foreground">
                  {service.connections} conn
                </div>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
};