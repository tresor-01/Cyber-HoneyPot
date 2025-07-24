import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ArrowRight, Clock } from "lucide-react";

interface LogEntry {
  id: string;
  timestamp: Date;
  event: "connection" | "authentication" | "command" | "file_access" | "disconnection";
  source: string;
  details: string;
  success: boolean;
}

export const ActivityLog = () => {
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const eventTypes = [
    { event: "connection", details: "New connection established", success: true },
    { event: "authentication", details: "Login attempt with credentials admin:admin", success: false },
    { event: "authentication", details: "Login attempt with credentials root:password", success: false },
    { event: "command", details: "Executed command: ls -la", success: true },
    { event: "command", details: "Executed command: cat /etc/passwd", success: true },
    { event: "file_access", details: "Attempted to access /etc/shadow", success: false },
    { event: "file_access", details: "Downloaded file: backup.zip", success: true },
    { event: "disconnection", details: "Connection terminated", success: true }
  ];

  const generateRandomIP = () => {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const generateLogEntry = (): LogEntry => {
    const eventType = eventTypes[Math.floor(Math.random() * eventTypes.length)];
    return {
      id: Math.random().toString(36).substr(2, 9),
      timestamp: new Date(),
      event: eventType.event as LogEntry["event"],
      source: generateRandomIP(),
      details: eventType.details,
      success: eventType.success
    };
  };

  useEffect(() => {
    // Add initial logs
    setLogs([generateLogEntry(), generateLogEntry(), generateLogEntry()]);

    const interval = setInterval(() => {
      if (Math.random() > 0.5) {
        setLogs(prev => [generateLogEntry(), ...prev.slice(0, 9)]);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const getEventColor = (event: LogEntry["event"]) => {
    switch (event) {
      case "connection": return "text-primary";
      case "authentication": return "text-warning";
      case "command": return "text-success";
      case "file_access": return "text-destructive";
      case "disconnection": return "text-muted-foreground";
      default: return "text-foreground";
    }
  };

  return (
    <Card className="neon-border">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-primary" />
          Activity Log
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {logs.length === 0 ? (
          <div className="text-center text-muted-foreground terminal-text py-8">
            No activity logged
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex items-start gap-3 p-3 rounded border border-border bg-muted/20">
              <Clock className="h-3 w-3 text-muted-foreground mt-1 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="terminal-text text-xs text-muted-foreground">
                    {log.timestamp.toLocaleTimeString()}
                  </span>
                  <Badge variant={log.success ? "success" : "destructive"} className="text-xs">
                    {log.event.toUpperCase()}
                  </Badge>
                </div>
                <div className="terminal-text text-sm mb-1">
                  {log.details}
                </div>
                <div className="flex items-center gap-1 terminal-text text-xs text-muted-foreground">
                  <span className="font-mono text-destructive">{log.source}</span>
                  <ArrowRight className="h-3 w-3" />
                  <span className="font-mono text-primary">honeypot.local</span>
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
};