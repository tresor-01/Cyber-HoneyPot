import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity, ArrowRight, Clock } from "lucide-react";
import type { ActivityLog as ActivityLogEntry } from "@/lib/api";

interface ActivityLogProps {
  logs: ActivityLogEntry[];
}

export const ActivityLog = ({ logs }: ActivityLogProps) => {

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
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                  <Badge variant={log.success ? "success" : "destructive"} className="text-xs">
                    {log.event_type.toUpperCase()}
                  </Badge>
                  <span className="terminal-text text-xs text-muted-foreground">[{log.service}]</span>
                </div>
                <div className="terminal-text text-sm mb-1">
                  {log.details}
                </div>
                <div className="flex items-center gap-1 terminal-text text-xs text-muted-foreground">
                  <span className="font-mono text-destructive">{log.source_ip}</span>
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