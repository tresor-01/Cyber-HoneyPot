import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Shield, Eye, Zap } from "lucide-react";
import type { Threat } from "@/lib/api";

interface ThreatFeedProps {
  threats: Threat[];
}

export const ThreatFeed = ({ threats }: ThreatFeedProps) => {

  const getSeverityVariant = (severity: Threat["severity"]) => {
    switch (severity) {
      case "critical": return "threat";
      case "high":     return "destructive";
      case "medium":   return "warning";
      case "low":      return "secondary";
      default:         return "secondary";
    }
  };

  const getSeverityIcon = (severity: Threat["severity"]) => {
    switch (severity) {
      case "critical": return <Zap className="h-3 w-3" />;
      case "high":     return <AlertTriangle className="h-3 w-3" />;
      case "medium":   return <Eye className="h-3 w-3" />;
      case "low":      return <Shield className="h-3 w-3" />;
      default:         return <Shield className="h-3 w-3" />;
    }
  };

  return (
    <Card className="neon-border">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-destructive" />
          Threat Feed
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {threats.length === 0 ? (
          <div className="text-center text-muted-foreground terminal-text py-8">
            No threats detected
          </div>
        ) : (
          threats.map((threat) => (
            <div key={threat.id} className="flex items-start gap-3 p-3 rounded border border-border bg-muted/20">
              <div className="flex-shrink-0 mt-0.5">
                {getSeverityIcon(threat.severity)}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant={getSeverityVariant(threat.severity) as any} className="text-xs">
                    {threat.severity.toUpperCase()}
                  </Badge>
                  <span className="terminal-text text-xs text-muted-foreground">
                    {new Date(threat.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div className="terminal-text text-sm font-medium mb-1">
                  {threat.description}
                </div>
                <div className="terminal-text text-xs text-muted-foreground">
                  From: <span className="text-destructive font-mono">{threat.source_ip}</span>
                  {" → "}
                  <span className="text-primary font-mono">{threat.target_service}</span>
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
};