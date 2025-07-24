import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, Shield, Eye, Zap } from "lucide-react";

interface ThreatEvent {
  id: string;
  type: "brute_force" | "port_scan" | "malware" | "ddos" | "injection";
  source: string;
  target: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: Date;
  description: string;
}

export const ThreatFeed = () => {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);

  const threatTypes = [
    { type: "brute_force", description: "SSH brute force attempt", severity: "high" },
    { type: "port_scan", description: "Port scanning detected", severity: "medium" },
    { type: "malware", description: "Malware signature detected", severity: "critical" },
    { type: "ddos", description: "DDoS attack pattern", severity: "high" },
    { type: "injection", description: "SQL injection attempt", severity: "high" }
  ];

  const generateRandomIP = () => {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  };

  const generateThreat = (): ThreatEvent => {
    const threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
    return {
      id: Math.random().toString(36).substr(2, 9),
      type: threatType.type as ThreatEvent["type"],
      source: generateRandomIP(),
      target: "honeypot.local",
      severity: threatType.severity as ThreatEvent["severity"],
      timestamp: new Date(),
      description: threatType.description
    };
  };

  useEffect(() => {
    // Add initial threats
    setThreats([generateThreat(), generateThreat(), generateThreat()]);

    const interval = setInterval(() => {
      if (Math.random() > 0.6) {
        setThreats(prev => [generateThreat(), ...prev.slice(0, 9)]);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const getSeverityVariant = (severity: ThreatEvent["severity"]) => {
    switch (severity) {
      case "critical": return "threat";
      case "high": return "destructive";
      case "medium": return "warning";
      case "low": return "secondary";
      default: return "secondary";
    }
  };

  const getSeverityIcon = (severity: ThreatEvent["severity"]) => {
    switch (severity) {
      case "critical": return <Zap className="h-3 w-3" />;
      case "high": return <AlertTriangle className="h-3 w-3" />;
      case "medium": return <Eye className="h-3 w-3" />;
      case "low": return <Shield className="h-3 w-3" />;
      default: return <Shield className="h-3 w-3" />;
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
                  <Badge variant={getSeverityVariant(threat.severity)} className="text-xs">
                    {threat.severity.toUpperCase()}
                  </Badge>
                  <span className="terminal-text text-xs text-muted-foreground">
                    {threat.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                <div className="terminal-text text-sm font-medium mb-1">
                  {threat.description}
                </div>
                <div className="terminal-text text-xs text-muted-foreground">
                  From: <span className="text-destructive font-mono">{threat.source}</span>
                  {" → "}
                  <span className="text-primary font-mono">{threat.target}</span>
                </div>
              </div>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
};