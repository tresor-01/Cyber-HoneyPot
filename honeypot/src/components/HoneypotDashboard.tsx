import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Shield, Activity, AlertTriangle, Eye, Server, Network, Terminal } from "lucide-react";
import { ServiceMonitor } from "./ServiceMonitor";
import { ThreatFeed } from "./ThreatFeed";
import { ActivityLog } from "./ActivityLog";

interface HoneypotStats {
  totalConnections: number;
  blockedAttacks: number;
  activeThreats: number;
  servicesRunning: number;
}

export const HoneypotDashboard = () => {
  const [stats, setStats] = useState<HoneypotStats>({
    totalConnections: 0,
    blockedAttacks: 0,
    activeThreats: 0,
    servicesRunning: 6,
  });

  const [isActive, setIsActive] = useState(true);

  // Simulate real-time updates
  useEffect(() => {
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        totalConnections: prev.totalConnections + Math.floor(Math.random() * 3),
        blockedAttacks: prev.blockedAttacks + (Math.random() > 0.7 ? 1 : 0),
        activeThreats: Math.floor(Math.random() * 5),
      }));
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary glow-text" />
            <div>
              <h1 className="text-3xl font-bold glow-text">Cybersecurity Honeypot</h1>
              <p className="text-muted-foreground terminal-text">Advanced threat detection & monitoring system</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Badge variant={isActive ? "active" : "secondary"}>
              {isActive ? "ACTIVE" : "INACTIVE"}
            </Badge>
            <Button
              onClick={() => setIsActive(!isActive)}
              variant={isActive ? "destructive" : "default"}
              className="font-mono"
            >
              {isActive ? "STOP" : "START"} HONEYPOT
            </Button>
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Connections</CardTitle>
              <Network className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary terminal-text">{stats.totalConnections}</div>
              <p className="text-xs text-muted-foreground">+12% from last hour</p>
            </CardContent>
          </Card>

          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Blocked Attacks</CardTitle>
              <Shield className="h-4 w-4 text-success" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-success terminal-text">{stats.blockedAttacks}</div>
              <p className="text-xs text-muted-foreground">Threats neutralized</p>
            </CardContent>
          </Card>

          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Active Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-destructive terminal-text">{stats.activeThreats}</div>
              <p className="text-xs text-muted-foreground">Requires attention</p>
            </CardContent>
          </Card>

          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Services Running</CardTitle>
              <Server className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary terminal-text">{stats.servicesRunning}</div>
              <p className="text-xs text-muted-foreground">Honeypot services active</p>
            </CardContent>
          </Card>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Service Monitor */}
          <div className="lg:col-span-1">
            <ServiceMonitor isActive={isActive} />
          </div>

          {/* Activity Log */}
          <div className="lg:col-span-1">
            <ActivityLog />
          </div>

          {/* Threat Feed */}
          <div className="lg:col-span-1">
            <ThreatFeed />
          </div>
        </div>

        {/* System Status */}
        <Card className="neon-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-primary" />
              System Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">CPU Usage</span>
                  <span className="text-primary terminal-text">23%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className="bg-primary h-2 rounded-full w-[23%] pulse-glow"></div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">Memory Usage</span>
                  <span className="text-warning terminal-text">67%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className="bg-warning h-2 rounded-full w-[67%]"></div>
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">Network I/O</span>
                  <span className="text-success terminal-text">45%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className="bg-success h-2 rounded-full w-[45%]"></div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};