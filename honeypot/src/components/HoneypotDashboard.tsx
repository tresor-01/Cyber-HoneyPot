import { useState } from "react";
import { useHoneypotWebSocket } from "@/hooks/useHoneypotWebSocket";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Shield, AlertTriangle, Server,
  Network, Terminal, Wifi, WifiOff, Loader2, Lock,
} from "lucide-react";
import { ServiceMonitor } from "./ServiceMonitor";
import { ThreatFeed }     from "./ThreatFeed";
import { ActivityLog }    from "./ActivityLog";

export const HoneypotDashboard = () => {
  const { state, toggleActive } = useHoneypotWebSocket();
  const { active, stats, services, logs, threats, wsStatus } = state;

  const [showPermissionDialog, setShowPermissionDialog] = useState(false);

  const handleToggle = () => {
    if (!active) {
      // Ask for permission before starting
      setShowPermissionDialog(true);
    } else {
      toggleActive(false);
    }
  };

  const honeypot = stats?.honeypot;
  const system   = stats?.system;

  const totalConnections = honeypot?.total_connections ?? 0;
  const blockedAttacks   = honeypot?.blocked_attacks   ?? 0;
  const activeThreats    = honeypot?.active_threats    ?? 0;
  const servicesRunning  = services.filter(s => s.status === "active").length;

  const cpuPct  = system?.cpu_percent        ?? 0;
  const memPct  = system?.memory_percent     ?? 0;
  const netSent = system?.network_bytes_sent ?? 0;
  const netPct  = Math.min(100, Math.round((netSent / 1_000_000) * 10));

  return (
    <div className="min-h-screen bg-background p-4">
      {/* ── Permission Dialog ─────────────────────────────────────────── */}
      <AlertDialog open={showPermissionDialog} onOpenChange={setShowPermissionDialog}>
        <AlertDialogContent className="neon-border max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-primary glow-text">
              <Lock className="h-5 w-5" />
              Permission Required
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-3 text-sm text-muted-foreground">
                <p>
                  You are about to start the <span className="text-foreground font-semibold">Cybersecurity Honeypot</span> on this machine.
                  This will open the following network listeners on your computer:
                </p>
                <ul className="grid grid-cols-2 gap-1 font-mono text-xs border border-border rounded-md p-3 bg-muted/30">
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> SSH &nbsp;&nbsp;&nbsp;:2222</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> FTP &nbsp;&nbsp;&nbsp;:2121</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> HTTP &nbsp;&nbsp;:8080</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> SMTP &nbsp;&nbsp;:2525</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> Telnet :2323</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> MySQL &nbsp;:3306</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> RDP &nbsp;&nbsp;&nbsp;:3389</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> Redis &nbsp;:6379</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> VNC &nbsp;&nbsp;&nbsp;:5900</li>
                  <li className="flex items-center gap-1"><span className="text-primary">▸</span> PgSQL &nbsp;:5432</li>
                </ul>
                <p className="text-warning text-xs flex items-start gap-1">
                  <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                  These ports will be accessible on your network. Only proceed if you understand the risks and have the necessary permissions to run honeypot services on this system.
                </p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="font-mono">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="font-mono bg-primary text-primary-foreground hover:bg-primary/90"
              onClick={() => {
                setShowPermissionDialog(false);
                toggleActive(true);
              }}
            >
              Allow &amp; Start
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <div className="max-w-7xl mx-auto space-y-6">
        {/* ── Header ────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary glow-text" />
            <div>
              <h1 className="text-3xl font-bold glow-text">Cybersecurity Honeypot</h1>
              <p className="text-muted-foreground terminal-text">Advanced threat detection &amp; monitoring system</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Live WebSocket status */}
            <div className="flex items-center gap-1 text-xs terminal-text">
              {wsStatus === "connected"    && <Wifi    className="h-3 w-3 text-success" />}
              {wsStatus === "disconnected" && <WifiOff className="h-3 w-3 text-destructive" />}
              {wsStatus === "connecting"   && <Loader2 className="h-3 w-3 text-warning animate-spin" />}
              <span className={wsStatus === "connected" ? "text-success" : wsStatus === "disconnected" ? "text-destructive" : "text-warning"}>
                {wsStatus === "connected" ? "LIVE" : wsStatus === "connecting" ? "CONNECTING…" : "OFFLINE"}
              </span>
            </div>
            <Badge variant={active ? "active" : "secondary"}>
              {active ? "ACTIVE" : "INACTIVE"}
            </Badge>
            <Button
              onClick={handleToggle}
              variant={active ? "destructive" : "default"}
              className="font-mono"
              disabled={wsStatus === "connecting"}
            >
              {active ? "STOP" : "START"} HONEYPOT
            </Button>
          </div>
        </div>

        {/* ── Stats Overview ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Connections</CardTitle>
              <Network className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary terminal-text">{totalConnections.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">All-time honeypot hits</p>
            </CardContent>
          </Card>
          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Blocked Attacks</CardTitle>
              <Shield className="h-4 w-4 text-success" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-success terminal-text">{blockedAttacks.toLocaleString()}</div>
              <p className="text-xs text-muted-foreground">Failed auth attempts</p>
            </CardContent>
          </Card>
          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Active Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-destructive terminal-text">{activeThreats}</div>
              <p className="text-xs text-muted-foreground">In last 5 minutes</p>
            </CardContent>
          </Card>
          <Card className="neon-border">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Services Running</CardTitle>
              <Server className="h-4 w-4 text-primary" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary terminal-text">{servicesRunning}</div>
              <p className="text-xs text-muted-foreground">Honeypot services active</p>
            </CardContent>
          </Card>
        </div>

        {/* ── Main content ───────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-1">
            <ServiceMonitor services={services} isActive={active} />
          </div>
          <div className="lg:col-span-1">
            <ActivityLog logs={logs} />
          </div>
          <div className="lg:col-span-1">
            <ThreatFeed threats={threats} />
          </div>
        </div>

        {/* ── System Status ──────────────────────────────────────────────── */}
        <Card className="neon-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-primary" />
              System Status
              {wsStatus !== "connected" && (
                <span className="text-xs text-muted-foreground font-normal ml-2">(last known values)</span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">CPU Usage</span>
                  <span className={`terminal-text ${cpuPct > 80 ? "text-destructive" : cpuPct > 50 ? "text-warning" : "text-primary"}`}>{cpuPct.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className={`h-2 rounded-full pulse-glow transition-all duration-500 ${cpuPct > 80 ? "bg-destructive" : cpuPct > 50 ? "bg-warning" : "bg-primary"}`} style={{ width: `${cpuPct}%` }} />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">Memory Usage</span>
                  <span className={`terminal-text ${memPct > 80 ? "text-destructive" : memPct > 60 ? "text-warning" : "text-success"}`}>{memPct.toFixed(1)}%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className={`h-2 rounded-full transition-all duration-500 ${memPct > 80 ? "bg-destructive" : memPct > 60 ? "bg-warning" : "bg-success"}`} style={{ width: `${memPct}%` }} />
                </div>
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="terminal-text text-sm">Network I/O</span>
                  <span className="text-success terminal-text">{netPct}%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div className="bg-success h-2 rounded-full transition-all duration-500" style={{ width: `${netPct}%` }} />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

