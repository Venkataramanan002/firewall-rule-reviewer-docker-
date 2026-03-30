/**
 * FirewallTopology.tsx
 * ────────────────────
 * Interactive firewall topology view showing detected firewalls, their zones,
 * connections, and trust relationships. Matches existing theme exactly.
 */

import { useState, useEffect, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Network, Shield, Server, Link2, AlertTriangle, Upload, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { getFirewallTopology, type FirewallTopologyData } from "@/lib/api";

const SeverityBadge = ({ level }: { level: string }) => {
  const cls = level === "critical" ? "badge-critical" : level === "high" ? "badge-high" : level === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{level}</span>;
};

// Module-level cache — survives route changes
let _cachedTopoData: FirewallTopologyData | null = null;

export default function FirewallTopology() {
  const [data, setData] = useState<FirewallTopologyData | null>(_cachedTopoData);
  const [loading, setLoading] = useState(_cachedTopoData === null);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    getFirewallTopology()
      .then((d) => { _cachedTopoData = d; if (mountedRef.current) setData(d); })
      .catch(() => {})
      .finally(() => { if (mountedRef.current) setLoading(false); });

    const onUpload = () => {
      setTimeout(() => {
        if (!mountedRef.current) return;
        setLoading(true);
        getFirewallTopology()
          .then((d) => { _cachedTopoData = d; if (mountedRef.current) setData(d); })
          .catch(() => {})
          .finally(() => { if (mountedRef.current) setLoading(false); });
      }, 2000);
    };
    window.addEventListener("firewall-upload-complete", onUpload);
    return () => {
      mountedRef.current = false;
      window.removeEventListener("firewall-upload-complete", onUpload);
    };
  }, []);

  if (loading) {
    return (
      <AppLayout title="Firewall Topology" breadcrumb={["Firewall Analytics"]}>
        <div className="flex items-center justify-center py-20">
          <Loader2 className="h-6 w-6 animate-spin text-primary" />
          <span className="ml-3 text-[12px] text-muted-foreground">Loading topology…</span>
        </div>
      </AppLayout>
    );
  }

  if (!data || data.firewalls.length === 0) {
    return (
      <AppLayout title="Firewall Topology" breadcrumb={["Firewall Analytics"]}>
        <div className="bg-card rounded-xl p-16 shadow-card text-center">
          <Network className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
          <p className="text-[14px] font-medium text-foreground mb-2">No firewall topology data</p>
          <p className="text-[12px] text-muted-foreground">Upload a firewall configuration to visualise the network topology.</p>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout title="Firewall Topology" breadcrumb={["Firewall Analytics"]}>
      {/* Chain Detection Banner */}
      {data.chain_detected && (
        <div className="bg-info/10 border border-info/20 rounded-xl p-4 mb-6 flex items-start gap-3">
          <Link2 className="h-4 w-4 text-info shrink-0 mt-0.5" />
          <div>
            <p className="text-[12px] font-semibold text-info mb-1">Multi-Firewall Topology Detected</p>
            <p className="text-[11px] text-muted-foreground">{data.chain_details}</p>
          </div>
        </div>
      )}

      {/* ── Topology Summary KPIs ── */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-card rounded-xl p-4 shadow-card">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Firewalls</p>
          <p className="text-2xl font-bold tabular-nums text-primary mt-1">{data.firewalls.length}</p>
        </div>
        <div className="bg-card rounded-xl p-4 shadow-card">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Total Zones</p>
          <p className="text-2xl font-bold tabular-nums text-foreground mt-1">
            {[...new Set(data.firewalls.flatMap(fw => fw.zones))].length}
          </p>
        </div>
        <div className="bg-card rounded-xl p-4 shadow-card">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Connections</p>
          <p className="text-2xl font-bold tabular-nums text-foreground mt-1">{data.connections.length}</p>
        </div>
        <div className="bg-card rounded-xl p-4 shadow-card">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Entry Points</p>
          <p className="text-2xl font-bold tabular-nums text-warning mt-1">
            {data.firewalls.filter(fw => fw.is_entry_point).length}
          </p>
        </div>
      </div>

      {/* ── Security Posture ── */}
      {(() => {
        const totalRulesCount = data.firewalls.reduce((s, fw) => s + fw.rules_count, 0);
        const entryPts = data.firewalls.filter(fw => fw.is_entry_point).length;
        const totalZones = [...new Set(data.firewalls.flatMap(fw => fw.zones))].length;
        const lowTrust = data.connections.filter(c => c.trust_level !== "high").length;
        const hasIssues = entryPts > 1 || lowTrust > 0;

        return (
          <div className={`rounded-xl p-5 mb-6 border ${
            hasIssues ? "bg-yellow-950/30 border-yellow-700/30" : "bg-emerald-950/30 border-emerald-700/30"
          }`}>
            <div className="flex items-center gap-4">
              <div className={`h-14 w-14 rounded-2xl flex items-center justify-center text-2xl shrink-0 ${
                hasIssues ? "bg-yellow-900/50" : "bg-emerald-900/50"
              }`}>
                {hasIssues ? "⚠️" : "✅"}
              </div>
              <div className="flex-1">
                <h3 className={`text-[14px] font-bold ${hasIssues ? "text-yellow-400" : "text-emerald-400"}`}>
                  {hasIssues ? "Topology Review Recommended" : "Topology Looks Healthy"}
                </h3>
                <p className="text-[12px] text-muted-foreground mt-1 leading-relaxed">
                  {data.firewalls.length} firewall{data.firewalls.length !== 1 ? "s" : ""} with{" "}
                  {totalRulesCount} total rules across {totalZones} zone{totalZones !== 1 ? "s" : ""}
                  {entryPts > 0 && ` · ${entryPts} internet-facing entry point${entryPts !== 1 ? "s" : ""}`}
                  {lowTrust > 0 && ` · ${lowTrust} connection${lowTrust !== 1 ? "s" : ""} below high trust`}
                  {data.chain_detected && " · Multi-firewall chain detected"}
                </p>
              </div>
              <div className="flex gap-3 shrink-0">
                <div className="text-center px-3 py-2 bg-black/20 rounded-xl">
                  <p className="text-xl font-bold tabular-nums text-primary">{totalRulesCount}</p>
                  <p className="text-[9px] text-muted-foreground uppercase tracking-wider">Rules</p>
                </div>
                <div className="text-center px-3 py-2 bg-black/20 rounded-xl">
                  <p className="text-xl font-bold tabular-nums text-foreground">{totalZones}</p>
                  <p className="text-[9px] text-muted-foreground uppercase tracking-wider">Zones</p>
                </div>
              </div>
            </div>
          </div>
        );
      })()}

      {/* Firewall Devices Grid */}
      <h3 className="text-[13px] font-semibold text-foreground mb-4">Detected Firewalls</h3>
      <div className="grid grid-cols-3 gap-4 mb-6">
        {data.firewalls.map((fw) => (
          <div key={fw.device_name} className="bg-card rounded-xl p-4 shadow-card">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center">
                <Shield className="h-4.5 w-4.5 text-primary" />
              </div>
              <div>
                <p className="text-[13px] font-semibold text-foreground">{fw.device_name}</p>
                <p className="text-[10px] text-muted-foreground capitalize">{(fw.vendor || fw.device_type || "").replace(/_/g, " ")}</p>
              </div>
              {fw.is_entry_point && (
                <span className="ml-auto badge-high px-2 py-0.5 rounded-full text-[9px] font-semibold uppercase">Entry Point</span>
              )}
            </div>

            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div>
                <span className="text-muted-foreground">IP:</span>{" "}
                <span className="font-mono text-foreground">{fw.ip_address}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Rules:</span>{" "}
                <span className="font-medium text-foreground">{fw.rules_count}</span>
              </div>
            </div>

            {fw.zones.length > 0 && (
              <div className="mt-3">
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Zones</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {fw.zones.map((z) => (
                    <SmartTooltip key={z} term={z} context={`Security zone on ${fw.device_name}`} page="Topology">
                      <span className="text-[10px] bg-secondary px-1.5 py-0.5 rounded font-mono cursor-help">{z}</span>
                    </SmartTooltip>
                  ))}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── Visual Network Map ── */}
      {data.firewalls.length > 0 && (() => {
        const fws = data.firewalls;
        const conns = data.connections;
        const W = 720, H = fws.length <= 2 ? 220 : 340, PAD = 90;
        const fwPos: Record<string, { x: number; y: number }> = {};

        if (fws.length === 1) {
          fwPos[fws[0].device_name] = { x: W / 2, y: H / 2 };
        } else if (fws.length === 2) {
          fwPos[fws[0].device_name] = { x: W / 3, y: H / 2 };
          fwPos[fws[1].device_name] = { x: (W * 2) / 3, y: H / 2 };
        } else {
          fws.forEach((fw, i) => {
            const angle = (i / fws.length) * Math.PI * 2 - Math.PI / 2;
            fwPos[fw.device_name] = {
              x: W / 2 + Math.cos(angle) * (W / 2 - PAD),
              y: H / 2 + Math.sin(angle) * (H / 2 - PAD),
            };
          });
        }

        return (
          <div className="bg-card rounded-xl p-5 shadow-card mb-6">
            <h3 className="text-[13px] font-semibold text-foreground mb-3">Network Topology Map</h3>
            <div className="overflow-x-auto">
              <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: Math.min(H, 360), display: "block" }}>
                {/* Connection lines */}
                {conns.map((conn, i) => {
                  const from = fwPos[conn.source];
                  const to = fwPos[conn.target];
                  if (!from || !to) return null;
                  const isHighTrust = conn.trust_level === "high";
                  return (
                    <g key={`conn-${i}`}>
                      <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                        stroke={isHighTrust ? "#22c55e" : "#eab308"} strokeWidth={2}
                        strokeDasharray={isHighTrust ? "none" : "6 3"} opacity={0.5} />
                      <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 10}
                        textAnchor="middle" fontSize={9} fill="#9ca3af">
                        {conn.trust_level} trust
                      </text>
                      {conn.shared_zones?.length > 0 && (
                        <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 + 4}
                          textAnchor="middle" fontSize={7.5} fill="#6b7280">
                          {conn.shared_zones.join(", ")}
                        </text>
                      )}
                    </g>
                  );
                })}
                {/* Firewall nodes */}
                {fws.map((fw) => {
                  const pos = fwPos[fw.device_name];
                  if (!pos) return null;
                  const label = fw.device_name.length > 16 ? fw.device_name.slice(0, 16) + "…" : fw.device_name;
                  return (
                    <g key={fw.device_name}>
                      {fw.is_entry_point && (
                        <circle cx={pos.x} cy={pos.y} r={38} fill="none" stroke="#3b82f6"
                          strokeWidth={1.5} strokeDasharray="4 2" opacity={0.5} />
                      )}
                      <circle cx={pos.x} cy={pos.y} r={30}
                        fill={fw.is_entry_point ? "#1e3a5f" : "#1f2937"}
                        stroke={fw.is_entry_point ? "#3b82f6" : "#374151"} strokeWidth={2} />
                      <text x={pos.x} y={pos.y - 5} textAnchor="middle" fontSize={16}>
                        {fw.is_entry_point ? "🌐" : "🛡️"}
                      </text>
                      <text x={pos.x} y={pos.y + 10} textAnchor="middle" fontSize={8} fill="#f9fafb" fontWeight="600">
                        {label}
                      </text>
                      <text x={pos.x} y={pos.y + 46} textAnchor="middle" fontSize={8} fill="#9ca3af">
                        {fw.rules_count} rules · {fw.zones.length} zone{fw.zones.length !== 1 ? "s" : ""}
                      </text>
                      {fw.is_entry_point && (
                        <text x={pos.x} y={pos.y + 22} textAnchor="middle" fontSize={7} fill="#93c5fd">ENTRY POINT</text>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>
            <div className="flex items-center gap-4 mt-2 pt-2 border-t border-border text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 bg-green-500 inline-block rounded" />High trust connection
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-4 h-0.5 inline-block" style={{ borderTop: "2px dashed #eab308" }} />Lower trust connection
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full border border-blue-500 bg-blue-950 inline-block" />Entry point
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full border border-gray-600 bg-gray-800 inline-block" />Internal firewall
              </span>
            </div>
          </div>
        );
      })()}

      {/* Connections */}
      {data.connections.length > 0 && (
        <>
          <h3 className="text-[13px] font-semibold text-foreground mb-4">Firewall Connections</h3>
          <div className="space-y-2 mb-6">
            {data.connections.map((conn, i) => (
              <div key={i} className="bg-card rounded-xl p-4 shadow-card flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <Server className="h-3.5 w-3.5 text-primary" />
                  <span className="text-[12px] font-medium text-foreground">{conn.source}</span>
                </div>
                <div className="flex-1 h-px bg-border relative">
                  <span className="absolute left-1/2 -translate-x-1/2 -top-2.5 text-[9px] bg-card px-2 text-muted-foreground">
                    {(() => {
                      const friendlyTypes: Record<string, string> = {
                        allow_rule: "Allowed Traffic",
                        shared_zone: "Shared Network Zone",
                        deny_rule: "Blocked Traffic",
                        nat_rule: "Address Translation",
                        vpn_tunnel: "VPN Tunnel",
                      };
                      return friendlyTypes[conn.type] || conn.type.replace(/_/g, " ");
                    })()}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[12px] font-medium text-foreground">{conn.target}</span>
                  <Server className="h-3.5 w-3.5 text-primary" />
                </div>
                <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                  conn.trust_level === "high" ? "bg-success/20 text-success" : "bg-warning/20 text-warning"
                }`}>
                  Trust: {conn.trust_level}
                </span>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Upload Connected Firewall Prompt */}
      <div className="bg-card rounded-xl p-5 shadow-card border border-dashed border-border">
        <div className="flex items-start gap-3">
          <Upload className="h-5 w-5 text-muted-foreground shrink-0 mt-0.5" />
          <div>
            <p className="text-[13px] font-semibold text-foreground mb-1">Add Another Firewall</p>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Have multiple firewalls? Upload additional configuration files to see how they connect and build a complete security map.
              Use the upload button in the sidebar to add more devices.
            </p>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
