import { useState, useEffect, useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import {
  Upload, RefreshCw, TrendingUp, ShieldAlert, Activity, Server,
  AlertTriangle, Target, Shield, FileText, Download, Link2,
  ChevronRight, ArrowUpRight, ArrowDownRight, Minus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { UploadConfig } from "../components/UploadConfig";
import { UploadModal } from "@/components/upload/UploadModal";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import {
  getIngestionStatus, getTopologySummary, getAnalyticsSummary, getRiskSummary, getThreats,
  getExecutiveSummary, getComplianceScores, getFirewallHealth, getAttackSurface, getFirewallTopology,
  downloadPDFReport, downloadCSVExport,
  type Threat,
} from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";
import { useNavigate } from "react-router-dom";

const n = (v: unknown, fallback = 0): number => {
  const num = typeof v === "number" ? v : parseFloat(String(v ?? fallback));
  return isNaN(num) ? fallback : num;
};

const KPICard = ({ icon: Icon, label, value, trend, color }: {
  icon: React.ElementType; label: string; value: string; trend?: string; color: string;
}) => (
  <div className="bg-card rounded-xl p-4 shadow-card">
    <div className="flex items-center justify-between mb-3">
      <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">{label}</span>
      <Icon className={`h-4 w-4 ${color}`} />
    </div>
    <p className="text-2xl font-bold tabular-nums text-foreground">{value}</p>
    {trend && <p className="text-xs text-muted-foreground mt-1">{trend}</p>}
  </div>
);

const SeverityBadge = ({ severity }: { severity: string }) => {
  const cls = severity === "critical" ? "badge-critical" : severity === "high" ? "badge-high" : severity === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{severity}</span>;
};

const DONUT_COLORS = ["hsl(217.2,91.2%,59.8%)", "hsl(142.1,70.6%,45.3%)", "hsl(38,92%,50%)", "hsl(262,83%,58%)"];

const TrendArrow = ({ trend }: { trend: string }) => {
  if (trend === "critical" || trend === "high") return <ArrowUpRight className="h-4 w-4 text-destructive" />;
  if (trend === "stable") return <Minus className="h-4 w-4 text-success" />;
  return <ArrowDownRight className="h-4 w-4 text-success" />;
};

// ── TanStack Query stale-time constants ───────────────────────────────────────
const LIVE_STALE  = 1000 * 30;         // 30 s — ingestion, threats
const STATIC_STALE = 1000 * 60 * 5;    // 5 min — topology, compliance, health, exec summary

export default function Dashboard() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [uploadOpen, setUploadOpen] = useState(false);

  // ── Queries ─────────────────────────────────────────────────────────────────
  const ingestionQ     = useQuery({ queryKey: ["ingestion"],      queryFn: getIngestionStatus,       staleTime: LIVE_STALE,   refetchInterval: 30_000 });
  const topologyQ      = useQuery({ queryKey: ["topology"],       queryFn: getTopologySummary,       staleTime: STATIC_STALE });
  const analyticsQ     = useQuery({ queryKey: ["analytics"],      queryFn: getAnalyticsSummary,      staleTime: LIVE_STALE,   refetchInterval: 30_000 });
  const riskQ          = useQuery({ queryKey: ["risk"],           queryFn: getRiskSummary,           staleTime: LIVE_STALE,   refetchInterval: 30_000 });
  const threatsQ       = useQuery({ queryKey: ["threats", 10],    queryFn: () => getThreats(10),     staleTime: LIVE_STALE,   refetchInterval: 30_000 });
  const execSummaryQ   = useQuery({ queryKey: ["execSummary"],    queryFn: getExecutiveSummary,      staleTime: STATIC_STALE });
  const complianceQ    = useQuery({ queryKey: ["compliance"],     queryFn: getComplianceScores,      staleTime: STATIC_STALE });
  const fwHealthQ      = useQuery({ queryKey: ["fwHealth"],       queryFn: getFirewallHealth,        staleTime: STATIC_STALE });
  const attackSurfaceQ = useQuery({ queryKey: ["attackSurface"],  queryFn: getAttackSurface,         staleTime: STATIC_STALE });
  const fwTopologyQ    = useQuery({ queryKey: ["fwTopology"],     queryFn: getFirewallTopology,      staleTime: STATIC_STALE });

  // Derive data from queries — undefined means "not yet fetched"
  const ingestion     = ingestionQ.data     ?? null;
  const topology      = topologyQ.data      ?? null;
  const analytics     = analyticsQ.data     ?? null;
  const risk          = riskQ.data          ?? null;
  const threats       = threatsQ.data       ?? ([] as Threat[]);
  const execSummary   = execSummaryQ.data   ?? null;
  const compliance    = complianceQ.data    ?? [];
  const fwHealth      = fwHealthQ.data      ?? null;
  const attackSurface = attackSurfaceQ.data ?? null;
  const fwTopology    = fwTopologyQ.data    ?? null;

  // "loading" = true only on first-ever fetch (no cached data). Background re-fetches are silent.
  const loading = ingestionQ.isLoading || topologyQ.isLoading || analyticsQ.isLoading || riskQ.isLoading;
  // Any query currently fetching in the background (for the spinner icon)
  const isFetching = ingestionQ.isFetching || topologyQ.isFetching || analyticsQ.isFetching ||
                     riskQ.isFetching || threatsQ.isFetching || execSummaryQ.isFetching ||
                     complianceQ.isFetching || fwHealthQ.isFetching || attackSurfaceQ.isFetching ||
                     fwTopologyQ.isFetching;

  // Invalidate all dashboard queries — used for manual refresh + after upload
  const refetchAll = useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ["ingestion"] });
    queryClient.invalidateQueries({ queryKey: ["topology"] });
    queryClient.invalidateQueries({ queryKey: ["analytics"] });
    queryClient.invalidateQueries({ queryKey: ["risk"] });
    queryClient.invalidateQueries({ queryKey: ["threats"] });
    queryClient.invalidateQueries({ queryKey: ["execSummary"] });
    queryClient.invalidateQueries({ queryKey: ["compliance"] });
    queryClient.invalidateQueries({ queryKey: ["fwHealth"] });
    queryClient.invalidateQueries({ queryKey: ["attackSurface"] });
    queryClient.invalidateQueries({ queryKey: ["fwTopology"] });
  }, [queryClient]);

  // Listen for upload-complete event → invalidate all queries with a small delay
  useEffect(() => {
    const onUpload = () => { setTimeout(refetchAll, 2000); };
    window.addEventListener("firewall-upload-complete", onUpload);
    return () => { window.removeEventListener("firewall-upload-complete", onUpload); };
  }, [refetchAll]);

  const progress = ingestion?.ingestion_progress ?? 0;
  const totalConns = n(analytics?.total_connections);
  const activeThreats = n(risk?.by_level?.critical) + n(risk?.by_level?.high);
  const totalRules = n(topology?.total_firewall_rules);
  const totalDevices = n(topology?.firewalls_count) + n(topology?.routers_count) + n(topology?.switches_count);

  const donutData = topology
    ? [
        { name: "Zones",     value: n(topology.total_zones) },
        { name: "Rules",     value: n(topology.total_firewall_rules) },
        { name: "Firewalls", value: n(topology.firewalls_count) },
        { name: "VLANs",     value: n(topology.vlans_count) },
      ].filter((d) => d.value > 0)
    : [];

  const protocolData = analytics?.protocols?.map((p) => ({ name: p.protocol, value: p.count })) ?? [];

  const normThreats = threats.map((t) => ({
    id: String((t as Record<string, unknown>).id ?? ''),
    timestamp: String((t as Record<string, unknown>).timestamp ?? ""),
    name: String((t as Record<string, unknown>).threat_name ?? (t as Record<string, unknown>).name ?? "Unknown Threat"),
    severity: String((t as Record<string, unknown>).severity ?? "medium"),
    sourceIp: String((t as Record<string, unknown>).src_ip ?? "—"),
    action: String((t as Record<string, unknown>).action ?? "Blocked"),
  }));

  const hasData = totalRules > 0 || totalConns > 0;

  const riskScoreColor = (score: number) =>
    score >= 70 ? "text-destructive" : score >= 40 ? "text-warning" : "text-success";

  const complianceStatusColor = (status: string) =>
    status === "Compliant" ? "text-success" : status === "Partial" ? "text-warning" :
    status === "At Risk" ? "text-warning" : "text-destructive";

  const healthGradeColor = (grade: string) =>
    grade === "A+" || grade === "A" ? "text-success" : grade === "B" ? "text-primary" :
    grade === "C" ? "text-warning" : "text-destructive";

  return (
    <AppLayout title="Dashboard" breadcrumb={["Firewall Analytics"]}>
      <UploadConfig />

      {/* Firewall Chain Detection Banner */}
      {fwTopology?.chain_detected && (
        <div className="bg-info/10 border border-info/20 rounded-xl p-4 mb-6 flex items-start gap-3">
          <Link2 className="h-4 w-4 text-info shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-[12px] font-semibold text-info mb-1">Firewall Chain Detected</p>
            <p className="text-[11px] text-muted-foreground">{fwTopology.chain_details}</p>
            {fwTopology.firewalls.length > 1 && (
              <div className="flex gap-2 mt-2">
                {fwTopology.firewalls.map((fw) => (
                  <span key={fw.device_name} className="text-[10px] bg-info/10 text-info px-2 py-0.5 rounded font-medium">
                    {fw.device_name} ({fw.vendor || fw.device_type})
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Upload bar + Export buttons */}
      <div className="bg-card rounded-xl p-4 shadow-card mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button onClick={() => setUploadOpen(true)} className="bg-primary text-primary-foreground hover:bg-primary/90 active:scale-95 transition-all">
              <Upload className="h-4 w-4 mr-2" />Upload Firewall Data
            </Button>
            <div className="flex items-center gap-6 text-[12px]">
              <div><span className="text-muted-foreground">Rules:</span>{" "}<span className="font-medium text-foreground">{totalRules || "—"}</span></div>
              <div><span className="text-muted-foreground">Last Upload:</span>{" "}
                <span className="font-medium text-foreground font-mono">
                  {ingestion?.last_ingestion_time
                    ? new Date(ingestion.last_ingestion_time).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }) + " UTC"
                    : "—"}
                </span>
              </div>
              <div><span className="text-muted-foreground">Errors:</span>{" "}<span className="font-medium text-destructive">{ingestion?.total_errors_count ?? "—"}</span></div>
              <div><span className="text-muted-foreground">Warnings:</span>{" "}<span className="font-medium text-warning">{ingestion?.total_warnings_count ?? "—"}</span></div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {hasData && (
              <>
                <Button variant="outline" size="sm" className="h-8 text-[11px]" onClick={downloadPDFReport}>
                  <FileText className="h-3.5 w-3.5 mr-1.5" />Export PDF
                </Button>
                <Button variant="outline" size="sm" className="h-8 text-[11px]" onClick={downloadCSVExport}>
                  <Download className="h-3.5 w-3.5 mr-1.5" />Export CSV
                </Button>
              </>
            )}
            <button onClick={refetchAll} className="flex items-center gap-2 text-[11px] text-muted-foreground hover:text-foreground transition-smooth ml-2">
              <RefreshCw className={`h-3 w-3 ${isFetching ? "animate-spin" : ""}`} />
              <span>{isFetching ? "Refreshing…" : "Refresh"}</span>
            </button>
          </div>
        </div>
        {progress > 0 && (
          <div className="mt-3 h-1.5 w-full bg-secondary rounded-full overflow-hidden">
            <div className="h-full bg-primary rounded-full transition-all duration-500" style={{ width: `${progress}%` }} />
          </div>
        )}
      </div>

      {!hasData ? (
        <div className="bg-card rounded-xl p-16 shadow-card text-center">
          <Upload className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-[15px] font-semibold text-foreground mb-2">No data yet</p>
          <p className="text-[12px] text-muted-foreground mb-6">Upload a firewall config to populate all analytics — no mock data is shown.</p>
          <Button onClick={() => setUploadOpen(true)}>Upload Firewall Config</Button>
        </div>
      ) : (
        <>
          {/* ── Security Status At-a-Glance ── */}
          {(() => {
            const riskScore = execSummary?.risk_score ?? 0;
            const critPaths = n(attackSurface?.critical_paths);
            const critThreats = n(risk?.by_level?.critical);
            const isCritical = riskScore >= 70 || critPaths > 0 || critThreats > 0;
            const isModerate = riskScore >= 40;

            return (
              <div className={`rounded-xl p-5 mb-6 border ${
                isCritical ? "bg-red-950/30 border-red-800/30" :
                isModerate ? "bg-yellow-950/30 border-yellow-700/30" :
                "bg-emerald-950/30 border-emerald-700/30"
              }`}>
                <div className="flex items-center gap-5">
                  <div className={`h-16 w-16 rounded-2xl flex items-center justify-center text-3xl shrink-0 ${
                    isCritical ? "bg-red-900/50" : isModerate ? "bg-yellow-900/50" : "bg-emerald-900/50"
                  }`}>
                    {isCritical ? "🚨" : isModerate ? "⚠️" : "✅"}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <h2 className={`text-[17px] font-bold ${
                        isCritical ? "text-red-400" : isModerate ? "text-yellow-400" : "text-emerald-400"
                      }`}>
                        {isCritical ? "Immediate Action Required" : isModerate ? "Review Recommended" : "Security Posture: Healthy"}
                      </h2>
                      {fwHealth?.grade && (
                        <span className={`text-[13px] font-bold px-3 py-1 rounded-lg ${
                          fwHealth.grade.startsWith("A") ? "bg-emerald-900/50 text-emerald-400" :
                          fwHealth.grade === "B" ? "bg-blue-900/50 text-blue-400" :
                          "bg-yellow-900/50 text-yellow-400"
                        }`}>
                          Grade: {fwHealth.grade}
                        </span>
                      )}
                    </div>
                    <p className="text-[12px] text-muted-foreground mt-1.5 leading-relaxed">
                      {isCritical
                        ? `Your firewall configuration has ${critThreats} critical threat${critThreats !== 1 ? "s" : ""} and ${critPaths} critical attack path${critPaths !== 1 ? "s" : ""}. Review findings below and prioritize remediation.`
                        : isModerate
                        ? "Some areas need attention. Review the findings below and plan your remediation timeline."
                        : "Your firewall configuration shows a healthy security posture. Continue monitoring for changes."}
                    </p>
                  </div>
                  <div className="flex gap-3 shrink-0">
                    {[
                      { label: "Risk Score", value: riskScore.toFixed(0), color: riskScore >= 70 ? "text-red-400" : riskScore >= 40 ? "text-yellow-400" : "text-emerald-400" },
                      { label: "Threats", value: String(activeThreats), color: activeThreats > 0 ? "text-red-400" : "text-emerald-400" },
                      { label: "Rules", value: String(totalRules), color: "text-primary" },
                    ].map(m => (
                      <div key={m.label} className="text-center px-4 py-2 bg-black/20 rounded-xl">
                        <p className={`text-xl font-bold tabular-nums ${m.color}`}>{m.value}</p>
                        <p className="text-[9px] text-muted-foreground uppercase tracking-wider mt-0.5">{m.label}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })()}

          {/* ── Quick Navigation ── */}
          <div className="grid grid-cols-4 gap-3 mb-6">
            {[
              { label: "Attack Paths", desc: `${n(attackSurface?.critical_paths)} critical paths`, icon: "🎯", path: "/attack-paths",
                color: n(attackSurface?.critical_paths) > 0 ? "border-red-900/30 hover:border-red-700/40" : "border-border hover:border-primary/30" },
              { label: "Remediation", desc: `${n(risk?.by_level?.critical) + n(risk?.by_level?.high)} issues to fix`, icon: "🔧", path: "/remediation",
                color: (n(risk?.by_level?.critical) + n(risk?.by_level?.high)) > 0 ? "border-orange-900/30 hover:border-orange-700/40" : "border-border hover:border-primary/30" },
              { label: "FW Topology", desc: `${n(topology?.firewalls_count)} firewall${n(topology?.firewalls_count) !== 1 ? "s" : ""}`, icon: "🌐", path: "/firewall-topology",
                color: "border-border hover:border-primary/30" },
              { label: "Threats", desc: `${n(risk?.by_level?.critical)} critical threats`, icon: "🛡️", path: "/threats",
                color: n(risk?.by_level?.critical) > 0 ? "border-red-900/30 hover:border-red-700/40" : "border-border hover:border-primary/30" },
            ].map(nav => (
              <button key={nav.label} onClick={() => navigate(nav.path)}
                className={`bg-card rounded-xl p-4 shadow-card text-left border transition-all duration-200 hover:shadow-lg ${nav.color}`}>
                <div className="flex items-center gap-3">
                  <span className="text-xl">{nav.icon}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-semibold text-foreground">{nav.label}</p>
                    <p className="text-[10px] text-muted-foreground">{nav.desc}</p>
                  </div>
                  <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                </div>
              </button>
            ))}
          </div>

          {/* Executive Summary */}
          {execSummary && (
            <div className="bg-card rounded-xl p-5 shadow-card mb-6">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="h-4 w-4 text-primary" />
                <h3 className="text-[13px] font-semibold text-foreground">Executive Summary</h3>
                <span className="text-[10px] bg-primary/10 text-primary px-2 py-0.5 rounded-full font-medium">Auto-Generated from Your Data</span>
              </div>
              <p className="text-[12px] text-muted-foreground leading-relaxed">{execSummary.summary}</p>
            </div>
          )}

          {/* Risk Score + Health + Attack Surface — top row */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            {/* Overall Risk Score */}
            <div className="bg-card rounded-xl p-5 shadow-card">
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Overall Risk Score</span>
              <div className="flex items-center gap-3 mt-3">
                <span className={`text-4xl font-bold tabular-nums ${riskScoreColor(execSummary?.risk_score ?? 0)}`}>
                  {execSummary?.risk_score?.toFixed(0) ?? "—"}
                </span>
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-1">
                    <TrendArrow trend={execSummary?.risk_trend ?? "stable"} />
                    <span className="text-[10px] text-muted-foreground capitalize">{execSummary?.risk_trend ?? "stable"}</span>
                  </div>
                  <span className="text-[10px] text-muted-foreground">Industry avg: 45</span>
                </div>
              </div>
              <div className="mt-3 h-2 bg-secondary rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${
                    (execSummary?.risk_score ?? 0) >= 70 ? "bg-destructive" :
                    (execSummary?.risk_score ?? 0) >= 40 ? "bg-warning" : "bg-success"
                  }`}
                  style={{ width: `${execSummary?.risk_score ?? 0}%` }}
                />
              </div>
            </div>

            {/* Firewall Health Score */}
            <div className="bg-card rounded-xl p-5 shadow-card">
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Firewall Health Score</span>
              <div className="flex items-center gap-3 mt-3">
                <span className={`text-4xl font-bold tabular-nums ${healthGradeColor(fwHealth?.grade ?? "N/A")}`}>
                  {fwHealth?.score?.toFixed(0) ?? "—"}
                </span>
                <span className={`text-2xl font-bold ${healthGradeColor(fwHealth?.grade ?? "N/A")}`}>
                  {fwHealth?.grade ?? "—"}
                </span>
              </div>
              {fwHealth?.breakdown && (() => {
                const friendlyNames: Record<string, string> = {
                  rule_hygiene: "Rule Cleanliness",
                  risk_posture: "Security Strength",
                  access_control: "Access Control",
                  config_quality: "Config Quality",
                };
                return (
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1 mt-3">
                    {Object.entries(fwHealth.breakdown).map(([key, val]) => (
                      <div key={key} className="flex justify-between text-[10px]">
                        <span className="text-muted-foreground">{friendlyNames[key] || key.replace(/_/g, " ")}</span>
                        <span className={`font-medium tabular-nums ${val >= 80 ? "text-success" : val >= 50 ? "text-warning" : "text-destructive"}`}>{val.toFixed(0)}%</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>

            {/* Attack Surface */}
            <div className="bg-card rounded-xl p-5 shadow-card">
              <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Attack Surface</span>
              {attackSurface ? (
                <div className="grid grid-cols-2 gap-3 mt-3">
                  <div>
                    <p className="text-xl font-bold text-warning tabular-nums">{attackSurface.exposed_ports}</p>
                    <p className="text-[10px] text-muted-foreground">Exposed Ports</p>
                  </div>
                  <div>
                    <p className="text-xl font-bold text-destructive tabular-nums">{attackSurface.internet_facing_rules}</p>
                    <p className="text-[10px] text-muted-foreground">Internet-Facing Rules</p>
                  </div>
                  <div>
                    <p className="text-xl font-bold text-primary tabular-nums">{attackSurface.entry_points}</p>
                    <p className="text-[10px] text-muted-foreground">Entry Points</p>
                  </div>
                  <div>
                    <p className="text-xl font-bold text-info tabular-nums">{attackSurface.critical_paths}</p>
                    <p className="text-[10px] text-muted-foreground">Critical Paths</p>
                  </div>
                </div>
              ) : (
                <div className="h-24 flex items-center justify-center text-[11px] text-muted-foreground">Loading…</div>
              )}
            </div>
          </div>

          {/* KPI Cards */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <KPICard icon={TrendingUp} label="Network Traffic" value={totalConns.toLocaleString()} trend={`${analytics?.protocols?.length ?? 0} protocols seen`} color="text-primary" />
            <KPICard icon={ShieldAlert} label="Active Threats" value={String(activeThreats)} trend={activeThreats > 0 ? `${n(risk?.by_level?.critical)} need immediate fix` : "No active threats"} color="text-destructive" />
            <KPICard icon={Activity} label="Firewall Rules" value={String(totalRules)} trend={`Spanning ${n(topology?.total_zones)} security zones`} color="text-warning" />
            <KPICard icon={Server} label="Network Devices" value={String(totalDevices)} trend={`${n(topology?.firewalls_count)} firewalls · ${n(topology?.routers_count)} routers`} color="text-success" />
          </div>

          {/* Top 5 Critical Findings + Compliance Status */}
          <div className="grid grid-cols-2 gap-6 mb-6">
            {/* Top 5 Critical Findings */}
            <div className="bg-card rounded-xl p-5 shadow-card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-[13px] font-semibold text-foreground">Top 5 Critical Findings</h3>
                <Button variant="ghost" size="sm" className="h-6 text-[10px] text-primary" onClick={() => navigate("/analysis")}>
                  View All <ChevronRight className="h-3 w-3 ml-1" />
                </Button>
              </div>
              {execSummary?.top_findings?.length ? (
                <div className="space-y-2">
                  {execSummary.top_findings.map((f, i) => (
                    <div key={i} className="flex items-center gap-3 p-2 rounded-lg hover:bg-primary/5 transition-smooth">
                      <span className={`text-[13px] font-bold tabular-nums ${
                        f.risk_level === "critical" ? "text-destructive" : "text-warning"
                      }`}>
                        {f.risk_score.toFixed(1)}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[12px] font-medium text-foreground truncate">{f.rule_name}</p>
                        <p className="text-[10px] text-muted-foreground truncate">{f.reason}</p>
                      </div>
                      <SeverityBadge severity={f.risk_level} />
                    </div>
                  ))}
                </div>
              ) : (
                <div className="h-32 flex items-center justify-center text-[12px] text-muted-foreground">No critical findings detected</div>
              )}
            </div>

            {/* Compliance Status */}
            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Compliance Status</h3>
              {compliance.length > 0 ? (
                <div className="space-y-4">
                  {compliance.map((c) => (
                    <div key={c.framework}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[12px] font-medium text-foreground">{c.framework}</span>
                        <div className="flex items-center gap-2">
                          <span className={`text-[13px] font-bold tabular-nums ${complianceStatusColor(c.status)}`}>
                            {c.score.toFixed(0)}%
                          </span>
                          <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                            c.status === "Compliant" ? "bg-success/20 text-success" :
                            c.status === "Partial" ? "bg-warning/20 text-warning" :
                            "bg-destructive/20 text-destructive"
                          }`}>
                            {c.status}
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            c.score >= 80 ? "bg-success" : c.score >= 60 ? "bg-warning" : "bg-destructive"
                          }`}
                          style={{ width: `${c.score}%` }}
                        />
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-1">{c.findings} finding{c.findings !== 1 ? "s" : ""} · {c.details[0]}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="h-32 flex items-center justify-center text-[12px] text-muted-foreground">Upload a config to see compliance scores</div>
              )}
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-2 gap-6 mb-6">
            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Protocol Distribution</h3>
              {protocolData.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={protocolData} layout="vertical">
                    <XAxis type="number" stroke="hsl(240,5%,40%)" fontSize={11} />
                    <YAxis type="category" dataKey="name" stroke="hsl(240,5%,40%)" fontSize={11} width={55} />
                    <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 12 }} />
                    <Bar dataKey="value" radius={[0,4,4,0]}>
                      {protocolData.map((_, i) => <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-60 flex items-center justify-center text-[12px] text-muted-foreground">Upload a config to see protocol breakdown</div>
              )}
            </div>

            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Topology Summary</h3>
              {donutData.length > 0 ? (
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie data={donutData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} dataKey="value" paddingAngle={2}>
                      {donutData.map((_, i) => <Cell key={i} fill={DONUT_COLORS[i]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 12 }} />
                    <Legend iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-60 flex items-center justify-center text-[12px] text-muted-foreground">No topology data yet</div>
              )}
            </div>
          </div>

          {/* Risk breakdown + Threats table */}
          <div className="grid grid-cols-2 gap-6">
            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Risk Level Breakdown</h3>
              {risk ? (
                <div className="space-y-3">
                  {(["critical", "high", "medium", "low"] as const).map((level) => {
                    const count = n(risk.by_level?.[level]);
                    const total = Object.values(risk.by_level ?? {}).reduce((a, b) => a + n(b), 0) || 1;
                    const pct = (count / total) * 100;
                    const colors: Record<string, string> = { critical: "bg-red-500", high: "bg-orange-400", medium: "bg-yellow-400", low: "bg-green-500" };
                    const friendlyLevel: Record<string, string> = { critical: "Critical — Fix Immediately", high: "High — Fix Soon", medium: "Medium — Plan to Fix", low: "Low — Monitor" };
                    return (
                      <div key={level}>
                        <div className="flex items-center justify-between text-[11px] mb-1">
                          <span className="text-foreground font-medium">{friendlyLevel[level]}</span>
                          <span className="text-muted-foreground tabular-nums">{count} issue{count !== 1 ? "s" : ""}</span>
                        </div>
                        <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${colors[level]} transition-all`} style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="h-40 flex items-center justify-center text-[12px] text-muted-foreground">Run rule analysis to see risk breakdown</div>
              )}
            </div>

            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Recent Threats</h3>
              {normThreats.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-[12px] text-muted-foreground">No threats detected yet</div>
              ) : (
                <div className="overflow-auto">
                  <table className="w-full text-[12px]">
                    <thead>
                      <tr className="border-b border-border text-left">
                        {["Time", "Threat", "Severity", "Source"].map((h) => (
                          <th key={h} className="pb-2 text-[10px] uppercase tracking-widest text-muted-foreground font-bold">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {normThreats.map((t) => (
                        <tr key={t.id} className="border-b border-border/50 hover:bg-primary/5 transition-smooth">
                          <td className="py-2 font-mono text-muted-foreground whitespace-nowrap">
                            {t.timestamp ? (() => {
                              const parts = t.timestamp.split(" ");
                              const date = parts[0] ?? "";
                              const time = parts[1]?.slice(0, 5) ?? "";
                              return time ? `${date.slice(5)} ${time}` : "—";
                            })() : "—"}
                          </td>
                          <td className="py-2 text-foreground font-medium max-w-[160px] truncate">
                            <SmartTooltip term={t.name} context="Threat detected" severity={t.severity} page="Dashboard">
                              {t.name}
                            </SmartTooltip>
                          </td>
                          <td className="py-2"><SeverityBadge severity={t.severity} /></td>
                          <td className="py-2 font-mono text-muted-foreground">{t.sourceIp}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      <UploadModal open={uploadOpen} onOpenChange={setUploadOpen} onUploadComplete={refetchAll} />
    </AppLayout>
  );
}
