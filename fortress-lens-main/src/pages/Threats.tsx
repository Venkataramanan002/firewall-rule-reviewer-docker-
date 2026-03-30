import { useState, useEffect, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { ShieldAlert, ShieldX, Shield, Eye, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { getThreats } from "@/lib/api";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from "recharts";

const COLORS = ["hsl(0,84.2%,60.2%)", "hsl(38,92%,50%)", "hsl(217.2,91.2%,59.8%)", "hsl(142.1,70.6%,45.3%)"];

interface NormThreat {
  id: string; timestamp: string; name: string; severity: string;
  sourceIp: string; dstIp: string; threatType: string; riskScore: number; action: string;
}

function norm(t: Record<string, unknown>): NormThreat {
  return {
    id: String(t.id ?? Math.random()),
    timestamp: String(t.timestamp ?? ""),
    name: String(t.threat_name ?? t.name ?? "Unknown Threat"),
    severity: String(t.severity ?? "medium"),
    sourceIp: String(t.src_ip ?? "—"),
    dstIp: String(t.dst_ip ?? "—"),
    threatType: String(t.threat_type ?? "—"),
    riskScore: Number(t.risk_score ?? 0),
    action: String(t.action ?? "Blocked"),
  };
}

const SeverityBadge = ({ severity }: { severity: string }) => {
  const cls = severity === "critical" ? "badge-critical" : severity === "high" ? "badge-high" : severity === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{severity}</span>;
};

const severityFilters = ["All", "Critical", "High", "Medium", "Low"];

// Module-level cache — survives route changes
let _cachedThreats: NormThreat[] = [];

export default function Threats() {
  const [filter, setFilter] = useState("All");
  const [threats, setThreats] = useState<NormThreat[]>(_cachedThreats);
  const [selected, setSelected] = useState<NormThreat | null>(null);
  const [loading, setLoading] = useState(false);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  async function fetchThreats() {
    setLoading(true);
    try {
      const data = await getThreats(200);
      const mapped = (data as Record<string, unknown>[]).map(norm);
      _cachedThreats = mapped;
      if (mountedRef.current) setThreats(mapped);
    } catch { /* stay empty */ }
    if (mountedRef.current) setLoading(false);
  }

  useEffect(() => { fetchThreats(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const filtered = filter === "All" ? threats : threats.filter((t) => t.severity === filter.toLowerCase());
  const criticalCount = threats.filter((t) => t.severity === "critical").length;
  const highCount = threats.filter((t) => t.severity === "high").length;

  const severityChart = (["critical", "high", "medium", "low"] as const).map((s, i) => ({
    severity: s.charAt(0).toUpperCase() + s.slice(1),
    count: threats.filter((t) => t.severity === s).length,
    fill: COLORS[i],
  })).filter((d) => d.count > 0);

  const typeChart = (() => {
    const map: Record<string, number> = {};
    threats.forEach((t) => { map[t.threatType] = (map[t.threatType] ?? 0) + 1; });
    return Object.entries(map).map(([name, value]) => ({ name, value }));
  })();

  return (
    <AppLayout title="Threats" breadcrumb={["Firewall Analytics"]}>
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-card rounded-xl p-4 shadow-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Critical Threats</span>
            <ShieldX className="h-4 w-4 text-destructive" />
          </div>
          <p className="text-2xl font-bold tabular-nums text-destructive">{criticalCount}</p>
        </div>
        <div className="bg-card rounded-xl p-4 shadow-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">High Risk</span>
            <ShieldAlert className="h-4 w-4 text-warning" />
          </div>
          <p className="text-2xl font-bold tabular-nums text-warning">{highCount}</p>
        </div>
        <div className="bg-card rounded-xl p-4 shadow-card">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Total Detected</span>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </div>
          <p className="text-2xl font-bold tabular-nums text-foreground">{threats.length}</p>
        </div>
      </div>

      {threats.length === 0 ? (
        <div className="bg-card rounded-xl p-16 shadow-card text-center">
          <Shield className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
          <p className="text-[14px] font-medium text-foreground mb-2">No threats yet</p>
          <p className="text-[12px] text-muted-foreground">Upload a traffic CSV log to view detected threats.</p>
        </div>
      ) : (
        <>
          {/* ── Threat Verdict Banner ── */}
          {(() => {
            const isCritical = criticalCount > 0;
            const isWarning = !isCritical && highCount > 0;
            return (
              <div className={`rounded-xl p-5 mb-6 border ${
                isCritical ? "bg-red-950/40 border-red-800/40" :
                isWarning ? "bg-yellow-950/30 border-yellow-700/30" :
                "bg-emerald-950/30 border-emerald-700/30"
              }`}>
                <div className="flex items-center gap-4">
                  <div className={`h-14 w-14 rounded-2xl flex items-center justify-center text-2xl shrink-0 ${
                    isCritical ? "bg-red-900/60" : isWarning ? "bg-yellow-900/50" : "bg-emerald-900/50"
                  }`}>
                    {isCritical ? "🚨" : isWarning ? "⚠️" : "✅"}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-[15px] font-bold ${
                      isCritical ? "text-red-400" : isWarning ? "text-yellow-400" : "text-emerald-400"
                    }`}>
                      {isCritical ? `${criticalCount} Critical Threat${criticalCount !== 1 ? "s" : ""} Detected — Immediate Action Needed` :
                       isWarning ? `${highCount} High-Risk Threat${highCount !== 1 ? "s" : ""} Found — Review Recommended` :
                       "No Critical Threats — Network Looks Healthy"}
                    </h3>
                    <p className="text-[12px] text-muted-foreground mt-1">
                      {threats.length} total threat{threats.length !== 1 ? "s" : ""} detected across your network
                      {criticalCount > 0 && ` · ${criticalCount} critical`}
                      {highCount > 0 && ` · ${highCount} high-risk`}
                    </p>
                  </div>
                </div>
              </div>
            );
          })()}

          <div className="grid grid-cols-2 gap-6 mb-6">
            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Threats by Severity</h3>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={severityChart} layout="vertical">
                  <XAxis type="number" stroke="hsl(240,5%,40%)" fontSize={11} />
                  <YAxis type="category" dataKey="severity" stroke="hsl(240,5%,40%)" fontSize={11} width={60} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0,4,4,0]}>
                    {severityChart.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-card rounded-xl p-5 shadow-card">
              <h3 className="text-[13px] font-semibold text-foreground mb-4">Threat Type Distribution</h3>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={typeChart} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" paddingAngle={2}>
                    {typeChart.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "hsl(240,10%,6%)", border: "1px solid hsl(240,5%,12%)", borderRadius: 8, fontSize: 12 }} />
                  <Legend iconType="circle" wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-card rounded-xl p-5 shadow-card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-1">
                {severityFilters.map((f) => (
                  <button key={f} onClick={() => setFilter(f)}
                    className={`px-3 py-1.5 rounded-lg text-[11px] font-medium transition-smooth ${filter === f ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
                    {f}
                  </button>
                ))}
              </div>
              <Button size="sm" variant="ghost" className="h-7 text-[11px]" onClick={fetchThreats} disabled={loading}>
                <RefreshCw className={`h-3 w-3 mr-1.5 ${loading ? "animate-spin" : ""}`} />Refresh
              </Button>
            </div>
            <table className="w-full text-[12px]">
              <thead>
                <tr className="border-b border-border text-left">
                  {["Time", "Threat", "Type", "Severity", "Source IP", ""].map((h) => (
                    <th key={h} className="pb-2 text-[10px] uppercase tracking-widest text-muted-foreground font-bold">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((t) => (
                  <tr key={t.id} className="border-b border-border/50 hover:bg-primary/5 transition-smooth cursor-pointer" onClick={() => setSelected(t)}>
                    <td className="py-2 font-mono text-muted-foreground whitespace-nowrap">{(() => {
                      const parts = t.timestamp.split(" ");
                      const date = parts[0] ?? "";
                      const time = parts[1]?.slice(0, 5) ?? "";
                      return time ? `${date.slice(5)} ${time}` : "—";
                    })()}</td>
                    <td className="py-2 text-foreground font-medium max-w-[200px] truncate">
                      <SmartTooltip term={t.name} context={`Threat type: ${t.threatType}`} severity={t.severity} page="Threats">
                        {t.name}
                      </SmartTooltip>
                    </td>
                    <td className="py-2 text-muted-foreground">
                      <SmartTooltip term={t.threatType} context="Threat category" severity={t.severity} page="Threats">
                        {t.threatType}
                      </SmartTooltip>
                    </td>
                    <td className="py-2"><SeverityBadge severity={t.severity} /></td>
                    <td className="py-2 font-mono text-muted-foreground">{t.sourceIp}</td>
                    <td className="py-2"><Eye className="h-3.5 w-3.5 text-muted-foreground" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="bg-card border-border max-w-md">
          <DialogHeader><DialogTitle className="text-[14px] font-semibold">{selected?.name}</DialogTitle></DialogHeader>
          {selected && (
            <div className="space-y-3 mt-2">
              {/* Risk Score with context */}
              <div className="rounded-lg p-3 mb-1" style={{
                background: selected.riskScore >= 8 ? "rgba(239,68,68,0.08)" :
                  selected.riskScore >= 6 ? "rgba(249,115,22,0.08)" :
                  selected.riskScore >= 4 ? "rgba(234,179,8,0.08)" : "rgba(34,197,94,0.08)"
              }}>
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-muted-foreground uppercase tracking-wider font-bold">Risk Score</span>
                  <div className="text-right">
                    <span className={`text-xl font-bold tabular-nums ${
                      selected.riskScore >= 8 ? "text-destructive" : selected.riskScore >= 6 ? "text-warning" :
                      selected.riskScore >= 4 ? "text-primary" : "text-success"
                    }`}>{selected.riskScore}</span>
                    <span className="text-[10px] text-muted-foreground"> / 10</span>
                  </div>
                </div>
                <p className="text-[10px] text-muted-foreground mt-1">
                  {selected.riskScore >= 8 ? "Very dangerous — requires immediate attention" :
                   selected.riskScore >= 6 ? "Significant risk — should be addressed soon" :
                   selected.riskScore >= 4 ? "Moderate risk — plan to investigate" :
                   "Low risk — monitor as needed"}
                </p>
              </div>
              {[["Severity", <SeverityBadge severity={selected.severity} />],
                ["Threat Type", selected.threatType],
                ["Source Address", selected.sourceIp],
                ["Destination Address", selected.dstIp],
                ["Action Taken", selected.action],
                ["Detected At", selected.timestamp],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex items-center justify-between">
                  <span className="text-[11px] text-muted-foreground uppercase tracking-wider font-bold">{label}</span>
                  <span className="text-[12px] font-mono text-foreground">{value}</span>
                </div>
              ))}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </AppLayout>
  );
}
