import { useState, useEffect, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Search, ChevronDown, ChevronUp, CheckCircle2, Clock, CircleDot, Zap, Gauge, Hammer, RefreshCw, Wrench } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { toast } from "sonner";
import { getRemediation, type RemediationItem } from "@/lib/api";

type Status = "open" | "in-progress" | "resolved";

const filters = ["All", "Critical Only", "High Priority", "Open Items", "Resolved"];

const PriorityBadge = ({ priority }: { priority: string }) => {
  const cls = priority === "critical" ? "badge-critical" : priority === "high" ? "badge-high" : priority === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{priority}</span>;
};

const StatusIcon = ({ status }: { status: Status }) => {
  if (status === "resolved")    return <CheckCircle2 className="h-3.5 w-3.5 text-success" />;
  if (status === "in-progress") return <Clock className="h-3.5 w-3.5 text-warning" />;
  return <CircleDot className="h-3.5 w-3.5 text-muted-foreground" />;
};

const EffortBadge = ({ effort }: { effort: string }) => {
  const icon = effort === "easy" ? <Zap className="h-3 w-3" /> : effort === "medium" ? <Gauge className="h-3 w-3" /> : <Hammer className="h-3 w-3" />;
  const cls  = effort === "easy" ? "text-success bg-success/10" : effort === "medium" ? "text-warning bg-warning/10" : "text-destructive bg-destructive/10";
  const label = effort === "easy" ? "Quick Fix" : effort === "medium" ? "Some Effort" : "Complex Fix";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold capitalize inline-flex items-center gap-1`} title={label}>{icon}{effort}</span>;
};

const riskColor = (score: number) => score >= 8 ? "text-destructive" : score >= 6 ? "text-warning" : score >= 4 ? "text-primary" : "text-success";

interface Task {
  id: string; title: string; device: string; riskScore: number;
  priority: string; effort: string; category: string; recommendation: string;
}

function mapItem(item: RemediationItem): Task {
  return {
    id: item.rule_id ?? '',
    title: item.rule_name ?? 'Untitled Rule',
    device: item.device_name ?? 'Unknown Device',
    riskScore: Number(item.risk_score ?? 0),
    priority: item.risk_level ?? 'unknown',
    effort: item.effort ?? 'medium',
    category: item.category ?? 'uncategorized',
    recommendation: item.recommendation ?? 'No recommendation provided.',
  };
}

// Module-level cache — survives route changes
let _cachedRemTasks: Task[] = [];

export default function Remediation() {
  const [filter, setFilter]     = useState("All");
  const [search, setSearch]     = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [tasks, setTasks]       = useState<Task[]>(_cachedRemTasks);
  const [states, setStates]     = useState<Record<string, { status: Status; assignedTo: string }>>(
    Object.fromEntries(_cachedRemTasks.map((t) => [t.id, { status: "open" as Status, assignedTo: "" }]))
  );
  const [loading, setLoading]   = useState(false);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  async function fetchTasks() {
    setLoading(true);
    try {
      const data = await getRemediation();
      const mapped = data.map(mapItem);
      _cachedRemTasks = mapped;
      if (mountedRef.current) {
        setTasks(mapped);
        setStates(Object.fromEntries(mapped.map((t) => [t.id, { status: "open" as Status, assignedTo: "" }])));
      }
    } catch { /* stay empty */ }
    if (mountedRef.current) setLoading(false);
  }

  useEffect(() => { fetchTasks(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const priorityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

  const filtered = tasks
    .filter((t) => {
      if (search && !t.title.toLowerCase().includes(search.toLowerCase())) return false;
      const st = states[t.id]?.status ?? "open";
      if (filter === "Critical Only") return t.priority === "critical";
      if (filter === "High Priority") return t.priority === "critical" || t.priority === "high";
      if (filter === "Open Items")    return st === "open";
      if (filter === "Resolved")      return st === "resolved";
      return true;
    })
    .sort((a, b) => (priorityOrder[a.priority] ?? 3) - (priorityOrder[b.priority] ?? 3));

  function cycleStatus(id: string) {
    setStates((prev) => {
      const cur  = prev[id]?.status ?? "open";
      const next: Status = cur === "open" ? "in-progress" : cur === "in-progress" ? "resolved" : "open";
      return { ...prev, [id]: { ...prev[id], status: next } };
    });
    toast.success("Task status updated");
  }

  const criticalCount    = tasks.filter((t) => t.priority === "critical").length;
  const inProgressCount  = Object.values(states).filter((s) => s.status === "in-progress").length;
  const resolvedCount    = Object.values(states).filter((s) => s.status === "resolved").length;

  return (
    <AppLayout title="Remediation" breadcrumb={["Firewall Analytics"]}>
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[["Total Issues", tasks.length, "text-foreground"],["Critical", criticalCount, "text-destructive"],
          ["In Progress", inProgressCount, "text-warning"],["Resolved", resolvedCount, "text-success"]].map(([label, value, color]) => (
          <div key={String(label)} className="bg-card rounded-xl p-4 shadow-card">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">{label}</p>
            <p className={`text-2xl font-bold tabular-nums mt-1 ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* ── Remediation Insights Panel ── */}
      {tasks.length > 0 && (() => {
        const total = tasks.length;
        const resolved = resolvedCount;
        const pct = total > 0 ? Math.round((resolved / total) * 100) : 0;
        const topItems = [...tasks].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);
        const catCounts: Record<string, number> = {};
        tasks.forEach(t => { catCounts[t.category] = (catCounts[t.category] || 0) + 1; });
        const topCats = Object.entries(catCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
        const isCriticalPosture = criticalCount > 0 && resolvedCount < criticalCount;

        return (
          <>
            {/* Status Verdict Banner */}
            <div className={`rounded-xl p-5 mb-6 border ${
                isCriticalPosture ? "bg-red-950/40 border-red-800/40" :
                pct >= 80 ? "bg-emerald-950/30 border-emerald-700/30" :
                pct >= 40 ? "bg-yellow-950/30 border-yellow-700/30" :
                "bg-orange-950/30 border-orange-700/30"
            }`}>
              <div className="flex items-center gap-4">
                <div className={`h-14 w-14 rounded-2xl flex items-center justify-center text-2xl shrink-0 ${
                  isCriticalPosture ? "bg-red-900/60" : pct >= 80 ? "bg-emerald-900/50" : pct >= 40 ? "bg-yellow-900/50" : "bg-orange-900/50"
                }`}>
                  {isCriticalPosture ? "🚨" : pct >= 80 ? "✅" : pct >= 40 ? "🔧" : "⚠️"}
                </div>
                <div className="flex-1">
                  <h3 className={`text-[15px] font-bold ${
                    isCriticalPosture ? "text-red-400" : pct >= 80 ? "text-emerald-400" : pct >= 40 ? "text-yellow-400" : "text-orange-400"
                  }`}>
                    {isCriticalPosture ? `${criticalCount} Critical Issue${criticalCount !== 1 ? "s" : ""} Need Immediate Attention` :
                     pct >= 80 ? "Remediation Nearly Complete" :
                     pct >= 40 ? "Good Progress — Keep Going" :
                     `${total - resolved} Issue${total - resolved !== 1 ? "s" : ""} Require Remediation`}
                  </h3>
                  <p className="text-[12px] text-muted-foreground mt-1">
                    {resolved} of {total} issues resolved · {inProgressCount} in progress
                    {criticalCount > 0 && ` · ${criticalCount} critical`}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <p className={`text-3xl font-bold tabular-nums ${pct >= 80 ? "text-emerald-400" : pct >= 40 ? "text-yellow-400" : "text-orange-400"}`}>
                    {pct}%
                  </p>
                  <p className="text-[10px] text-muted-foreground">Resolved</p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-3 gap-4 mb-6">
              {/* Progress Ring */}
              <div className="bg-card rounded-xl p-5 shadow-card flex items-center gap-5">
                <div className="relative h-20 w-20 shrink-0">
                  <svg viewBox="0 0 36 36" className="h-20 w-20 -rotate-90">
                    <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(240,5%,15%)" strokeWidth="3" />
                    <circle cx="18" cy="18" r="15.9" fill="none"
                      stroke={pct >= 80 ? "#22c55e" : pct >= 50 ? "#eab308" : "#ef4444"}
                      strokeWidth="3" strokeDasharray={`${pct} ${100 - pct}`} strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className={`text-[16px] font-bold tabular-nums ${pct >= 80 ? "text-success" : pct >= 50 ? "text-warning" : "text-destructive"}`}>{pct}%</span>
                  </div>
                </div>
                <div>
                  <p className="text-[13px] font-semibold text-foreground">Completion</p>
                  <p className="text-[11px] text-muted-foreground mt-1">{resolved} of {total} resolved</p>
                  <p className="text-[11px] text-muted-foreground">{inProgressCount} in progress</p>
                </div>
              </div>

              {/* Top Priority Items */}
              <div className="bg-card rounded-xl p-5 shadow-card">
                <div className="flex items-center gap-2 mb-3">
                  <Zap className="h-4 w-4 text-warning" />
                  <p className="text-[13px] font-semibold text-foreground">Top Priority</p>
                </div>
                <div className="space-y-2">
                  {topItems.map(item => (
                    <div key={item.id} className="flex items-center gap-2 bg-destructive/5 rounded-lg p-2">
                      <span className={`text-[12px] font-bold tabular-nums shrink-0 ${riskColor(item.riskScore)}`}>
                        {item.riskScore.toFixed(1)}
                      </span>
                      <p className="text-[11px] text-foreground truncate flex-1">{item.title}</p>
                      <span className={`${
                        item.priority === "critical" ? "badge-critical" : "badge-high"
                      } px-1.5 py-0.5 rounded text-[8px] font-semibold uppercase shrink-0`}>{item.priority}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Category Breakdown */}
              <div className="bg-card rounded-xl p-5 shadow-card">
                <p className="text-[13px] font-semibold text-foreground mb-3">Issue Categories</p>
                {topCats.length > 0 ? (
                  <div className="space-y-2">
                    {topCats.map(([cat, count]) => {
                      const pctCat = (count / total) * 100;
                      const friendlyCats: Record<string, string> = {
                        overly_permissive: "Too Broad Access",
                        weak_authentication: "Weak Login Security",
                        unnecessary_exposure: "Unnecessary Exposure",
                        insecure_protocol: "Insecure Protocols",
                        missing_logging: "Missing Activity Logs",
                        uncategorized: "General Issues",
                      };
                      const displayName = friendlyCats[cat] || cat.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
                      return (
                        <div key={cat}>
                          <div className="flex items-center justify-between text-[11px] mb-0.5">
                            <span className="text-foreground">{displayName}</span>
                            <span className="text-muted-foreground tabular-nums">{count}</span>
                          </div>
                          <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                            <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${pctCat}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-[11px] text-muted-foreground">No categories detected</p>
                )}
              </div>
            </div>
          </>
        );
      })()}

      <div className="flex items-center gap-3 mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input placeholder="Search tasks…" value={search} onChange={(e) => setSearch(e.target.value)}
            className="pl-9 h-8 text-[12px] bg-secondary border-border w-56" />
        </div>
        <div className="flex items-center gap-1">
          {filters.map((f) => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg text-[11px] font-medium transition-smooth ${filter === f ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
              {f}
            </button>
          ))}
        </div>
        <Button size="sm" variant="ghost" className="h-7 text-[11px] ml-auto" onClick={fetchTasks} disabled={loading}>
          <RefreshCw className={`h-3 w-3 mr-1.5 ${loading ? "animate-spin" : ""}`} />Refresh
        </Button>
      </div>

      {tasks.length === 0 && !loading ? (
        <div className="bg-card rounded-xl p-16 shadow-card text-center">
          <Wrench className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
          <p className="text-[14px] font-medium text-foreground mb-2">No remediation items yet</p>
          <p className="text-[12px] text-muted-foreground">Upload a firewall config — risk analysis runs automatically and populates this list.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((task) => {
            const state = states[task.id] ?? { status: "open", assignedTo: "" };
            return (
              <div key={task.id} className="bg-card rounded-xl shadow-card overflow-hidden">
                <div
                  className="w-full flex items-center gap-4 p-4 text-left"
                  role="button"
                  tabIndex={0}
                  onClick={() => setExpanded(expanded === task.id ? null : task.id)}
                  onKeyDown={(e) => {
                    if (e.key !== "Enter" && e.key !== " ") return;
                    e.preventDefault();
                    setExpanded(expanded === task.id ? null : task.id);
                  }}
                >
                  <button onClick={(e) => { e.stopPropagation(); cycleStatus(task.id); }} className="shrink-0 hover:scale-110 transition-smooth" title={`Status: ${state.status} — Click to change`}>
                    <StatusIcon status={state.status} />
                  </button>
                  <span className={`text-[15px] font-bold tabular-nums shrink-0 ${riskColor(task.riskScore)}`}>
                    <SmartTooltip term={`Risk Score ${task.riskScore.toFixed(1)}`} context={`Risk score for ${task.title} — ${task.riskScore >= 8 ? "Very dangerous" : task.riskScore >= 6 ? "Significant risk" : task.riskScore >= 4 ? "Moderate risk" : "Low risk"}`} severity={task.priority} page="Remediation">
                      {task.riskScore.toFixed(1)}
                    </SmartTooltip>
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-medium text-foreground truncate">
                      <SmartTooltip term={task.title} context={`Firewall rule on ${task.device}`} severity={task.priority} page="Remediation">
                        {task.title}
                      </SmartTooltip>
                    </p>
                    <p className="text-[10px] text-muted-foreground">{task.device}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <PriorityBadge priority={task.priority} />
                    <EffortBadge effort={task.effort} />
                    {expanded === task.id ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                  </div>
                </div>
                {expanded === task.id && (
                  <div className="px-4 pb-4 pt-0 border-t border-border space-y-3">
                    {task.recommendation && (
                      <p className="text-[12px] text-muted-foreground mt-3">
                        <span className="text-foreground font-medium">Recommendation: </span>
                        <SmartTooltip term={task.recommendation} context={`Fix for ${task.title}`} page="Remediation">
                          {task.recommendation}
                        </SmartTooltip>
                      </p>
                    )}
                    {task.category && (
                      <p className="text-[11px] text-muted-foreground">
                        <span className="text-foreground font-medium">Category: </span>
                        <SmartTooltip term={task.category} context="Vulnerability category" severity={task.priority} page="Remediation">
                          {task.category}
                        </SmartTooltip>
                      </p>
                    )}
                    <div className="flex items-center gap-3 mt-3">
                      <label className="text-[11px] text-muted-foreground shrink-0">Assigned to:</label>
                      <input value={state.assignedTo}
                        onChange={(e) => setStates((prev) => ({ ...prev, [task.id]: { ...prev[task.id], assignedTo: e.target.value } }))}
                        placeholder="Enter name or team…"
                        className="flex-1 h-7 px-3 rounded-lg bg-secondary border border-border text-[11px] text-foreground placeholder:text-muted-foreground"
                        onClick={(e) => e.stopPropagation()} />
                      <Button size="sm" className="h-7 text-[11px]" onClick={(e) => { e.stopPropagation(); toast.success("Task saved"); }}>Save</Button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {filtered.length === 0 && <div className="bg-card rounded-xl p-8 text-center text-[12px] text-muted-foreground shadow-card">No tasks match the current filters.</div>}
        </div>
      )}
    </AppLayout>
  );
}
