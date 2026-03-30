import { useState, useEffect, useCallback, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import {
  ChevronDown, ChevronUp, Loader2, RefreshCw,
  AlertTriangle, Shield, X, Info, Zap, Lock, AlertCircle
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { CompromiseNarrativeCard } from "@/components/CompromiseNarrative";
import { IpVulnerabilitySection } from "@/components/IpVulnerabilitySection";
import {
  getAttackPaths, getAttackPathSummary, getMalwareEntryPoints,
  getAttackGraph,
  type GraphNode, type GraphEdge, type AttackGraph,
} from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Hop {
  target: string;
  port: string;
  risk: number;
  rule_name: string;
  from?: string;
}

interface Path {
  id: string;
  entry_point: string;
  target: string;
  hops: number;
  total_risk_score: number;
  risk_level: string;
  path_nodes: string[];
  path_hops: Hop[];
  weakest_link: string;
  vulnerable_ports: string[];
  attack_difficulty: number;
}

interface EntryPoint {
  node_id: string;
  device_name: string;
  zone: string;
  ip_address: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const num = (v: unknown, fb = 0): number => {
  const n = typeof v === "number" ? v : parseFloat(String(v ?? fb));
  return isNaN(n) ? fb : n;
};

const riskHex = (score: unknown): string => {
  const s = num(score);
  if (s >= 8) return "#ef4444";
  if (s >= 6) return "#f97316";
  if (s >= 3) return "#eab308";
  return "#22c55e";
};

const riskLabel = (level: string) => {
  const m: Record<string, string> = {
    critical: "badge-critical", high: "badge-high",
    medium: "badge-medium", low: "badge-low",
  };
  return m[level] ?? "badge-low";
};

// ── NODE DETAIL PANEL ─────────────────────────────────────────────────────────

function NodePanel({
  node, edges, onClose,
}: {
  node: GraphNode;
  edges: GraphEdge[];
  onClose: () => void;
}) {
  const inbound  = edges.filter((e) => e.target === node.id && !e.is_deny);
  const outbound = edges.filter((e) => e.source === node.id && !e.is_deny);
  const denied   = edges.filter((e) => (e.source === node.id || e.target === node.id) && e.is_deny);
  const maxRisk  = Math.max(...inbound.map((e) => num(e.risk_score)), 0);

  return (
    <div className="fixed right-0 top-0 h-full w-80 bg-card border-l border-border shadow-2xl z-50 overflow-y-auto">
      <div className="flex items-center justify-between p-4 border-b border-border sticky top-0 bg-card">
        <div>
          <p className="text-[13px] font-semibold text-foreground">{node.label}</p>
          <p className="text-[10px] text-muted-foreground font-mono">{node.ip_address}</p>
        </div>
        <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-smooth">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Zone info */}
        <div className="space-y-2">
          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Zone Details</p>
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="bg-secondary/40 rounded p-2">
              <p className="text-muted-foreground">Type</p>
              <p className="text-foreground font-medium capitalize">{node.device_type}</p>
            </div>
            <div className="bg-secondary/40 rounded p-2">
              <p className="text-muted-foreground">Role</p>
              <p className={`font-medium ${node.is_entry_point ? "text-blue-400" : node.is_target ? "text-red-400" : "text-foreground"}`}>
                {node.is_entry_point ? "Entry Point" : node.is_target ? "Attack Target" : "Internal"}
              </p>
            </div>
            <div className="bg-secondary/40 rounded p-2">
              <p className="text-muted-foreground">Max Inbound Risk</p>
              <p className="font-bold" style={{ color: riskHex(maxRisk) }}>{maxRisk.toFixed(1)}</p>
            </div>
            <div className="bg-secondary/40 rounded p-2">
              <p className="text-muted-foreground">Device</p>
              <p className="text-foreground font-medium truncate">{node.device_name}</p>
            </div>
          </div>
        </div>

        {/* Inbound allow rules */}
        {inbound.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">
              Inbound Allow Rules ({inbound.length})
            </p>
            <div className="space-y-1.5">
              {inbound.map((e) => (
                <div key={e.id} className="bg-secondary/30 rounded p-2 text-[11px]">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-foreground font-medium truncate">{e.rule_name}</span>
                    <span className="font-bold ml-2 shrink-0" style={{ color: riskHex(e.risk_score) }}>
                      {num(e.risk_score).toFixed(1)}
                    </span>
                  </div>
                  <p className="text-muted-foreground">
                    From: <span className="text-foreground">{e.source}</span>
                    {e.port !== "any" && <> · Port <span className="font-mono">{e.port}</span></>}
                  </p>
                  {e.reason && <p className="text-warning/80 mt-0.5 text-[10px]">{e.reason}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Outbound allow rules */}
        {outbound.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">
              Outbound Allow Rules ({outbound.length})
            </p>
            <div className="space-y-1.5">
              {outbound.map((e) => (
                <div key={e.id} className="bg-secondary/30 rounded p-2 text-[11px]">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-foreground font-medium truncate">{e.rule_name}</span>
                    <span className="font-bold ml-2 shrink-0" style={{ color: riskHex(e.risk_score) }}>
                      {num(e.risk_score).toFixed(1)}
                    </span>
                  </div>
                  <p className="text-muted-foreground">
                    To: <span className="text-foreground">{e.target}</span>
                    {e.port !== "any" && <> · Port <span className="font-mono">{e.port}</span></>}
                  </p>
                  {e.recommendation && (
                    <p className="text-success/80 mt-0.5 text-[10px]">{e.recommendation}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Deny rules */}
        {denied.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">
              Deny Rules ({denied.length})
            </p>
            <div className="space-y-1.5">
              {denied.map((e) => (
                <div key={e.id} className="bg-destructive/10 rounded p-2 text-[11px]">
                  <p className="text-foreground font-medium">{e.rule_name}</p>
                  <p className="text-muted-foreground">{e.source} → {e.target} · Port {e.port}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── FULL ATTACK GRAPH (forced layout) ────────────────────────────────────────

function AttackGraphView({
  graph,
  onNodeClick,
  selectedNode,
}: {
  graph: AttackGraph;
  onNodeClick: (node: GraphNode) => void;
  selectedNode: string | null;
}) {
  const [hoveredEdge, setHoveredEdge] = useState<string | null>(null);
  const [filterDeny, setFilterDeny]   = useState(false);
  const svgRef = useRef<SVGSVGElement>(null);

  const { nodes, edges } = graph;

  // ── Layered layout ────────────────────────────────────────────────────────
  const allowEdges = filterDeny ? edges.filter((e) => !e.is_deny) : edges;

  // Assign layers: entry=0, then BFS outward
  const layerOf: Record<string, number> = {};
  nodes.forEach((nd) => {
    layerOf[nd.id] = nd.is_entry_point ? 0 : nd.is_target ? 999 : -1;
  });

  let changed = true;
  let pass = 0;
  while (changed && pass < 20) {
    changed = false; pass++;
    allowEdges.forEach(({ source, target, is_deny }) => {
      if (is_deny) return;
      const newL = (layerOf[source] ?? 0) + 1;
      if (newL > (layerOf[target] ?? -1) && layerOf[target] !== 999) {
        layerOf[target] = newL;
        changed = true;
      }
    });
  }
  // Targets always go last
  const maxLayer = Math.max(...Object.values(layerOf).filter((v) => v !== 999), 1);
  nodes.forEach((nd) => { if (nd.is_target) layerOf[nd.id] = maxLayer + 1; });
  nodes.forEach((nd) => { if (layerOf[nd.id] === -1) layerOf[nd.id] = Math.floor(maxLayer / 2); });

  const byLayer: Record<number, GraphNode[]> = {};
  nodes.forEach((nd) => {
    const l = layerOf[nd.id] ?? 0;
    byLayer[l] = byLayer[l] ?? [];
    byLayer[l].push(nd);
  });

  const layers = Object.keys(byLayer).map(Number).sort((a, b) => a - b);
  const W = Math.max(900, layers.length * 180);
  const H = Math.max(400, Math.max(...layers.map((l) => (byLayer[l]?.length ?? 0))) * 90 + 80);
  const PAD_X = 90, PAD_Y = 60;
  const NR = 32; // node radius

  const positions: Record<string, { x: number; y: number }> = {};
  layers.forEach((layer, li) => {
    const nodesInLayer = byLayer[layer] ?? [];
    const x = layers.length === 1
      ? W / 2
      : PAD_X + li * ((W - PAD_X * 2) / Math.max(layers.length - 1, 1));
    nodesInLayer.forEach((nd, ni) => {
      const total = nodesInLayer.length;
      const y = total === 1
        ? H / 2
        : PAD_Y + ni * ((H - PAD_Y * 2) / Math.max(total - 1, 1));
      positions[nd.id] = { x, y };
    });
  });

  return (
    <div className="bg-card rounded-xl p-5 shadow-card mb-6">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-[13px] font-semibold text-foreground">Full Attack Graph</h3>
          <p className="text-[11px] text-muted-foreground mt-0.5">
            {graph.stats.total_nodes} zones · {graph.stats.allow_edges} allow edges ·{" "}
            <span className="text-destructive">{graph.stats.high_risk_edges} high-risk</span>
            {" · "}Click any zone to inspect its rules
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFilterDeny(!filterDeny)}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-medium transition-smooth border ${
              filterDeny
                ? "bg-primary text-primary-foreground border-primary"
                : "text-muted-foreground border-border hover:text-foreground"
            }`}
          >
            {filterDeny ? "Allow rules only" : "Show all rules"}
          </button>
        </div>
      </div>

      <div className="overflow-x-auto">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${W} ${H}`}
          style={{ width: "100%", height: Math.min(H, 480), display: "block" }}
        >
          <defs>
            <marker id="ag-arr" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill="#6b7280" />
            </marker>
            <marker id="ag-arr-red" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill="#ef4444" />
            </marker>
            <marker id="ag-arr-deny" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L7,3 z" fill="#374151" />
            </marker>
            <filter id="glow">
              <feGaussianBlur stdDeviation="2" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>

          {/* Edges */}
          {allowEdges.map((edge, i) => {
            const from = positions[edge.source];
            const to   = positions[edge.target];
            if (!from || !to || edge.source === edge.target) return null;

            const isHigh  = num(edge.risk_score) >= 6;
            const isDeny  = edge.is_deny;
            const isHov   = hoveredEdge === edge.id;
            const dx = to.x - from.x, dy = to.y - from.y;
            const len = Math.sqrt(dx * dx + dy * dy) || 1;
            const x1 = from.x + (dx / len) * NR;
            const y1 = from.y + (dy / len) * NR;
            const x2 = to.x   - (dx / len) * NR;
            const y2 = to.y   - (dy / len) * NR;

            // Slight curve for parallel edges
            const mx = (x1 + x2) / 2 - dy * 0.15;
            const my = (y1 + y2) / 2 + dx * 0.15;

            const stroke = isDeny ? "#374151" : isHigh ? "#ef4444" : "#4b5563";
            const marker = isDeny ? "url(#ag-arr-deny)" : isHigh ? "url(#ag-arr-red)" : "url(#ag-arr)";

            return (
              <g key={i}>
                <path
                  d={`M ${x1},${y1} Q ${mx},${my} ${x2},${y2}`}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={isHov ? 3 : isHigh ? 2 : 1.5}
                  strokeDasharray={isDeny ? "3 3" : isHigh ? "none" : "4 3"}
                  markerEnd={marker}
                  opacity={isHov ? 1 : isDeny ? 0.25 : 0.65}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHoveredEdge(edge.id)}
                  onMouseLeave={() => setHoveredEdge(null)}
                />
                {isHov && (
                  <g>
                    <rect
                      x={(x1 + x2) / 2 - 70} y={(y1 + y2) / 2 - 28}
                      width={140} height={20} rx={4}
                      fill="#111827" stroke="#374151" strokeWidth={1} opacity={0.95}
                    />
                    <text
                      x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 14}
                      textAnchor="middle" fontSize={8.5} fill="#f3f4f6"
                    >
                      {edge.rule_name.slice(0, 22)}{edge.rule_name.length > 22 ? "…" : ""} · :{edge.port} · risk {num(edge.risk_score).toFixed(1)}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((nd) => {
            const pos = positions[nd.id];
            if (!pos) return null;
            const { x, y } = pos;
            const isEntry    = nd.is_entry_point;
            const isTarget   = nd.is_target;
            const isSelected = selectedNode === nd.id;
            const fillColor  = isTarget ? "#7f1d1d" : isEntry ? "#1e3a5f" : "#1f2937";
            const ringColor  = isTarget ? "#ef4444" : isEntry ? "#3b82f6" : "#374151";
            const label      = nd.label.length > 12 ? nd.label.slice(0, 12) + "…" : nd.label;

            // Inbound risk glow
            const inboundRisk = Math.max(
              ...edges.filter((e) => e.target === nd.id && !e.is_deny).map((e) => num(e.risk_score)),
              0
            );

            return (
              <g
                key={nd.id}
                style={{ cursor: "pointer" }}
                onClick={() => onNodeClick(nd)}
              >
                {/* Glow for high-risk nodes */}
                {inboundRisk >= 6 && (
                  <circle cx={x} cy={y} r={NR + 8} fill={riskHex(inboundRisk)} opacity={0.15} filter="url(#glow)" />
                )}
                {/* Selection ring */}
                {isSelected && (
                  <circle cx={x} cy={y} r={NR + 5} fill="none" stroke="#a78bfa" strokeWidth={2} />
                )}
                {/* Entry/Target outer ring */}
                {(isEntry || isTarget) && (
                  <circle cx={x} cy={y} r={NR + 3} fill="none" stroke={ringColor} strokeWidth={1.5} strokeDasharray="4 2" opacity={0.6} />
                )}
                {/* Main circle */}
                <circle cx={x} cy={y} r={NR} fill={fillColor} stroke={ringColor} strokeWidth={2} />
                {/* Zone icon */}
                <text x={x} y={y - 7} textAnchor="middle" fontSize={14} fill={isTarget ? "#fca5a5" : isEntry ? "#93c5fd" : "#9ca3af"}>
                  {isTarget ? "🎯" : isEntry ? "🌐" : "🔒"}
                </text>
                {/* Label */}
                <text x={x} y={y + 8} textAnchor="middle" fontSize={8} fill="#f9fafb" fontWeight="600">
                  {label}
                </text>
                {/* Role badge */}
                {isEntry  && <text x={x} y={y + 20} textAnchor="middle" fontSize={6.5} fill="#93c5fd">ENTRY</text>}
                {isTarget && <text x={x} y={y + 20} textAnchor="middle" fontSize={6.5} fill="#fca5a5">TARGET</text>}
                {/* Risk dot */}
                {inboundRisk >= 6 && (
                  <circle cx={x + NR - 4} cy={y - NR + 4} r={5} fill={riskHex(inboundRisk)} stroke="#111827" strokeWidth={1} />
                )}
              </g>
            );
          })}
        </svg>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 mt-3 pt-3 border-t border-border text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-blue-900 border border-blue-500 inline-block"/>Entry point</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-red-900 border border-red-500 inline-block"/>Attack target</span>
        <span className="flex items-center gap-1.5"><span className="inline-block w-4 h-0.5 bg-red-500"/>High-risk allow</span>
        <span className="flex items-center gap-1.5"><span className="inline-block w-4 h-0.5 bg-gray-600" style={{borderTop:"2px dashed #4b5563",height:0}}/>Low-risk allow</span>
        <span className="flex items-center gap-1.5"><span className="inline-block w-4 h-0.5" style={{borderTop:"2px dashed #374151",height:0}}/>Deny</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-full bg-red-500 opacity-50 inline-block"/>High inbound risk</span>
        <span className="ml-auto text-purple-400">Purple ring = selected zone</span>
      </div>
    </div>
  );
}

// ── SEQUENTIAL PATH FLOW ──────────────────────────────────────────────────────

function PathFlow({ path }: { path: Path }) {
  const nodes = Array.isArray(path.path_nodes) && path.path_nodes.length > 0
    ? path.path_nodes.filter(Boolean)
    : [path.entry_point, path.target].filter(Boolean);

  return (
    <div className="overflow-x-auto pb-2">
      <div className="flex items-center gap-0 min-w-max">
        {nodes.map((node, i) => {
          const hop = path.path_hops?.[i - 1];
          const isEntry  = i === 0;
          const isTarget = i === nodes.length - 1;
          const hopRisk  = num(hop?.risk);

          return (
            <div key={i} className="flex items-center gap-0">
              {/* Arrow + hop info */}
              {i > 0 && (
                <div className="flex flex-col items-center mx-1">
                  <div className="flex items-center gap-1">
                    <div
                      className="h-0.5 w-12"
                      style={{ backgroundColor: riskHex(hopRisk) }}
                    />
                    <div
                      className="w-0 h-0"
                      style={{
                        borderTop: "4px solid transparent",
                        borderBottom: "4px solid transparent",
                        borderLeft: `6px solid ${riskHex(hopRisk)}`,
                      }}
                    />
                  </div>
                  {hop && (
                    <div className="text-center mt-0.5">
                      <p className="text-[8px] font-mono text-muted-foreground">
                        :{hop.port !== "any" ? hop.port : "*"}
                      </p>
                      <p className="text-[7px]" style={{ color: riskHex(hopRisk) }}>
                        {hopRisk.toFixed(1)}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {/* Node box */}
              <div
                className={`flex flex-col items-center justify-center rounded-lg border px-3 py-2 min-w-[80px] text-center ${
                  isTarget
                    ? "bg-red-950/50 border-red-700"
                    : isEntry
                    ? "bg-blue-950/50 border-blue-700"
                    : "bg-secondary/60 border-border"
                }`}
              >
                <span className="text-base mb-0.5">
                  {isTarget ? "🎯" : isEntry ? "🌐" : "🔒"}
                </span>
                <p className="text-[9px] font-medium text-foreground leading-tight">
                  {node.replace(/_/g, " ")}
                </p>
                {isEntry  && <p className="text-[7px] text-blue-400 mt-0.5">ENTRY</p>}
                {isTarget && <p className="text-[7px] text-red-400 mt-0.5">TARGET</p>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Module-level cache: data survives React Router unmounts ──────────────────
// First visit: all empty, loading=true. Return visit: shows cached data
// instantly while a background re-fetch refreshes it silently.
const _ap = {
  paths:       [] as Path[],
  graph:       null as AttackGraph | null,
  entryPoints: [] as EntryPoint[],
  summary:     null as { critical_paths_count: number; high_risk_paths_count: number; average_path_risk: number; } | null,
  fetched:     false,
};

// ── MAIN PAGE ─────────────────────────────────────────────────────────────────

export default function AttackPaths() {
  const [paths, setPaths]           = useState<Path[]>(_ap.paths);
  const [graph, setGraph]           = useState<AttackGraph | null>(_ap.graph);
  const [entryPoints, setEntryPts]  = useState<EntryPoint[]>(_ap.entryPoints);
  const [summary, setSummary]       = useState<{
    critical_paths_count: number;
    high_risk_paths_count: number;
    average_path_risk: number;
  } | null>(_ap.summary);
  const [loading, setLoading]       = useState(!_ap.fetched);
  const [expanded, setExpanded]     = useState<string | null>(null);
  const [selectedNode, setSelected] = useState<GraphNode | null>(null);
  const [activeTab, setTab]         = useState<"graph" | "paths">("graph");
  const [error, setError]           = useState("");
  const mountedRef = useRef(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [p, s, e, g] = await Promise.allSettled([
        getAttackPaths(0, 50),
        getAttackPathSummary(),
        getMalwareEntryPoints(),
        getAttackGraph(),
      ]);
      if (!mountedRef.current) return;
      if (p.status === "fulfilled") { const v = (p.value as Path[]) ?? []; setPaths(v); _ap.paths = v; }
      if (s.status === "fulfilled") { setSummary(s.value); _ap.summary = s.value; }
      if (e.status === "fulfilled") { const v = (e.value as EntryPoint[]) ?? []; setEntryPts(v); _ap.entryPoints = v; }
      if (g.status === "fulfilled") { setGraph(g.value); _ap.graph = g.value; }
      _ap.fetched = true;
    } catch {
      if (mountedRef.current) setError("Failed to load attack data.");
    }
    if (mountedRef.current) setLoading(false);
  }, []);

  // Auto-refresh every 30s + listen for upload-complete event (instant update)
  useEffect(() => {
    mountedRef.current = true;
    load();
    const id = setInterval(load, 30_000);
    const onUpload = () => { setTimeout(load, 2000); }; // 2s delay for backend to finish
    window.addEventListener("firewall-upload-complete", onUpload);
    return () => {
      mountedRef.current = false;
      clearInterval(id);
      window.removeEventListener("firewall-upload-complete", onUpload);
    };
  }, [load]);

  const hasData = paths.length > 0 || (graph && graph.nodes.length > 0);

  return (
    <AppLayout title="Attack Paths" breadcrumb={["Firewall Analytics"]}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[15px] font-semibold text-foreground">Attack Path Analysis</h2>
          <p className="text-[12px] text-muted-foreground mt-0.5">
            Dynamic — powered entirely by your uploaded firewall config.
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={load} disabled={loading} className="text-[11px]">
          <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-[13px] text-muted-foreground py-20 justify-center">
          <Loader2 className="h-5 w-5 animate-spin" />
          Loading attack data…
        </div>
      ) : error ? (
        <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-6 flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 text-destructive shrink-0" />
          <p className="text-[13px] text-destructive">{error}</p>
        </div>
      ) : !hasData ? (
        <div className="bg-card rounded-xl p-14 shadow-card text-center">
          <Shield className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-[15px] font-semibold text-foreground mb-2">No data yet</p>
          <p className="text-[12px] text-muted-foreground">
            Upload a firewall config on the Dashboard — attack paths and the full
            topology graph are calculated automatically.
          </p>
        </div>
      ) : (
        <>
          {/* ── Risk Verdict Banner ── */}
          {(() => {
            const critCount = summary?.critical_paths_count ?? 0;
            const highCount = summary?.high_risk_paths_count ?? 0;
            const avgRisk = num(summary?.average_path_risk);
            const totalPaths = paths.length;
            const isCritical = critCount > 0;
            const isHigh = highCount > 0;
            const isClean = totalPaths === 0 || avgRisk < 3;

            return (
              <div className={`rounded-xl p-5 mb-6 border ${
                isCritical ? "bg-red-950/40 border-red-800/40" :
                isHigh ? "bg-orange-950/30 border-orange-700/30" :
                isClean ? "bg-emerald-950/30 border-emerald-700/30" :
                "bg-yellow-950/30 border-yellow-700/30"
              }`}>
                <div className="flex items-center gap-4">
                  <div className={`h-14 w-14 rounded-2xl flex items-center justify-center text-2xl shrink-0 ${
                    isCritical ? "bg-red-900/60" : isHigh ? "bg-orange-900/50" : isClean ? "bg-emerald-900/50" : "bg-yellow-900/50"
                  }`}>
                    {isCritical ? "🚨" : isHigh ? "⚠️" : isClean ? "✅" : "🔍"}
                  </div>
                  <div className="flex-1">
                    <h3 className={`text-[15px] font-bold ${
                      isCritical ? "text-red-400" : isHigh ? "text-orange-400" : isClean ? "text-emerald-400" : "text-yellow-400"
                    }`}>
                      {isCritical ? "Critical Attack Paths Detected" :
                       isHigh ? "High-Risk Attack Paths Found" :
                       isClean ? "No Significant Attack Paths" :
                       "Moderate Risk Detected"}
                    </h3>
                    <p className="text-[12px] text-muted-foreground mt-1 leading-relaxed">
                      {isCritical
                        ? `${critCount} critical path${critCount !== 1 ? "s" : ""} can be exploited to reach sensitive targets. Immediate action required — go to Remediation.`
                        : isHigh
                        ? `${highCount} high-risk path${highCount !== 1 ? "s" : ""} detected across your network. Review and remediate soon.`
                        : isClean
                        ? "Your firewall configuration shows no significant attack paths between entry points and critical targets."
                        : `${totalPaths} attack path${totalPaths !== 1 ? "s" : ""} identified with an average risk of ${avgRisk.toFixed(1)}/10. Monitor these paths regularly.`}
                    </p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={`text-3xl font-bold tabular-nums ${
                      avgRisk >= 8 ? "text-red-400" : avgRisk >= 6 ? "text-orange-400" : avgRisk >= 3 ? "text-yellow-400" : "text-emerald-400"
                    }`}>{avgRisk.toFixed(1)}</p>
                    <p className="text-[10px] text-muted-foreground">Avg Risk Score</p>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Summary cards */}
          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-card rounded-xl p-4 shadow-card">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">Critical Paths</p>
              <p className="text-2xl font-bold tabular-nums text-red-500">{summary?.critical_paths_count ?? 0}</p>
            </div>
            <div className="bg-card rounded-xl p-4 shadow-card">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">High Risk Paths</p>
              <p className="text-2xl font-bold tabular-nums text-orange-400">{summary?.high_risk_paths_count ?? 0}</p>
            </div>
            <div className="bg-card rounded-xl p-4 shadow-card">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">Avg Risk Score</p>
              <p className="text-2xl font-bold tabular-nums text-primary">{num(summary?.average_path_risk).toFixed(1)}</p>
            </div>
            <div className="bg-card rounded-xl p-4 shadow-card">
              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">Connections</p>
              <p className="text-2xl font-bold tabular-nums text-foreground">{graph?.stats.total_edges ?? 0}</p>
              <p className="text-[10px] text-muted-foreground">{graph?.stats.high_risk_edges ?? 0} high-risk</p>
            </div>
          </div>

          {/* ── Risk Distribution Bar ── */}
          {paths.length > 0 && (() => {
            const dist = { critical: 0, high: 0, medium: 0, low: 0 };
            paths.forEach(p => {
              const l = (p.risk_level || "low").toLowerCase();
              if (l in dist) dist[l as keyof typeof dist]++;
            });
            const total = paths.length;
            const colors = { critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e" };

            return (
              <div className="bg-card rounded-xl p-5 shadow-card mb-6">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-[13px] font-semibold text-foreground">Path Risk Distribution</h3>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      {total} total attack path{total !== 1 ? "s" : ""} analyzed
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    {(["critical", "high", "medium", "low"] as const).map(level =>
                      dist[level] > 0 ? (
                        <div key={level} className="flex items-center gap-1.5 text-[11px]">
                          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: colors[level] }} />
                          <span className="text-muted-foreground capitalize">{level}</span>
                          <span className="font-bold text-foreground">{dist[level]}</span>
                        </div>
                      ) : null
                    )}
                  </div>
                </div>
                <div className="h-4 bg-secondary rounded-full overflow-hidden flex">
                  {(["critical", "high", "medium", "low"] as const).map(level => {
                    const pct = (dist[level] / total) * 100;
                    return pct > 0 ? (
                      <div
                        key={level}
                        className="h-full transition-all duration-500 first:rounded-l-full last:rounded-r-full"
                        style={{ width: `${pct}%`, backgroundColor: colors[level] }}
                        title={`${level}: ${dist[level]} path${dist[level] !== 1 ? "s" : ""} (${pct.toFixed(0)}%)`}
                      />
                    ) : null;
                  })}
                </div>
              </div>
            );
          })()}

          {/* ── Top Priority Path ── */}
          {paths.length > 0 && (() => {
            const topPath = [...paths].sort((a, b) => num(b.total_risk_score) - num(a.total_risk_score))[0];
            if (!topPath || num(topPath.total_risk_score) < 4) return null;
            return (
              <div className="bg-card rounded-xl p-5 shadow-card mb-6 border border-red-900/30 relative overflow-hidden">
                <div className="absolute top-0 right-0 bg-red-600 text-white px-3 py-1 text-[9px] font-bold uppercase tracking-wider rounded-bl-lg">
                  Fix First
                </div>
                <div className="flex items-center gap-4">
                  <div className="h-12 w-12 rounded-xl bg-red-950/60 border border-red-800/40 flex items-center justify-center shrink-0">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[10px] uppercase tracking-widest text-red-400/80 font-bold mb-1">Highest Priority Attack Path</p>
                    <p className="text-[14px] font-semibold text-foreground">
                      {topPath.entry_point?.replace(/_/g, " ")} → {topPath.target?.replace(/_/g, " ")}
                    </p>
                    <p className="text-[11px] text-muted-foreground mt-0.5">
                      {topPath.hops} hop{topPath.hops !== 1 ? "s" : ""} · Risk {num(topPath.total_risk_score).toFixed(1)}/10
                      {topPath.weakest_link && (
                        <> · Weakest rule: <span className="text-warning font-mono">{topPath.weakest_link}</span></>
                      )}
                    </p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-3xl font-bold tabular-nums" style={{ color: riskHex(topPath.total_risk_score) }}>
                      {num(topPath.total_risk_score).toFixed(1)}
                    </p>
                    <span className={`${riskLabel(topPath.risk_level)} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase mt-1 inline-block`}>
                      {topPath.risk_level}
                    </span>
                  </div>
                </div>
              </div>
            );
          })()}

          {/* Tab switcher */}
          <div className="flex items-center gap-1 mb-6 bg-card rounded-xl p-1 shadow-card w-fit">
            {([["graph", "Attack Graph", <Zap className="h-3.5 w-3.5" />], ["paths", "Attack Paths", <AlertCircle className="h-3.5 w-3.5" />]] as const).map(([id, label, icon]) => (
              <button
                key={id}
                onClick={() => setTab(id as "graph" | "paths")}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-[12px] font-medium transition-smooth ${
                  activeTab === id ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {icon}{label}
              </button>
            ))}
          </div>

          {/* ── TAB: FULL ATTACK GRAPH ── */}
          {activeTab === "graph" && graph && graph.nodes.length > 0 && (
            <AttackGraphView
              graph={graph}
              onNodeClick={setSelected}
              selectedNode={selectedNode?.id ?? null}
            />
          )}

          {/* ── TAB: ATTACK PATHS ── */}
          {activeTab === "paths" && (
            <>
              {paths.length === 0 ? (
                <div className="bg-card rounded-xl p-10 shadow-card text-center mb-6">
                  <p className="text-[12px] text-muted-foreground">No attack paths were found between entry points and targets.</p>
                </div>
              ) : (
                <div className="space-y-4 mb-6">
                  {paths.map((path) => (
                    <div key={path.id} className="bg-card rounded-xl shadow-card overflow-hidden">
                      {/* Header row */}
                      <button
                        className="w-full flex items-center gap-4 p-4 text-left"
                        onClick={() => setExpanded(expanded === path.id ? null : path.id)}
                      >
                        <span
                          className="text-[18px] font-bold tabular-nums shrink-0 cursor-help"
                          style={{ color: riskHex(path.total_risk_score) }}
                        >
                          <SmartTooltip term={`CVSS ${num(path.total_risk_score).toFixed(1)}`} context={`Attack path from ${path.entry_point} to ${path.target}`} severity={path.risk_level} page="AttackPaths">
                            {num(path.total_risk_score).toFixed(1)}
                          </SmartTooltip>
                        </span>
                        <div className="flex-1 min-w-0">
                          <p className="text-[13px] font-semibold text-foreground">
                            <SmartTooltip term={path.entry_point?.replace(/_/g, " ")} context="Attack path entry point" severity={path.risk_level} page="AttackPaths">
                              {path.entry_point?.replace(/_/g, " ")}
                            </SmartTooltip>
                            {" → "}
                            <SmartTooltip term={path.target?.replace(/_/g, " ")} context="Attack path target" severity={path.risk_level} page="AttackPaths">
                              {path.target?.replace(/_/g, " ")}
                            </SmartTooltip>
                          </p>
                          <p className="text-[11px] text-muted-foreground">
                            {path.hops} step{path.hops !== 1 ? "s" : ""} ·{" "}
                            {num(path.attack_difficulty) >= 8 ? "Very easy to exploit" :
                             num(path.attack_difficulty) >= 6 ? "Fairly easy to exploit" :
                             num(path.attack_difficulty) >= 4 ? "Moderate difficulty" :
                             "Hard to exploit"} ({num(path.attack_difficulty).toFixed(1)}/10)
                          </p>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className={`${riskLabel(path.risk_level)} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>
                            {path.risk_level}
                          </span>
                          {expanded === path.id
                            ? <ChevronUp className="h-4 w-4 text-muted-foreground" />
                            : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                        </div>
                      </button>

                      {expanded === path.id && (
                        <div className="px-4 pb-5 pt-0 border-t border-border">
                          {/* Sequential flow diagram */}
                          <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mt-3 mb-3">
                            Attack Flow
                          </p>
                          <PathFlow path={path} />

                          <div className="grid grid-cols-2 gap-4 mt-4">
                            {path.weakest_link && (
                              <div>
                                <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">Weakest Rule</p>
                                <SmartTooltip term={path.weakest_link} context="Weakest link in attack path" severity={path.risk_level} page="AttackPaths">
                                  <p className="text-[11px] text-warning font-mono cursor-help">{path.weakest_link}</p>
                                </SmartTooltip>
                              </div>
                            )}
                            {path.vulnerable_ports?.length > 0 && (
                              <div>
                                <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-1">Vulnerable Ports</p>
                                <div className="flex flex-wrap gap-1">
                                  {path.vulnerable_ports.map((port) => (
                                    <SmartTooltip key={port} term={`Port ${port}`} context={`Vulnerable port in attack path`} severity={path.risk_level} page="AttackPaths">
                                      <span className="text-[10px] bg-destructive/10 text-destructive px-1.5 py-0.5 rounded font-mono cursor-help">
                                        :{port}
                                      </span>
                                    </SmartTooltip>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>

                          {/* Hop detail table */}
                          {Array.isArray(path.path_hops) && path.path_hops.length > 0 && (
                            <div className="mt-4">
                              <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-2">Hop Details</p>
                              <table className="w-full text-[11px]">
                                <thead>
                                  <tr className="border-b border-border">
                                    <th className="text-left pb-1.5 text-muted-foreground font-semibold">#</th>
                                    <th className="text-left pb-1.5 text-muted-foreground font-semibold">Zone</th>
                                    <th className="text-left pb-1.5 text-muted-foreground font-semibold">Port</th>
                                    <th className="text-left pb-1.5 text-muted-foreground font-semibold">Rule</th>
                                    <th className="text-right pb-1.5 text-muted-foreground font-semibold">Risk</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {path.path_hops.map((hop, i) => (
                                    <tr key={i} className="border-b border-border/40">
                                      <td className="py-1.5 text-muted-foreground">{i + 1}</td>
                                      <td className="py-1.5 text-foreground font-medium">{hop.target}</td>
                                      <td className="py-1.5 font-mono text-muted-foreground">
                                        {hop.port && hop.port !== "any" ? `:${hop.port}` : "*"}
                                      </td>
                                      <td className="py-1.5 text-muted-foreground truncate max-w-[120px]">{hop.rule_name}</td>
                                      <td className="py-1.5 text-right font-bold" style={{ color: riskHex(hop.risk) }}>
                                        {num(hop.risk).toFixed(1)}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                          {/* Compromise Narrative for critical/high paths */}
                          <CompromiseNarrativeCard findingKey={`path-${path.id}`} riskLevel={path.risk_level} />
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Entry points */}
              {entryPoints.length > 0 && (
                <div>
                  <h3 className="text-[13px] font-semibold text-foreground mb-3">
                    Identified Entry Points ({entryPoints.length})
                  </h3>
                  <div className="grid grid-cols-2 gap-3">
                    {entryPoints.map((ep) => (
                      <div key={ep.node_id} className="bg-card rounded-xl p-4 shadow-card flex items-start gap-3">
                        <div className="w-8 h-8 rounded-lg bg-blue-900/50 border border-blue-700 flex items-center justify-center shrink-0">
                          <Lock className="h-4 w-4 text-blue-400" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <p className="text-[12px] font-medium text-foreground truncate">{ep.device_name}</p>
                            <span className="badge-critical px-1.5 py-0.5 rounded text-[9px] font-semibold shrink-0">
                              Internet Exposed
                            </span>
                          </div>
                          <p className="text-[11px] text-muted-foreground">
                            Zone: <span className="text-foreground">{ep.zone}</span>
                            {ep.ip_address && ep.ip_address !== "—" && (
                              <> · <span className="font-mono">{ep.ip_address}</span></>
                            )}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* ── IP-to-IP Vulnerability Analysis ── */}
      <IpVulnerabilitySection />

      {/* Node detail slide-in panel */}
      {selectedNode && graph && (
        <NodePanel
          node={selectedNode}
          edges={graph.edges}
          onClose={() => setSelected(null)}
        />
      )}
    </AppLayout>
  );
}
