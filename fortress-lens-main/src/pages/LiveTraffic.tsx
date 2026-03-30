import { useState, useMemo, useEffect, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Search, Download, RefreshCw, AlertTriangle, ChevronLeft, ChevronRight, X, Activity } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { getConnections } from "@/lib/api";

interface Row {
  id: string; timestamp: string; srcIp: string; srcPort: number; dstIp: string; dstPort: number;
  protocol: string; application: string; user: string; bytesSent: number; bytesReceived: number;
  action: string; threatDetected: boolean; duration: number; ruleId: string;
  srcZone: string; dstZone: string; srcCountry: string; dstCountry: string; url?: string;
}

function mapRow(c: Record<string, unknown>): Row {
  return {
    id: String(c.id ?? Math.random()),
    timestamp: String(c.timestamp ?? ""),
    srcIp: String(c.src_ip ?? "—"),
    srcPort: Number(c.src_port ?? 0),
    dstIp: String(c.dst_ip ?? "—"),
    dstPort: Number(c.dst_port ?? 0),
    protocol: String(c.protocol ?? "—").toUpperCase(),
    application: String(c.app_name ?? "—"),
    user: String(c.username ?? "—"),
    bytesSent: Number(c.bytes_sent ?? 0),
    bytesReceived: Number(c.bytes_received ?? 0),
    action: String(c.action ?? "allow"),
    threatDetected: Boolean(c.threat_detected),
    duration: Number(c.duration_seconds ?? 0),
    ruleId: String(c.rule_id ?? "—"),
    srcZone: String(c.zone_from ?? "—"),
    dstZone: String(c.zone_to ?? "—"),
    srcCountry: String(c.geo_src_country ?? "—"),
    dstCountry: String(c.geo_dst_country ?? "—"),
    url: c.url ? String(c.url) : undefined,
  };
}

function formatBytes(b: number) {
  if (b >= 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b / 1e3).toFixed(1)} KB`;
  return `${b} B`;
}

const ActionBadge = ({ action }: { action: string }) => {
  const a = action.toLowerCase();
  const cls = a === "allow" ? "badge-allow" : a === "deny" ? "badge-deny" : "badge-drop";
  return <span className={`${cls} px-2 py-0.5 rounded text-[10px] font-semibold capitalize`}>{action}</span>;
};

const DetailField = ({ label, value }: { label: string; value: string | number | undefined }) => (
  <div><p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold mb-0.5">{label}</p>
  <p className="text-[12px] font-mono text-foreground">{value ?? "—"}</p></div>
);

// Module-level cache — survives route changes
let _cachedTraffic: Row[] = [];

export default function LiveTraffic() {
  const [search, setSearch]         = useState("");
  const [actionFilter, setFilter]   = useState("All");
  const [autoRefresh, setAuto]      = useState(false);
  const [page, setPage]             = useState(0);
  const [selected, setSelected]     = useState<Row | null>(null);
  const [traffic, setTraffic]       = useState<Row[]>(_cachedTraffic);
  const [loading, setLoading]       = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const perPage = 15;

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  async function fetchRows() {
    setLoading(true);
    try {
      const data = await getConnections(200);
      const mapped = (data as Record<string, unknown>[]).map(mapRow);
      _cachedTraffic = mapped;
      if (mountedRef.current) setTraffic(mapped);
    } catch { /* stay empty */ }
    if (mountedRef.current) setLoading(false);
  }

  useEffect(() => { fetchRows(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    if (autoRefresh) intervalRef.current = setInterval(fetchRows, 10_000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh]);

  const filtered = useMemo(() => traffic.filter((e) => {
    if (search && !e.srcIp.includes(search) && !e.dstIp.includes(search)) return false;
    if (actionFilter !== "All" && e.action.toLowerCase() !== actionFilter.toLowerCase()) return false;
    return true;
  }), [search, actionFilter, traffic]);

  const paged      = filtered.slice(page * perPage, (page + 1) * perPage);
  const totalPages = Math.max(1, Math.ceil(filtered.length / perPage));

  function exportCSV() {
    const headers = ["timestamp","srcIp","srcPort","dstIp","dstPort","protocol","action","bytesSent","bytesReceived"];
    const rows = filtered.map((e) => headers.map((h) => String((e as Record<string,unknown>)[h] ?? "")).join(","));
    const blob = new Blob([headers.join(",") + "\n" + rows.join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "traffic-export.csv"; a.click();
  }

  return (
    <AppLayout title="Live Traffic" breadcrumb={["Firewall Analytics"]}>
      <div className="flex items-center gap-3 p-3 bg-card rounded-xl shadow-card mb-6">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input placeholder="Search by IP" value={search} onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            className="pl-9 h-8 text-[12px] bg-secondary border-border" />
        </div>
        <select value={actionFilter} onChange={(e) => { setFilter(e.target.value); setPage(0); }}
          className="h-8 px-3 rounded-lg bg-secondary border border-border text-[12px] text-foreground">
          {["All","Allow","Deny","Drop"].map((o) => <option key={o}>{o}</option>)}
        </select>
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
          <Switch checked={autoRefresh} onCheckedChange={setAuto} />
          <span>Auto-refresh</span>
          {autoRefresh && <RefreshCw className="h-3 w-3 animate-spin" />}
        </div>
        <Button variant="outline" size="sm" className="text-[11px] h-8 ml-auto" onClick={fetchRows} disabled={loading}>
          <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} />{loading ? "Loading…" : "Refresh"}
        </Button>
        <Button variant="outline" size="sm" className="text-[11px] h-8" onClick={exportCSV} disabled={!traffic.length}>
          <Download className="h-3.5 w-3.5 mr-1.5" />Export CSV
        </Button>
      </div>

      {traffic.length === 0 && !loading ? (
        <div className="bg-card rounded-xl p-16 shadow-card text-center">
          <Activity className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
          <p className="text-[14px] font-medium text-foreground mb-2">No traffic data yet</p>
          <p className="text-[12px] text-muted-foreground">Upload a traffic CSV log to populate this view.</p>
        </div>
      ) : (
        <>
        {/* ── Traffic Summary Banner ── */}
        {(() => {
          const threatCount = traffic.filter(e => e.threatDetected).length;
          const deniedCount = traffic.filter(e => e.action.toLowerCase() === "deny" || e.action.toLowerCase() === "drop").length;
          const isCritical = threatCount > 0;
          return (
            <div className={`rounded-xl p-5 mb-6 border ${
              isCritical ? "bg-red-950/40 border-red-800/40" :
              deniedCount > 0 ? "bg-yellow-950/30 border-yellow-700/30" :
              "bg-emerald-950/30 border-emerald-700/30"
            }`}>
              <div className="flex items-center gap-4">
                <div className={`h-14 w-14 rounded-2xl flex items-center justify-center text-2xl shrink-0 ${
                  isCritical ? "bg-red-900/60" : deniedCount > 0 ? "bg-yellow-900/50" : "bg-emerald-900/50"
                }`}>
                  {isCritical ? "🚨" : deniedCount > 0 ? "⚠️" : "✅"}
                </div>
                <div className="flex-1">
                  <h3 className={`text-[15px] font-bold ${
                    isCritical ? "text-red-400" : deniedCount > 0 ? "text-yellow-400" : "text-emerald-400"
                  }`}>
                    {isCritical ? `${threatCount} Threat${threatCount !== 1 ? "s" : ""} Detected in Traffic` :
                     deniedCount > 0 ? `${deniedCount} Connection${deniedCount !== 1 ? "s" : ""} Blocked by Firewall` :
                     "All Traffic Looks Normal"}
                  </h3>
                  <p className="text-[12px] text-muted-foreground mt-1">
                    {traffic.length} connection{traffic.length !== 1 ? "s" : ""} recorded
                    {threatCount > 0 && ` · ${threatCount} flagged as threats`}
                    {deniedCount > 0 && ` · ${deniedCount} denied/dropped`}
                  </p>
                </div>
              </div>
            </div>
          );
        })()}

        <div className="bg-card rounded-xl shadow-card overflow-hidden">
          <div className="overflow-auto">
            <table className="w-full text-[12px]">
              <thead>
                <tr className="border-b border-border">
                  {["Time","Source","Destination","Protocol","App","User","Data Sent","Data Received","Action",""].map((h) => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] uppercase tracking-widest text-muted-foreground font-bold whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paged.map((e) => (
                  <tr key={e.id} onClick={() => setSelected(e)}
                    className={`border-b border-border/50 hover:bg-primary/5 transition-smooth cursor-pointer ${e.threatDetected ? "bg-destructive/5" : ""}`}>
                    <td className="px-4 py-2.5 font-mono text-muted-foreground whitespace-nowrap">{(() => {
                      const parts = e.timestamp.split(" ");
                      const date = parts[0] ?? "";
                      const time = parts[1]?.slice(0, 5) ?? "";
                      return time ? `${date.slice(5)} ${time}` : "—";
                    })()}</td>
                    <td className="px-4 py-2.5 font-mono text-foreground whitespace-nowrap">{e.srcIp}:{e.srcPort}</td>
                    <td className="px-4 py-2.5 font-mono text-foreground whitespace-nowrap">{e.dstIp}:{e.dstPort}</td>
                    <td className="px-4 py-2.5">
                      <SmartTooltip term={e.protocol} context="Network protocol" page="LiveTraffic">
                        <span className="bg-secondary px-1.5 py-0.5 rounded text-[10px] font-mono cursor-help">{e.protocol}</span>
                      </SmartTooltip>
                    </td>
                    <td className="px-4 py-2.5 text-foreground">{e.application}</td>
                    <td className="px-4 py-2.5 text-muted-foreground">{e.user}</td>
                    <td className="px-4 py-2.5 text-muted-foreground tabular-nums">{formatBytes(e.bytesSent)}</td>
                    <td className="px-4 py-2.5 text-muted-foreground tabular-nums">{formatBytes(e.bytesReceived)}</td>
                    <td className="px-4 py-2.5"><ActionBadge action={e.action} /></td>
                    <td className="px-4 py-2.5">{e.threatDetected && <AlertTriangle className="h-3.5 w-3.5 text-warning" />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-[11px] text-muted-foreground">{filtered.length} connections</span>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setPage((p) => Math.max(0, p-1))} disabled={page === 0}><ChevronLeft className="h-4 w-4" /></Button>
              <span className="text-[11px] text-muted-foreground tabular-nums">{page+1} / {totalPages}</span>
              <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => setPage((p) => Math.min(totalPages-1, p+1))} disabled={page >= totalPages-1}><ChevronRight className="h-4 w-4" /></Button>
            </div>
          </div>
        </div>
        </>
      )}

      <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
        <DialogContent className="bg-card border-border max-w-lg max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <div className="flex items-center justify-between">
              <DialogTitle className="text-[14px] font-semibold">Connection Detail</DialogTitle>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setSelected(null)}><X className="h-4 w-4" /></Button>
            </div>
          </DialogHeader>
          {selected && (
            <div className="grid grid-cols-2 gap-4 mt-2">
              <DetailField label="Timestamp" value={selected.timestamp} />
              <DetailField label="Action Taken" value={selected.action} />
              <DetailField label="Source Address" value={selected.srcIp} />
              <DetailField label="Source Port" value={selected.srcPort} />
              <DetailField label="Destination Address" value={selected.dstIp} />
              <DetailField label="Destination Port" value={selected.dstPort} />
              <DetailField label="Protocol" value={selected.protocol} />
              <DetailField label="Application" value={selected.application} />
              <DetailField label="User" value={selected.user} />
              <DetailField label="Firewall Rule" value={selected.ruleId} />
              <DetailField label="Data Sent" value={formatBytes(selected.bytesSent)} />
              <DetailField label="Data Received" value={formatBytes(selected.bytesReceived)} />
              <DetailField label="Source Zone" value={selected.srcZone} />
              <DetailField label="Destination Zone" value={selected.dstZone} />
              <DetailField label="Source Country" value={selected.srcCountry} />
              <DetailField label="Destination Country" value={selected.dstCountry} />
              <DetailField label="Duration" value={`${selected.duration}s`} />
              {selected.url && <div className="col-span-2"><DetailField label="URL" value={selected.url} /></div>}
              {selected.threatDetected && (
                <div className="col-span-2 bg-destructive/10 border border-destructive/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-destructive shrink-0" />
                  <span className="text-[12px] text-destructive font-medium">Threat detected on this connection — investigate immediately</span>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </AppLayout>
  );
}
