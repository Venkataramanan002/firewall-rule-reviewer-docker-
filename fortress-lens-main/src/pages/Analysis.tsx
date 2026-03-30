import { useState, useEffect, useRef } from "react";
import { AppLayout } from "@/components/layout/AppLayout";
import { Play, ChevronDown, ChevronUp, AlertTriangle, Loader2, BarChart3, Skull, Shield, Info } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SmartTooltip } from "@/components/ui/SmartTooltip";
import { CompromiseNarrativeCard } from "@/components/CompromiseNarrative";
import { analyzeReachability, getVulnerablePorts, getRiskyRules, triggerRuleAnalysis, type VulnerablePort, type RiskyRule } from "@/lib/api";

const tabs = ["Reachability Analysis", "Vulnerable Ports", "Rule Impact"];

const SeverityBadge = ({ level }: { level: string }) => {
  const cls = level === "critical" ? "badge-critical" : level === "high" ? "badge-high" : level === "medium" ? "badge-medium" : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{level}</span>;
};

// Module-level cache — survives route changes
let _cachedPorts: VulnerablePort[] = [];
let _cachedRules: RiskyRule[] = [];

export default function Analysis() {
  const [activeTab, setActiveTab]   = useState(0);
  const [selectedZone, setZone]     = useState("All");
  const [portFilter, setPortFilter] = useState("All");
  const [expandedPort, setExpandedPort]   = useState<number | null>(null);
  const [expandedRule, setExpandedRule]   = useState<string | null>(null);

  const [reachDevices, setReachDevices]   = useState<{ id: string; name: string; zone: string; confidence: string; allowed_ports: number[] }[]>([]);
  const [livePorts, setLivePorts]         = useState<VulnerablePort[]>(_cachedPorts);
  const [liveRules, setLiveRules]         = useState<RiskyRule[]>(_cachedRules);
  const [loadingReach, setLoadingReach]   = useState(false);
  const [loadingPorts, setLoadingPorts]   = useState(_cachedPorts.length === 0);
  const [loadingRules, setLoadingRules]   = useState(_cachedRules.length === 0);
  const [analysisTriggered, setTriggered] = useState(false);

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    getVulnerablePorts()
      .then((d) => { _cachedPorts = d; if (mountedRef.current) setLivePorts(d); })
      .catch(() => {})
      .finally(() => { if (mountedRef.current) setLoadingPorts(false); });
    getRiskyRules(1, 100)
      .then((d) => { _cachedRules = d; if (mountedRef.current) setLiveRules(d); })
      .catch(() => {})
      .finally(() => { if (mountedRef.current) setLoadingRules(false); });
    return () => { mountedRef.current = false; };
  }, []);

  async function handleRunReachability() {
    setLoadingReach(true);
    try {
      const res = await analyzeReachability(selectedZone);
      if (res.reachable_devices.length > 0) setReachDevices(res.reachable_devices);
    } catch { /* stay empty */ }
    setLoadingReach(false);
  }

  async function handleAnalyzeRules() {
    setTriggered(true);
    await triggerRuleAnalysis().catch(() => {});
    setTimeout(() => { getRiskyRules(0, 100).then(setLiveRules).catch(() => {}); }, 3000);
  }

  const zones = ["All", ...Array.from(new Set(reachDevices.map((d) => d.zone)))];
  const filteredDevices = selectedZone === "All" ? reachDevices : reachDevices.filter((d) => d.zone === selectedZone);
  const anomalies = reachDevices.filter((d) => d.confidence === "critical");

  const filteredPorts = portFilter === "All" ? livePorts : livePorts.filter((p) => p.risk_level === portFilter.toLowerCase());

  const riskColor = (score: number) => score >= 8 ? "text-destructive" : score >= 6 ? "text-warning" : score >= 4 ? "text-primary" : "text-success";

  return (
    <AppLayout title="Analysis" breadcrumb={["Firewall Analytics"]}>
      {/* ── Guidance Banner ── */}
      <div className="bg-primary/5 border border-primary/20 rounded-xl p-4 mb-6 flex items-start gap-3">
        <Info className="h-4 w-4 text-primary shrink-0 mt-0.5" />
        <div>
          <p className="text-[12px] font-semibold text-primary mb-1">How to Use This Page</p>
          <p className="text-[11px] text-muted-foreground leading-relaxed">
            <strong>Step 1:</strong> Check <em>Vulnerable Ports</em> to see which services are exposed to risk.{" "}
            <strong>Step 2:</strong> Review <em>Rule Impact</em> to identify the most dangerous firewall rules.{" "}
            <strong>Step 3:</strong> Use <em>Reachability</em> to test which devices can reach each other across zones.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-1 mb-6 bg-card rounded-xl p-1 shadow-card w-fit">
        {tabs.map((tab, i) => (
          <button key={tab} onClick={() => setActiveTab(i)}
            className={`px-4 py-2 rounded-lg text-[12px] font-medium transition-smooth ${activeTab === i ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
            {tab}
          </button>
        ))}
      </div>

      {/* Tab 1: Reachability */}
      {activeTab === 0 && (
        <div>
          <div className="flex items-center gap-3 mb-6">
            <select value={selectedZone} onChange={(e) => setZone(e.target.value)}
              className="h-8 px-3 rounded-lg bg-secondary border border-border text-[12px] text-foreground">
              {zones.map((z) => <option key={z}>{z}</option>)}
            </select>
            <Button size="sm" className="h-8 text-[11px]" onClick={handleRunReachability} disabled={loadingReach}>
              {loadingReach ? <Loader2 className="h-3 w-3 animate-spin mr-1.5" /> : <Play className="h-3 w-3 mr-1.5" />}
              Run Analysis
            </Button>
          </div>

          {anomalies.length > 0 && (
            <div className="bg-destructive/5 border border-destructive/20 rounded-xl p-4 mb-4 flex items-start gap-3">
              <AlertTriangle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div>
                <p className="text-[12px] font-semibold text-destructive mb-1">{anomalies.length} critical anomalies detected</p>
                <p className="text-[11px] text-muted-foreground">{anomalies.map((a) => a.name).join(", ")}</p>
              </div>
            </div>
          )}

          {filteredDevices.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <BarChart3 className="h-10 w-10 text-muted-foreground mx-auto mb-4" />
              <p className="text-[13px] font-medium text-foreground mb-2">No reachability data</p>
              <p className="text-[12px] text-muted-foreground">Click "Run Analysis" after uploading a config to map zone reachability.</p>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-4">
              {filteredDevices.map((device) => (
                <div key={device.id} className="bg-card rounded-xl p-4 shadow-card">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-[13px] font-semibold text-foreground">
                      <SmartTooltip term={device.name} context={`Device in zone ${device.zone}`} severity={device.confidence} page="Analysis">
                        {device.name}
                      </SmartTooltip>
                    </h4>
                    <SeverityBadge level={device.confidence} />
                  </div>
                  <p className="text-[11px] text-muted-foreground mb-3">
                    Zone:{" "}
                    <SmartTooltip term={device.zone} context="Network security zone" page="Analysis">
                      {device.zone}
                    </SmartTooltip>
                  </p>
                  {device.allowed_ports?.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {device.allowed_ports.slice(0, 6).map((port) => (
                        <SmartTooltip key={port} term={`Port ${port}`} context={`Open port on ${device.name}`} severity={device.confidence} page="Analysis">
                          <span className="text-[10px] bg-secondary px-1.5 py-0.5 rounded font-mono cursor-help">{port}</span>
                        </SmartTooltip>
                      ))}
                      {device.allowed_ports.length > 6 && <span className="text-[10px] text-muted-foreground">+{device.allowed_ports.length - 6}</span>}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Vulnerable Ports */}
      {activeTab === 1 && (
        <div>
          {loadingPorts ? (
            <div className="flex items-center gap-2 text-[12px] text-muted-foreground py-8"><Loader2 className="h-4 w-4 animate-spin" />Loading…</div>
          ) : livePorts.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <p className="text-[13px] font-medium text-foreground mb-2">No vulnerable ports found</p>
              <p className="text-[12px] text-muted-foreground">Upload a config and run analysis to identify exposed ports.</p>
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 mb-6">
                <select value={portFilter} onChange={(e) => setPortFilter(e.target.value)}
                  className="h-8 px-3 rounded-lg bg-secondary border border-border text-[12px] text-foreground">
                  {["All","Critical","High","Medium","Low"].map((f) => <option key={f}>{f}</option>)}
                </select>
                <span className="text-[11px] text-muted-foreground">{filteredPorts.length} exposed port{filteredPorts.length !== 1 ? "s" : ""} found</span>
              </div>
              <div className="space-y-2">
                {filteredPorts.map((port) => (
                  <div key={port.port} className="bg-card rounded-xl shadow-card overflow-hidden">
                    <button className="w-full flex items-center justify-between p-4 text-left" onClick={() => setExpandedPort(expandedPort === port.port ? null : port.port)}>
                      <div className="flex items-center gap-3">
                        <SmartTooltip term={`Port ${port.port}`} context={`${port.service} — ${port.reason}`} severity={port.risk_level} page="Analysis">
                          <span className="font-mono text-[13px] text-primary font-bold cursor-help">{port.port}</span>
                        </SmartTooltip>
                        <SmartTooltip term={port.service} context={`Service on port ${port.port}`} severity={port.risk_level} page="Analysis">
                          <span className="text-[12px] font-medium text-foreground cursor-help">{port.service}</span>
                        </SmartTooltip>
                        <SeverityBadge level={port.risk_level} />
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-[11px] text-muted-foreground">{port.exposed_devices?.length ?? 0} device{(port.exposed_devices?.length ?? 0) !== 1 ? "s" : ""}</span>
                        {expandedPort === port.port ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </div>
                    </button>
                    {expandedPort === port.port && (
                      <div className="px-4 pb-4 pt-0 border-t border-border space-y-2">
                        <p className="text-[12px] text-muted-foreground">
                          <span className="text-foreground font-medium">Reason:</span>{" "}
                          <SmartTooltip term={port.reason} context={`Port ${port.port} exposure reason`} severity={port.risk_level} page="Analysis">
                            {port.reason}
                          </SmartTooltip>
                        </p>
                        <p className="text-[12px] text-muted-foreground">
                          <span className="text-foreground font-medium">Recommendation:</span>{" "}
                          <SmartTooltip term={port.recommendation} context={`Fix for port ${port.port}`} page="Remediation">
                            {port.recommendation}
                          </SmartTooltip>
                        </p>
                        {port.exposed_devices?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {port.exposed_devices.map((d) => <span key={d} className="text-[10px] bg-secondary px-1.5 py-0.5 rounded font-mono">{d}</span>)}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}

      {/* Tab 3: Rule Impact */}
      {activeTab === 2 && (
        <div>
          <div className="flex items-center gap-3 mb-6">
            <Button size="sm" variant="outline" className="h-8 text-[11px]" onClick={handleAnalyzeRules} disabled={analysisTriggered}>
              {analysisTriggered ? <><Loader2 className="h-3 w-3 animate-spin mr-1.5" />Analysing…</> : <><Play className="h-3 w-3 mr-1.5" />Re-analyse Rules</>}
            </Button>
            <span className="text-[11px] text-muted-foreground">{liveRules.length} rule{liveRules.length !== 1 ? "s" : ""}</span>
          </div>
          {loadingRules ? (
            <div className="flex items-center gap-2 text-[12px] text-muted-foreground py-8"><Loader2 className="h-4 w-4 animate-spin" />Loading rule analysis…</div>
          ) : liveRules.length === 0 ? (
            <div className="bg-card rounded-xl p-12 shadow-card text-center">
              <p className="text-[13px] font-medium text-foreground mb-2">No rules analysed yet</p>
              <p className="text-[12px] text-muted-foreground">Upload a config — risk analysis runs automatically. Click Re-analyse to refresh.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {liveRules.map((rule) => (
                <div key={rule.id} className="bg-card rounded-xl shadow-card overflow-hidden">
                  <button className="w-full flex items-center justify-between p-4 text-left" onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}>
                    <div className="flex items-center gap-3">
                      <SmartTooltip term={`Risk Score ${Number(rule.risk_score).toFixed(1)}`} context={`Risk score for rule ${rule.rule_name} — ${Number(rule.risk_score) >= 8 ? "Very dangerous" : Number(rule.risk_score) >= 6 ? "Significant risk" : Number(rule.risk_score) >= 4 ? "Moderate risk" : "Low risk"}`} severity={rule.risk_level} page="Analysis">
                        <span className={`text-[15px] font-bold tabular-nums cursor-help ${riskColor(Number(rule.risk_score))}`}>
                          {Number(rule.risk_score).toFixed(1)}
                        </span>
                      </SmartTooltip>
                      <SmartTooltip term={rule.rule_name} context={`Firewall rule on ${rule.device_name}`} severity={rule.risk_level} page="Analysis">
                        <span className="text-[12px] font-medium text-foreground cursor-help">{rule.rule_name}</span>
                      </SmartTooltip>
                      <SeverityBadge level={rule.risk_level} />
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-[11px] text-muted-foreground">{rule.device_name}</span>
                      {expandedRule === rule.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </div>
                  </button>
                  {expandedRule === rule.id && (
                    <div className="px-4 pb-4 pt-0 border-t border-border space-y-2">
                      <p className="text-[12px] text-muted-foreground">
                        <span className="text-foreground font-medium">Reason:</span>{" "}
                        <SmartTooltip term={rule.reason} context={`Reason for rule ${rule.rule_name}`} severity={rule.risk_level} page="Analysis">
                          {rule.reason}
                        </SmartTooltip>
                      </p>
                      <p className="text-[12px] text-muted-foreground">
                        <span className="text-foreground font-medium">Recommendation:</span>{" "}
                        <SmartTooltip term={rule.recommendation} context={`Fix for rule ${rule.rule_name}`} page="Remediation">
                          {rule.recommendation}
                        </SmartTooltip>
                      </p>
                      <p className="text-[12px] text-muted-foreground">
                        <span className="text-foreground font-medium">Source:</span>{" "}
                        <SmartTooltip term={rule.source} context={`Source address/port for rule ${rule.rule_name}`} page="Analysis">
                          {rule.source}
                        </SmartTooltip>
                        {" → "}
                        <SmartTooltip term={rule.destination} context={`Destination address/port for rule ${rule.rule_name}`} page="Analysis">
                          <span className="font-medium text-foreground cursor-help">{rule.destination}</span>
                        </SmartTooltip>
                      </p>
                      <p className="text-[12px] text-muted-foreground">
                        <span className="text-foreground font-medium">Protocol:</span>{" "}
                        <SmartTooltip term={rule.protocol} context={`Protocol for rule ${rule.rule_name}`} page="Analysis">
                          {rule.protocol}
                        </SmartTooltip>
                      </p>
                      {/* Enhanced Compromise Narrative — only for high/critical rules */}
                      <CompromiseNarrativeCard findingKey={`rule-${rule.id}`} riskLevel={rule.risk_level} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </AppLayout>
  );
}
