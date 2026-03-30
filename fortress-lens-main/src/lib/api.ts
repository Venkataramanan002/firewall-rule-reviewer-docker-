/**
 * Firewall Analytics — API Service Layer
 *
 * How the base URL is resolved (in priority order):
 *  1. VITE_API_URL env var  — set in .env.local, e.g. VITE_API_URL=http://localhost:8000
 *  2. Same-origin /api      — works when Vite proxy is active (npm run dev)
 *  3. http://localhost:8000 — fallback for direct file access / Lovable preview
 */

const BASE = (() => {
  // Injected at build time by Vite from .env / .env.local
  const envUrl = (import.meta as Record<string, unknown>).env
    ? ((import.meta as {env: Record<string,string>}).env.VITE_API_URL ?? "").trim()
    : "";
  if (envUrl) return envUrl.replace(/\/$/, "") + "/api";

  // If we are served from localhost (Vite dev server with proxy), use relative path
  if (typeof window !== "undefined" && window.location.hostname === "localhost") {
    return "/api";
  }

  // Fallback: direct call to backend (needed when frontend is opened without dev server)
  return "http://localhost:8000/api";
})();

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  // Hard 15-second timeout — prevents pages from getting stuck in loading state forever.
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15_000);
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: { "Content-Type": "application/json", ...options?.headers },
      signal: controller.signal,
      ...options,
    });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${path} → ${res.status}: ${text}`);
    }
    return res.json() as Promise<T>;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ─── Types ──────────────────────────────────────────────────────────────────

export interface IngestionStatus {
  filename: string;
  ingestion_progress: number;
  configs_processed_count: number;
  last_ingestion_time: string;
  total_errors_count: number;
  total_warnings_count: number;
  unsupported_configs_count: number;
}

export interface TopologySummary {
  total_zones: number;
  total_firewall_rules: number;
  total_routing_entries: number;
  firewalls_count: number;
  routers_count: number;
  switches_count: number;
  vlans_count: number;
  subnets_count: number;
}

export interface AnalyticsSummary {
  total_connections: number;
  total_bytes: number;
  protocols: Array<{ protocol: string; count: number }>;
}

export interface RiskSummary {
  by_level: { critical: number; high: number; medium: number; low: number };
  by_category: {
    shadowed: number;
    unused: number;
    insecure_service: number;
    overly_permissive: number;
  };
  overall_avg_score: number;
}

export interface RiskyRule {
  id: string;
  device_name: string;
  rule_name: string;
  source: string;
  destination: string;
  protocol: string;
  action: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  recommendation: string;
  cvss_color: string;
}

export interface AttackPath {
  id: string;
  entry_point: string;
  target: string;
  hops: number;
  total_risk_score: number;
  risk_level: string;
  path_nodes?: string[];
}

export interface AttackPathSummary {
  critical_paths_count: number;
  high_risk_paths_count: number;
  average_path_risk: number;
}

export interface MalwareEntryPoint {
  node_id: string;
  device_name: string;
  zone: string;
  ip_address: string;
  is_active_threat_vector: boolean;
}

export interface VulnerablePort {
  port: number;
  service: string;
  risk_level: string;
  reason: string;
  exposed_devices: string[];
  zones: string[];
  recommendation: string;
}

export interface RemediationItem {
  rule_id: string;
  rule_name: string;
  device_name: string;
  risk_score: number;
  risk_level: string;
  category: string;
  recommendation: string;
}

export interface RuleStats {
  total: number;
  by_action: Record<string, number>;
  enabled: number;
  disabled: number;
}

export interface Connection {
  id: string;
  timestamp: string;
  src_ip?: string;
  dst_ip?: string;
  protocol?: string;
  bytes_sent?: number;
  bytes_received?: number;
  action?: string;
}

export interface Threat {
  id: string;
  timestamp: string;
  name?: string;           // backend returns 'name' (mapped from threat_name)
  threat_name?: string;    // raw field alias
  severity?: string;
  src_ip?: string;         // backend returns src_ip
  source_ip?: string;      // kept for compatibility
  dst_ip?: string;
  threat_type?: string;
  risk_score?: number;
  device_name?: string;
  action?: string;
}

export interface UploadConfigResponse {
  upload_id: string;
  vendor: string;
}

export interface ValidationResult {
  valid: boolean;
  total: number;
  validRows: number;
  invalidRows: number;
  errors: string[];
}

export interface ReachabilityResult {
  reachable_devices: Array<{
    id: string;
    name: string;
    type: string;
    zone: string;
    confidence: string;
    allowed_ports: number[];
    traffic_volume_30d: number;
  }>;
  anomalies: string[];
}

// ─── Dashboard ──────────────────────────────────────────────────────────────

export const getIngestionStatus = () =>
  request<IngestionStatus>("/ingestion-status");

export const getTopologySummary = () =>
  request<TopologySummary>("/topology/summary");

export const getAnalyticsSummary = () =>
  request<AnalyticsSummary>("/analytics/summary");

// ─── Upload / Config ────────────────────────────────────────────────────────

export async function uploadConfig(file: File): Promise<UploadConfigResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/upload-config`, { method: "POST", body: form });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text);
  }
  return res.json();
}

export async function parseConfig(uploadId: string): Promise<{ message: string }> {
  const res = await fetch(`${BASE}/parse-config/${uploadId}`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function uploadData(file: File): Promise<unknown> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/upload-data`, { method: "POST", body: form });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(text);
  }
  return res.json();
}

export async function validateUpload(file: File): Promise<ValidationResult> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/validate-upload`, { method: "POST", body: form });
  if (!res.ok) throw new Error(await res.text());
  const raw = await res.json();
  // Normalise to the shape the UI expects
  return {
    valid: raw.valid ?? true,
    total: raw.total ?? 0,
    validRows: raw.valid_rows ?? raw.validRows ?? 0,
    invalidRows: raw.invalid_rows ?? raw.invalidRows ?? 0,
    errors: raw.errors ?? [],
  };
}

export const downloadTemplate = (format: "csv" | "json" | "excel") =>
  window.open(`${BASE}/download-template?format=${format}`, "_blank");

// ─── Risk / Analysis ────────────────────────────────────────────────────────

export const getRiskSummary = () =>
  request<RiskSummary>("/risk-analysis/summary");

export const getRiskyRules = (minScore = 0, limit = 100) =>
  request<RiskyRule[]>(`/risky-rules?min_score=${minScore}&limit=${limit}`);

export const triggerRuleAnalysis = () =>
  request<{ message: string }>("/analyze-rules", { method: "POST" });

export const getVulnerablePorts = () =>
  request<VulnerablePort[]>("/vulnerable-ports");

export const analyzeReachability = (sourceZone: string) =>
  request<ReachabilityResult>("/analyze-reachability", {
    method: "POST",
    body: JSON.stringify({ source_zone: sourceZone }),
  });

export const getRuleStats = () => request<RuleStats>("/rule-stats");

// ─── Attack Paths ────────────────────────────────────────────────────────────

export const getAttackPaths = (minRisk = 0, limit = 50) =>
  request<AttackPath[]>(`/attack-paths?min_risk=${minRisk}&limit=${limit}`);

export const getAttackPathSummary = () =>
  request<AttackPathSummary>("/attack-paths/summary");

export const triggerAttackPathAnalysis = (
  entryPoint: string,
  target: string,
  maxHops = 10
) =>
  request<{ message: string }>("/analyze-attack-paths", {
    method: "POST",
    body: JSON.stringify({
      entry_point: entryPoint,
      target,
      max_hops: maxHops,
    }),
  });

export const getMalwareEntryPoints = () =>
  request<MalwareEntryPoint[]>("/malware-entry-points");

// ─── Threats / Live Traffic ──────────────────────────────────────────────────

export const getThreats = (limit = 100) =>
  request<Threat[]>(`/threats?limit=${limit}`);

export const getConnections = (limit = 100) =>
  request<Connection[]>(`/connections?limit=${limit}`);

// ─── Remediation ────────────────────────────────────────────────────────────

export const getRemediation = () => request<RemediationItem[]>("/remediation");

// ─── Attack Graph (full topology) ────────────────────────────────────────────

export interface GraphNode {
  id: string;
  label: string;
  device_name: string;
  device_type: string;
  ip_address: string;
  is_entry_point: boolean;
  is_target: boolean;
  ports_open: number[];
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  rule_name: string;
  rule_id: string;
  port: string;
  protocol: string;
  action: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  recommendation: string;
  is_deny: boolean;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    total_nodes: number;
    total_edges: number;
    allow_edges: number;
    deny_edges: number;
    high_risk_edges: number;
  };
}

export const getAttackGraph = () => request<AttackGraph>("/attack-graph");

// ─── Enterprise: Executive Summary ──────────────────────────────────────────

export interface ExecutiveSummaryResponse {
  summary: string;
  risk_score: number;
  risk_trend: string;
  top_findings: Array<{
    rule_name: string;
    risk_score: number;
    risk_level: string;
    reason: string;
    device: string;
  }>;
}

export const getExecutiveSummary = () =>
  request<ExecutiveSummaryResponse>("/dashboard/executive-summary");

// ─── Enterprise: Compliance ─────────────────────────────────────────────────

export interface ComplianceScoreData {
  framework: string;
  score: number;
  status: string;
  findings: number;
  details: string[];
}

export const getComplianceScores = () =>
  request<ComplianceScoreData[]>("/compliance-scores");

// ─── Enterprise: Firewall Health ────────────────────────────────────────────

export interface FirewallHealthData {
  score: number;
  grade: string;
  breakdown: Record<string, number>;
  recommendations: string[];
}

export const getFirewallHealth = () =>
  request<FirewallHealthData>("/firewall-health");

// ─── Enterprise: Attack Surface ─────────────────────────────────────────────

export interface AttackSurfaceData {
  exposed_ports: number;
  internet_facing_rules: number;
  crown_jewel_assets: number;
  total_attack_paths: number;
  critical_paths: number;
  entry_points: number;
}

export const getAttackSurface = () =>
  request<AttackSurfaceData>("/attack-surface");

// ─── Enterprise: Firewall Topology ──────────────────────────────────────────

export interface FirewallTopologyData {
  firewalls: Array<{
    device_name: string;
    device_type: string;
    vendor: string;
    zones: string[];
    ip_address: string;
    rules_count: number;
    is_entry_point: boolean;
  }>;
  connections: Array<{
    source: string;
    target: string;
    type: string;
    shared_zones: string[];
    trust_level: string;
  }>;
  chain_detected: boolean;
  chain_details?: string;
}

export const getFirewallTopology = () =>
  request<FirewallTopologyData>("/firewall-topology");

// ─── Enterprise: Export ─────────────────────────────────────────────────────

export function downloadPDFReport() {
  window.open(`${BASE}/export/pdf`, "_blank");
}

export function downloadCSVExport() {
  window.open(`${BASE}/export/csv`, "_blank");
}

// ─── IP-to-IP Vulnerability Analysis ────────────────────────────────────────

export interface IPEntry {
  ip: string;
  label: string;
  zone?: string;
  device_type?: string;
  is_firewall: boolean;
}

export interface IPListResponse {
  ips: IPEntry[];
  total: number;
}

export interface VulnNode {
  id: string;
  ip: string;
  label: string;
  zone?: string;
  device_type?: string;
  is_firewall: boolean;
  is_source: boolean;
  is_target: boolean;
}

export interface VulnEdge {
  id: string;
  source_node: string;
  target_node: string;
  rule_name: string;
  port: string;
  protocol: string;
  risk_score: number;
  risk_level: string;
  compromise_method: string;
  compromisability: number;
  remediations: string[];
}

export interface IPVulnerabilityResponse {
  source?: IPEntry;
  target?: IPEntry;
  nodes: VulnNode[];
  edges: VulnEdge[];
  overall_risk: number;
  risk_level: string;
  path_exists: boolean;
  hop_count: number;
  summary: string;
  source_found: boolean;
  target_found: boolean;
}

export const getFirewallIPs = () =>
  request<IPListResponse>("/topology/ips");

export const analyzeIPVulnerability = (source_ip: string, target_ip: string) =>
  request<IPVulnerabilityResponse>("/ip-vulnerability", {
    method: "POST",
    body: JSON.stringify({ source_ip, target_ip }),
  });

// ─── Attack Surface Analysis (CSV + XML) ─────────────────────────────────────

export interface AttackSurfacePortDetail {
  port: string;
  service: string;
  protocol: string;
  access_type: string;
  base_risk: number;
  modifier: number;
  total: number;
  lateral_movement: boolean;
  attack_vector: string;
  explanation: string;
}

export interface AttackSurfaceGraphNode {
  id: string;
  ip: string;
  is_source: boolean;
  is_target: boolean;
}

export interface AttackSurfaceGraphEdge {
  source: string;
  target: string;
  port: string;
  protocol: string;
  risk_score: number;
  access_type: string;
}

export interface AttackSurfaceGraph {
  nodes: AttackSurfaceGraphNode[];
  edges: AttackSurfaceGraphEdge[];
}

export interface AttackSurfaceResponse {
  source_ip: string;
  destination_ip: string;
  path_exists: boolean;
  risk_score: number;
  risk_level: string;            // Low / Medium / High / Critical
  allowed_ports: AttackSurfacePortDetail[];
  explanation: string[];
  lateral_movement_risk: string; // None / Possible / High
  lateral_movement_paths: string[];
  attack_vectors: string[];
  bidirectional_exposure: boolean;
  graph: AttackSurfaceGraph;
}

export const analyzeAttackSurface = (source_ip: string, target_ip: string) =>
  request<AttackSurfaceResponse>("/attack-surface", {
    method: "POST",
    body: JSON.stringify({ source_ip, target_ip }),
  });
