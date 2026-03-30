import { useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronUp,
  Skull,
  UserX,
  Search,
  ListOrdered,
  Server,
  Database,
  Zap,
  DollarSign,
  Clock,
  Eye,
} from "lucide-react";

const SectionIcon = ({ section }: { section: string }) => {
  const icons: Record<string, React.ElementType> = {
    attacker_profile: UserX,
    discovery_method: Search,
    attack_steps: ListOrdered,
    systems_compromised: Server,
    data_at_risk: Database,
    blast_radius: Zap,
    business_impact: DollarSign,
    time_to_exploit: Clock,
    detection_difficulty: Eye,
  };
  const Icon = icons[section] || Skull;
  return <Icon className="h-3.5 w-3.5 text-destructive flex-shrink-0 mt-0.5" />;
};

const DifficultyBadge = ({ level }: { level: string }) => {
  const cls =
    level.toLowerCase().includes("very hard")
      ? "badge-critical"
      : level.toLowerCase().includes("hard")
      ? "badge-high"
      : level.toLowerCase().includes("medium")
      ? "badge-medium"
      : "badge-low";
  return <span className={`${cls} px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase`}>{level}</span>;
};

interface CompromiseNarrativeCardProps {
  findingKey: string;
  riskLevel: string;
}

function buildNarrative(riskLevel: string) {
  const critical = riskLevel === "critical";
  return {
    attacker_profile: critical
      ? "External attacker actively targeting exposed administrative or legacy services"
      : "Adversary with foothold in an adjacent segment abusing allowed traffic paths",
    discovery_method:
      "Routine host and service enumeration followed by validation of reachable allow rules",
    attack_steps: [
      "Scan exposed hosts and enumerate reachable services from the source segment.",
      "Probe weak authentication, missing patches, and protocol misconfigurations.",
      "Gain initial access and pivot through permitted east-west communications.",
      "Harvest credentials and query sensitive systems reachable through policy paths.",
      "Exfiltrate data over approved outbound channels to reduce detection noise.",
    ],
    systems_compromised: [
      "Source-facing workload in the origin zone",
      "Intermediate service host reachable via allow rules",
      "High-value target system in downstream segment",
    ],
    data_at_risk: [
      "Credentials and service account secrets",
      "Configuration and network mapping information",
      "Business and operational data exposed by reachable applications",
    ],
    blast_radius:
      "Compromise can spread across connected zones where permissive rules allow lateral movement.",
    business_impact:
      critical
        ? "Potential for severe downtime, incident response costs, and mandatory compliance reporting."
        : "Elevated risk of service disruption and data exposure if controls are not tightened.",
    time_to_exploit: critical ? "Minutes to a few hours" : "Hours to days",
    detection_difficulty: critical ? "Hard" : "Medium",
  };
}

export function CompromiseNarrativeCard({ findingKey, riskLevel }: CompromiseNarrativeCardProps) {
  const [open, setOpen] = useState(false);
  const narrative = useMemo(() => buildNarrative(riskLevel), [riskLevel]);

  if (riskLevel !== "critical" && riskLevel !== "high") return null;

  return (
    <div className="mt-2 rounded-xl border border-destructive/20 bg-destructive/5 overflow-hidden">
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-destructive/10 transition-colors"
        onClick={() => setOpen(!open)}
      >
        <div className="flex items-center gap-2">
          <Skull className="h-3.5 w-3.5 text-destructive flex-shrink-0" />
          <span className="text-[11px] font-semibold text-destructive uppercase tracking-wide">
            How This Gets Exploited
          </span>
          <span className="text-[10px] text-muted-foreground">— Risk playbook for {findingKey}</span>
        </div>
        {open ? <ChevronUp className="h-3.5 w-3.5 text-destructive" /> : <ChevronDown className="h-3.5 w-3.5 text-destructive" />}
      </button>

      {open && (
        <div className="px-4 pb-4 pt-0 border-t border-destructive/20">
          <div className="space-y-3 pt-3">
            {[
              { key: "attacker_profile", label: "Attacker Profile", content: narrative.attacker_profile },
              { key: "discovery_method", label: "Discovery Method", content: narrative.discovery_method },
              { key: "attack_steps", label: "Step-by-Step Attack", list: narrative.attack_steps },
              { key: "systems_compromised", label: "Systems Compromised", list: narrative.systems_compromised },
              { key: "data_at_risk", label: "Data at Risk", list: narrative.data_at_risk },
              { key: "blast_radius", label: "Blast Radius", content: narrative.blast_radius },
              { key: "business_impact", label: "Business Impact", content: narrative.business_impact },
              { key: "time_to_exploit", label: "Time to Exploit", content: narrative.time_to_exploit },
              { key: "detection_difficulty", label: "Detection Difficulty", content: narrative.detection_difficulty },
            ].map(({ key, label, content, list }) => (
              <div key={key} className="flex items-start gap-2.5">
                <SectionIcon section={key} />
                <div className="flex-1 min-w-0">
                  <p className="text-[10px] uppercase tracking-widest text-destructive/70 font-bold mb-0.5">{label}</p>
                  {key === "detection_difficulty" && content ? (
                    <div className="flex items-center gap-2">
                      <DifficultyBadge level={content} />
                    </div>
                  ) : list ? (
                    <ol className="space-y-1">
                      {list.map((item, i) => (
                        <li key={i} className="text-[11px] text-foreground leading-relaxed flex gap-1.5">
                          <span className="text-destructive/60 font-mono text-[10px] mt-px">{i + 1}.</span>
                          <span>{item}</span>
                        </li>
                      ))}
                    </ol>
                  ) : (
                    <p className="text-[11px] text-foreground leading-relaxed">{content}</p>
                  )}
                </div>
              </div>
            ))}
            <p className="text-[9px] text-muted-foreground italic pt-1">
              Generated from current risk findings and rule relationships
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
