import * as React from "react";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { cn } from "@/lib/utils";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-destructive/15 text-destructive border border-destructive/30",
  high: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  low: "bg-success/15 text-success border border-success/30",
  info: "bg-primary/15 text-primary border border-primary/30",
};

function SeverityPill({ level }: { level?: string }) {
  if (!level) return null;
  const key = level.toLowerCase();
  return (
    <span
      className={cn(
        "inline-block px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wide leading-none",
        SEVERITY_STYLES[key] ?? "bg-muted text-muted-foreground border border-border"
      )}
    >
      {level}
    </span>
  );
}

function buildText(term: string, context?: string, severity?: string) {
  const termText = term.trim();
  const contextText = (context ?? "").trim();
  const sevText = (severity ?? "").trim();

  const explanation = contextText
    ? `${termText} is part of this finding: ${contextText}.`
    : `${termText} is part of this firewall analysis result.`;

  const riskImplication = sevText
    ? `Current severity is ${sevText.toUpperCase()}. Treat this item according to your risk policy and business impact.`
    : "Review source, destination, protocol, and exposure scope before deciding remediation priority.";

  const recommendedAction =
    "Validate business need, restrict access to minimum required scope, and monitor traffic for abuse patterns.";

  return { explanation, riskImplication, recommendedAction };
}

export interface SmartTooltipProps {
  term: string;
  context?: string;
  severity?: string;
  page?: string;
  side?: "top" | "bottom" | "left" | "right";
  children?: React.ReactNode;
  className?: string;
}

export function SmartTooltip({
  term,
  context,
  severity,
  side = "top",
  children,
  className,
}: SmartTooltipProps) {
  const { explanation, riskImplication, recommendedAction } = buildText(term, context, severity);

  return (
    <TooltipPrimitive.Root delayDuration={200}>
      <TooltipPrimitive.Trigger asChild>
        <span
          className={cn(
            "cursor-help border-b border-dashed border-muted-foreground/50 transition-colors hover:border-primary/70",
            className
          )}
        >
          {children ?? term}
        </span>
      </TooltipPrimitive.Trigger>

      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className={cn(
            "z-[9999] w-72 rounded-xl border border-border bg-popover p-0 shadow-xl",
            "animate-in fade-in-0 zoom-in-95",
            "data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95",
            "data-[side=bottom]:slide-in-from-top-2",
            "data-[side=top]:slide-in-from-bottom-2",
            "data-[side=left]:slide-in-from-right-2",
            "data-[side=right]:slide-in-from-left-2"
          )}
        >
          <div className="flex items-start justify-between gap-2 px-3 pt-3 pb-2 border-b border-border">
            <p className="text-[12px] font-semibold text-foreground leading-snug line-clamp-2 flex-1">
              {term}
            </p>
            <SeverityPill level={severity} />
          </div>

          <div className="px-3 py-2.5 space-y-2.5">
            <p className="text-[11px] text-popover-foreground leading-relaxed">{explanation}</p>

            <div className="space-y-0.5">
              <p className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground leading-none">
                Risk Implication
              </p>
              <p className="text-[11px] text-popover-foreground leading-relaxed">{riskImplication}</p>
            </div>

            <div className="space-y-0.5">
              <p className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground leading-none">
                Recommended Action
              </p>
              <p className="text-[11px] text-popover-foreground leading-relaxed">{recommendedAction}</p>
            </div>
          </div>

          <div className="px-3 py-1.5 border-t border-border bg-muted/30 rounded-b-xl">
            <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-medium">
              ComplyGuard Security Notes
            </p>
          </div>

          <TooltipPrimitive.Arrow className="fill-border" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

export function T(props: SmartTooltipProps) {
  return <SmartTooltip {...props} />;
}
