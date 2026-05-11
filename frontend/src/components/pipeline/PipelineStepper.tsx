import { Check, Circle, Loader2, X } from "lucide-react";

import type { StepId } from "@/api/types";
import { cn } from "@/lib/utils";

import { STEP_DEFINITIONS, type StepKind, type StepStatus } from "./steps";

interface PipelineStepperProps {
  /** Status of every step keyed by step id. */
  statuses: Record<StepId, StepStatus>;
  /** Which step is currently focused (drives the highlight). */
  activeStep: StepId;
  onSelect?: (step: StepId) => void;
}

export function PipelineStepper({ statuses, activeStep, onSelect }: PipelineStepperProps) {
  return (
    <ol className="relative space-y-1.5">
      {/* connecting vertical line */}
      <div
        aria-hidden
        className="absolute left-[19px] top-3 bottom-3 w-px bg-border"
      />
      {STEP_DEFINITIONS.map((step) => {
        const status = statuses[step.id];
        const isActive = step.id === activeStep;
        const clickable = onSelect !== undefined && status !== "pending";

        return (
          <li key={step.id}>
            <button
              type="button"
              disabled={!clickable}
              onClick={clickable ? () => onSelect?.(step.id) : undefined}
              className={cn(
                "relative w-full flex items-start gap-3 rounded-md px-2 py-2 text-left transition-colors",
                isActive && "bg-accent",
                clickable && !isActive && "hover:bg-accent/40 cursor-pointer",
                !clickable && "cursor-default",
              )}
            >
              <StatusIcon status={status} />
              <div className="min-w-0">
                <div
                  className={cn(
                    "text-sm font-medium leading-tight",
                    status === "pending" && "text-muted-foreground",
                  )}
                >
                  {step.label}
                </div>
                <div className="text-[11px] text-muted-foreground leading-tight mt-0.5 flex items-center gap-1.5">
                  <span>{step.caption}</span>
                  <KindBadge kind={step.kind} />
                </div>
              </div>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function StatusIcon({ status }: { status: StepStatus }) {
  const baseClass = "h-5 w-5 mt-0.5 shrink-0 relative z-[1] rounded-full bg-card";
  switch (status) {
    case "done":
      return (
        <span className={cn(baseClass, "flex items-center justify-center")}>
          <Check className="h-4 w-4 text-primary" strokeWidth={3} />
        </span>
      );
    case "running":
      return (
        <span className={cn(baseClass, "flex items-center justify-center")}>
          <Loader2 className="h-4 w-4 text-primary animate-spin" />
        </span>
      );
    case "error":
      return (
        <span className={cn(baseClass, "flex items-center justify-center")}>
          <X className="h-4 w-4 text-destructive" strokeWidth={3} />
        </span>
      );
    case "active":
      return (
        <span className={cn(baseClass, "flex items-center justify-center")}>
          <span className="h-2.5 w-2.5 rounded-full bg-primary ring-2 ring-primary/30" />
        </span>
      );
    case "pending":
    default:
      return (
        <span className={cn(baseClass, "flex items-center justify-center")}>
          <Circle className="h-3.5 w-3.5 text-muted-foreground/60" />
        </span>
      );
  }
}

function KindBadge({ kind }: { kind: StepKind }) {
  const label = kind === "ui" ? "ui" : kind === "script" ? "script" : "llm";
  return (
    <span
      className={cn(
        "rounded px-1 py-px text-[9px] font-medium tracking-wider uppercase",
        "bg-muted text-muted-foreground",
      )}
    >
      {label}
    </span>
  );
}
