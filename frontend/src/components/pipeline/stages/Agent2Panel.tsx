import { CheckCircle2, HelpCircle, MinusCircle, ShieldAlert, XCircle } from "lucide-react";

import type { Agent2Result, PivotVerdict, Verdict } from "@/api/stage-results";
import { Badge } from "@/components/ui/badge";
import type { StepStatus } from "@/components/pipeline/steps";

import { Mono, StagePanelFrame } from "./common";

interface Props {
  status: StepStatus;
  result?: Agent2Result;
  progressMessage?: string;
}

export function Agent2Panel({ status, result, progressMessage }: Props) {
  if (!result) {
    return <StagePanelFrame stage="agent2" status={status} progressMessage={progressMessage} />;
  }

  return (
    <StagePanelFrame stage="agent2" status={status} progressMessage={progressMessage}>
      <div className="space-y-3">
        <div className="text-sm text-muted-foreground">
          {result.verdicts.length} subject{result.verdicts.length === 1 ? "" : "s"} reviewed.
        </div>
        {result.verdicts.map((v, i) => (
          <VerdictCard key={`${v.subject}-${i}`} v={v} />
        ))}
      </div>
    </StagePanelFrame>
  );
}

function VerdictCard({ v }: { v: PivotVerdict }) {
  return (
    <div className="rounded-md border border-border bg-card/60 p-3 space-y-2">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="font-medium text-sm">{v.subject}</div>
        <div className="flex items-center gap-2">
          <VerdictBadge verdict={v.verdict} />
          <ConfidenceMeter value={v.confidence} />
        </div>
      </div>
      <p className="text-sm text-foreground/90 leading-relaxed">{v.rationale}</p>
      {v.evidence_refs.length > 0 && (
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-1">
            Evidence
          </div>
          <div className="flex flex-wrap gap-1">
            {v.evidence_refs.map((r) => (
              <Mono key={r}>{r}</Mono>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const map: Record<
    Verdict,
    { label: string; variant: "destructive" | "warning" | "info" | "success" | "secondary"; icon: React.ReactNode }
  > = {
    confirmed_malicious: {
      label: "Confirmed",
      variant: "destructive",
      icon: <ShieldAlert className="h-3 w-3" />,
    },
    likely_malicious: {
      label: "Likely",
      variant: "warning",
      icon: <XCircle className="h-3 w-3" />,
    },
    needs_more_data: {
      label: "Needs data",
      variant: "info",
      icon: <HelpCircle className="h-3 w-3" />,
    },
    benign: {
      label: "Benign",
      variant: "success",
      icon: <CheckCircle2 className="h-3 w-3" />,
    },
    false_positive: {
      label: "False +",
      variant: "secondary",
      icon: <MinusCircle className="h-3 w-3" />,
    },
  };
  const m = map[verdict] ?? map.needs_more_data;
  return (
    <Badge variant={m.variant} className="gap-1">
      {m.icon} {m.label}
    </Badge>
  );
}

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, Math.round(value * 100)));
  // colour follows the confidence; high = primary, mid = yellow, low = muted
  const colour =
    pct >= 80
      ? "bg-primary"
      : pct >= 50
        ? "bg-yellow-400"
        : "bg-muted-foreground";
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1.5 w-20 rounded-full bg-secondary overflow-hidden">
        <div className={`h-full ${colour}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] text-muted-foreground tabular-nums w-8">
        {pct}%
      </span>
    </div>
  );
}
