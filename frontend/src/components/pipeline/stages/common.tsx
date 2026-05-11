import { Loader2 } from "lucide-react";

import type { StageId } from "@/api/types";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { STEP_DEFINITIONS, type StepStatus } from "@/components/pipeline/steps";

/** Reusable card frame used by every per-stage panel. */
export function StagePanelFrame({
  stage,
  status,
  progressMessage,
  children,
  empty,
}: {
  stage: StageId;
  status: StepStatus;
  progressMessage?: string;
  children?: React.ReactNode;
  /** Optional fallback text when no result is available yet. */
  empty?: string;
}) {
  const def = STEP_DEFINITIONS.find((s) => s.id === stage);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {def?.label ?? stage}
          {status === "running" && (
            <Loader2 className="h-4 w-4 animate-spin text-primary" />
          )}
        </CardTitle>
        <CardDescription>
          {def?.caption}
          {status === "running" && progressMessage ? ` -- ${progressMessage}` : ""}
        </CardDescription>
      </CardHeader>
      <CardContent>
        {children ?? (
          <div className="text-sm text-muted-foreground rounded-md border border-dashed border-border p-6 text-center">
            {status === "pending" ? "Not started yet." : (empty ?? "Waiting for results...")}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

/** Small stat tile used in headers. */
export function Stat({
  label,
  value,
}: {
  label: string;
  value: string | number;
}) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="text-sm font-medium tabular-nums truncate" title={String(value)}>
        {value}
      </div>
    </div>
  );
}

/** Truncated mono row used for hashes, file paths, etc. */
export function Mono({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <code
      className="font-mono text-xs text-foreground/90 break-all"
      title={title}
    >
      {children}
    </code>
  );
}
