import { useMemo } from "react";
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

interface GenericStagePanelProps {
  stage: StageId;
  status: StepStatus;
  /** May be undefined while the stage is still running. */
  result: unknown;
  progressMessage?: string;
}

export function GenericStagePanel({
  stage,
  status,
  result,
  progressMessage,
}: GenericStagePanelProps) {
  const def = STEP_DEFINITIONS.find((s) => s.id === stage);
  const json = useMemo(
    () => (result !== undefined ? JSON.stringify(result, null, 2) : null),
    [result],
  );

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
        {status === "pending" ? (
          <div className="text-sm text-muted-foreground rounded-md border border-dashed border-border p-6 text-center">
            Not started yet.
          </div>
        ) : json === null ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Waiting for first
            result event...
          </div>
        ) : (
          <pre className="text-xs leading-relaxed overflow-auto max-h-[60vh] rounded-md border border-border bg-muted/40 p-3 font-mono whitespace-pre">
            {json}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}
