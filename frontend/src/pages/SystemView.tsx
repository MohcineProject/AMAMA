import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, Home } from "lucide-react";

import type { StepId } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { PipelineStepper } from "@/components/pipeline/PipelineStepper";
import { ProgressBar } from "@/components/pipeline/ProgressBar";
import { STEP_DEFINITIONS, type StepStatus } from "@/components/pipeline/steps";
import { StartStage } from "@/components/pipeline/stages/StartStage";
import { useWorkspace } from "@/store/workspace";

/** Initial state: the user is focused on `start`, nothing has run yet. */
function initialStatuses(): Record<StepId, StepStatus> {
  return STEP_DEFINITIONS.reduce(
    (acc, step) => {
      acc[step.id] = step.id === "start" ? "active" : "pending";
      return acc;
    },
    {} as Record<StepId, StepStatus>,
  );
}

export function SystemView() {
  const { path: workspace } = useWorkspace();
  const [searchParams] = useSearchParams();
  const caseName = searchParams.get("case") ?? "";

  const [statuses] = useState<Record<StepId, StepStatus>>(() => initialStatuses());
  const [activeStep, setActiveStep] = useState<StepId>("start");

  // Picked by `activeStep`. For now nothing actually runs, so progress stays 0
  // and the button just toggles a local flag. SSE wiring lands in commit 8.
  const [isRunning, setIsRunning] = useState(false);
  const progress = 0;

  const headerLabel = useMemo(
    () => STEP_DEFINITIONS.find((s) => s.id === activeStep)?.label ?? activeStep,
    [activeStep],
  );

  // ---- guard: missing workspace or case -> friendly error ----
  if (!workspace) {
    return (
      <MissingPrereq
        title="No working directory set"
        message="Pick a working directory on the Home page first."
      />
    );
  }
  if (!caseName) {
    return (
      <MissingPrereq
        title="No case in URL"
        message="Open this page from the Home page after selecting a case."
      />
    );
  }

  return (
    <div className="h-[calc(100vh-3.5rem)] grid grid-cols-[260px_1fr]">
      {/* ---------- LEFT: stepper ---------- */}
      <aside className="border-r border-border bg-card/40 overflow-y-auto">
        <div className="p-4 border-b border-border">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">
            Case
          </div>
          <div className="font-medium text-sm truncate" title={caseName}>
            {caseName}
          </div>
        </div>
        <div className="p-3">
          <PipelineStepper
            statuses={statuses}
            activeStep={activeStep}
            onSelect={setActiveStep}
          />
        </div>
      </aside>

      {/* ---------- RIGHT: progress + active stage content ---------- */}
      <section className="overflow-y-auto">
        <div className="border-b border-border bg-card/40 px-6 py-4">
          <div className="flex items-center justify-between gap-4 mb-3">
            <div>
              <div className="text-xs uppercase tracking-wide text-muted-foreground">
                Stage
              </div>
              <div className="font-medium">{headerLabel}</div>
            </div>
            <div className="w-56">
              <ProgressBar value={progress} label="Progress" />
            </div>
          </div>
        </div>

        <div className="p-6 max-w-4xl">
          {activeStep === "start" ? (
            <StartStage
              workspace={workspace}
              caseName={caseName}
              isRunning={isRunning}
              onLaunch={() => setIsRunning(true) /* placeholder; SSE in commit 8 */}
            />
          ) : (
            <Placeholder stepId={activeStep} />
          )}
        </div>
      </section>
    </div>
  );
}

function Placeholder({ stepId }: { stepId: StepId }) {
  const def = STEP_DEFINITIONS.find((s) => s.id === stepId);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{def?.label ?? stepId}</CardTitle>
        <CardDescription>
          Output will appear here once the analysis reaches this stage.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="text-sm text-muted-foreground">
          (Real content lands in upcoming commits.)
        </div>
      </CardContent>
    </Card>
  );
}

function MissingPrereq({ title, message }: { title: string; message: string }) {
  return (
    <div className="container py-12 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            {title}
          </CardTitle>
          <CardDescription>{message}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <Link to="/">
              <Home className="h-4 w-4" />
              Back to Home
            </Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
