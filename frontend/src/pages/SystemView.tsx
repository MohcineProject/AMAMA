import { useCallback, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AlertTriangle, Home } from "lucide-react";

import type { StageId, StepId } from "@/api/types";
import { STAGES } from "@/api/types";
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
import { GenericStagePanel } from "@/components/pipeline/stages/GenericStagePanel";
import { StartStage } from "@/components/pipeline/stages/StartStage";
import { useAnalysisRun } from "@/hooks/useAnalysisRun";
import { useWorkspace } from "@/store/workspace";

export function SystemView() {
  const { path: workspace } = useWorkspace();
  const [searchParams] = useSearchParams();
  const caseName = searchParams.get("case") ?? "";

  const { state, launch } = useAnalysisRun({
    workspace: workspace ?? "",
    caseName,
  });

  // If the user manually clicks a step (other than "start" pre-launch), we
  // stop auto-following the backend. We track that as a pinned step.
  const [pinnedStep, setPinnedStep] = useState<StepId | null>(null);

  /** Where the right pane is focused. */
  const activeStep: StepId = useMemo(() => {
    if (pinnedStep) return pinnedStep;
    if (state.isComplete) return "report";
    if (state.currentStage) return state.currentStage;
    if (state.statuses.start === "done") return "start"; // run_start fired but no stage yet
    return "start";
  }, [pinnedStep, state.isComplete, state.currentStage, state.statuses.start]);

  const onSelectStep = useCallback((step: StepId) => {
    setPinnedStep(step);
  }, []);

  const onLaunch = useCallback(() => {
    setPinnedStep(null);
    void launch();
  }, [launch]);

  const headerLabel = useMemo(
    () => STEP_DEFINITIONS.find((s) => s.id === activeStep)?.label ?? activeStep,
    [activeStep],
  );

  // Overall progress: completed stages contribute fully, the in-flight stage
  // contributes proportionally to its percent.
  const overallPercent = useMemo(() => {
    if (state.isComplete) return 100;
    const doneCount = STAGES.filter((s) => state.statuses[s] === "done").length;
    if (state.currentStage === null) return (doneCount / STAGES.length) * 100;
    const completedShare = (doneCount / STAGES.length) * 100;
    const inStageShare = state.progressPercent / STAGES.length;
    return completedShare + inStageShare;
  }, [state.isComplete, state.currentStage, state.statuses, state.progressPercent]);

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
          {pinnedStep && (
            <button
              onClick={() => setPinnedStep(null)}
              className="text-[11px] text-primary hover:underline mt-2"
            >
              Resume live view
            </button>
          )}
        </div>
        <div className="p-3">
          <PipelineStepper
            statuses={state.statuses}
            activeStep={activeStep}
            onSelect={onSelectStep}
          />
        </div>
      </aside>

      {/* ---------- RIGHT: progress + active stage content ---------- */}
      <section className="overflow-y-auto">
        <div className="border-b border-border bg-card/40 px-6 py-4">
          <div className="flex items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="text-xs uppercase tracking-wide text-muted-foreground">
                Stage
              </div>
              <div className="font-medium truncate">{headerLabel}</div>
              {state.isRunning && state.progressMessage && (
                <div className="text-xs text-muted-foreground mt-0.5 truncate">
                  {state.progressMessage}
                </div>
              )}
            </div>
            <div className="w-60 shrink-0">
              <ProgressBar
                value={overallPercent}
                label={state.isComplete ? "Complete" : "Overall"}
              />
            </div>
          </div>
        </div>

        <div className="p-6 max-w-4xl space-y-4">
          {state.error && (
            <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
              <AlertTriangle className="h-4 w-4 mt-0.5 text-destructive shrink-0" />
              <div>
                <div className="font-medium">Run failed</div>
                <div className="text-muted-foreground text-xs mt-0.5">
                  {state.error}
                </div>
              </div>
            </div>
          )}

          <ActivePanel
            activeStep={activeStep}
            workspace={workspace}
            caseName={caseName}
            isRunning={state.isRunning}
            currentStage={state.currentStage}
            progressMessage={state.progressMessage}
            stageResults={state.stageResults}
            stageStatuses={state.statuses}
            isComplete={state.isComplete}
            onLaunch={onLaunch}
          />
        </div>
      </section>
    </div>
  );
}

interface ActivePanelProps {
  activeStep: StepId;
  workspace: string;
  caseName: string;
  isRunning: boolean;
  currentStage: StageId | null;
  progressMessage: string;
  stageResults: Partial<Record<StageId, unknown>>;
  stageStatuses: Record<StepId, StepStatus>;
  isComplete: boolean;
  onLaunch: () => void;
}

function ActivePanel({
  activeStep,
  workspace,
  caseName,
  isRunning,
  currentStage,
  progressMessage,
  stageResults,
  stageStatuses,
  isComplete,
  onLaunch,
}: ActivePanelProps) {
  if (activeStep === "start") {
    return (
      <StartStage
        workspace={workspace}
        caseName={caseName}
        isRunning={isRunning}
        onLaunch={onLaunch}
      />
    );
  }

  if (activeStep === "report") {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Report</CardTitle>
          <CardDescription>
            Final 6-section narrative will be rendered here in the next commit.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {stageResults.agent3 === undefined ? (
            <div className="text-sm text-muted-foreground">
              {isComplete
                ? "No report data was received."
                : "Waiting for the report writer to finish..."}
            </div>
          ) : (
            <pre className="text-xs leading-relaxed overflow-auto max-h-[60vh] rounded-md border border-border bg-muted/40 p-3 font-mono whitespace-pre">
              {JSON.stringify(stageResults.agent3, null, 2)}
            </pre>
          )}
        </CardContent>
      </Card>
    );
  }

  const stage = activeStep as StageId;
  return (
    <GenericStagePanel
      stage={stage}
      status={stageStatuses[stage]}
      result={stageResults[stage]}
      progressMessage={stage === currentStage ? progressMessage : undefined}
    />
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
