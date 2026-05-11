import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/api/client";
import type { SseEvent, StageId, StepId } from "@/api/types";
import { STAGES } from "@/api/types";
import type { StepStatus } from "@/components/pipeline/steps";
import { STEP_DEFINITIONS } from "@/components/pipeline/steps";

/** Public shape consumed by SystemView. SSE state only -- activeStep is
 * derived in the component so we don't fight over a single source of truth. */
export interface AnalysisRunState {
  statuses: Record<StepId, StepStatus>;
  /** Stage the backend is currently working on, or null between stages. */
  currentStage: StageId | null;
  progressPercent: number;
  progressMessage: string;
  stageResults: Partial<Record<StageId, unknown>>;
  /** True from the moment Launch is clicked until run_complete/error. */
  isRunning: boolean;
  /** Set to true once `run_complete` has been received. */
  isComplete: boolean;
  /** Populated on error. */
  error: string | null;
  runId: string | null;
}

interface UseAnalysisRunArgs {
  workspace: string;
  caseName: string;
}

function initialStatuses(): Record<StepId, StepStatus> {
  return STEP_DEFINITIONS.reduce(
    (acc, step) => {
      acc[step.id] = step.id === "start" ? "active" : "pending";
      return acc;
    },
    {} as Record<StepId, StepStatus>,
  );
}

const initialState = (): AnalysisRunState => ({
  statuses: initialStatuses(),
  currentStage: null,
  progressPercent: 0,
  progressMessage: "",
  stageResults: {},
  isRunning: false,
  isComplete: false,
  error: null,
  runId: null,
});

/**
 * Drives a single analysis run end-to-end:
 *   POST /api/cases/analyze  -> run_id
 *   EventSource /api/runs/<run_id>/events -> live state updates
 */
export function useAnalysisRun({ workspace, caseName }: UseAnalysisRunArgs) {
  const [state, setState] = useState<AnalysisRunState>(initialState);
  const esRef = useRef<EventSource | null>(null);

  const cleanup = useCallback(() => {
    esRef.current?.close();
    esRef.current = null;
  }, []);

  useEffect(() => cleanup, [cleanup]);

  const handleEvent = useCallback((evt: SseEvent) => {
    setState((prev) => {
      const next: AnalysisRunState = {
        ...prev,
        statuses: { ...prev.statuses },
        stageResults: { ...prev.stageResults },
      };
      switch (evt.type) {
        case "run_start":
          next.runId = evt.run_id;
          next.statuses.start = "done";
          break;

        case "stage_start": {
          // defensive: ensure any previously-running stage is marked done
          for (const sid of STAGES) {
            if (next.statuses[sid] === "running") next.statuses[sid] = "done";
          }
          next.statuses[evt.stage] = "running";
          next.currentStage = evt.stage;
          next.progressPercent = 0;
          next.progressMessage = "";
          break;
        }

        case "stage_progress":
          if (evt.stage === next.currentStage) {
            next.progressPercent = evt.percent;
            next.progressMessage = evt.message;
          }
          break;

        case "stage_result":
          next.stageResults[evt.stage] = evt.data;
          break;

        case "stage_complete":
          next.statuses[evt.stage] = "done";
          // After agent3 finishes, the UI-only `report` step becomes the
          // logical "current" step so derived activeStep can move to it.
          if (evt.stage === "agent3") {
            next.statuses.report = "active";
          }
          break;

        case "run_complete":
          next.statuses.report = "done";
          next.isRunning = false;
          next.isComplete = true;
          next.currentStage = null;
          next.progressPercent = 100;
          break;

        case "error": {
          if (evt.stage) next.statuses[evt.stage] = "error";
          next.error = evt.message;
          next.isRunning = false;
          break;
        }
      }
      return next;
    });
  }, []);

  const launch = useCallback(async () => {
    cleanup();
    setState({ ...initialState(), isRunning: true });

    try {
      const { run_id } = await api.analyze({ workspace, case: caseName });
      setState((s) => ({ ...s, runId: run_id }));

      const es = new EventSource(api.runEventsUrl(run_id));
      esRef.current = es;

      es.onmessage = (msgEvent) => {
        try {
          const data = JSON.parse(msgEvent.data) as SseEvent;
          handleEvent(data);
          if (data.type === "run_complete" || data.type === "error") {
            cleanup();
          }
        } catch (err) {
          console.error("Bad SSE payload", err, msgEvent.data);
        }
      };

      es.onerror = () => {
        // EventSource auto-reconnects on transient errors; we close on
        // terminal events ourselves, so reaching here means a real failure.
        setState((s) =>
          s.isComplete
            ? s
            : { ...s, error: "Connection to backend lost.", isRunning: false },
        );
        cleanup();
      };
    } catch (err) {
      setState((s) => ({
        ...s,
        error: err instanceof Error ? err.message : "Failed to start analysis.",
        isRunning: false,
      }));
    }
  }, [workspace, caseName, cleanup, handleEvent]);

  const cancel = useCallback(() => {
    cleanup();
    setState((s) => ({ ...s, isRunning: false }));
  }, [cleanup]);

  return { state, launch, cancel };
}
