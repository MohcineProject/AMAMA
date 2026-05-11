/**
 * TypeScript mirrors of the FastAPI pydantic models. Keep these in sync with
 * `backend_dummy/app/models.py` (the canonical source of truth) and the SSE
 * event shapes documented in `backend_dummy/README.md`.
 */

// ---- REST ----

export interface ValidateWorkspaceRequest {
  path: string;
}

export interface ValidateWorkspaceResponse {
  valid: boolean;
  has_cases_dir: boolean;
  resolved_path: string;
  message: string | null;
}

export interface CasesListResponse {
  workspace: string;
  cases: string[];
}

export interface CaseFile {
  name: string;
  size: number;
  sha256?: string | null;
}

export interface CaseFilesResponse {
  workspace: string;
  case: string;
  files: CaseFile[];
}

export interface AnalyzeRequest {
  workspace: string;
  case: string;
}

export interface AnalyzeResponse {
  run_id: string;
  workspace: string;
  case: string;
}

// ---- SSE pipeline events ----

export type StageId = "collector" | "agent1" | "grep" | "agent2" | "agent3";

/** All visible left-stepper steps, including the UI-only bookends. */
export type StepId = "start" | StageId | "report";

export const STAGES: readonly StageId[] = [
  "collector",
  "agent1",
  "grep",
  "agent2",
  "agent3",
] as const;

export const STEPS: readonly StepId[] = [
  "start",
  "collector",
  "agent1",
  "grep",
  "agent2",
  "agent3",
  "report",
] as const;

export type SseEvent =
  | { type: "run_start"; run_id: string; workspace: string; case: string }
  | { type: "stage_start"; stage: StageId; kind: "script" | "llm" }
  | { type: "stage_progress"; stage: StageId; percent: number; message: string }
  | { type: "stage_result"; stage: StageId; data: unknown }
  | { type: "stage_complete"; stage: StageId }
  | { type: "run_complete"; run_id: string }
  | { type: "error"; stage?: StageId; message: string };
