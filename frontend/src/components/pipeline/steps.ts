import type { StepId } from "@/api/types";

/** Per-step status. `active` is "currently focused in the UI". */
export type StepStatus =
  | "pending"
  | "active"
  | "running"
  | "done"
  | "error";

export type StepKind = "ui" | "script" | "llm";

export interface StepDefinition {
  id: StepId;
  label: string;
  /** Optional short caption shown under the label. */
  caption?: string;
  kind: StepKind;
}

export const STEP_DEFINITIONS: readonly StepDefinition[] = [
  { id: "start",     label: "Start",     caption: "select & launch",    kind: "ui" },
  { id: "collector", label: "Collector", caption: "volatility runner",  kind: "script" },
  { id: "agent1",    label: "Agent 1",   caption: "triage analyst",     kind: "llm" },
  { id: "grep",      label: "Grep",      caption: "targeted pivots",    kind: "script" },
  { id: "agent2",    label: "Agent 2",   caption: "pivot analyst",      kind: "llm" },
  { id: "agent3",    label: "Agent 3",   caption: "report writer",      kind: "llm" },
  { id: "report",    label: "Report",    caption: "final narrative",    kind: "ui" },
] as const;
