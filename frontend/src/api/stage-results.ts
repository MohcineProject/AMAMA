/**
 * TypeScript shapes for each stage's `data` payload (the `stage_result` SSE
 * event). These mirror the dicts produced in
 * `backend_dummy/app/fixtures.py`. All fields are intentionally optional or
 * narrowed defensively so a partial result doesn't blow up the UI.
 */

export interface CollectorResult {
  image_info: {
    filename: string;
    size_bytes: number;
    sha256: string;
    profile: string;
  };
  plugins_run: string[];
  high_level: {
    processes_total?: number;
    network_connections?: number;
    services_total?: number;
    scheduled_tasks?: number;
    unsigned_binaries?: number;
  };
  duration_seconds?: number;
}

export interface SuspiciousProcess {
  pid: number;
  name: string;
  path: string;
  reason: string;
}
export interface SuspiciousService {
  name: string;
  binary: string;
  start_type: string;
  reason: string;
}
export interface SuspiciousPath {
  path: string;
  reason: string;
}
export interface SuspiciousTask {
  name: string;
  command: string;
  reason: string;
}

export interface Agent1Result {
  suspicious_processes: SuspiciousProcess[];
  suspicious_services: SuspiciousService[];
  suspicious_paths: SuspiciousPath[];
  suspicious_tasks: SuspiciousTask[];
}

export interface GrepPidPivot {
  cmdline?: string;
  privileges?: string[];
  handles?: string[];
  dlllist?: string[];
  envars?: Record<string, string>;
  parent?: { pid: number; name: string };
}

export interface GrepPathPivot {
  filescan?: Array<{ offset: string; path: string }>;
  registry_printkey?: Array<{ key: string; value?: string; data?: string }>;
}

export interface GrepResult {
  pivots_by_pid: Record<string, GrepPidPivot>;
  pivots_by_path: Record<string, GrepPathPivot>;
}

export type Verdict =
  | "confirmed_malicious"
  | "likely_malicious"
  | "needs_more_data"
  | "benign"
  | "false_positive";

export interface PivotVerdict {
  subject: string;
  verdict: Verdict;
  confidence: number; // 0..1
  rationale: string;
  evidence_refs: string[];
}

export interface Agent2Result {
  verdicts: PivotVerdict[];
}

export interface Agent3Result {
  case: string;
  summary: string;
  sections: {
    initial_access: string;
    execution_chain: string;
    persistence: string;
    credential_access: string;
    staging: string;
    files_of_interest: string[];
  };
  confidence_overall: number; // 0..1
}
