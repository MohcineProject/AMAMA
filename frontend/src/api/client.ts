/**
 * Tiny fetch wrapper for the dummy backend.
 *
 * Vite proxies `/api/*` and `/health` to http://localhost:8000 in dev (see
 * vite.config.ts) so we use same-origin relative URLs everywhere.
 */

import type {
  AnalyzeRequest,
  AnalyzeResponse,
  CaseFilesResponse,
  CasesListResponse,
  ValidateWorkspaceRequest,
  ValidateWorkspaceResponse,
} from "./types";

async function http<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // body wasn't JSON; keep statusText
    }
    throw new Error(`${res.status} ${detail}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => http<{ status: string; service: string; version: string }>("/health"),

  validateWorkspace: (body: ValidateWorkspaceRequest) =>
    http<ValidateWorkspaceResponse>("/api/workspace/validate", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  listCases: (workspacePath: string) =>
    http<CasesListResponse>(
      `/api/workspace/cases?path=${encodeURIComponent(workspacePath)}`,
    ),

  listCaseFiles: (workspacePath: string, caseName: string) =>
    http<CaseFilesResponse>(
      `/api/cases/files?workspace=${encodeURIComponent(workspacePath)}&case=${encodeURIComponent(caseName)}`,
    ),

  analyze: (body: AnalyzeRequest) =>
    http<AnalyzeResponse>("/api/cases/analyze", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** Returns the SSE URL for a run. Open with `new EventSource(url)`. */
  runEventsUrl: (runId: string): string => `/api/runs/${runId}/events`,
};
