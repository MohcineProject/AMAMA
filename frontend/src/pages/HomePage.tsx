import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  FolderOpen,
  Loader2,
  Pencil,
} from "lucide-react";

import { api } from "@/api/client";
import type { ValidateWorkspaceResponse } from "@/api/types";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useWorkspace } from "@/store/workspace";

export function HomePage() {
  const { path, setPath, clearPath } = useWorkspace();

  if (path === null) {
    return <PickWorkspacePane onPicked={(p) => setPath(p)} />;
  }
  return <CasesPane workspacePath={path} onChange={clearPath} />;
}

// ---------- 1. First-visit: pick & validate a working directory ----------

function PickWorkspacePane({ onPicked }: { onPicked: (path: string) => void }) {
  const [draft, setDraft] = useState("");
  const [serverMsg, setServerMsg] = useState<ValidateWorkspaceResponse | null>(null);

  const validate = useMutation({
    mutationFn: (p: string) => api.validateWorkspace({ path: p }),
    onSuccess: (res) => {
      setServerMsg(res);
      if (res.valid) onPicked(res.resolved_path);
    },
    onError: (err) =>
      setServerMsg({
        valid: false,
        has_cases_dir: false,
        resolved_path: draft,
        message: err instanceof Error ? err.message : "Validation failed.",
      }),
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed) return;
    setServerMsg(null);
    validate.mutate(trimmed);
  };

  return (
    <div className="container py-12 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-primary" />
            Select working directory
          </CardTitle>
          <CardDescription>
            Point AMAMA at the analyst working directory. Cases are expected
            under <code className="text-foreground">&lt;path&gt;/cases/&lt;case_name&gt;</code>.
          </CardDescription>
        </CardHeader>
        <form onSubmit={submit}>
          <CardContent className="space-y-3">
            <Label htmlFor="workdir">Path</Label>
            <Input
              id="workdir"
              placeholder="/home/analyst/DFIR_agent"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              disabled={validate.isPending}
              autoFocus
              autoComplete="off"
              spellCheck={false}
            />
            {serverMsg && !serverMsg.valid && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
                <AlertCircle className="h-4 w-4 mt-0.5 text-destructive shrink-0" />
                <div>
                  <div className="font-medium">Invalid path</div>
                  <div className="text-muted-foreground text-xs mt-0.5">
                    {serverMsg.message}{" "}
                    <span className="text-foreground/70">
                      (resolved as <code>{serverMsg.resolved_path}</code>)
                    </span>
                  </div>
                </div>
              </div>
            )}
            {serverMsg?.valid && !serverMsg.has_cases_dir && (
              <div className="flex items-start gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 p-3 text-sm">
                <AlertCircle className="h-4 w-4 mt-0.5 text-yellow-500 shrink-0" />
                <div>
                  <div className="font-medium">Workspace has no cases yet</div>
                  <div className="text-muted-foreground text-xs mt-0.5">
                    {serverMsg.message}
                  </div>
                </div>
              </div>
            )}
          </CardContent>
          <CardFooter className="justify-end">
            <Button type="submit" disabled={!draft.trim() || validate.isPending}>
              {validate.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : null}
              Set
            </Button>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}

// ---------- 2. Cached: pick a case from the workspace ----------

function CasesPane({
  workspacePath,
  onChange,
}: {
  workspacePath: string;
  onChange: () => void;
}) {
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string>("");

  const cases = useQuery({
    queryKey: ["cases", workspacePath],
    queryFn: () => api.listCases(workspacePath),
  });

  const openCase = () => {
    if (!selected) return;
    const params = new URLSearchParams({ case: selected });
    navigate(`/system?${params.toString()}`);
  };

  return (
    <div className="container py-12 max-w-3xl space-y-6">
      {/* current working directory bar */}
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 gap-4">
          <div className="space-y-1 min-w-0">
            <CardDescription>Working directory</CardDescription>
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle2 className="h-4 w-4 text-primary shrink-0" />
              <code className="truncate text-foreground" title={workspacePath}>
                {workspacePath}
              </code>
            </div>
          </div>
          <Button variant="outline" size="sm" onClick={onChange}>
            <Pencil className="h-4 w-4" />
            Change
          </Button>
        </CardHeader>
      </Card>

      {/* case picker */}
      <Card>
        <CardHeader>
          <CardTitle>Open a case</CardTitle>
          <CardDescription>
            Cases discovered under{" "}
            <code className="text-foreground">{workspacePath}/cases/</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {cases.isPending ? (
            <div className="text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading cases...
            </div>
          ) : cases.isError ? (
            <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
              <AlertCircle className="h-4 w-4 mt-0.5 text-destructive shrink-0" />
              <div>
                <div className="font-medium">Failed to list cases</div>
                <div className="text-muted-foreground text-xs mt-0.5">
                  {cases.error instanceof Error
                    ? cases.error.message
                    : "Unknown error"}
                </div>
              </div>
            </div>
          ) : cases.data.cases.length === 0 ? (
            <div className="text-sm text-muted-foreground">
              No cases found. Create a folder under{" "}
              <code>{workspacePath}/cases/</code> and reload.
            </div>
          ) : (
            <div className="space-y-2">
              <Label htmlFor="case">Case</Label>
              <select
                id="case"
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <option value="">Select a case...</option>
                {cases.data.cases.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
          )}
        </CardContent>
        <CardFooter className="justify-end">
          <Button
            onClick={openCase}
            disabled={!selected || cases.isPending || cases.isError}
          >
            Open case
            <ArrowRight className="h-4 w-4" />
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
