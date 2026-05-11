import { useQuery } from "@tanstack/react-query";
import { AlertCircle, FileText, Loader2, Play } from "lucide-react";

import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { formatBytes } from "@/lib/format";

interface StartStageProps {
  workspace: string;
  caseName: string;
  /** True once the run has been kicked off (button shows running state). */
  isRunning: boolean;
  /** Called when the user clicks the Launch button. */
  onLaunch: () => void;
}

export function StartStage({
  workspace,
  caseName,
  isRunning,
  onLaunch,
}: StartStageProps) {
  const files = useQuery({
    queryKey: ["case-files", workspace, caseName],
    queryFn: () => api.listCaseFiles(workspace, caseName),
  });

  const fileCount = files.data?.files.length ?? 0;
  const totalSize = files.data?.files.reduce((acc, f) => acc + f.size, 0) ?? 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileText className="h-5 w-5 text-primary" />
          Case files
        </CardTitle>
        <CardDescription>
          Files available in{" "}
          <code className="text-foreground">{workspace}/cases/{caseName}/</code>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {files.isPending ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Reading case folder...
          </div>
        ) : files.isError ? (
          <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertCircle className="h-4 w-4 mt-0.5 text-destructive shrink-0" />
            <div>
              <div className="font-medium">Couldn't read case folder</div>
              <div className="text-muted-foreground text-xs mt-0.5">
                {files.error instanceof Error
                  ? files.error.message
                  : "Unknown error"}
              </div>
            </div>
          </div>
        ) : (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-sm">
              <SummaryStat label="Files" value={fileCount.toString()} />
              <SummaryStat label="Total size" value={formatBytes(totalSize)} />
              <SummaryStat label="Case" value={caseName} className="sm:col-span-1" />
            </div>

            {fileCount === 0 ? (
              <div className="text-sm text-muted-foreground rounded-md border border-dashed border-border p-4 text-center">
                No files in this case folder.
              </div>
            ) : (
              <div className="rounded-md border border-border">
                <div className="grid grid-cols-[1fr_auto] gap-3 px-3 py-2 text-[11px] tracking-wide uppercase text-muted-foreground border-b border-border">
                  <span>Name</span>
                  <span>Size</span>
                </div>
                <ul className="divide-y divide-border">
                  {files.data.files.map((f) => (
                    <li
                      key={f.name}
                      className="grid grid-cols-[1fr_auto] gap-3 px-3 py-2 text-sm items-center"
                    >
                      <span className="truncate font-mono text-xs" title={f.name}>
                        {f.name}
                      </span>
                      <span className="text-muted-foreground tabular-nums">
                        {formatBytes(f.size)}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <Button
                size="lg"
                onClick={onLaunch}
                disabled={isRunning || fileCount === 0}
              >
                {isRunning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                {isRunning ? "Analysis running..." : "Launch analysis"}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function SummaryStat({
  label,
  value,
  className,
}: {
  label: string;
  value: string;
  className?: string;
}) {
  return (
    <div
      className={`rounded-md border border-border bg-card px-3 py-2 ${className ?? ""}`}
    >
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className="text-sm font-medium truncate" title={value}>
        {value}
      </div>
    </div>
  );
}
