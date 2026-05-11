import { Cpu, Hash, Layers, Network, ShieldOff, Wrench } from "lucide-react";

import type { CollectorResult } from "@/api/stage-results";
import { Badge } from "@/components/ui/badge";
import { formatBytes } from "@/lib/format";
import type { StepStatus } from "@/components/pipeline/steps";

import { Mono, StagePanelFrame, Stat } from "./common";

interface Props {
  status: StepStatus;
  result?: CollectorResult;
  progressMessage?: string;
}

export function CollectorPanel({ status, result, progressMessage }: Props) {
  if (!result) {
    return <StagePanelFrame stage="collector" status={status} progressMessage={progressMessage} />;
  }
  const hl = result.high_level ?? {};
  return (
    <StagePanelFrame stage="collector" status={status} progressMessage={progressMessage}>
      <div className="space-y-4">
        {/* image info */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <Stat label="Filename" value={result.image_info.filename} />
          <Stat label="Size" value={formatBytes(result.image_info.size_bytes)} />
          <Stat label="Profile" value={result.image_info.profile} />
          <Stat
            label="Duration"
            value={result.duration_seconds ? `${result.duration_seconds.toFixed(1)} s` : "-"}
          />
        </div>

        <div className="rounded-md border border-border bg-card px-3 py-2">
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
            <Hash className="h-3 w-3" /> sha256
          </div>
          <Mono>{result.image_info.sha256}</Mono>
        </div>

        {/* high-level numbers */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <NumberStat icon={<Cpu className="h-3.5 w-3.5" />} label="Processes" value={hl.processes_total ?? 0} />
          <NumberStat icon={<Network className="h-3.5 w-3.5" />} label="Net conn." value={hl.network_connections ?? 0} />
          <NumberStat icon={<Wrench className="h-3.5 w-3.5" />} label="Services" value={hl.services_total ?? 0} />
          <NumberStat icon={<Layers className="h-3.5 w-3.5" />} label="Tasks" value={hl.scheduled_tasks ?? 0} />
          <NumberStat
            icon={<ShieldOff className="h-3.5 w-3.5" />}
            label="Unsigned"
            value={hl.unsigned_binaries ?? 0}
            tone="warn"
          />
        </div>

        {/* plugins */}
        <div>
          <div className="text-[11px] uppercase tracking-wide text-muted-foreground mb-2">
            Plugins run ({result.plugins_run.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {result.plugins_run.map((p) => (
              <Badge key={p} variant="secondary" className="font-mono">
                {p}
              </Badge>
            ))}
          </div>
        </div>
      </div>
    </StagePanelFrame>
  );
}

function NumberStat({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  tone?: "warn";
}) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
        {icon} {label}
      </div>
      <div
        className={`text-lg font-semibold tabular-nums ${
          tone === "warn" && value > 0 ? "text-yellow-400" : ""
        }`}
      >
        {value}
      </div>
    </div>
  );
}
