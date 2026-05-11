import { useState } from "react";
import { FolderSearch, KeySquare, Network } from "lucide-react";

import type { GrepPathPivot, GrepPidPivot, GrepResult } from "@/api/stage-results";
import { Badge } from "@/components/ui/badge";
import type { StepStatus } from "@/components/pipeline/steps";
import { cn } from "@/lib/utils";

import { Mono, StagePanelFrame } from "./common";

interface Props {
  status: StepStatus;
  result?: GrepResult;
  progressMessage?: string;
}

type Tab = "by_pid" | "by_path";

export function GrepPanel({ status, result, progressMessage }: Props) {
  const [tab, setTab] = useState<Tab>("by_pid");

  if (!result) {
    return <StagePanelFrame stage="grep" status={status} progressMessage={progressMessage} />;
  }

  const pidEntries = Object.entries(result.pivots_by_pid);
  const pathEntries = Object.entries(result.pivots_by_path);

  return (
    <StagePanelFrame stage="grep" status={status} progressMessage={progressMessage}>
      <div className="flex items-center gap-1 border-b border-border mb-4">
        <TabButton active={tab === "by_pid"} onClick={() => setTab("by_pid")}>
          By PID
          <Badge variant="secondary" className="ml-1">
            {pidEntries.length}
          </Badge>
        </TabButton>
        <TabButton active={tab === "by_path"} onClick={() => setTab("by_path")}>
          By path
          <Badge variant="secondary" className="ml-1">
            {pathEntries.length}
          </Badge>
        </TabButton>
      </div>

      {tab === "by_pid" ? (
        <div className="space-y-3">
          {pidEntries.map(([pid, pivot]) => (
            <PidCard key={pid} pid={pid} pivot={pivot} />
          ))}
        </div>
      ) : (
        <div className="space-y-3">
          {pathEntries.map(([path, pivot]) => (
            <PathCard key={path} path={path} pivot={pivot} />
          ))}
        </div>
      )}
    </StagePanelFrame>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "px-3 py-2 text-sm border-b-2 -mb-px transition-colors flex items-center gap-1.5",
        active
          ? "border-primary text-foreground"
          : "border-transparent text-muted-foreground hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

function PidCard({ pid, pivot }: { pid: string; pivot: GrepPidPivot }) {
  return (
    <div className="rounded-md border border-border bg-card/60 p-3 space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <Badge variant="info" className="font-mono">PID {pid}</Badge>
        {pivot.parent && (
          <span className="text-xs text-muted-foreground">
            parent: {pivot.parent.name} (PID {pivot.parent.pid})
          </span>
        )}
      </div>
      {pivot.cmdline && (
        <KV label="cmdline">
          <Mono>{pivot.cmdline}</Mono>
        </KV>
      )}
      {pivot.privileges && pivot.privileges.length > 0 && (
        <KV label="privileges">
          <ChipList items={pivot.privileges} variant="warning" />
        </KV>
      )}
      {pivot.handles && pivot.handles.length > 0 && (
        <KV label="handles">
          <ul className="space-y-0.5">
            {pivot.handles.map((h) => (
              <li key={h}><Mono>{h}</Mono></li>
            ))}
          </ul>
        </KV>
      )}
      {pivot.dlllist && pivot.dlllist.length > 0 && (
        <KV label="dlllist">
          <ChipList items={pivot.dlllist} variant="secondary" />
        </KV>
      )}
      {pivot.envars && Object.keys(pivot.envars).length > 0 && (
        <KV label="envars">
          <div className="space-y-0.5">
            {Object.entries(pivot.envars).map(([k, v]) => (
              <div key={k} className="text-xs">
                <span className="text-muted-foreground">{k}=</span>
                <Mono>{v}</Mono>
              </div>
            ))}
          </div>
        </KV>
      )}
    </div>
  );
}

function PathCard({ path, pivot }: { path: string; pivot: GrepPathPivot }) {
  return (
    <div className="rounded-md border border-border bg-card/60 p-3 space-y-2">
      <Mono>{path}</Mono>

      {pivot.filescan && pivot.filescan.length > 0 && (
        <KV label="filescan" icon={<FolderSearch className="h-3 w-3" />}>
          <ul className="space-y-0.5">
            {pivot.filescan.map((f) => (
              <li key={f.offset} className="text-xs">
                <span className="text-muted-foreground">{f.offset}</span>{" "}
                <Mono>{f.path}</Mono>
              </li>
            ))}
          </ul>
        </KV>
      )}

      {pivot.registry_printkey && pivot.registry_printkey.length > 0 && (
        <KV label="registry" icon={<KeySquare className="h-3 w-3" />}>
          <ul className="space-y-0.5">
            {pivot.registry_printkey.map((r, i) => (
              <li key={`${r.key}-${i}`} className="text-xs">
                <Mono>{r.key}</Mono>
                {r.value && <span className="text-muted-foreground"> :: {r.value}</span>}
                {r.data && <> = <Mono>{r.data}</Mono></>}
              </li>
            ))}
          </ul>
        </KV>
      )}

      {(!pivot.filescan || pivot.filescan.length === 0) &&
        (!pivot.registry_printkey || pivot.registry_printkey.length === 0) && (
          <div className="text-xs text-muted-foreground flex items-center gap-1.5">
            <Network className="h-3 w-3" /> no hits in this slice
          </div>
        )}
    </div>
  );
}

function KV({
  label,
  icon,
  children,
}: {
  label: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[100px_1fr] gap-3 items-start">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground pt-0.5 flex items-center gap-1">
        {icon}
        {label}
      </div>
      <div className="min-w-0">{children}</div>
    </div>
  );
}

function ChipList({
  items,
  variant = "secondary",
}: {
  items: string[];
  variant?: "secondary" | "warning";
}) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((i) => (
        <Badge key={i} variant={variant} className="font-mono">
          {i}
        </Badge>
      ))}
    </div>
  );
}
