import { CalendarClock, FolderTree, Server, Terminal } from "lucide-react";

import type {
  Agent1Result,
  SuspiciousPath,
  SuspiciousProcess,
  SuspiciousService,
  SuspiciousTask,
} from "@/api/stage-results";
import { Badge } from "@/components/ui/badge";
import type { StepStatus } from "@/components/pipeline/steps";

import { Mono, StagePanelFrame } from "./common";

interface Props {
  status: StepStatus;
  result?: Agent1Result;
  progressMessage?: string;
}

export function Agent1Panel({ status, result, progressMessage }: Props) {
  if (!result) {
    return <StagePanelFrame stage="agent1" status={status} progressMessage={progressMessage} />;
  }

  const totalCount =
    result.suspicious_processes.length +
    result.suspicious_services.length +
    result.suspicious_paths.length +
    result.suspicious_tasks.length;

  return (
    <StagePanelFrame stage="agent1" status={status} progressMessage={progressMessage}>
      <div className="space-y-5">
        <div className="text-sm text-muted-foreground">
          Shortlist of {totalCount} item{totalCount === 1 ? "" : "s"} to investigate.
        </div>

        <Group
          icon={<Terminal className="h-4 w-4" />}
          title="Processes"
          count={result.suspicious_processes.length}
        >
          {result.suspicious_processes.map((p) => (
            <ProcessRow key={`${p.pid}-${p.name}`} item={p} />
          ))}
        </Group>

        <Group
          icon={<Server className="h-4 w-4" />}
          title="Services"
          count={result.suspicious_services.length}
        >
          {result.suspicious_services.map((s) => (
            <ServiceRow key={s.name} item={s} />
          ))}
        </Group>

        <Group
          icon={<FolderTree className="h-4 w-4" />}
          title="Paths"
          count={result.suspicious_paths.length}
        >
          {result.suspicious_paths.map((p) => (
            <PathRow key={p.path} item={p} />
          ))}
        </Group>

        <Group
          icon={<CalendarClock className="h-4 w-4" />}
          title="Scheduled tasks"
          count={result.suspicious_tasks.length}
        >
          {result.suspicious_tasks.map((t) => (
            <TaskRow key={t.name} item={t} />
          ))}
        </Group>
      </div>
    </StagePanelFrame>
  );
}

function Group({
  icon,
  title,
  count,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  count: number;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="flex items-center gap-2 mb-2 text-sm font-medium">
        <span className="text-primary">{icon}</span>
        {title}
        <Badge variant="secondary">{count}</Badge>
      </div>
      {count === 0 ? (
        <div className="text-xs text-muted-foreground pl-6">None flagged.</div>
      ) : (
        <ul className="space-y-2">{children}</ul>
      )}
    </section>
  );
}

function Row({ children }: { children: React.ReactNode }) {
  return (
    <li className="rounded-md border border-border bg-card/60 p-3 space-y-1">
      {children}
    </li>
  );
}

function Reason({ text }: { text: string }) {
  return <div className="text-xs text-muted-foreground">{text}</div>;
}

function ProcessRow({ item }: { item: SuspiciousProcess }) {
  return (
    <Row>
      <div className="flex items-center gap-2 flex-wrap">
        <Badge variant="info" className="font-mono">PID {item.pid}</Badge>
        <span className="text-sm font-medium">{item.name}</span>
      </div>
      <Mono>{item.path}</Mono>
      <Reason text={item.reason} />
    </Row>
  );
}

function ServiceRow({ item }: { item: SuspiciousService }) {
  return (
    <Row>
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-sm font-medium">{item.name}</span>
        <Badge variant="warning">{item.start_type}</Badge>
      </div>
      <Mono>{item.binary}</Mono>
      <Reason text={item.reason} />
    </Row>
  );
}

function PathRow({ item }: { item: SuspiciousPath }) {
  return (
    <Row>
      <Mono>{item.path}</Mono>
      <Reason text={item.reason} />
    </Row>
  );
}

function TaskRow({ item }: { item: SuspiciousTask }) {
  return (
    <Row>
      <Mono>{item.name}</Mono>
      <Mono>{item.command}</Mono>
      <Reason text={item.reason} />
    </Row>
  );
}
