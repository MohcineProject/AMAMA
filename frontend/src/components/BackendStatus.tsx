import { useQuery } from "@tanstack/react-query";

import { api } from "@/api/client";
import { cn } from "@/lib/utils";

/**
 * Tiny "is the backend reachable?" dot for the layout header. Polls /health
 * every 15s. Three states: ok (green), checking (pulsing muted), down (red).
 */
export function BackendStatus() {
  const q = useQuery({
    queryKey: ["health"],
    queryFn: () => api.health(),
    refetchInterval: 15_000,
    retry: 0,
  });

  let label = "Backend: checking...";
  let dotClass = "bg-muted-foreground animate-pulse";
  if (q.isSuccess) {
    label = `Backend: ${q.data.service} v${q.data.version}`;
    dotClass = "bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]";
  } else if (q.isError) {
    label = "Backend: unreachable";
    dotClass = "bg-destructive";
  }

  return (
    <div
      className="flex items-center gap-1.5 text-xs text-muted-foreground"
      title={label}
    >
      <span className={cn("h-2 w-2 rounded-full", dotClass)} aria-hidden />
      <span className="hidden sm:inline tabular-nums">{label}</span>
    </div>
  );
}
