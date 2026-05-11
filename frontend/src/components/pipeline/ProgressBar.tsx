import { cn } from "@/lib/utils";

interface ProgressBarProps {
  /** 0-100. Clamped. */
  value: number;
  label?: string;
  /** When true, shows a subtle stripe animation instead of a fixed value. */
  indeterminate?: boolean;
  className?: string;
}

export function ProgressBar({
  value,
  label,
  indeterminate = false,
  className,
}: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div className={cn("space-y-1.5", className)}>
      {(label || !indeterminate) && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{label}</span>
          {!indeterminate && <span className="tabular-nums">{Math.round(pct)}%</span>}
        </div>
      )}
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-secondary">
        <div
          className={cn(
            "h-full bg-primary transition-[width] duration-300 ease-out",
            indeterminate && "animate-pulse w-1/3",
          )}
          style={indeterminate ? undefined : { width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
