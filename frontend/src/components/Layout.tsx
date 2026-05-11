import { Link, Outlet } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

/** Top-level chrome: header + routed page content. */
export function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-border bg-card/50 backdrop-blur sticky top-0 z-10">
        <div className="container flex h-14 items-center justify-between">
          <Link to="/" className="flex items-center gap-2 font-semibold tracking-tight">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span>AMAMA</span>
            <span className="text-muted-foreground font-normal text-sm">
              DFIR Triage
            </span>
          </Link>
          <div className="text-xs text-muted-foreground">v0.1.0</div>
        </div>
      </header>
      <main className="flex-1">
        <Outlet />
      </main>
    </div>
  );
}
