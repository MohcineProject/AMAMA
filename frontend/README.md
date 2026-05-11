# frontend

React + TypeScript UI for the AMAMA DFIR triage tool. Built with Vite, Tailwind, and the shadcn/ui pattern. Dark theme by default.

## Stack

- Vite + React 18 + TypeScript
- TailwindCSS + shadcn/ui pattern (CSS variables in `src/index.css`)
- React Router v6
- TanStack Query v5
- `lucide-react` icons
- Native `EventSource` for SSE (added in a later commit)

## Run

```bash
# from frontend/
npm install
npm run dev   # http://localhost:5173
```

Vite proxies `/api/*` and `/health` to <http://localhost:8000> (the dummy backend), so make sure the backend is running too:

```bash
# in another terminal, from backend_dummy/
uvicorn app.main:app --reload --port 8000
```

## Layout

```
src/
  main.tsx              # bootstraps React + imports global CSS
  App.tsx               # QueryClientProvider + Router
  index.css             # Tailwind + shadcn CSS variables (dark by default)
  api/
    client.ts           # fetch wrapper hitting /api/* and /health
    types.ts            # TS mirror of backend pydantic models + SSE event shapes
  components/
    Layout.tsx          # header + <Outlet/>
    ui/                 # shadcn-style primitives (added per commit as needed)
  lib/
    utils.ts            # cn() helper
  pages/
    HomePage.tsx        # working directory + case picker (commit 6)
    SystemView.tsx      # pipeline view (commits 7-10)
```

## Routes

| Path | Page | Notes |
|---|---|---|
| `/` | `HomePage` | choose workdir + case |
| `/system?case=<name>` | `SystemView` | run the pipeline |
