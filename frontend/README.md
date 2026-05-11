# frontend

React + TypeScript UI for the AMAMA DFIR triage tool.

## Status

Placeholder. The Vite + React + TS + Tailwind + shadcn/ui scaffold is added in a later commit.

## Planned stack

- Vite + React + TypeScript
- TailwindCSS + shadcn/ui (dark theme by default)
- React Router
- TanStack Query
- Native `EventSource` for SSE

## Planned pages

- **`/`** — Home: pick the working directory (cached in `localStorage`) and a case
- **`/system?case=...`** — System view: left stepper of the 7 pipeline stages, right progress bar + per-stage results panel

## Run (coming later)

```bash
npm install
npm run dev
```
