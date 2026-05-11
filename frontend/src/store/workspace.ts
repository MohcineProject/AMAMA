import { useLocalStorage } from "@/hooks/useLocalStorage";

/** localStorage key used by both Home and SystemView to share the workdir. */
export const WORKSPACE_STORAGE_KEY = "amama.workspace.path";

/**
 * Returns the cached working-directory path along with setters.
 * `path` is `null` until the user has picked a directory.
 */
export function useWorkspace() {
  const [path, setPath, clearPath] = useLocalStorage<string | null>(
    WORKSPACE_STORAGE_KEY,
    null,
  );
  return { path, setPath, clearPath };
}
