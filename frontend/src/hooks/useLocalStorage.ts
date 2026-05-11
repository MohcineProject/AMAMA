import { useCallback, useEffect, useState } from "react";

/**
 * Persist a small piece of state in `window.localStorage`.
 *
 * Tries hard to behave like `useState`: the initial render returns the value
 * from storage (so the UI doesn't flash an "empty" state on reload), and
 * updates from other tabs are picked up via the `storage` event.
 */
export function useLocalStorage<T>(
  key: string,
  initialValue: T,
): [T, (value: T | ((prev: T) => T)) => void, () => void] {
  const read = useCallback((): T => {
    if (typeof window === "undefined") return initialValue;
    try {
      const raw = window.localStorage.getItem(key);
      if (raw === null) return initialValue;
      return JSON.parse(raw) as T;
    } catch {
      return initialValue;
    }
  }, [key, initialValue]);

  const [value, setValue] = useState<T>(read);

  const setStored = useCallback(
    (next: T | ((prev: T) => T)) => {
      setValue((prev) => {
        const resolved =
          typeof next === "function" ? (next as (p: T) => T)(prev) : next;
        try {
          window.localStorage.setItem(key, JSON.stringify(resolved));
        } catch {
          /* quota exceeded or storage disabled; keep in-memory value */
        }
        return resolved;
      });
    },
    [key],
  );

  const clearStored = useCallback(() => {
    try {
      window.localStorage.removeItem(key);
    } catch {
      /* ignore */
    }
    setValue(initialValue);
  }, [key, initialValue]);

  useEffect(() => {
    const handler = (e: StorageEvent) => {
      if (e.key === key) setValue(read());
    };
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, [key, read]);

  return [value, setStored, clearStored];
}
