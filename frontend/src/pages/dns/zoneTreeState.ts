import { useCallback, useSyncExternalStore } from "react";

// A sessionStorage-backed Set<string> that every component reading the same
// key sees change at once (#4203). The sidebar zone tree and the Zones tab
// table both hold the reverse-zone folder state, and `useSessionState` keeps a
// private copy per component, so collapsing one would not move the other.

const listeners = new Set<() => void>();
const parsed = new Map<string, { raw: string | null; value: Set<string> }>();

function read(key: string): Set<string> {
  let raw: string | null = null;
  try {
    raw = sessionStorage.getItem(key);
  } catch {
    // sessionStorage may be unavailable in private browsing
  }
  const hit = parsed.get(key);
  if (hit && hit.raw === raw) return hit.value; // stable identity per raw value
  let value = new Set<string>();
  try {
    const arr = raw === null ? [] : JSON.parse(raw);
    if (Array.isArray(arr)) value = new Set(arr.map(String));
  } catch {
    // a corrupt entry reads as empty
  }
  parsed.set(key, { raw, value });
  return value;
}

export function useSharedSessionSet(
  key: string,
): [Set<string>, (fn: (prev: Set<string>) => Set<string>) => void] {
  const subscribe = useCallback((cb: () => void) => {
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  }, []);
  const value = useSyncExternalStore(
    subscribe,
    () => read(key),
    () => read(key),
  );
  const update = useCallback(
    (fn: (prev: Set<string>) => Set<string>) => {
      const next = fn(read(key));
      try {
        sessionStorage.setItem(key, JSON.stringify([...next]));
      } catch {
        // ignore: the in-page state below still moves
        parsed.set(key, { raw: JSON.stringify([...next]), value: next });
      }
      listeners.forEach((l) => l());
    },
    [key],
  );
  return [value, update];
}
