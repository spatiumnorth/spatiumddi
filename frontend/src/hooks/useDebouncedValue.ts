import { useEffect, useState } from "react";

/** `value`, but only after it has stopped changing for `delayMs`. Keeps a
 * filter box that fires a request per keystroke from doing so (#3171). */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}
