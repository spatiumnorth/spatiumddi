import { useCallback, useState } from "react";

import { safeLocalStorage } from "@/lib/safeStorage";

/** A boolean preference remembered per browser profile (localStorage, via the
 *  never-throwing wrapper of #3231). */
export function useLocalBoolPref(
  key: string,
  initial: boolean,
): [boolean, (v: boolean) => void] {
  const [value, setValue] = useState<boolean>(() => {
    const raw = safeLocalStorage.getItem(key);
    return raw === null ? initial : raw === "1";
  });
  const set = useCallback(
    (v: boolean) => {
      setValue(v);
      safeLocalStorage.setItem(key, v ? "1" : "0");
    },
    [key],
  );
  return [value, set];
}

/** The IP address table's and DNS record list's icon column (#5022). */
export const SHOW_ICONS_KEY = "spatium-show-icons";
