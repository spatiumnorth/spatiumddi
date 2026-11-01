import { useState, useEffect } from "react";

import { safeLocalStorage } from "@/lib/safeStorage";

type Theme = "light" | "dark";

function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

function initialTheme(): Theme {
  const saved = safeLocalStorage.getItem("theme");
  if (saved === "light" || saved === "dark") return saved;
  // Fall back to OS preference on first visit
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

export function useTheme() {
  const [theme, setThemeState] = useState<Theme>(initialTheme);

  useEffect(() => {
    applyTheme(theme);
    safeLocalStorage.setItem("theme", theme);
  }, [theme]);

  const setTheme = (t: Theme) => setThemeState(t);
  const toggleTheme = () =>
    setThemeState((t) => (t === "light" ? "dark" : "light"));

  return { theme, setTheme, toggleTheme };
}
