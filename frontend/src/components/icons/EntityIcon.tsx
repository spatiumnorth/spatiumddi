import { useEffect, useSyncExternalStore } from "react";

import { cn } from "@/lib/utils";
import {
  cachedIconPath,
  iconLabel,
  iconName,
  loadIconPath,
  subscribeIconPaths,
} from "@/lib/icons/catalog";

/** A built-in icon (#5022): an inline SVG path in ``currentColor`` inside a
 *  fixed box, so a row never shifts when a lazily loaded icon arrives.
 *
 *  ``icon`` is the stored ``mdi:<name>`` value; null / unknown draws nothing
 *  (the box is not rendered either: an empty cell stays empty).
 *  ``decorative`` is for a place where the adjacent text already says what
 *  the icon means (it is then ``aria-hidden``); otherwise the icon is an
 *  ``img`` named by ``label`` or, by default, its own name. */
export function EntityIcon({
  icon,
  label,
  decorative = false,
  size = 16,
  className,
}: {
  icon: string | null | undefined;
  label?: string;
  decorative?: boolean;
  size?: 16 | 20;
  className?: string;
}) {
  const name = iconName(icon);
  const path = useSyncExternalStore(
    subscribeIconPaths,
    () => (name ? cachedIconPath(name) : undefined),
    () => undefined,
  );
  useEffect(() => {
    if (name && !cachedIconPath(name)) loadIconPath(name).catch(() => {});
  }, [name]);
  if (!name) return null;
  const a11y = decorative
    ? ({ "aria-hidden": true } as const)
    : ({ role: "img", "aria-label": label ?? iconLabel(icon) } as const);
  return (
    <svg
      {...a11y}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="currentColor"
      className={cn("inline-block flex-shrink-0", className)}
      data-icon={name}
    >
      {path ? <path d={path} /> : null}
    </svg>
  );
}
