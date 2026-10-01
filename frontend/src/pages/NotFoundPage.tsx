import { Link, useLocation } from "react-router-dom";
import { ArrowLeft, ToggleLeft } from "lucide-react";

import { useFeatureModules } from "@/hooks/useFeatureModules";
import {
  ALL_NAV_DESTINATIONS,
  navEntryVisible,
  type NavDestination,
} from "@/lib/navigation";
import { formatCombo, OPEN_GLOBAL_SEARCH } from "@/lib/shortcuts";

/**
 * The catch-all route (issue #1360).
 *
 * Before this, an unknown URL matched no route, `<Routes>` rendered null,
 * and the operator got a blank page with no sidebar and no way back — and
 * a signed-out user never reached `ProtectedRoute`, so was not sent to
 * /login either. This page is mounted as the last child of the protected
 * layout route, so it renders inside the app chrome and inherits the
 * login redirect.
 *
 * The quick links come from `lib/navigation.ts`, filtered by the same
 * module predicate the sidebar and the palette use, so this page can never
 * suggest a destination the sidebar is hiding.
 */

/** Longest path we echo back before eliding the middle of it. */
const MAX_PATH_CHARS = 120;
const MAX_LINKS = 6;

// Shown when nothing under the requested path's first segment matches.
const DEFAULT_LINKS = [
  "/ipam",
  "/dhcp",
  "/dns",
  "/network/devices",
  "/reports",
  "/settings",
];

function displayPath(pathname: string): string {
  // The router hands back the encoded form (`/%3Cscript%3E`), which is
  // safe but unreadable. Decode for display only — React renders it as a
  // text node either way — and keep the raw form if it is malformed.
  let path = pathname;
  try {
    path = decodeURI(pathname);
  } catch {
    // Malformed percent-encoding: show it exactly as requested.
  }
  if (path.length <= MAX_PATH_CHARS) return path;
  const half = Math.floor((MAX_PATH_CHARS - 1) / 2);
  return `${path.slice(0, half)}…${path.slice(-half)}`;
}

function firstSegment(path: string): string {
  return path.split("/").filter(Boolean)[0] ?? "";
}

function suggestions(
  pathname: string,
  moduleEnabled: (id: string) => boolean,
): NavDestination[] {
  const visible = ALL_NAV_DESTINATIONS.filter((d) =>
    navEntryVisible(d, moduleEnabled),
  );
  const seg = firstSegment(pathname).toLowerCase();
  const out: NavDestination[] = [];
  const add = (d: NavDestination | undefined) => {
    if (!d || d.to === "/dashboard" || out.some((o) => o.to === d.to)) return;
    if (out.length < MAX_LINKS) out.push(d);
  };
  // Pages under the same first segment first: a typo in `/dns/zonez` is
  // most likely aiming at something else under `/dns`.
  if (seg) {
    for (const d of visible) {
      if (firstSegment(d.to) === seg) add(d);
    }
  }
  for (const to of DEFAULT_LINKS) add(visible.find((d) => d.to === to));
  return out;
}

export function NotFoundPage() {
  const { pathname } = useLocation();
  const { enabled: moduleEnabled } = useFeatureModules();
  const shown = displayPath(pathname);
  const links = suggestions(pathname, moduleEnabled);

  return (
    <div className="mx-auto max-w-3xl p-6">
      <h1 className="text-2xl font-bold tracking-tight">Page not found</h1>
      <p className="mt-2 text-sm text-muted-foreground">
        Nothing in SpatiumDDI lives at this address:
      </p>
      <p
        className="mt-2 break-all rounded-md border bg-muted/40 px-3 py-2 font-mono text-sm"
        title={shown === pathname ? undefined : pathname}
        data-testid="not-found-path"
      >
        {shown}
      </p>

      <pre
        aria-hidden="true"
        className="mt-4 overflow-x-auto rounded-md border bg-muted/40 px-3 py-2 font-mono text-xs leading-relaxed text-muted-foreground"
      >
        {`;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN\n;; QUESTION SECTION:\n;${shown}\tIN\tPAGE`}
      </pre>

      <div className="mt-6 flex flex-wrap items-center gap-3">
        <Link
          to="/dashboard"
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to dashboard
        </Link>
        <span className="text-sm text-muted-foreground">
          or press{" "}
          <kbd className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
            {formatCombo(OPEN_GLOBAL_SEARCH.combos[0])}
          </kbd>{" "}
          to search.
        </span>
      </div>

      <p className="mt-6 flex items-start gap-2 text-sm text-muted-foreground">
        <ToggleLeft className="mt-0.5 h-4 w-4 flex-shrink-0" />
        <span>
          If you followed a link or bookmark, the page may belong to a feature
          that is turned off. An administrator can check{" "}
          <Link to="/admin/features" className="text-primary hover:underline">
            Settings → Features
          </Link>
          .
        </span>
      </p>

      {links.length > 0 && (
        <section className="mt-6">
          <h2 className="text-sm font-semibold">You might be looking for</h2>
          <ul className="mt-2 grid gap-2 sm:grid-cols-2">
            {links.map((d) => {
              const Icon = d.icon;
              return (
                <li key={d.to}>
                  <Link
                    to={d.to}
                    className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted"
                  >
                    <Icon className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                    <span className="min-w-0 truncate">{d.label}</span>
                    <span className="ml-auto flex-shrink-0 text-xs text-muted-foreground">
                      {d.section}
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </section>
      )}
    </div>
  );
}
