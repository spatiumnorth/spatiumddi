import { useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Clock, Loader2 } from "lucide-react";

import { settingsApi, formatApiError } from "@/lib/api";
import { HOST_TZ_ALIASES, canonicalHostTimezone } from "@/lib/hostTimezones";
import { isValidTimeZone, timeZoneSuggestions } from "@/lib/timezones";

/**
 * Appliance timezone control (issue #165).
 *
 * Settings → NTP tab uses this. The picker is a text input backed by
 * a ``<datalist>`` of the IANA tz names the browser reports via
 * ``Intl.supportedValuesOf("timeZone")`` plus UTC — gives auto-complete
 * without committing to a long ``<select>`` UX.
 *
 * Empty string clears the operator-set override BUT does NOT revert
 * the host's actual timezone — the supervisor's
 * ``maybe_fire_timezone`` short-circuits on empty so no trigger
 * file is written. To revert to UTC (or any other tz), the operator
 * picks that value explicitly. Documented as such in the form copy
 * so this doesn't surprise anyone (#305 review polish — Copilot
 * caught the original "falls back to install-time default" wording
 * which was a misread of the supervisor behaviour).
 *
 * Apply flow: PUT ``/api/v1/settings`` → ``platform_settings.timezone``
 * → supervisor heartbeat ships ``desired_timezone`` → supervisor's
 * ``maybe_fire_timezone`` writes ``/var/lib/spatiumddi-host/release-
 * state/tz-pending`` → host ``spatiumddi-tz-reload.path`` fires →
 * runner calls ``timedatectl set-timezone``.
 *
 * The change typically lands within a heartbeat cycle (~5-10 s on
 * the default cadence). The current value field reflects the
 * operator-set DB value, NOT the host's current tz — those can drift
 * during the apply window but converge after the runner reports
 * back. (A future commit could surface the host's last-applied tz
 * via the heartbeat's ``host_state``; deferred to keep this PR
 * focused on the operator-set path.)
 */
interface Props {
  currentValue: string;
  isSuperadmin: boolean;
  applianceMode: boolean;
}

const CANONICAL_TARGETS = new Set(Object.values(HOST_TZ_ALIASES));

export function TimezoneSection({
  currentValue,
  isSuperadmin,
  applianceMode,
}: Props) {
  const qc = useQueryClient();
  const [tz, setTz] = useState(currentValue);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  // Suggestions only; validity is asked of Intl (see lib/timezones).
  // Chromium spells some zones only by a legacy alias (Asia/Calcutta,
  // Europe/Kiev ...) and the host has no tzdata-legacy, so map every
  // entry to its canonical name rather than dropping it (#4416).
  const ianaList = useMemo(
    () => [...new Set(timeZoneSuggestions().map(canonicalHostTimezone))],
    [],
  );

  const save = useMutation({
    mutationFn: (value: string) => settingsApi.update({ timezone: value }),
    onSuccess: (_data, value) => {
      qc.invalidateQueries({ queryKey: ["settings"] });
      setTz(value);
      setSavedNote(
        value === ""
          ? "Timezone override cleared — the host keeps its current value. Set the field to your desired tz to change it."
          : `Timezone set to ${value}. Applies on the host within one heartbeat cycle.`,
      );
    },
    onError: () => setSavedNote(null),
  });

  const disabled = !isSuperadmin || !applianceMode || save.isPending;
  const trimmed = tz.trim();
  // An alias is saved as its canonical name (the API does the same).
  const canonical = canonicalHostTimezone(trimmed);
  const isValid =
    trimmed === "" ||
    isValidTimeZone(canonical) ||
    CANONICAL_TARGETS.has(canonical);
  const dirty = canonical !== currentValue.trim();

  return (
    <section className="rounded-lg border bg-card p-4">
      <div className="mb-3 flex items-center gap-2">
        <Clock className="h-4 w-4" />
        <h3 className="text-sm font-semibold">Host timezone</h3>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        IANA timezone name applied to the appliance host (e.g.{" "}
        <code>America/Toronto</code>, <code>Europe/Berlin</code>,{" "}
        <code>UTC</code>). The installer wizard captures the initial value; this
        control changes it post-install. Clearing this field stops SpatiumDDI
        from pushing further timezone changes — the host stays on whatever
        timezone the runner most recently applied. To actually revert to the
        install-time default, set the field to that default explicitly and save.
      </p>
      {!applianceMode && (
        <p className="mb-3 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300">
          This control only applies on SpatiumDDI OS appliances. Docker and
          Kubernetes deployments inherit timezone from the host / container
          runtime; set it there instead.
        </p>
      )}
      <div className="flex items-center gap-2">
        <input
          list="iana-timezones"
          value={tz}
          onChange={(e) => {
            setTz(e.target.value);
            setSavedNote(null);
          }}
          placeholder="UTC"
          disabled={disabled}
          className="w-72 rounded-md border bg-background px-3 py-1.5 text-sm font-mono disabled:opacity-60"
        />
        <datalist id="iana-timezones">
          {ianaList.map((name) => (
            <option key={name} value={name} />
          ))}
        </datalist>
        <button
          type="button"
          disabled={disabled || !isValid || !dirty}
          onClick={() => save.mutate(canonical)}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          {save.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          Save
        </button>
      </div>
      {!isValid && (
        <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">
          Not a recognised IANA timezone. Use the autocomplete or pick from{" "}
          <a
            href="https://en.wikipedia.org/wiki/List_of_tz_database_time_zones"
            target="_blank"
            rel="noreferrer"
            className="underline"
          >
            the IANA database list
          </a>
          .
        </p>
      )}
      {savedNote && (
        <p className="mt-2 text-xs text-emerald-700 dark:text-emerald-300">
          {savedNote}
        </p>
      )}
      {save.error && !savedNote && (
        <p className="mt-2 text-xs text-rose-700 dark:text-rose-300">
          {formatApiError(save.error)}
        </p>
      )}
    </section>
  );
}
