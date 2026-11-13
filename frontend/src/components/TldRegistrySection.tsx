import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Globe, RefreshCw } from "lucide-react";
import { dnsApi, formatApiError } from "@/lib/api";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import { FormError } from "@/components/ui/form-error";

/**
 * IANA root-zone TLD list — the data behind a zone's name scope (#986).
 *
 * SpatiumDDI ships a copy of the list with every release, so classification
 * works on an install that has never made an outbound call. This card exists
 * for the gap in between: IANA delegates a handful of TLDs a year, and until
 * the next SpatiumDDI release a brand-new one would read as "Undelegated".
 *
 * There is deliberately **no scheduled fetch** — TLD churn does not justify a
 * standing connection to a third party (non-negotiable #17). The operator
 * clicks the button, or waits for the next release.
 */

const SOURCE_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";

function Row({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-baseline justify-between gap-2 border-b py-2 last:border-0">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      <span className="text-xs">{children}</span>
    </div>
  );
}

export function TldRegistrySection({
  isSuperadmin,
}: {
  isSuperadmin: boolean;
}) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState("");

  const {
    data: info,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["dns-tld-registry"],
    queryFn: dnsApi.getTldRegistry,
    retry: false,
  });

  const refresh = useMutation({
    mutationFn: dnsApi.refreshTldRegistry,
    onSuccess: () => {
      setError("");
      setConfirm(false);
      qc.invalidateQueries({ queryKey: ["dns-tld-registry"] });
      // The pills are derived from this list, so every zone read is now
      // potentially wrong until it is refetched.
      qc.invalidateQueries({ queryKey: ["dns-zones"] });
      qc.invalidateQueries({ queryKey: ["domains"] });
      // …and so is the create-zone modal's live hint, which caches per
      // typed name for 5 minutes. Without this, an operator who refreshes
      // and then opens the modal is told a freshly-delegated TLD is still
      // undelegated — the one moment the answer is most likely to matter.
      qc.invalidateQueries({ queryKey: ["dns-name-scope"] });
    },
    onError: (e: unknown) => setError(formatApiError(e)),
  });

  return (
    <>
      <div className="py-3">
        <div className="text-xs text-muted-foreground">
          Source file:{" "}
          <a
            href={SOURCE_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="font-mono underline decoration-dotted underline-offset-2 hover:text-foreground"
          >
            {SOURCE_URL}
          </a>
        </div>
        <div className="mt-1 text-xs text-muted-foreground">
          Fetched by the control plane (not your browser), only when you click
          Refresh — there is no scheduled fetch. A refreshed list is stored in
          Postgres so every node of a multi-node control plane classifies names
          the same way, and it is used only when it is <em>newer</em> than the
          copy bundled with this release. The special-use table (
          <code>.local</code>, <code>.internal</code>, <code>example.com</code>,
          …) is not part of this download and is never overwritten by it.
        </div>
      </div>

      {isLoading && (
        <p className="py-2 text-xs text-muted-foreground">Loading…</p>
      )}

      {/* This endpoint sits behind the DNS router's read gate, so a user
          who can reach Settings but holds no DNS permission gets a 403.
          Say that, rather than spinning on "Loading…" forever. */}
      {!isLoading && loadError && (
        <p className="py-2 text-xs text-muted-foreground">
          {formatApiError(loadError, "Could not read the TLD registry.")} This
          card needs permission to read DNS.
        </p>
      )}

      {info && (
        <div className="rounded-md border px-3">
          <Row label="In use">
            <span className="inline-flex items-center gap-1.5">
              <Globe className="h-3.5 w-3.5 text-muted-foreground" />
              {info.origin === "snapshot"
                ? "Refreshed copy"
                : "Bundled with this release"}
            </span>
          </Row>
          <Row label="Version">
            <span className="font-mono">{info.version || "—"}</span>
          </Row>
          <Row label="Fetched">
            {info.fetched_at ? (
              <>
                {new Date(info.fetched_at).toLocaleString()}
                {info.age_days !== null && (
                  <span
                    className={
                      info.stale
                        ? "ml-2 text-amber-600 dark:text-amber-400"
                        : "ml-2 text-muted-foreground"
                    }
                  >
                    ({info.age_days} day{info.age_days === 1 ? "" : "s"} ago
                    {info.stale ? " — consider refreshing" : ""})
                  </span>
                )}
              </>
            ) : (
              "—"
            )}
          </Row>
          <Row label="Top-level domains">
            <span className="font-mono tabular-nums">
              {info.count.toLocaleString()}
            </span>
          </Row>
          {info.snapshot_version && info.origin === "bundled" && (
            <Row label="Stored copy">
              <span className="text-muted-foreground">
                v{info.snapshot_version} — not in use, the bundled list (v
                {info.bundled_version}) is newer
              </span>
            </Row>
          )}
        </div>
      )}

      {error && (
        <FormError className="mt-2 rounded border border-destructive/40 bg-destructive/10 px-2 py-1.5 text-xs text-destructive">
          {error}
        </FormError>
      )}

      <div className="mt-3">
        <button
          onClick={() => setConfirm(true)}
          disabled={!isSuperadmin || refresh.isPending}
          className="flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium hover:bg-accent disabled:opacity-40"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${refresh.isPending ? "animate-spin" : ""}`}
          />
          {refresh.isPending ? "Refreshing…" : "Refresh now"}
        </button>
        {!isSuperadmin && (
          <p className="mt-1 text-[11px] text-muted-foreground">
            Superadmin only.
          </p>
        )}
      </div>

      <ConfirmModal
        open={confirm}
        title="Refresh the TLD registry?"
        message={
          <>
            This control plane will make one outbound HTTPS request to{" "}
            <span className="font-mono">data.iana.org</span> and store the
            result. Nothing about this install is sent — it is an
            unauthenticated GET of a public file.
            <br />
            <br />
            If the download fails or comes back the wrong shape it is rejected
            and the current list stays in force.
          </>
        }
        confirmLabel="Refresh"
        loading={refresh.isPending}
        onClose={() => setConfirm(false)}
        onConfirm={() => refresh.mutate()}
      />
    </>
  );
}
