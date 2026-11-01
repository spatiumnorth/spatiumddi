import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle,
  Download,
  FileArchive,
  KeyRound,
  Loader2,
  ShieldCheck,
} from "lucide-react";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  formatApiError,
  supportBundleApi,
  type SupportBundleDecodeMap,
  type SupportBundlePreview,
} from "@/lib/api";

/**
 * Support bundle (#875) — generate a scrubbed diagnostics archive for a
 * bug report.
 *
 * The review step is the point of this screen, not decoration. Attachments
 * on a public GitHub issue are readable by anyone who can see the issue,
 * and deleting the comment does not reliably purge the file — so the
 * operator sees the file list and what the scrubber replaced *before* a
 * download button appears.
 */
export function SupportBundleSection() {
  const [preview, setPreview] = useState<SupportBundlePreview | null>(null);
  const [scrubbed, setScrubbed] = useState(true);
  const [confirmRaw, setConfirmRaw] = useState(false);
  const [decodeMap, setDecodeMap] = useState<SupportBundleDecodeMap | null>(
    null,
  );
  const [error, setError] = useState("");

  const previewMut = useMutation({
    mutationFn: (wantScrubbed: boolean) =>
      supportBundleApi.preview(wantScrubbed),
    onSuccess: (data) => {
      setPreview(data);
      setError("");
    },
    onError: (e) => setError(formatApiError(e, "Preview failed")),
  });

  const downloadMut = useMutation({
    mutationFn: async (wantScrubbed: boolean) => {
      const blob = await supportBundleApi.download(wantScrubbed);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download =
        preview?.filename ??
        `spatiumddi-support-bundle-${new Date().toISOString().slice(0, 10)}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },
    // supportBundleApi.download decodes the Blob error body
    // (rethrowBlobError), so formatApiError reads the server's reason.
    onError: (e) => {
      setError(formatApiError(e, "Download failed"));
    },
  });

  const decodeMut = useMutation({
    mutationFn: () => supportBundleApi.decodeMap(),
    onSuccess: setDecodeMap,
    onError: (e) => setError(formatApiError(e, "Could not build decode map")),
  });

  const scrub = (preview?.manifest?.scrub ?? {}) as Record<string, unknown>;
  const safetyNetHits = (scrub.safety_net_hits as string[] | undefined) ?? [];

  const runPreview = (wantScrubbed: boolean) => {
    setScrubbed(wantScrubbed);
    setPreview(null);
    setDecodeMap(null);
    previewMut.mutate(wantScrubbed);
  };

  return (
    <div className="space-y-4">
      <div className="rounded border bg-card p-4">
        <div className="flex items-start gap-2">
          <FileArchive className="mt-0.5 h-4 w-4 flex-shrink-0 text-muted-foreground" />
          <div className="min-w-0 space-y-1">
            <h3 className="text-sm font-medium">Support bundle</h3>
            <p className="text-xs text-muted-foreground">
              A diagnostics archive for a bug report: versions, schema head,
              recent errors, alert history, configuration shape, an audit tail
              and whatever logs this deployment can reach. Credentials are
              excluded in every mode.
            </p>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => runPreview(true)}
            disabled={previewMut.isPending}
            className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {previewMut.isPending && scrubbed ? (
              <Loader2 className="h-3 w-3 animate-spin" />
            ) : (
              <ShieldCheck className="h-3 w-3" />
            )}
            Review scrubbed bundle
          </button>
          <button
            type="button"
            onClick={() => setConfirmRaw(true)}
            disabled={previewMut.isPending}
            className="inline-flex items-center gap-1.5 rounded border border-amber-500/40 px-3 py-1.5 text-xs text-amber-700 hover:bg-amber-500/10 disabled:opacity-50 dark:text-amber-400"
          >
            <AlertTriangle className="h-3 w-3" />
            Unscrubbed (local only)
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
          {error}
        </p>
      )}

      {preview && (
        <div className="space-y-3 rounded border bg-card p-4">
          <div
            className={`rounded border p-2 text-xs ${
              preview.scrubbed
                ? "border-border bg-muted/40 text-muted-foreground"
                : "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-300"
            }`}
          >
            {preview.warning}
          </div>

          {safetyNetHits.length > 0 && (
            <div className="rounded border border-destructive/40 bg-destructive/5 p-2 text-xs text-destructive">
              <strong>The redaction safety net fired.</strong> Something reached
              the archive that a collector should have redacted itself. It was
              removed, but please report this — it is a bug in SpatiumDDI:
              <ul className="mt-1 list-inside list-disc">
                {safetyNetHits.map((h) => (
                  <li key={h} className="font-mono">
                    {h}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {preview.scrubbed && (
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-5">
              {(
                [
                  ["IPv4", "ipv4_mapped"],
                  ["IPv6", "ipv6_mapped"],
                  ["MACs", "macs_mapped"],
                  ["Hostnames", "hostnames_mapped"],
                  ["Usernames", "usernames_mapped"],
                ] as const
              ).map(([label, key]) => (
                <div key={key}>
                  <dt className="text-muted-foreground">{label} replaced</dt>
                  <dd className="font-medium">{String(scrub[key] ?? 0)}</dd>
                </div>
              ))}
            </dl>
          )}

          {preview.section_errors.length > 0 && (
            <div className="rounded border border-amber-500/40 bg-amber-500/5 p-2 text-xs">
              <strong>Some sections could not be collected.</strong> The rest of
              the bundle is still usable.
              <ul className="mt-1 list-inside list-disc text-muted-foreground">
                {preview.section_errors.map((e) => (
                  <li key={e} className="font-mono break-all">
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <p className="mb-1 text-xs font-medium">
              {preview.files.length} files ·{" "}
              {(preview.total_bytes / 1024).toFixed(0)} KB compressed
            </p>
            <div className="max-h-56 overflow-y-auto rounded border">
              <table className="w-full text-xs">
                <tbody>
                  {preview.files.map((f) => (
                    <tr key={f.path} className="border-b last:border-0">
                      <td className="px-2 py-1 font-mono break-all">
                        {f.path}
                      </td>
                      <td className="whitespace-nowrap px-2 py-1 text-right text-muted-foreground">
                        {f.bytes.toLocaleString()} B
                        {f.truncated && (
                          <span
                            className="ml-1 text-amber-600 dark:text-amber-400"
                            title="Truncated by the per-section size cap"
                          >
                            trunc
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {preview.sample && (
            <div>
              <p className="mb-1 text-xs font-medium">
                Sample of the scrubbed content
              </p>
              <pre className="max-h-40 overflow-auto rounded border bg-muted/40 p-2 text-[11px] leading-relaxed">
                {preview.sample}
              </pre>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2 border-t pt-3">
            <button
              type="button"
              onClick={() => downloadMut.mutate(preview.scrubbed)}
              disabled={downloadMut.isPending}
              className="inline-flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {downloadMut.isPending ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Download className="h-3 w-3" />
              )}
              Download {preview.scrubbed ? "" : "UNSCRUBBED "}bundle
            </button>
            {preview.scrubbed && (
              <button
                type="button"
                onClick={() => decodeMut.mutate()}
                disabled={decodeMut.isPending}
                className="inline-flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs hover:bg-muted/50 disabled:opacity-50"
                title="Maps the synthetic values back to the real ones. Keep it local."
              >
                {decodeMut.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <KeyRound className="h-3 w-3" />
                )}
                Decode map
              </button>
            )}
            <span className="text-[11px] text-muted-foreground">
              Regenerated on download, so a busy install may differ by a line.
            </span>
          </div>
        </div>
      )}

      {decodeMap && (
        <div className="space-y-2 rounded border border-amber-500/40 bg-amber-500/5 p-4">
          <p className="text-xs font-medium text-amber-800 dark:text-amber-300">
            {decodeMap.warning}
          </p>
          <p className="text-xs text-muted-foreground">
            {Object.entries(decodeMap.counts)
              .map(([k, n]) => `${n} ${k}`)
              .join(" · ")}
          </p>
          <pre className="max-h-64 overflow-auto rounded border bg-background p-2 text-[11px]">
            {JSON.stringify(decodeMap.mappings, null, 2)}
          </pre>
        </div>
      )}

      <ConfirmModal
        open={confirmRaw}
        title="Generate an unscrubbed bundle?"
        confirmLabel="Generate unscrubbed bundle"
        tone="destructive"
        requireCheckboxLabel="I will not attach this to a public issue"
        onClose={() => setConfirmRaw(false)}
        onConfirm={() => {
          setConfirmRaw(false);
          runPreview(false);
        }}
        message={
          <div className="space-y-2 text-sm">
            <p>
              An unscrubbed bundle contains <strong>real</strong> hostnames, IP
              addresses, MAC addresses and usernames from this install.
            </p>
            <p>
              It is for debugging on your own systems. Attachments on a public
              GitHub issue are readable by anyone who can see the issue, and
              deleting the comment does not reliably remove the file.
            </p>
            <p className="text-xs text-muted-foreground">
              Credentials are excluded from this bundle too — that part never
              changes.
            </p>
          </div>
        }
      />
    </div>
  );
}
