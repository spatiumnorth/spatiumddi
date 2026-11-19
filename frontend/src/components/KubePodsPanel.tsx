import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Box } from "lucide-react";
import { containersApi, streamPodLogs, type PodRow } from "@/lib/api";
import { cn, zebraBodyCls } from "@/lib/utils";

const MAX_LINES = 2000;

/** Live, server-redacted log follower for one pod (#3761). */
function PodLogViewer({ name }: { name: string }) {
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const boxRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    const ctl = new AbortController();
    setLines([]);
    setError(null);
    (async () => {
      try {
        for await (const line of streamPodLogs(name, ctl.signal)) {
          setLines((prev) => [...prev, line].slice(-MAX_LINES));
        }
      } catch (e) {
        if (!ctl.signal.aborted) {
          setError(e instanceof Error ? e.message : "log stream failed");
        }
      }
    })();
    return () => ctl.abort();
  }, [name]);

  useEffect(() => {
    const el = boxRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines]);

  return (
    <div className="space-y-1">
      <div className="text-xs font-medium">Logs: {name}</div>
      {error && <div className="text-xs text-red-600">{error}</div>}
      <pre
        ref={boxRef}
        data-testid="pod-log-viewer"
        className="max-h-80 overflow-auto rounded border bg-muted/30 p-2 font-mono text-[11px]"
      >
        {lines.join("\n")}
      </pre>
    </div>
  );
}

export function KubePodsPanel({ namespace }: { namespace?: string | null }) {
  const [selected, setSelected] = useState<string | null>(null);
  const pods = useQuery({
    queryKey: ["container-pods"],
    queryFn: containersApi.pods,
    refetchInterval: 10_000,
  });

  if (pods.data && !pods.data.available) {
    return (
      <div className="rounded border border-amber-500/40 bg-amber-500/5 p-4 text-xs text-muted-foreground">
        Kubernetes pods not available: {pods.data.reason}
      </div>
    );
  }
  const rows: PodRow[] = pods.data?.rows ?? [];

  return (
    <div className="space-y-3" data-testid="kube-pods">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Box className="h-4 w-4" />
        Kubernetes pods{namespace ? ` (${namespace})` : ""}
      </div>
      <div className="overflow-x-auto rounded border">
        <table className="w-full min-w-[640px] text-sm">
          <thead className="bg-muted/40 text-xs">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Pod</th>
              <th className="px-3 py-2 text-left font-medium">Component</th>
              <th className="px-3 py-2 text-left font-medium">Status</th>
              <th className="px-3 py-2 text-right font-medium">Logs</th>
            </tr>
          </thead>
          <tbody className={zebraBodyCls}>
            {rows.length === 0 && (
              <tr>
                <td
                  colSpan={4}
                  className="px-3 py-4 text-center text-xs text-muted-foreground"
                >
                  No pods found.
                </td>
              </tr>
            )}
            {rows.map((p) => (
              <tr key={p.name}>
                <td className="px-3 py-1.5">
                  <div className="font-medium">{p.name}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {p.image}
                  </div>
                </td>
                <td className="px-3 py-1.5">{p.component}</td>
                <td className="px-3 py-1.5">
                  <span
                    className={cn(
                      "inline-flex rounded px-1.5 py-0.5 text-[10px] font-medium",
                      p.state === "running"
                        ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-400"
                        : "bg-muted text-muted-foreground",
                    )}
                  >
                    {p.status}
                  </span>
                </td>
                <td className="px-3 py-1.5 text-right">
                  <button
                    type="button"
                    onClick={() => setSelected(p.name)}
                    className="rounded-md border px-2 py-0.5 text-xs hover:bg-muted"
                  >
                    View logs
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && <PodLogViewer name={selected} />}
    </div>
  );
}
