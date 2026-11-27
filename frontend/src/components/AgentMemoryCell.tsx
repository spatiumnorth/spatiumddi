import type { AgentMemoryStatus } from "@/lib/api";
import { memoryUsage } from "@/lib/agent-memory";

/**
 * The server list's Memory column (#4193): container memory used against its
 * limit, amber above 80 %. "—" means the agent has not reported memory (an
 * older agent, an agentless driver), which is not the same as 0.
 */
export function AgentMemoryCell({
  server,
  className = "",
}: {
  server: { memory_status?: AgentMemoryStatus | null };
  className?: string;
}) {
  const m = memoryUsage(server.memory_status);
  const title =
    m.percent == null
      ? m.text === "—"
        ? "Memory not reported by this agent"
        : "Container memory in use (no limit set)"
      : `Container memory: ${Math.round(m.percent)}% of the limit${m.warn ? " — close to the limit" : ""}`;
  return (
    <span
      data-testid="agent-memory-cell"
      title={title}
      className={`whitespace-nowrap text-xs tabular-nums ${
        m.warn
          ? "font-medium text-amber-700 dark:text-amber-400"
          : "text-muted-foreground"
      } ${className}`}
    >
      <span className="mr-1 text-[10px] uppercase tracking-wide">Mem</span>
      {m.text}
    </span>
  );
}
