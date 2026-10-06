import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useSessionState } from "@/lib/useSessionState";
import {
  Archive,
  BookOpen,
  Check,
  Copy,
  History as HistoryIcon,
  Info,
  Loader2,
  MessageSquarePlus,
  Pencil,
  Send,
  Sparkles,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import { copyToClipboard } from "@/lib/clipboard";
import {
  aiApi,
  nmapApi,
  streamChatTurn,
  type AIChatMessage,
  type AIChatSessionSummary,
  type AIPrompt,
  type NmapScanRead,
} from "@/lib/api";

/** Render assistant content as Markdown with a curated set of element
 *  overrides tuned for the chat-bubble aesthetic. Used by both the
 *  committed-message bubble and the in-flight streaming bubble — the
 *  partial token stream during streaming may briefly show half-formed
 *  ``**`` or fence markers, but every popular chat UI does this and the
 *  end state always renders correctly.
 *
 *  GFM is enabled for tables, strikethrough, and task lists. We don't
 *  load math or syntax-highlight plugins — code fences render as
 *  monospace blocks (sufficient for the CIDR / shell snippet cases the
 *  copilot actually emits).
 */
function MarkdownContent({ children }: { children: string }) {
  return (
    <div className="prose-chat space-y-2 text-sm leading-relaxed [overflow-wrap:anywhere]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          p: ({ children }) => <p className="my-0">{children}</p>,
          ul: ({ children }) => (
            <ul className="my-1 list-disc space-y-0.5 pl-5">{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className="my-1 list-decimal space-y-0.5 pl-5">{children}</ol>
          ),
          li: ({ children }) => <li className="my-0">{children}</li>,
          strong: ({ children }) => (
            <strong className="font-semibold">{children}</strong>
          ),
          em: ({ children }) => <em className="italic">{children}</em>,
          h1: ({ children }) => (
            <h1 className="mt-2 mb-1 text-base font-semibold">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="mt-2 mb-1 text-sm font-semibold">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="mt-2 mb-1 text-sm font-semibold">{children}</h3>
          ),
          a: ({ children, href }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              className="text-primary underline underline-offset-2 hover:text-primary/80"
            >
              {children}
            </a>
          ),
          code: ({ children, className }) => {
            // ``react-markdown`` v9 doesn't pass an ``inline`` prop —
            // a code element with no language class is inline; one
            // with ``language-*`` is a fenced block.
            const isBlock = /language-/.test(className ?? "");
            if (isBlock) {
              return (
                <code
                  className={`block whitespace-pre-wrap rounded bg-background/60 px-2 py-1 font-mono text-xs ${className ?? ""}`}
                >
                  {children}
                </code>
              );
            }
            return (
              <code className="rounded bg-background/60 px-1 py-0.5 font-mono text-[0.85em]">
                {children}
              </code>
            );
          },
          pre: ({ children }) => (
            <pre className="my-1 overflow-x-auto rounded border bg-background/60 p-2 text-xs">
              {children}
            </pre>
          ),
          blockquote: ({ children }) => (
            <blockquote className="my-1 border-l-2 border-muted-foreground/30 pl-3 text-muted-foreground">
              {children}
            </blockquote>
          ),
          table: ({ children }) => (
            <div className="my-1 overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                {children}
              </table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border-b px-2 py-1 text-left font-medium">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border-b border-foreground/10 px-2 py-1">
              {children}
            </td>
          ),
          hr: () => <hr className="my-2 border-foreground/10" />,
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}

/**
 * Chat drawer (issue #90 Wave 3). Slides in from the right when the
 * floating button (or Cmd/Ctrl+K) opens it.
 *
 * Layout:
 *   ┌─────────────────────────────────────┐
 *   │ ✨ Operator Copilot   [history ▾] x │
 *   │ model: llama3.1:8b on local-ollama  │
 *   ├─────────────────────────────────────┤
 *   │ <message stream>                    │
 *   │   user message    →                 │
 *   │   ← assistant response              │
 *   │   ← [tool: list_subnets] ✓          │
 *   ├─────────────────────────────────────┤
 *   │ [textarea]                  [send]  │
 *   └─────────────────────────────────────┘
 */
export function CopilotDrawer({
  onClose,
  pendingContext,
  onContextConsumed,
  pendingPrompt,
  onPromptConsumed,
}: {
  onClose: () => void;
  /** Set when the drawer was opened via ``askAI({ context })``. Forwarded
   *  to the chat endpoint as ``initial_context`` on the first new-session
   *  turn so it pre-seeds the system prompt. */
  pendingContext?: string | null;
  /** Called by the drawer once ``pendingContext`` has been consumed
   *  (i.e. the first chat turn fired with it included), so the parent
   *  can clear its state and avoid re-injecting on subsequent opens. */
  onContextConsumed?: () => void;
  /** Set when the drawer was opened via ``askAI({ prompt })``
   *  (typically from the Cmd-K palette). Pre-fills the chat composer
   *  textarea so the operator can review or edit before sending. */
  pendingPrompt?: string | null;
  /** Called once ``pendingPrompt`` has been written into the composer
   *  state, so the parent doesn't keep re-injecting it on re-renders. */
  onPromptConsumed?: () => void;
}) {
  const qc = useQueryClient();
  // Persist across drawer close/reopen within the same browser session
  // so the operator doesn't lose their place when they click off the
  // chat. Cleared by the "New session" / "Delete session" actions and
  // when the active session id is no longer reachable on the backend.
  const [activeSessionId, setActiveSessionId] = useSessionState<string | null>(
    "spatium.copilot.activeSessionId",
    null,
  );
  // Persisted bubble geometry — top-left anchor + width + height.
  // Survives close/reopen via sessionStorage. Default places the
  // bubble in the lower-right corner with a Gmail-compose-ish size.
  // Clamped on every render so a stale value (e.g. from a different
  // monitor) doesn't paint off-screen.
  type Geom = { left: number; top: number; width: number; height: number };
  const computeDefault = (): Geom => {
    const W = typeof window !== "undefined" ? window.innerWidth : 1280;
    const H = typeof window !== "undefined" ? window.innerHeight : 800;
    const width = 440;
    const height = Math.min(680, Math.max(480, H - 120));
    return {
      width,
      height,
      left: Math.max(16, W - width - 24),
      top: Math.max(16, H - height - 24),
    };
  };
  const [geom, setGeom] = useSessionState<Geom>(
    "spatium.copilot.geom",
    computeDefault(),
  );
  // Drag state — captures the pointer offset on mousedown so the
  // bubble follows the cursor rather than snapping its top-left to
  // the cursor.
  const dragRef = useRef<{ dx: number; dy: number } | null>(null);
  // Resize state — captures starting pointer + starting size; the
  // handle is on the top-left corner of the bubble (the only corner
  // that can grow without crowding the bottom-right anchor).
  const resizeRef = useRef<{
    startX: number;
    startY: number;
    startW: number;
    startH: number;
    startLeft: number;
    startTop: number;
  } | null>(null);

  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      const W = window.innerWidth;
      const H = window.innerHeight;
      if (dragRef.current) {
        const left = Math.max(
          0,
          Math.min(W - 80, e.clientX - dragRef.current.dx),
        );
        const top = Math.max(
          0,
          Math.min(H - 40, e.clientY - dragRef.current.dy),
        );
        setGeom((g) => ({ ...g, left, top }));
      } else if (resizeRef.current) {
        const r = resizeRef.current;
        // Top-left handle: dragging up/left grows the bubble. We move
        // ``left`` + ``top`` inversely so the bottom-right corner
        // stays pinned, and adjust width/height by the same delta.
        const dx = e.clientX - r.startX;
        const dy = e.clientY - r.startY;
        const minW = 320;
        const minH = 320;
        const newWidth = Math.max(minW, Math.min(W - 24, r.startW - dx));
        const newHeight = Math.max(minH, Math.min(H - 24, r.startH - dy));
        const newLeft = r.startLeft + (r.startW - newWidth);
        const newTop = r.startTop + (r.startH - newHeight);
        setGeom({
          left: Math.max(0, newLeft),
          top: Math.max(0, newTop),
          width: newWidth,
          height: newHeight,
        });
      }
    };
    const onUp = () => {
      dragRef.current = null;
      resizeRef.current = null;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [setGeom]);

  const startDrag = (e: React.MouseEvent) => {
    // Don't start dragging when the click landed on an interactive
    // control inside the title bar (close button, new-chat button,
    // etc.) — same hit-test as ``useDraggableModal``.
    const target = e.target as HTMLElement;
    if (target.closest("button, input, select, textarea, a")) return;
    dragRef.current = {
      dx: e.clientX - geom.left,
      dy: e.clientY - geom.top,
    };
    e.preventDefault();
    document.body.style.cursor = "grabbing";
    document.body.style.userSelect = "none";
  };
  const startResize = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    resizeRef.current = {
      startX: e.clientX,
      startY: e.clientY,
      startW: geom.width,
      startH: geom.height,
      startLeft: geom.left,
      startTop: geom.top,
    };
    document.body.style.cursor = "nwse-resize";
    document.body.style.userSelect = "none";
  };
  const effectiveGeom = useMemo<Geom>(() => {
    if (typeof window === "undefined") return geom;
    const W = window.innerWidth;
    const H = window.innerHeight;
    const width = Math.max(320, Math.min(W - 24, geom.width));
    const height = Math.max(320, Math.min(H - 24, geom.height));
    return {
      width,
      height,
      left: Math.max(0, Math.min(W - 80, geom.left)),
      top: Math.max(0, Math.min(H - 40, geom.top)),
    };
  }, [geom]);
  // Local in-flight stream — mirror of what's also being persisted on
  // the backend. Reset whenever a stream ends (success or failure).
  const [streamingContent, setStreamingContent] = useState<string>("");
  const [streamingTools, setStreamingTools] = useState<
    {
      id: string;
      name: string;
      arguments: string;
      preview?: string;
      is_error?: boolean;
    }[]
  >([]);
  const [streamingError, setStreamingError] = useState<string | null>(null);
  // Failover notices emitted by the backend orchestrator when the
  // primary provider failed transiently and the request was retried
  // on a fallback. ``null`` when no failover happened on this turn.
  const [streamingFailover, setStreamingFailover] = useState<{
    from_provider: string;
    to_provider: string;
    to_model: string;
    reason: string;
  } | null>(null);
  // Echo of the just-sent user message — kept in component state until
  // the backend stream ends and detailQ refetches the persisted version.
  // Without this, second-and-later turns appear to "swallow" the user
  // message: the textbox clears but nothing renders until the LLM
  // finishes responding (which may be 5–30 s on a slow local model).
  const [pendingUserMessage, setPendingUserMessage] = useState<string | null>(
    null,
  );
  const [showHistory, setShowHistory] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const sessionsQ = useQuery({
    queryKey: ["ai-sessions"],
    queryFn: () => aiApi.listSessions(false),
    staleTime: 30 * 1000,
  });

  // Wave 4 — operator's own today-so-far totals + caps. Refetches
  // after every chat turn so the drawer's progress bar stays current.
  const usageQ = useQuery({
    queryKey: ["ai-usage-me"],
    queryFn: aiApi.myUsage,
    staleTime: 10 * 1000,
    refetchOnWindowFocus: false,
  });

  const detailQ = useQuery({
    queryKey: ["ai-session", activeSessionId],
    queryFn: () =>
      activeSessionId
        ? aiApi.getSession(activeSessionId)
        : Promise.resolve(null),
    enabled: activeSessionId !== null,
    // 404 here means the persisted session id (from sessionStorage)
    // points at a session that no longer exists — relogin, manual
    // delete from the DB, etc. Don't retry; we'll clear it below.
    retry: false,
  });

  // Drop a stale persisted session id when the backend says it's gone.
  // Without this the drawer gets stuck showing a "session not found"
  // error on every open.
  useEffect(() => {
    if (detailQ.isError && activeSessionId) {
      setActiveSessionId(null);
    }
  }, [detailQ.isError, activeSessionId, setActiveSessionId]);

  // ``pendingContext`` arrives when the drawer was opened via
  // ``askAI({ context })`` (right-click "Ask AI about this"). Whenever
  // a context is present, force a fresh session — the operator's
  // intent is "ask the model about this resource I'm looking at",
  // not "tack this onto whatever conversation I had open." Without
  // this reset the context would be silently dropped on existing
  // sessions because the system prompt is snapshotted at session
  // create.
  useEffect(() => {
    if (pendingContext) {
      setActiveSessionId(null);
    }
  }, [pendingContext]);

  // Esc closes the drawer.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  // Auto-scroll the message list as new content arrives.
  const scrollRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [
    detailQ.data,
    streamingContent,
    streamingTools.length,
    streamingError,
    pendingUserMessage,
  ]);

  const sendMut = useMutation({
    mutationFn: async (
      message: string,
    ): Promise<{ sessionId: string | null; error: string | null }> => {
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      setStreamingContent("");
      setStreamingTools([]);
      setStreamingError(null);
      setStreamingFailover(null);
      setPendingUserMessage(message);
      let resolvedSessionId = activeSessionId;
      // Track an SSE-emitted ``error`` event locally so onSuccess can
      // distinguish "true success" from "stream completed but reported
      // an error event" — the latter must keep the optimistic echo +
      // banner around for the inline retry affordance to work.
      let localError: string | null = null;
      // ``initial_context`` only matters on a *new* session — the
      // backend ignores it once a session has its system prompt
      // snapshotted. Notify the parent the moment we send it so it
      // doesn't reinject on a follow-up "Ask AI" without resetting.
      const includeContext =
        activeSessionId === null && Boolean(pendingContext);
      try {
        for await (const ev of streamChatTurn(
          {
            message,
            session_id: activeSessionId ?? undefined,
            initial_context: includeContext
              ? (pendingContext ?? undefined)
              : undefined,
          },
          ctrl.signal,
        )) {
          if (ev.event === "session") {
            const sid = ev.data.session_id as string;
            if (!resolvedSessionId) {
              resolvedSessionId = sid;
              setActiveSessionId(sid);
            }
          } else if (ev.event === "content") {
            setStreamingContent((prev) => prev + (ev.data.delta as string));
          } else if (ev.event === "tool_call") {
            setStreamingTools((prev) => [
              ...prev,
              {
                id: ev.data.id as string,
                name: ev.data.name as string,
                arguments: ev.data.arguments as string,
              },
            ]);
          } else if (ev.event === "tool_result") {
            setStreamingTools((prev) =>
              prev.map((t) =>
                t.id === ev.data.tool_call_id
                  ? {
                      ...t,
                      preview: ev.data.preview as string,
                      is_error: ev.data.is_error as boolean,
                    }
                  : t,
              ),
            );
          } else if (ev.event === "info") {
            // Phase 2 failover notice — primary provider failed
            // transiently and the orchestrator retried on a fallback.
            if (ev.data.kind === "failover") {
              setStreamingFailover({
                from_provider: ev.data.from_provider as string,
                to_provider: ev.data.to_provider as string,
                to_model: ev.data.to_model as string,
                reason: ev.data.reason as string,
              });
            }
          } else if (ev.event === "error") {
            localError = ev.data.message as string;
            setStreamingError(localError);
          }
        }
      } finally {
        abortRef.current = null;
        if (includeContext) {
          // Tell the parent we consumed the initial context — it will
          // clear its ``pendingContext`` state so subsequent opens
          // (without an ``askAI`` event) don't re-inject anything.
          onContextConsumed?.();
        }
      }
      return { sessionId: resolvedSessionId, error: localError };
    },
    onSuccess: ({ error }) => {
      // True success → clear the optimistic echo so the refetched
      // persisted version slides in cleanly. On SSE-emitted error
      // (``error`` non-null) we deliberately keep both the echo and
      // ``streamingError`` so the inline retry block downstream can
      // re-send the same text without the operator retyping.
      if (!error) {
        setPendingUserMessage(null);
      }
    },
    onError: (err: unknown) => {
      // mutationFn threw — typically AbortError (operator hit Stop)
      // or a network/parse error from the SSE stream itself. Treat
      // AbortError as a soft cancel (clear everything; the operator
      // explicitly asked to stop). Real exceptions surface as a
      // retry affordance + keep the echo around.
      const e = err as { name?: string; message?: string };
      if (e?.name === "AbortError") {
        setPendingUserMessage(null);
        setStreamingError(null);
      } else {
        setStreamingError(e?.message || "Stream failed");
      }
    },
    onSettled: (data) => {
      // Refetch the session detail + session list so the persisted
      // assistant message appears + the in-flight buffer drops.
      qc.invalidateQueries({ queryKey: ["ai-sessions"] });
      const sid = data?.sessionId;
      if (sid) {
        qc.invalidateQueries({ queryKey: ["ai-session", sid] });
      }
      // Refresh the usage panel — message count + cost will have
      // ticked up after the persisted assistant message.
      qc.invalidateQueries({ queryKey: ["ai-usage-me"] });
      setStreamingContent("");
      setStreamingTools([]);
      // Note: ``setPendingUserMessage(null)`` is in onSuccess (and
      // the AbortError branch of onError) only — leaving it set on
      // real errors keeps the echo + retry block usable.
    },
  });

  const renameMut = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      aiApi.updateSession(id, { name }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ai-sessions"] }),
  });

  const archiveMut = useMutation({
    mutationFn: (id: string) => aiApi.updateSession(id, { archived: true }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["ai-sessions"] });
      if (id === activeSessionId) {
        setActiveSessionId(null);
      }
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => aiApi.deleteSession(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["ai-sessions"] });
      // Cascade-delete on ai_chat_message drops the row's tokens
      // from the today-so-far rollup; refresh the usage chip so
      // the operator doesn't see a stale tally.
      qc.invalidateQueries({ queryKey: ["ai-usage-me"] });
      if (id === activeSessionId) {
        setActiveSessionId(null);
      }
    },
  });

  // Multi-select for bulk delete in the History panel.
  // Local-only state — the ids don't need to survive close/reopen.
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const bulkDeleteMut = useMutation({
    // No dedicated bulk-delete endpoint — fan out per-id deletes in
    // parallel. Practical chat-history sizes (single-digit to low-100s)
    // are well within what the API can handle.
    mutationFn: async (ids: string[]) => {
      await Promise.all(ids.map((id) => aiApi.deleteSession(id)));
    },
    onSuccess: (_, ids) => {
      qc.invalidateQueries({ queryKey: ["ai-sessions"] });
      qc.invalidateQueries({ queryKey: ["ai-usage-me"] });
      if (activeSessionId && ids.includes(activeSessionId)) {
        setActiveSessionId(null);
      }
      setSelectedIds(new Set());
    },
  });
  function toggleSelected(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const messages = useMemo<AIChatMessage[]>(() => {
    if (!detailQ.data) return [];
    return detailQ.data.messages.filter((m) => m.role !== "system");
  }, [detailQ.data]);

  // Every user message in the persisted history, oldest → newest.
  // Powers the composer's ↑/↓ history walk. Index 0 = oldest,
  // length-1 = newest.
  const userMessages = useMemo<string[]>(
    () => messages.filter((m) => m.role === "user").map((m) => m.content),
    [messages],
  );
  // Used to suppress the optimistic ``pendingUserMessage`` bubble
  // once the canonical version has shown up — without this, the first
  // turn of a new session double-renders the user message: once from
  // ``pendingUserMessage`` (still set until onSettled), once from
  // detailQ (refetched the moment ``session_id`` arrives mid-stream).
  const lastUserMessageContent =
    userMessages.length > 0 ? userMessages[userMessages.length - 1] : null;
  const showPendingUserMessage =
    pendingUserMessage !== null &&
    pendingUserMessage !== lastUserMessageContent;

  const sessionLabel = useMemo(() => {
    if (!detailQ.data) return null;
    return `${detailQ.data.model}${detailQ.data.provider_id ? "" : " (provider missing)"}`;
  }, [detailQ.data]);

  return (
    // Bubble — positioned, draggable, resizable; doesn't block the
    // page behind it (no backdrop). Operator can keep the chat open
    // while clicking around IPAM / DNS / DHCP, dragging it out of the
    // way as needed (Gmail-compose pattern).
    <div
      className="fixed z-50 flex flex-col rounded-lg border bg-card shadow-2xl"
      style={{
        left: `${effectiveGeom.left}px`,
        top: `${effectiveGeom.top}px`,
        width: `${effectiveGeom.width}px`,
        height: `${effectiveGeom.height}px`,
      }}
    >
      {/* Resize handle — top-left corner; the only corner that can
          grow without fighting the operator's mental model that the
          bubble is anchored to the bottom-right. */}
      <div
        onMouseDown={startResize}
        className="group absolute -top-1 -left-1 z-10 h-4 w-4 cursor-nwse-resize select-none"
        title="Drag to resize"
      >
        <div className="absolute inset-1 rounded-tl border-l-2 border-t-2 border-border transition-colors group-hover:border-primary/60 group-active:border-primary" />
      </div>
      {/* Header — also the drag handle. Click on empty header areas
          drags; clicks on the buttons / session label stay scoped. */}
      <div
        onMouseDown={startDrag}
        className="flex flex-wrap items-center justify-between gap-2 rounded-t-lg border-b px-4 py-3 cursor-grab active:cursor-grabbing select-none"
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-primary" />
            <h2 className="text-sm font-semibold">Operator Copilot</h2>
          </div>
          {sessionLabel && (
            <div className="mt-0.5 truncate text-xs text-muted-foreground font-mono">
              {sessionLabel}
            </div>
          )}
          {usageQ.data && <UsageChip usage={usageQ.data} />}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            onClick={() => setActiveSessionId(null)}
            title="New chat"
            className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
          >
            <MessageSquarePlus className="h-3.5 w-3.5" />
            New chat
          </button>
          <button
            type="button"
            onClick={() => setShowHistory((v) => !v)}
            title="Recent chats"
            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs ${
              showHistory
                ? "bg-accent text-foreground"
                : "text-muted-foreground hover:bg-accent"
            }`}
          >
            <HistoryIcon className="h-3.5 w-3.5" />
            History
          </button>
          <button
            type="button"
            onClick={onClose}
            title="Close (Esc)"
            className="rounded-md border px-2 py-1 text-xs text-muted-foreground hover:bg-accent"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* History dropdown */}
      {showHistory && (
        <div className="max-h-[40vh] overflow-y-auto border-b bg-muted/30">
          {(sessionsQ.data ?? []).length === 0 && (
            <div className="px-4 py-6 text-center text-xs text-muted-foreground">
              No chat history yet.
            </div>
          )}
          {(sessionsQ.data ?? []).length > 0 && (
            <div className="sticky top-0 z-10 flex items-center justify-between gap-2 border-b bg-card px-4 py-1.5 text-xs">
              {selectedIds.size > 0 ? (
                <>
                  <span className="text-muted-foreground">
                    {selectedIds.size} selected
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setSelectedIds(new Set())}
                      className="rounded border px-2 py-0.5 hover:bg-accent"
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      disabled={bulkDeleteMut.isPending}
                      onClick={() => {
                        const ids = Array.from(selectedIds);
                        if (
                          confirm(
                            `Delete ${ids.length} chat${ids.length === 1 ? "" : "s"}? This cannot be undone.`,
                          )
                        ) {
                          bulkDeleteMut.mutate(ids);
                        }
                      }}
                      className="rounded border border-destructive/40 bg-destructive/10 px-2 py-0.5 text-destructive hover:bg-destructive/20 disabled:opacity-50"
                    >
                      {bulkDeleteMut.isPending
                        ? "Deleting…"
                        : `Delete ${selectedIds.size}`}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    onClick={() => {
                      const all = new Set(
                        (sessionsQ.data ?? []).map((s) => s.id),
                      );
                      setSelectedIds(all);
                    }}
                    className="rounded border px-2 py-0.5 text-muted-foreground hover:bg-accent"
                  >
                    Select all
                  </button>
                  <button
                    type="button"
                    disabled={bulkDeleteMut.isPending}
                    onClick={() => {
                      const ids = (sessionsQ.data ?? []).map((s) => s.id);
                      if (
                        ids.length > 0 &&
                        confirm(
                          `Delete all ${ids.length} chats? This cannot be undone.`,
                        )
                      ) {
                        bulkDeleteMut.mutate(ids);
                      }
                    }}
                    className="rounded border border-destructive/30 px-2 py-0.5 text-destructive hover:bg-destructive/10 disabled:opacity-50"
                  >
                    Delete all
                  </button>
                </>
              )}
            </div>
          )}
          {(sessionsQ.data ?? []).map((s) => (
            <SessionRow
              key={s.id}
              session={s}
              active={s.id === activeSessionId}
              selected={selectedIds.has(s.id)}
              onToggleSelect={() => toggleSelected(s.id)}
              onPick={() => {
                setActiveSessionId(s.id);
                setShowHistory(false);
              }}
              onRename={(name) => renameMut.mutate({ id: s.id, name })}
              onArchive={() => archiveMut.mutate(s.id)}
              onDelete={() => deleteMut.mutate(s.id)}
            />
          ))}
        </div>
      )}

      {/* Message stream */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4">
        {!activeSessionId && !sendMut.isPending && (
          <EmptyState onPick={(q) => sendMut.mutate(q)} />
        )}
        {messages.map((m, idx) => (
          <MessageBubble
            key={m.id}
            message={m}
            onAnswerYesNo={
              // Only the very last message can be a "live" yes/no
              // question — the orchestrator suspends the round loop
              // right after it, so anything beyond it in history
              // means the operator already answered (issue #120).
              idx === messages.length - 1 && !sendMut.isPending
                ? (answer) => sendMut.mutate(answer)
                : undefined
            }
          />
        ))}
        {/* Optimistic echo of the just-sent user message. Stays
              visible from the moment the operator hits Send until
              detailQ refetches with the persisted version after the
              stream closes — without this, second-and-later turns
              appear to swallow the user's message during the LLM's
              think time. */}
        {showPendingUserMessage && (
          <div className="mb-3 flex justify-end">
            <div className="max-w-[85%] rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground">
              <pre className="whitespace-pre-wrap break-words font-sans">
                {pendingUserMessage}
              </pre>
            </div>
          </div>
        )}
        {/* In-flight streaming */}
        {sendMut.isPending && (
          <StreamingBubble
            content={streamingContent}
            tools={streamingTools}
            error={streamingError}
            failover={streamingFailover}
          />
        )}
        {/* Post-stream error + retry. Visible after the mutation
            settles (``isPending`` false) when an SSE ``error`` event
            arrived or the stream threw mid-flight. The user message
            is kept around (see ``sendMut.onSuccess`` /
            ``sendMut.onError``) so Retry can resend the same text. */}
        {!sendMut.isPending && streamingError && (
          <StreamErrorBlock
            error={streamingError}
            canRetry={Boolean(pendingUserMessage)}
            onRetry={() => {
              const text = pendingUserMessage;
              if (!text) {
                setStreamingError(null);
                return;
              }
              sendMut.mutate(text);
            }}
            onDismiss={() => {
              setStreamingError(null);
              setPendingUserMessage(null);
            }}
          />
        )}
      </div>

      {/* "Asking about: …" chip — visible while ``pendingContext``
          is set (operator opened the drawer via ``askAI({ context })``
          from any "Ask AI about this" affordance). The chip is the
          *only* visible signal that the system prompt has been
          seeded; without it the empty drawer reads as "the button
          did nothing." Clears once the first turn fires (via
          ``onContextConsumed`` in ``sendMut.mutationFn``) or when
          the operator hits ×. */}
      {pendingContext && (
        <div className="flex items-center gap-1.5 border-t border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-300">
          <Sparkles className="h-3 w-3 shrink-0" />
          <span className="shrink-0 font-medium">Asking about:</span>
          <span
            className="truncate"
            title={pendingContext}
            aria-label={`Context attached: ${pendingContext}`}
          >
            {pendingContext}
          </span>
          <button
            type="button"
            onClick={() => onContextConsumed?.()}
            title="Clear context"
            aria-label="Clear context"
            className="ml-auto inline-flex shrink-0 rounded p-0.5 hover:bg-amber-500/20"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      )}

      {/* Composer */}
      <ChatComposer
        disabled={sendMut.isPending}
        onSend={(text) => sendMut.mutate(text)}
        onCancel={() => abortRef.current?.abort()}
        isStreaming={sendMut.isPending}
        pendingPrompt={pendingPrompt ?? null}
        onPromptConsumed={onPromptConsumed}
        userMessages={userMessages}
      />
    </div>
  );
}

// Curated starter prompts grouped by intent. The Operator Copilot's
// tool surface is wide enough that a flat 5-prompt list under-sells
// it; grouping helps operators discover what the chat can actually
// do. Some prompts target tools that are default-disabled (WHOIS,
// TLS check, live DNS) — clicking those on a fresh install surfaces
// the "ask your admin to enable" path naturally, which is a good
// first taste of the Tool Catalog.
const STARTER_GROUPS: { label: string; examples: string[] }[] = [
  {
    label: "Triage",
    examples: [
      "What's broken right now?",
      "Who changed something in the last hour?",
      "Show me failed login attempts in the last 24 hours",
      "Are there any open critical alerts?",
    ],
  },
  {
    label: "IPAM",
    examples: [
      "How many subnets do I have?",
      "Find the IP 192.168.0.1",
      "Which subnets are above 80% utilisation?",
      "List the IP spaces",
    ],
  },
  {
    label: "DNS",
    examples: [
      "List my DNS zones",
      "What records does example.com have?",
      "Resolve cloudflare.com",
      "What's the PTR for 1.1.1.1?",
    ],
  },
  {
    label: "DHCP",
    examples: [
      "What DHCP scopes are configured?",
      "Show me recent leases",
      "What's the current lease count by scope?",
    ],
  },
  {
    label: "Network",
    examples: [
      "List the ASNs I track",
      "What overlays do I have?",
      "Who owns 8.8.8.8?",
      "Who registered cloudflare.com?",
      "When does the cloudflare.com TLS cert expire?",
    ],
  },
  {
    label: "RBAC & audit",
    examples: [
      "How do I grant read-only on subnets to a group?",
      "What did admin do today?",
      "What did Bob change last week?",
    ],
  },
];

function EmptyState({ onPick }: { onPick: (text: string) => void }) {
  // Dropdown-driven prompt picker. The previous flat list of all
  // groups + examples scrolled forever in the resizable bubble; now
  // operators pick a category and see just that category's prompts.
  // Default starts on the first group ("Triage") so the panel isn't
  // empty on first render.
  const [groupLabel, setGroupLabel] = useState<string>(
    STARTER_GROUPS[0]?.label ?? "",
  );
  const group = STARTER_GROUPS.find((g) => g.label === groupLabel);
  return (
    <div className="mx-auto max-w-md py-6 text-sm">
      <div className="text-center">
        <Sparkles className="mx-auto mb-2 h-6 w-6 text-primary" />
        <p className="font-medium">
          Ask the copilot anything about your infrastructure.
        </p>
        <p className="mt-1 text-xs text-muted-foreground">
          Pick a category to see example prompts, or type your own. Some
          examples need their underlying tool turned on in Administration → AI
          Tool Catalog.
        </p>
      </div>
      <div className="mt-4 space-y-2">
        <div className="flex items-center gap-2">
          <label className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Examples
          </label>
          <select
            value={groupLabel}
            onChange={(e) => setGroupLabel(e.target.value)}
            className="rounded-md border bg-background px-2 py-1 text-xs focus:outline-none focus:ring-2 focus:ring-ring"
          >
            {STARTER_GROUPS.map((g) => (
              <option key={g.label} value={g.label}>
                {g.label}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          {(group?.examples ?? []).map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => onPick(q)}
              className="block w-full rounded-md border bg-muted/30 px-3 py-1.5 text-left text-xs text-muted-foreground transition-colors hover:border-primary/40 hover:bg-primary/5 hover:text-foreground"
            >
              {q}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function MessageBubble({
  message,
  onAnswerYesNo,
}: {
  message: AIChatMessage;
  /** Called when the operator clicks a button in a YesNoCard. The
   *  parent (CopilotDrawer) submits ``answer`` as a fresh user
   *  message via the existing send mutation. */
  onAnswerYesNo?: (answer: string) => void;
}) {
  if (message.role === "tool") {
    // Detect proposal-shape tool results — render the Approve / Reject
    // card instead of the raw JSON tool envelope. Pattern matches the
    // contract from ``app/services/ai/tools/proposals.py``.
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(message.content);
    } catch {
      // Not JSON — fall through to plain ToolCard.
    }
    if (
      parsed != null &&
      typeof parsed === "object" &&
      (parsed as { kind?: string }).kind === "proposal" &&
      typeof (parsed as { proposal_id?: string }).proposal_id === "string"
    ) {
      return (
        <ProposalCard
          proposalId={(parsed as { proposal_id: string }).proposal_id}
          operation={(parsed as { operation?: string }).operation ?? ""}
          previewText={(parsed as { preview?: string }).preview ?? ""}
        />
      );
    }
    // ask_yes_no — render the Yes/No buttons (issue #120). Pattern
    // matches the contract from
    // ``app/services/ai/tools/copilot.py``. The card also detects
    // whether the operator already answered (via a follow-up user
    // message in the surrounding history) so a chat replay shows
    // the answered state.
    if (
      parsed != null &&
      typeof parsed === "object" &&
      (parsed as { kind?: string }).kind === "yes_no_question"
    ) {
      const p = parsed as {
        question?: string;
        context?: string | null;
        yes_label?: string;
        no_label?: string;
      };
      return (
        <YesNoCard
          question={p.question ?? ""}
          context={p.context ?? null}
          yesLabel={p.yes_label || "Yes"}
          noLabel={p.no_label || "No"}
          onAnswer={onAnswerYesNo}
        />
      );
    }
    return <ToolCard message={message} />;
  }
  const isUser = message.role === "user";
  return (
    <div
      className={`mb-3 flex flex-col ${isUser ? "items-end" : "items-start"}`}
    >
      <div
        className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
          isUser
            ? "bg-primary text-primary-foreground"
            : "bg-muted text-foreground"
        }`}
      >
        {message.content &&
          (isUser ? (
            // User messages are plain text — they typed it, not Markdown.
            <pre className="whitespace-pre-wrap break-words font-sans">
              {message.content}
            </pre>
          ) : (
            <MarkdownContent>{message.content}</MarkdownContent>
          ))}
        {message.tool_calls && message.tool_calls.length > 0 && (
          <div className="mt-2 space-y-1">
            {message.tool_calls.map((tc) => (
              <div
                key={tc.id}
                className="flex items-center gap-1.5 rounded border border-foreground/10 bg-background/50 px-2 py-1 text-xs"
              >
                <Wrench className="h-3 w-3" />
                <code className="font-mono">{tc.name}</code>
                <span className="truncate text-muted-foreground">
                  {tc.arguments && tc.arguments !== "{}" ? tc.arguments : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
      {!isUser && message.content && <MessageFooter message={message} />}
    </div>
  );
}

/** Sub-bubble metadata row rendered below assistant messages.
 *
 *  Mirrors the OpenWebUI footer pattern: token count, copy button,
 *  info popover with timing + cost. Hidden during streaming because
 *  ``StreamingBubble`` is the in-flight surface — the footer attaches
 *  to the *committed* row that lands when the turn finishes.
 */
function MessageFooter({ message }: { message: AIChatMessage }) {
  const [copied, setCopied] = useState(false);
  const [showInfo, setShowInfo] = useState(false);
  const tokensIn = message.tokens_in;
  const tokensOut = message.tokens_out;
  const totalTokens =
    tokensIn !== null && tokensOut !== null ? tokensIn + tokensOut : null;

  async function onCopy() {
    const ok = await copyToClipboard(message.content);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }
  }

  return (
    <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
      {totalTokens !== null && (
        <span className="tabular-nums">
          {totalTokens.toLocaleString()} tokens
          {tokensIn !== null && tokensOut !== null && (
            <span className="opacity-70">
              {" "}
              ({tokensIn.toLocaleString()} in / {tokensOut.toLocaleString()}{" "}
              out)
            </span>
          )}
        </span>
      )}
      <button
        type="button"
        onClick={onCopy}
        title="Copy message"
        className="inline-flex items-center gap-1 rounded px-1 py-0.5 hover:bg-accent"
      >
        {copied ? (
          <Check className="h-3 w-3 text-emerald-600" />
        ) : (
          <Copy className="h-3 w-3" />
        )}
      </button>
      <div className="relative">
        <button
          type="button"
          onClick={() => setShowInfo((v) => !v)}
          title="Message details"
          className={`inline-flex items-center rounded px-1 py-0.5 hover:bg-accent ${
            showInfo ? "bg-accent text-foreground" : ""
          }`}
        >
          <Info className="h-3 w-3" />
        </button>
        {showInfo && (
          <div className="absolute z-10 mt-1 w-56 rounded-md border bg-popover p-2 text-[11px] shadow-md">
            <div className="mb-1 font-medium text-foreground">
              Message details
            </div>
            <dl className="space-y-0.5">
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Sent</dt>
                <dd className="tabular-nums">
                  {new Date(message.created_at).toLocaleString()}
                </dd>
              </div>
              {tokensIn !== null && (
                <div className="flex justify-between gap-2">
                  <dt className="text-muted-foreground">Tokens in</dt>
                  <dd className="tabular-nums">{tokensIn.toLocaleString()}</dd>
                </div>
              )}
              {tokensOut !== null && (
                <div className="flex justify-between gap-2">
                  <dt className="text-muted-foreground">Tokens out</dt>
                  <dd className="tabular-nums">{tokensOut.toLocaleString()}</dd>
                </div>
              )}
              {message.latency_ms !== null && (
                <div className="flex justify-between gap-2">
                  <dt className="text-muted-foreground">Latency</dt>
                  <dd className="tabular-nums">
                    {(message.latency_ms / 1000).toFixed(2)}s
                  </dd>
                </div>
              )}
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Role</dt>
                <dd>{message.role}</dd>
              </div>
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}

/** Yes / No card rendered in place of a raw tool result for
 *  ``ask_yes_no`` payloads (issue #120). Buttons feed the answer
 *  back as a fresh user message via the parent's send mutation. On
 *  chat replay the buttons are disabled — the answer's already in
 *  history a couple of messages later — but the question + context
 *  still render for context. */
function YesNoCard({
  question,
  context,
  yesLabel,
  noLabel,
  onAnswer,
}: {
  question: string;
  context: string | null;
  yesLabel: string;
  noLabel: string;
  /** When undefined, the card renders as "answered" (buttons
   *  disabled) — the parent decides this based on whether the
   *  question still sits at the tail of the message list. */
  onAnswer?: (answer: string) => void;
}) {
  const live = !!onAnswer;
  return (
    <div className="mb-3 flex justify-start">
      <div className="max-w-[85%] rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-primary" />
          <span className="font-medium">Question</span>
          <span
            className={`ml-auto rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
              live
                ? "border-primary/30 bg-primary/10 text-primary"
                : "border-zinc-500/30 bg-zinc-500/10 text-zinc-600"
            }`}
          >
            {live ? "pending" : "answered"}
          </span>
        </div>
        <div className="mt-2 whitespace-pre-wrap break-words font-sans text-foreground/90">
          {question}
        </div>
        {context && (
          <div className="mt-1.5 whitespace-pre-wrap break-words text-xs text-muted-foreground">
            {context}
          </div>
        )}
        <div className="mt-3 flex items-center gap-2">
          <button
            type="button"
            onClick={() => onAnswer?.(yesLabel)}
            disabled={!live}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {yesLabel}
          </button>
          <button
            type="button"
            onClick={() => onAnswer?.(noLabel)}
            disabled={!live}
            className="inline-flex items-center gap-1.5 rounded-md border px-3 py-1 text-xs font-medium hover:bg-accent disabled:opacity-50"
          >
            {noLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Approve / Reject card rendered in place of a raw tool result for
 *  proposal-shape payloads. Lazy-fetches the canonical proposal row
 *  on mount so it can show the latest terminal state when the chat
 *  history is replayed (e.g. the operator already approved or
 *  rejected earlier). The DB / API still call the fields
 *  ``applied_at`` and ``discarded_at`` — the rename is UI-only.
 */
function ProposalCard({
  proposalId,
  operation,
  previewText,
}: {
  proposalId: string;
  operation: string;
  previewText: string;
}) {
  const qc = useQueryClient();
  const proposalQ = useQuery({
    queryKey: ["ai-proposal", proposalId],
    queryFn: () => aiApi.getProposal(proposalId),
    // Refresh on every mount so a session replay shows the right
    // applied / discarded / expired state.
    staleTime: 0,
  });

  const applyMut = useMutation({
    mutationFn: () => aiApi.applyProposal(proposalId),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["ai-proposal", proposalId] });
    },
  });
  const discardMut = useMutation({
    mutationFn: () => aiApi.discardProposal(proposalId),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["ai-proposal", proposalId] });
    },
  });

  const proposal = proposalQ.data;
  const applied = !!proposal?.applied_at;
  const discarded = !!proposal?.discarded_at;
  const expired =
    !!proposal?.expires_at &&
    !applied &&
    !discarded &&
    new Date(proposal.expires_at).getTime() < Date.now();
  const pending = !applied && !discarded && !expired;

  let badge: { text: string; cls: string };
  if (applied) {
    badge = {
      text: "approved",
      cls: "bg-emerald-500/10 text-emerald-600 border-emerald-500/30",
    };
  } else if (discarded) {
    badge = {
      text: "rejected",
      cls: "bg-zinc-500/10 text-zinc-600 border-zinc-500/30",
    };
  } else if (expired) {
    badge = {
      text: "expired",
      cls: "bg-amber-500/10 text-amber-600 border-amber-500/30",
    };
  } else {
    badge = {
      text: "pending",
      cls: "bg-primary/10 text-primary border-primary/30",
    };
  }

  return (
    <div className="mb-3 flex justify-start">
      <div className="max-w-[85%] rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm">
        <div className="flex items-center gap-2">
          <Sparkles className="h-3.5 w-3.5 text-primary" />
          <span className="font-medium">Proposed: {operation}</span>
          <span
            className={`ml-auto rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${badge.cls}`}
          >
            {badge.text}
          </span>
        </div>
        <div className="mt-2 whitespace-pre-wrap break-words font-sans text-xs text-foreground/90">
          {proposal?.preview_text || previewText || "(no preview)"}
        </div>
        {applied && proposal?.result && (
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer text-muted-foreground">
              Result
            </summary>
            <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px]">
              {JSON.stringify(proposal.result, null, 2)}
            </pre>
          </details>
        )}
        {applied &&
          operation === "run_nmap_scan" &&
          typeof (proposal?.result as { id?: string } | null)?.id ===
            "string" && (
            <NmapScanLiveResult
              scanId={(proposal!.result as { id: string }).id}
            />
          )}
        {proposal?.error && (
          <div className="mt-2 rounded border border-destructive/30 bg-destructive/5 p-2 text-xs text-destructive">
            {proposal.error}
          </div>
        )}
        {pending && (
          <div className="mt-3 flex items-center gap-2">
            <button
              type="button"
              onClick={() => applyMut.mutate()}
              disabled={applyMut.isPending || discardMut.isPending}
              className="inline-flex items-center gap-1.5 rounded-md bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-700 disabled:opacity-50 dark:bg-emerald-600 dark:hover:bg-emerald-500"
            >
              {applyMut.isPending ? "Approving…" : "Approve"}
            </button>
            <button
              type="button"
              onClick={() => discardMut.mutate()}
              disabled={applyMut.isPending || discardMut.isPending}
              className="inline-flex items-center gap-1.5 rounded-md bg-destructive px-3 py-1 text-xs font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
            >
              {discardMut.isPending ? "Rejecting…" : "Reject"}
            </button>
            {proposal?.expires_at && (
              <span className="ml-auto text-[10px] text-muted-foreground">
                expires {new Date(proposal.expires_at).toLocaleTimeString()}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ToolCard({ message }: { message: AIChatMessage }) {
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(message.content);
  } catch {
    parsed = message.content;
  }
  const isError =
    parsed != null &&
    typeof parsed === "object" &&
    "error" in (parsed as Record<string, unknown>);
  return (
    <div className="mb-3 flex justify-start">
      <details
        className={`max-w-[85%] rounded-lg border px-3 py-2 text-xs ${
          isError
            ? "border-destructive/30 bg-destructive/5 text-destructive"
            : "border-foreground/10 bg-muted/40 text-muted-foreground"
        }`}
      >
        <summary className="flex cursor-pointer items-center gap-1.5">
          <Wrench className="h-3 w-3" />
          <code className="font-mono">{message.name ?? "tool"}</code>
          <span className="ml-1 text-foreground/60">
            {isError ? "↯ failed" : "✓"}
          </span>
        </summary>
        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] leading-relaxed">
          {JSON.stringify(parsed, null, 2)}
        </pre>
      </details>
    </div>
  );
}

/** Live nmap-scan progress + results rendered inside the proposal card.
 *
 *  Polls ``GET /nmap/scans/{id}`` every 2 s until the scan reaches a
 *  terminal state. Shows status pill while running; on completion
 *  renders host_state, open ports table, OS guess.
 *
 *  Single-host scans render the top-level summary; CIDR scans render
 *  the per-host list when present.
 */
function NmapScanLiveResult({ scanId }: { scanId: string }) {
  const scanQ = useQuery({
    queryKey: ["nmap-scan", scanId],
    queryFn: () => nmapApi.getScan(scanId),
    // Poll until terminal state lands. ``refetchInterval`` returns
    // false once we're done so React Query stops the timer.
    refetchInterval: (q) => {
      const s = (q.state.data as NmapScanRead | undefined)?.status;
      if (s && ["completed", "failed", "cancelled"].includes(s)) return false;
      return 2000;
    },
    refetchIntervalInBackground: false,
  });

  const scan = scanQ.data;
  if (!scan) {
    return (
      <div className="mt-2 flex items-center gap-2 rounded border bg-background/40 px-2 py-1.5 text-[11px] text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" /> Loading scan…
      </div>
    );
  }

  const terminal = ["completed", "failed", "cancelled"].includes(scan.status);
  const statusCls =
    scan.status === "completed"
      ? "bg-emerald-500/10 text-emerald-600 border-emerald-500/30"
      : scan.status === "failed"
        ? "bg-destructive/10 text-destructive border-destructive/30"
        : scan.status === "cancelled"
          ? "bg-zinc-500/10 text-zinc-600 border-zinc-500/30"
          : "bg-amber-500/10 text-amber-600 border-amber-500/30";

  const ports = scan.summary?.ports ?? [];
  const openPorts = ports.filter((p) => p.state === "open");
  const hosts = scan.summary?.hosts ?? null;

  return (
    <div className="mt-2 rounded border bg-background/40 p-2 text-[11px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Scan</span>
        <span
          className={`rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${statusCls}`}
        >
          {scan.status}
        </span>
        {!terminal && <Loader2 className="h-3 w-3 animate-spin" />}
        {scan.duration_seconds !== null && terminal && (
          <span className="text-muted-foreground">
            {scan.duration_seconds.toFixed(1)}s
          </span>
        )}
      </div>

      {scan.status === "completed" && (
        <div className="mt-2 space-y-2">
          {scan.summary?.host_state && !hosts && (
            <div>
              <span className="text-muted-foreground">Host state: </span>
              <span className="font-mono">{scan.summary.host_state}</span>
            </div>
          )}
          {!hosts && openPorts.length > 0 && (
            <div>
              <div className="mb-1 text-muted-foreground">
                Open ports ({openPorts.length})
              </div>
              <table className="w-full font-mono text-[10px]">
                <thead className="text-muted-foreground">
                  <tr>
                    <th className="text-left">Port</th>
                    <th className="text-left">Service</th>
                    <th className="text-left">Version</th>
                  </tr>
                </thead>
                <tbody>
                  {openPorts.map((p) => (
                    <tr
                      key={`${p.proto}-${p.port}`}
                      className="border-t border-foreground/10"
                    >
                      <td className="py-0.5 pr-2">
                        {p.port}/{p.proto}
                      </td>
                      <td className="py-0.5 pr-2">{p.service ?? "—"}</td>
                      <td className="py-0.5 break-all">
                        {[p.product, p.version, p.extrainfo]
                          .filter(Boolean)
                          .join(" ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!hosts && openPorts.length === 0 && (
            <div className="text-muted-foreground">No open ports detected.</div>
          )}
          {scan.summary?.os?.name && (
            <div>
              <span className="text-muted-foreground">OS guess: </span>
              <span className="font-mono">{scan.summary.os.name}</span>
              {typeof scan.summary.os.accuracy === "number" && (
                <span className="text-muted-foreground">
                  {" "}
                  ({scan.summary.os.accuracy}%)
                </span>
              )}
            </div>
          )}
          {hosts && (
            <div>
              <div className="mb-1 text-muted-foreground">
                {hosts.length} host{hosts.length === 1 ? "" : "s"}
              </div>
              <table className="w-full font-mono text-[10px]">
                <thead className="text-muted-foreground">
                  <tr>
                    <th className="text-left">Address</th>
                    <th className="text-left">State</th>
                    <th className="text-left">Open ports</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.map((h) => (
                    <tr
                      key={h.address ?? Math.random()}
                      className="border-t border-foreground/10"
                    >
                      <td className="py-0.5 pr-2">{h.address ?? "—"}</td>
                      <td className="py-0.5 pr-2">{h.host_state}</td>
                      <td className="py-0.5">
                        {(h.ports ?? [])
                          .filter((p) => p.state === "open")
                          .map((p) => `${p.port}/${p.proto}`)
                          .join(", ") || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {scan.status === "failed" && scan.error_message && (
        <div className="mt-2 rounded border border-destructive/30 bg-destructive/5 p-1.5 text-destructive">
          {scan.error_message}
        </div>
      )}
    </div>
  );
}

function StreamErrorBlock({
  error,
  canRetry,
  onRetry,
  onDismiss,
}: {
  error: string;
  canRetry: boolean;
  onRetry: () => void;
  onDismiss: () => void;
}) {
  // Renders after the mutation settles when the SSE stream emitted
  // an error or the request threw. The user message stays in
  // ``pendingUserMessage`` so the operator can resend the same text
  // by clicking Retry — no retyping. Dismiss clears both the error
  // and the optimistic echo (operator gave up on the turn).
  return (
    <div className="mb-3 flex justify-start">
      <div className="max-w-[85%] rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
        <div className="mb-1 font-medium">Stream failed</div>
        <div className="mb-2 break-words text-xs opacity-90">{error}</div>
        <div className="flex gap-2">
          {canRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="rounded-md border border-destructive/40 bg-destructive/20 px-2 py-0.5 text-xs hover:bg-destructive/30"
            >
              Retry
            </button>
          )}
          <button
            type="button"
            onClick={onDismiss}
            className="rounded-md border border-destructive/40 px-2 py-0.5 text-xs hover:bg-destructive/10"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}

function StreamingBubble({
  content,
  tools,
  error,
  failover,
}: {
  content: string;
  tools: {
    id: string;
    name: string;
    arguments: string;
    preview?: string;
    is_error?: boolean;
  }[];
  error: string | null;
  failover: {
    from_provider: string;
    to_provider: string;
    to_model: string;
    reason: string;
  } | null;
}) {
  return (
    <div className="mb-3 flex justify-start">
      <div className="max-w-[85%] space-y-2">
        {failover && (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-300">
            <span className="font-medium">Failed over</span>{" "}
            <span className="opacity-80">
              from <code className="font-mono">{failover.from_provider}</code>{" "}
              to <code className="font-mono">{failover.to_provider}</code> ·
              model <code className="font-mono">{failover.to_model}</code> ·
              reason <code className="font-mono">{failover.reason}</code>
            </span>
          </div>
        )}
        {tools.map((t) => (
          <div
            key={t.id}
            className={`flex items-center gap-1.5 rounded border px-2 py-1 text-xs ${
              t.is_error
                ? "border-destructive/30 bg-destructive/5 text-destructive"
                : "border-foreground/10 bg-muted/40 text-muted-foreground"
            }`}
          >
            <Wrench className="h-3 w-3" />
            <code className="font-mono">{t.name}</code>
            {t.preview === undefined ? (
              <Loader2 className="ml-auto h-3 w-3 animate-spin" />
            ) : (
              <span className="ml-auto">{t.is_error ? "↯ failed" : "✓"}</span>
            )}
          </div>
        ))}
        {(content || (!content && tools.length === 0 && !error)) && (
          <div className="rounded-lg bg-muted px-3 py-2 text-sm">
            {content ? (
              <div className="relative">
                <MarkdownContent>{content}</MarkdownContent>
                <span className="ml-1 inline-block h-3 w-1 animate-pulse bg-foreground/50 align-middle" />
              </div>
            ) : (
              <Loader2 className="h-4 w-4 animate-spin" />
            )}
          </div>
        )}
        {error && (
          <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}
      </div>
    </div>
  );
}

function SessionRow({
  session,
  active,
  selected,
  onToggleSelect,
  onPick,
  onRename,
  onArchive,
  onDelete,
}: {
  session: AIChatSessionSummary;
  active: boolean;
  selected: boolean;
  onToggleSelect: () => void;
  onPick: () => void;
  onRename: (name: string) => void;
  onArchive: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      className={`group flex items-center gap-2 px-4 py-2 text-sm hover:bg-accent ${
        active ? "bg-accent" : ""
      }`}
    >
      <input
        type="checkbox"
        checked={selected}
        onChange={onToggleSelect}
        onClick={(e) => e.stopPropagation()}
        title="Select for bulk action"
        className="h-3.5 w-3.5 shrink-0 cursor-pointer accent-primary"
      />
      <button
        type="button"
        onClick={onPick}
        className="min-w-0 flex-1 text-left"
      >
        <div className="truncate font-medium">{session.name}</div>
        <div className="text-xs text-muted-foreground">
          {session.message_count} msg
          {" · "}
          <span className="font-mono">{session.model}</span>
        </div>
      </button>
      <button
        type="button"
        onClick={() => {
          const next = prompt("Rename session", session.name);
          if (next && next.trim()) onRename(next.trim());
        }}
        title="Rename"
        className="opacity-0 group-hover:opacity-100"
      >
        <Pencil className="h-3 w-3 text-muted-foreground hover:text-foreground" />
      </button>
      <button
        type="button"
        onClick={onArchive}
        title="Archive"
        className="opacity-0 group-hover:opacity-100"
      >
        <Archive className="h-3 w-3 text-muted-foreground hover:text-foreground" />
      </button>
      <button
        type="button"
        onClick={() => {
          if (confirm(`Delete chat "${session.name}"?`)) onDelete();
        }}
        title="Delete"
        className="opacity-0 group-hover:opacity-100"
      >
        <Trash2 className="h-3 w-3 text-muted-foreground hover:text-destructive" />
      </button>
    </div>
  );
}

function ChatComposer({
  disabled,
  onSend,
  onCancel,
  isStreaming,
  pendingPrompt,
  onPromptConsumed,
  userMessages,
}: {
  disabled: boolean;
  onSend: (text: string) => void;
  onCancel: () => void;
  isStreaming: boolean;
  pendingPrompt?: string | null;
  onPromptConsumed?: () => void;
  /** Every user message in the active session, oldest → newest.
   *  Powers the ↑/↓ history walk in the textarea (Claude Code /
   *  shell-style): ↑ from an empty textarea recalls the newest, each
   *  subsequent ↑ steps further back, ↓ steps forward, and ↓ past the
   *  newest returns to draft mode. */
  userMessages: string[];
}) {
  // Persist the half-typed message across drawer close/reopen so the
  // operator can step away mid-thought. Cleared on submit.
  const [text, setText] = useSessionState<string>("spatium.copilot.draft", "");
  const [showPrompts, setShowPrompts] = useState(false);
  // History walk state. ``null`` means "drafting fresh"; a number
  // means "currently showing the message at userMessages[idx]". The
  // moment the operator edits the recalled value, we drop back to
  // null so the next ↑ doesn't trample their edits.
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);
  const taRef = useRef<HTMLTextAreaElement | null>(null);

  // Whenever the underlying message list shifts (session switched,
  // chat deleted, new turn landed) drop any in-flight history walk so
  // we never index off the end of a stale array.
  useEffect(() => {
    setHistoryIndex(null);
  }, [userMessages]);

  function recallAt(idx: number) {
    const value = userMessages[idx];
    setHistoryIndex(idx);
    setText(value);
    // Caret to the end so the textarea reads top-down with the
    // cursor at the natural typing position.
    setTimeout(() => {
      const ta = taRef.current;
      if (ta) ta.setSelectionRange(value.length, value.length);
    }, 0);
  }

  // Pull the prompt library lazily — only fires when the operator
  // clicks the "Prompts ▾" button to open the picker.
  const promptsQ = useQuery({
    queryKey: ["ai-prompts"],
    queryFn: aiApi.listPrompts,
    enabled: showPrompts,
    staleTime: 60_000,
  });

  // Drain ``pendingPrompt`` into the textarea once. Notify the parent
  // via ``onPromptConsumed`` so it clears its state and we don't
  // overwrite operator edits on the next re-render.
  useEffect(() => {
    if (pendingPrompt) {
      setText(pendingPrompt);
      setHistoryIndex(null);
      onPromptConsumed?.();
      setTimeout(() => taRef.current?.focus(), 0);
    }
  }, [pendingPrompt, onPromptConsumed]);

  function submit() {
    const trimmed = text.trim();
    if (!trimmed || disabled) return;
    onSend(trimmed);
    setText("");
    setHistoryIndex(null);
    taRef.current?.focus();
  }

  function loadPrompt(p: AIPrompt) {
    setText(p.prompt_text);
    setHistoryIndex(null);
    setShowPrompts(false);
    // Defer focus until after the popover unmounts so React's
    // synchronous reconciliation doesn't steal it back.
    setTimeout(() => taRef.current?.focus(), 0);
  }

  return (
    <form
      className="relative flex flex-col gap-1.5 border-t p-3"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <div className="flex gap-2">
        <textarea
          ref={taRef}
          value={text}
          onChange={(e) => {
            const next = e.target.value;
            setText(next);
            // If the operator typed over a recalled message, exit
            // history mode so further ↑ doesn't blow away their edits.
            if (historyIndex !== null && next !== userMessages[historyIndex]) {
              setHistoryIndex(null);
            }
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              submit();
              return;
            }
            // ↑/↓ history walk. Modeled on shell readline + Claude
            // Code: ↑ from empty enters at newest, subsequent ↑ steps
            // older, ↓ steps newer, ↓ past newest returns to draft.
            // Once you start editing a recalled value, history mode
            // exits (handled in onChange) and ↑/↓ become no-ops.
            if (e.key === "ArrowUp") {
              if (userMessages.length === 0) return;
              if (historyIndex === null) {
                // Don't engage on a non-empty textarea — that would
                // overwrite the operator's draft and they'd have no
                // way to recover it.
                if (text) return;
                e.preventDefault();
                recallAt(userMessages.length - 1);
                return;
              }
              if (historyIndex > 0) {
                e.preventDefault();
                recallAt(historyIndex - 1);
              } else {
                // Already on the oldest — swallow ↑ so the caret
                // doesn't jump to the start of the textarea, which
                // would feel like the keystroke "didn't take".
                e.preventDefault();
              }
              return;
            }
            if (e.key === "ArrowDown") {
              if (historyIndex === null) return;
              e.preventDefault();
              if (historyIndex < userMessages.length - 1) {
                recallAt(historyIndex + 1);
              } else {
                // Past newest — return to draft mode.
                setHistoryIndex(null);
                setText("");
              }
              return;
            }
          }}
          rows={2}
          placeholder="Ask about IPAM / DNS / DHCP / alerts / audit log…"
          className="flex-1 resize-none rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        />
        {isStreaming ? (
          <button
            type="button"
            onClick={onCancel}
            className="self-end rounded-md border px-3 py-1.5 text-sm text-muted-foreground hover:bg-accent"
          >
            Stop
          </button>
        ) : (
          <button
            type="submit"
            disabled={!text.trim() || disabled}
            className="self-end rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            <Send className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => setShowPrompts((v) => !v)}
          className="inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs text-muted-foreground hover:bg-accent"
          title="Load a saved prompt"
        >
          <BookOpen className="h-3 w-3" />
          Prompts ▾
        </button>
        <span className="text-[11px] text-muted-foreground/60">
          Enter to send · Shift+Enter for newline · ↑/↓ to walk history
        </span>
      </div>
      {showPrompts && (
        <PromptsPopover
          prompts={promptsQ.data ?? []}
          isLoading={promptsQ.isLoading}
          onClose={() => setShowPrompts(false)}
          onPick={loadPrompt}
        />
      )}
    </form>
  );
}

/** Inline popover anchored above the prompts button. Closes on click
 *  outside or Escape. Two sections — shared prompts (curated) and the
 *  user's own private prompts.
 */
function PromptsPopover({
  prompts,
  isLoading,
  onClose,
  onPick,
}: {
  prompts: AIPrompt[];
  isLoading: boolean;
  onClose: () => void;
  onPick: (p: AIPrompt) => void;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
    }
    function onEsc(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onEsc);
    };
  }, [onClose]);

  const shared = prompts.filter((p) => p.is_shared);
  const mine = prompts.filter((p) => !p.is_shared);

  return (
    <div
      ref={ref}
      className="absolute bottom-[calc(100%-0.25rem)] left-3 z-50 max-h-72 w-80 overflow-auto rounded-md border bg-popover p-1 shadow-lg"
    >
      {isLoading ? (
        <div className="px-3 py-4 text-center text-xs text-muted-foreground">
          Loading…
        </div>
      ) : prompts.length === 0 ? (
        <div className="px-3 py-4 text-center text-xs text-muted-foreground">
          No saved prompts. Curate them at{" "}
          <a className="underline" href="/admin/ai/prompts">
            Admin → AI Prompts
          </a>
          .
        </div>
      ) : (
        <>
          {shared.length > 0 && (
            <div>
              <div className="px-2 py-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Shared
              </div>
              {shared.map((p) => (
                <PromptRow key={p.id} prompt={p} onPick={onPick} />
              ))}
            </div>
          )}
          {mine.length > 0 && (
            <div>
              <div className="px-2 py-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                Your prompts
              </div>
              {mine.map((p) => (
                <PromptRow key={p.id} prompt={p} onPick={onPick} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PromptRow({
  prompt,
  onPick,
}: {
  prompt: AIPrompt;
  onPick: (p: AIPrompt) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onPick(prompt)}
      className="block w-full rounded px-2 py-1.5 text-left text-xs hover:bg-accent"
    >
      <div className="font-medium">{prompt.name}</div>
      {prompt.description && (
        <div className="mt-0.5 text-[11px] text-muted-foreground line-clamp-2">
          {prompt.description}
        </div>
      )}
    </button>
  );
}

/**
 * Today-so-far usage indicator (Wave 4). Shows three chips when caps
 * are configured: messages today, tokens today, cost today. When a
 * cap is set, the relevant chip becomes a progress bar that fills as
 * the operator approaches the cap; over-cap chips render in
 * destructive tint.
 */
function UsageChip({ usage }: { usage: import("@/lib/api").AIUsageSnapshot }) {
  const tokens = usage.tokens_in + usage.tokens_out;
  const costNum = parseFloat(usage.cost_usd);
  const capCostNum = usage.cap_cost_usd ? parseFloat(usage.cap_cost_usd) : null;

  // Token cap progress
  const tokenPct =
    usage.cap_token != null && usage.cap_token > 0
      ? Math.min(100, (tokens / usage.cap_token) * 100)
      : null;
  // Cost cap progress
  const costPct =
    capCostNum != null && capCostNum > 0
      ? Math.min(100, (costNum / capCostNum) * 100)
      : null;

  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[10px] text-muted-foreground">
      <span>
        {usage.messages} msg
        {usage.messages === 1 ? "" : "s"} today
      </span>
      <span aria-hidden>·</span>
      {tokenPct !== null ? (
        <ProgressChip
          label={`${tokens.toLocaleString()} / ${usage.cap_token!.toLocaleString()} tokens`}
          pct={tokenPct}
        />
      ) : (
        <span>{tokens.toLocaleString()} tokens</span>
      )}
      {(costNum > 0 || capCostNum != null) && (
        <>
          <span aria-hidden>·</span>
          {costPct !== null ? (
            <ProgressChip
              label={`$${costNum.toFixed(2)} / $${capCostNum!.toFixed(2)}`}
              pct={costPct}
            />
          ) : (
            <span>${costNum.toFixed(2)}</span>
          )}
        </>
      )}
    </div>
  );
}

function ProgressChip({ label, pct }: { label: string; pct: number }) {
  const over = pct >= 100;
  return (
    <span
      className={`relative inline-flex items-center overflow-hidden rounded border px-1.5 py-0.5 ${
        over
          ? "border-destructive/40 bg-destructive/5 text-destructive"
          : "border-foreground/15"
      }`}
    >
      <span
        aria-hidden
        className={`absolute inset-y-0 left-0 ${
          over ? "bg-destructive/20" : "bg-primary/15"
        }`}
        style={{ width: `${pct}%` }}
      />
      <span className="relative">{label}</span>
    </span>
  );
}
