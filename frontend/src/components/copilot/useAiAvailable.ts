import { useQuery } from "@tanstack/react-query";
import { aiApi } from "@/lib/api";
import { useFeatureModules } from "@/hooks/useFeatureModules";

/**
 * Returns ``true`` when a new chat would find an enabled AI provider, so
 * the "Ask AI" affordances have something behind them. ``false`` while we
 * don't yet know, when the probe failed, and when the Operator Copilot
 * module is off: an Ask AI that opens a chat drawer with nothing to talk
 * to is worse than one that appears a moment later.
 *
 * Asks ``GET /ai/available``, which every signed-in user may read (#1345).
 * It used to read the provider list, which is superadmin-only, so every
 * page a non-superadmin opened raised a 403, and the refusal (no count)
 * read as available.
 *
 * Shared by every "Ask AI" consumer (``CopilotButton``, ``AskAIButton``,
 * the Cmd-K palette), one query key so React Query dedupes the fetch. The
 * key sits under ``["ai-providers"]`` so a provider edit on the AI
 * Providers page, which invalidates that prefix, refreshes the answer.
 */
export function useAiAvailable(): boolean {
  const { enabled, ready } = useFeatureModules();
  // Gate on ``ready`` so the query waits for the real module state — without
  // it, ``enabled`` returns true while the module set is still loading and
  // the gated /ai routes 404 once on every hard page load.
  const moduleOn = ready && enabled("ai.copilot");
  const availableQ = useQuery({
    queryKey: ["ai-providers", "available"],
    queryFn: aiApi.available,
    staleTime: 5 * 60 * 1000,
    retry: false,
    enabled: moduleOn,
  });
  // When the Operator Copilot module is off, the gated /ai routes 404 —
  // never fire the probe and never advertise AI as available.
  if (!moduleOn) return false;
  return availableQ.data === true;
}
