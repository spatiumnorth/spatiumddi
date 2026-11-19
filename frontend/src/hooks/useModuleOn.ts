import { useFeatureModules } from "@/hooks/useFeatureModules";

/**
 * ``ready && enabled(id)`` — the one-liner every data query and every piece
 * of module-specific UI should gate on (#2130). ``enabled`` alone answers
 * true while the module set is still loading, which is how a hard reload
 * fires a gated query once and 404s.
 *
 * Lives beside ``useFeatureModules`` rather than in it so a test that mocks
 * that module wholesale keeps working: this reads whatever it returns.
 */
export function useModuleOn(id: string): boolean {
  const { enabled, ready } = useFeatureModules();
  return ready && enabled(id);
}
