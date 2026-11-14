import { useFeatureModules } from "@/hooks/useFeatureModules";

/**
 * Which ownership fields a form may show (#4101). Customer, Site and
 * Provider are feature modules (`network.customer` / `network.site` /
 * `network.provider`); with one off its router is unmounted and every list
 * call 404s, so a picker for it is a dead dropdown under a live label.
 * Forms wrap the whole `<Field>` in the flag, not just the picker, so the
 * label and hint go too. `ready` keeps the field from flashing in on a hard
 * page load before the module set is known.
 *
 * Hiding a field never clears it: every edit form seeds its state from the
 * stored row and sends that value back unchanged, so a stored customer_id /
 * site_id survives a save made while the module is off.
 */
export function useOwnershipModules(): {
  customer: boolean;
  site: boolean;
  provider: boolean;
} {
  const { enabled, ready } = useFeatureModules();
  return {
    customer: ready && enabled("network.customer"),
    site: ready && enabled("network.site"),
    provider: ready && enabled("network.provider"),
  };
}
