// Request bodies for edit forms whose fields come and go with the mode.
//
// Update endpoints read an explicit JSON `null` as "clear this field" (#1596),
// so a field the form HIDES for the current mode must be omitted from an edit,
// not sent as `null` — otherwise saving a description change on a Manual
// blocking list wipes the feed URL it still holds. A field the operator can see
// and deliberately empties still goes out as `null`; that is the point of
// #1596. On create there is no stored value to protect, so the hidden fields
// keep going out as `null` exactly as before.

import type { CustomField, DNSBlockList, DNSPoolWrite } from "@/lib/api";

/** Blocking list: `feed_url` is shown for URL lists, `sinkhole_ip` for sinkhole mode. */
export function blocklistPayload(
  f: {
    name: string;
    description: string;
    category: string;
    sourceType: string;
    feedUrl: string;
    feedFormat: string;
    blockMode: string;
    sinkholeIp: string;
    updateHours: number;
    feedWildcard: boolean;
    enabled: boolean;
  },
  editing: boolean,
): Partial<DNSBlockList> {
  const body: Partial<DNSBlockList> = {
    name: f.name,
    description: f.description,
    category: f.category,
    source_type: f.sourceType,
    feed_format: f.feedFormat,
    block_mode: f.blockMode,
    update_interval_hours: f.updateHours,
    feed_entries_are_wildcard: f.feedWildcard,
    enabled: f.enabled,
  };
  if (f.sourceType === "url") body.feed_url = f.feedUrl || null;
  else if (!editing) body.feed_url = null;
  if (f.blockMode === "sinkhole") body.sinkhole_ip = f.sinkholeIp || null;
  else if (!editing) body.sinkhole_ip = null;
  return body;
}

/** DNS pool health check: the target port is hidden for `none` and `icmp`,
 *  TLS verification is shown only for `https`. */
export function poolHealthCheckFields(
  f: { hcType: DNSPoolWrite["hc_type"]; hcPort: number; hcVerifyTls: boolean },
  editing: boolean,
): Pick<DNSPoolWrite, "hc_target_port" | "hc_verify_tls"> {
  const out: Pick<DNSPoolWrite, "hc_target_port" | "hc_verify_tls"> = {};
  if (f.hcType !== "none" && f.hcType !== "icmp")
    out.hc_target_port = f.hcPort || null;
  else if (!editing) out.hc_target_port = null;
  if (f.hcType === "https") out.hc_verify_tls = f.hcVerifyTls;
  else if (!editing) out.hc_verify_tls = false;
  return out;
}

/** DHCP static assignment: the DUID field exists only on a v6 scope. */
export function staticDuidField(
  f: { isV6: boolean; duid: string },
  editing: boolean,
): { duid?: string | null } {
  if (f.isV6) return { duid: f.duid || null };
  return editing ? {} : { duid: null };
}

/** DNS server: the API port is hidden for cloud drivers (agentless, nothing
 *  to reach) and for `technitium_api` (addressed through its credential
 *  block's api_url). */
export function serverApiPortField(
  f: { driver: string; cloud: boolean; apiPort: string },
  editing: boolean,
): { api_port?: number | null } {
  if (f.cloud) return editing ? {} : { api_port: null };
  if (f.driver === "technitium_api" && editing) return {};
  return { api_port: f.apiPort ? parseInt(f.apiPort, 10) : null };
}

/** Custom field definition form state. */
export interface CustomFieldForm {
  resource_type: string;
  name: string;
  label: string;
  field_type: string;
  options: string;
  is_required: boolean;
  is_searchable: boolean;
  default_value: string;
  display_order: number;
  description: string;
}

/** Custom field, create: every column, `options` null unless `select`. */
export function customFieldCreatePayload(
  form: CustomFieldForm,
): Omit<CustomField, "id"> {
  return {
    resource_type: form.resource_type,
    name: form.name,
    label: form.label,
    field_type: form.field_type,
    options: form.field_type === "select" ? splitOptions(form.options) : null,
    is_required: form.is_required,
    is_searchable: form.is_searchable,
    default_value: form.default_value || null,
    display_order: form.display_order,
    description: form.description,
  };
}

/** Custom field, edit: resource type, name and type are fixed once created,
 *  and the options list is shown only for `select` fields. */
export function customFieldUpdatePayload(
  form: CustomFieldForm,
): Partial<Omit<CustomField, "id" | "resource_type" | "name" | "field_type">> {
  return {
    label: form.label,
    ...(form.field_type === "select"
      ? { options: splitOptions(form.options) }
      : {}),
    is_required: form.is_required,
    is_searchable: form.is_searchable,
    default_value: form.default_value || null,
    display_order: form.display_order,
    description: form.description,
  };
}

function splitOptions(raw: string): string[] {
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
