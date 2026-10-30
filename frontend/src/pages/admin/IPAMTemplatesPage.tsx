import { ListEmpty } from "@/components/ui/list-read-error";
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LayoutTemplate, Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import {
  ipamApi,
  dnsApi,
  dhcpApi,
  type IPAMTemplate,
  type IPAMTemplateAppliesTo,
  type IPAMTemplateCreate,
  type IPAMTemplateUpdate,
  formatApiError,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { parseTtlInput } from "@/lib/dnsNames";
import { permissionGate, usePermissions } from "@/hooks/usePermissions";
import { useModuleOn } from "@/hooks/useModuleOn";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

const APPLIES_TO_LABEL: Record<IPAMTemplateAppliesTo, string> = {
  block: "IP Block",
  subnet: "Subnet",
};

interface ChildEntryForm {
  prefix: string;
  name_template: string;
  description: string;
}

interface TemplateForm {
  name: string;
  description: string;
  applies_to: IPAMTemplateAppliesTo;
  tagsJson: string;
  cfsJson: string;
  dns_group_id: string;
  dns_zone_id: string;
  dhcp_group_id: string;
  ddns_enabled: boolean;
  ddns_hostname_policy: string;
  ddns_domain_override: string;
  ddns_ttl: string;
  childLayoutEnabled: boolean;
  children: ChildEntryForm[];
}

// eslint-disable-next-line react-refresh/only-export-components -- exported for its test
export const EMPTY: TemplateForm = {
  name: "",
  description: "",
  applies_to: "subnet",
  tagsJson: "{}",
  cfsJson: "{}",
  dns_group_id: "",
  dns_zone_id: "",
  dhcp_group_id: "",
  ddns_enabled: false,
  ddns_hostname_policy: "client_or_generated",
  ddns_domain_override: "",
  ddns_ttl: "",
  childLayoutEnabled: false,
  children: [],
};

function formFromTemplate(t: IPAMTemplate): TemplateForm {
  return {
    name: t.name,
    description: t.description ?? "",
    applies_to: t.applies_to,
    tagsJson: JSON.stringify(t.tags ?? {}, null, 2),
    cfsJson: JSON.stringify(t.custom_fields ?? {}, null, 2),
    dns_group_id: t.dns_group_id ?? "",
    dns_zone_id: t.dns_zone_id ?? "",
    dhcp_group_id: t.dhcp_group_id ?? "",
    ddns_enabled: t.ddns_enabled,
    ddns_hostname_policy: t.ddns_hostname_policy,
    ddns_domain_override: t.ddns_domain_override ?? "",
    ddns_ttl: t.ddns_ttl == null ? "" : String(t.ddns_ttl),
    childLayoutEnabled: t.child_layout != null,
    children: (t.child_layout?.children ?? []).map((c) => ({
      prefix: String(c.prefix),
      name_template: c.name_template ?? "",
      description: c.description ?? "",
    })),
  };
}

// eslint-disable-next-line react-refresh/only-export-components -- exported for its test
export function toCreatePayload(form: TemplateForm): IPAMTemplateCreate {
  let tags: Record<string, unknown> = {};
  let cfs: Record<string, unknown> = {};
  try {
    tags = JSON.parse(form.tagsJson || "{}");
  } catch {
    throw new Error("Tags must be valid JSON.");
  }
  try {
    cfs = JSON.parse(form.cfsJson || "{}");
  } catch {
    throw new Error("Custom fields must be valid JSON.");
  }
  let child_layout: IPAMTemplateCreate["child_layout"] = null;
  if (form.applies_to === "block" && form.childLayoutEnabled) {
    if (form.children.length === 0) {
      throw new Error("Add at least one child or disable child layout.");
    }
    child_layout = {
      children: form.children.map((c, idx) => {
        const prefix = parseInt(c.prefix, 10);
        if (!Number.isInteger(prefix) || prefix <= 0 || prefix > 128) {
          throw new Error(`Child[${idx}] prefix must be 1–128.`);
        }
        return {
          prefix,
          name_template: c.name_template,
          description: c.description || undefined,
        };
      }),
    };
  }
  // #2086 — "1h" is refused, never saved as 1; blank means no override.
  const ttl = parseTtlInput(form.ddns_ttl);
  if (typeof ttl === "string") {
    throw new Error(`TTL override ${ttl}. Leave blank for the zone default.`);
  }
  return {
    name: form.name.trim(),
    description: form.description,
    applies_to: form.applies_to,
    tags,
    custom_fields: cfs,
    dns_group_id: form.dns_group_id || null,
    dns_zone_id: form.dns_zone_id || null,
    dhcp_group_id: form.dhcp_group_id || null,
    ddns_enabled: form.ddns_enabled,
    ddns_hostname_policy:
      form.ddns_hostname_policy as IPAMTemplateCreate["ddns_hostname_policy"],
    ddns_domain_override: form.ddns_domain_override || null,
    ddns_ttl: ttl,
    child_layout,
  };
}

type TabKey = "general" | "stamp" | "ddns" | "children";

function TemplateEditor({
  initial,
  mode,
  onClose,
  onSave,
  saving,
  error,
}: {
  initial: TemplateForm;
  mode: "create" | "edit";
  onClose: () => void;
  onSave: (form: TemplateForm) => void;
  saving: boolean;
  error?: string;
}) {
  const [form, setForm] = useState<TemplateForm>(initial);
  const [tab, setTab] = useState<TabKey>("general");

  // #2135 — no DNS server groups to pick, no DNS zone or DDNS settings to
  // edit, while core.dns is off. The stored values stay in the form state
  // and are sent back unchanged on save.
  const dnsOn = useModuleOn("core.dns");
  const dnsGroupsQ = useQuery({
    queryKey: ["dns-groups"],
    queryFn: dnsApi.listGroups,
    enabled: dnsOn,
  });
  // #2130 — no DHCP server groups to pick while core.dhcp is off.
  const dhcpOn = useModuleOn("core.dhcp");
  const dhcpGroupsQ = useQuery({
    queryKey: ["dhcp-groups"],
    queryFn: dhcpApi.listGroups,
    enabled: dhcpOn,
  });

  function set<K extends keyof TemplateForm>(key: K, v: TemplateForm[K]) {
    setForm((p) => ({ ...p, [key]: v }));
  }

  function setChild(idx: number, key: keyof ChildEntryForm, value: string) {
    setForm((p) => ({
      ...p,
      children: p.children.map((c, i) =>
        i === idx ? { ...c, [key]: value } : c,
      ),
    }));
  }

  function addChild() {
    setForm((p) => ({
      ...p,
      children: [
        ...p.children,
        { prefix: "27", name_template: "{n}", description: "" },
      ],
    }));
  }
  function removeChild(idx: number) {
    setForm((p) => ({
      ...p,
      children: p.children.filter((_, i) => i !== idx),
    }));
  }

  return (
    <Modal
      title={mode === "create" ? "New IPAM Template" : `Edit — ${initial.name}`}
      onClose={onClose}
      wide
    >
      <div className="space-y-4">
        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="flex flex-wrap gap-1 border-b">
          {(
            [
              ["general", "General"],
              ["stamp", "Stamp values"],
              ["ddns", "DDNS"],
              ["children", "Child layout"],
            ] as [TabKey, string][]
          )
            // DDNS is DHCP updating DNS: it needs both modules, as the
            // IPAM dialogs' DDNS tab does (#2135).
            .filter(([k]) => (dnsOn && dhcpOn) || k !== "ddns")
            .map(([k, label]) => {
              const disabled = k === "children" && form.applies_to !== "block";
              return (
                <button
                  key={k}
                  type="button"
                  onClick={() => !disabled && setTab(k)}
                  disabled={disabled}
                  className={`-mb-px border-b-2 px-3 py-1.5 text-sm transition-colors ${
                    tab === k
                      ? "border-primary text-foreground"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  } ${disabled ? "opacity-40 cursor-not-allowed" : ""}`}
                >
                  {label}
                </button>
              );
            })}
        </div>

        {tab === "general" && (
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Name
              </label>
              <input
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                className={inputCls}
                placeholder="e.g. dev-app-subnet"
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Applies To
              </label>
              <select
                value={form.applies_to}
                onChange={(e) =>
                  set("applies_to", e.target.value as IPAMTemplateAppliesTo)
                }
                disabled={mode === "edit"}
                className={`${inputCls} disabled:opacity-60`}
              >
                <option value="block">{APPLIES_TO_LABEL.block}</option>
                <option value="subnet">{APPLIES_TO_LABEL.subnet}</option>
              </select>
              {mode === "edit" && (
                <p className="mt-1 text-xs text-muted-foreground">
                  Cannot change after creation — would invalidate every applied
                  instance.
                </p>
              )}
            </div>
            <div className="col-span-2">
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Description
              </label>
              <input
                value={form.description}
                onChange={(e) => set("description", e.target.value)}
                className={inputCls}
              />
            </div>
          </div>
        )}

        {tab === "stamp" && (
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Tags (JSON object)
              </label>
              <textarea
                value={form.tagsJson}
                onChange={(e) => set("tagsJson", e.target.value)}
                rows={4}
                className={`${inputCls} font-mono text-xs`}
              />
            </div>
            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Custom fields (JSON object)
              </label>
              <textarea
                value={form.cfsJson}
                onChange={(e) => set("cfsJson", e.target.value)}
                rows={4}
                className={`${inputCls} font-mono text-xs`}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              {dnsOn && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    DNS server group
                  </label>
                  <select
                    value={form.dns_group_id}
                    onChange={(e) => set("dns_group_id", e.target.value)}
                    className={inputCls}
                  >
                    <option value="">— none —</option>
                    {(dnsGroupsQ.data ?? []).map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              {dhcpOn && (
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    DHCP server group
                  </label>
                  <select
                    value={form.dhcp_group_id}
                    onChange={(e) => set("dhcp_group_id", e.target.value)}
                    className={inputCls}
                  >
                    <option value="">— none —</option>
                    {(dhcpGroupsQ.data ?? []).map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            {dnsOn && (
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Default DNS zone (optional)
                </label>
                <input
                  value={form.dns_zone_id}
                  onChange={(e) => set("dns_zone_id", e.target.value)}
                  placeholder="zone UUID — operator can leave blank"
                  className={`${inputCls} font-mono text-xs`}
                />
              </div>
            )}
          </div>
        )}

        {tab === "ddns" && (
          <div className="space-y-4">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.ddns_enabled}
                onChange={(e) => set("ddns_enabled", e.target.checked)}
              />
              Enable DDNS on the stamped carrier
            </label>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Hostname policy
                </label>
                <select
                  value={form.ddns_hostname_policy}
                  onChange={(e) => set("ddns_hostname_policy", e.target.value)}
                  className={inputCls}
                >
                  <option value="client_or_generated">
                    client_or_generated
                  </option>
                  <option value="client_provided">client_provided</option>
                  <option value="always_generate">always_generate</option>
                  <option value="disabled">disabled</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  TTL override (sec)
                </label>
                <input
                  value={form.ddns_ttl}
                  onChange={(e) => set("ddns_ttl", e.target.value)}
                  placeholder="(zone default)"
                  className={inputCls}
                />
              </div>
              <div className="col-span-2">
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Domain override (optional)
                </label>
                <input
                  value={form.ddns_domain_override}
                  onChange={(e) => set("ddns_domain_override", e.target.value)}
                  placeholder="e.g. dev.example.com"
                  className={inputCls}
                />
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              When any DDNS field is set, applying the template flips
              <code className="mx-1">ddns_inherit_settings=False</code>
              on the carrier so the stamped values take effect.
            </p>
          </div>
        )}

        {tab === "children" && (
          <div className="space-y-3">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.childLayoutEnabled}
                onChange={(e) => set("childLayoutEnabled", e.target.checked)}
                disabled={form.applies_to !== "block"}
              />
              Carve sub-subnets on apply
            </label>
            {form.childLayoutEnabled && (
              <>
                <p className="text-xs text-muted-foreground">
                  Children are carved sequentially from the block's network
                  address. <code>{"{n}"}</code> /<code>{" {oct1}–{oct4}"}</code>{" "}
                  are valid name-template tokens. Re-apply skips children that
                  already exist.
                </p>
                <div className="space-y-2">
                  {form.children.map((c, idx) => (
                    <div
                      key={idx}
                      className="grid grid-cols-[1fr_2fr_2fr_auto] gap-2"
                    >
                      <input
                        value={c.prefix}
                        onChange={(e) =>
                          setChild(idx, "prefix", e.target.value)
                        }
                        placeholder="prefix /N"
                        className={`${inputCls} font-mono`}
                      />
                      <input
                        value={c.name_template}
                        onChange={(e) =>
                          setChild(idx, "name_template", e.target.value)
                        }
                        placeholder="name template e.g. carved-{n}"
                        className={`${inputCls} font-mono text-xs`}
                      />
                      <input
                        value={c.description}
                        onChange={(e) =>
                          setChild(idx, "description", e.target.value)
                        }
                        placeholder="description (optional)"
                        className={inputCls}
                      />
                      <button
                        aria-label="Remove child"
                        title="Remove child"
                        type="button"
                        onClick={() => removeChild(idx)}
                        className="rounded-md border px-2 py-1 text-xs text-muted-foreground hover:text-destructive"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
                <button
                  type="button"
                  onClick={addChild}
                  className="inline-flex items-center gap-1 rounded-md border bg-background px-3 py-1.5 text-xs hover:bg-accent"
                >
                  <Plus className="h-3 w-3" /> Add child
                </button>
              </>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            disabled={saving || !form.name.trim()}
            onClick={() => onSave(form)}
            className="rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground disabled:opacity-50"
          >
            {saving ? "Saving…" : mode === "create" ? "Create" : "Save"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function ReapplyConfirmModal({
  template,
  onClose,
  onConfirm,
  busy,
}: {
  template: IPAMTemplate;
  onClose: () => void;
  onConfirm: () => void;
  busy: boolean;
}) {
  const [typed, setTyped] = useState("");
  return (
    <Modal title={`Reapply — ${template.name}`} onClose={onClose}>
      <div className="space-y-3 text-sm">
        <p>
          This will stamp the template across every recorded instance with
          <code className="mx-1">force=True</code>, overwriting any operator
          overrides. Capped at 200 instances per call.
        </p>
        <p>
          Type the template name to confirm:{" "}
          <span className="font-mono text-xs">{template.name}</span>
        </p>
        <input
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          className={inputCls}
        />
        <div className="flex justify-end gap-2 border-t pt-3">
          <button
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            disabled={busy || typed !== template.name}
            onClick={onConfirm}
            className="rounded-md bg-destructive px-3 py-1.5 text-sm text-destructive-foreground disabled:opacity-50"
          >
            {busy ? "Reapplying…" : "Reapply to all"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function IPAMTemplatesPage() {
  const dhcpOn = useModuleOn("core.dhcp");
  const dnsOn = useModuleOn("core.dns");
  // #1341 — a read-only user is offered no write it would be refused:
  // the router asks write (delete) on 'manage_ipam_templates'.
  const perms = usePermissions();
  const writeGate = permissionGate(
    perms.can("write", "manage_ipam_templates"),
    "Requires write permission on IPAM templates",
  );
  const deleteGate = permissionGate(
    perms.can("delete", "manage_ipam_templates"),
    "Requires delete permission on IPAM templates",
  );
  const qc = useQueryClient();
  const tplsQ = useQuery({
    queryKey: ["ipam-templates"],
    queryFn: () => ipamApi.listTemplates(),
  });

  const [filterApplies, setFilterApplies] = useState<
    "" | IPAMTemplateAppliesTo
  >("");
  const [search, setSearch] = useState("");
  const [editor, setEditor] = useState<
    | null
    | { mode: "create"; initial: TemplateForm }
    | { mode: "edit"; tpl: IPAMTemplate; initial: TemplateForm }
  >(null);
  const [editorErr, setEditorErr] = useState<string>("");
  const [reapplyTarget, setReapplyTarget] = useState<IPAMTemplate | null>(null);

  const visible = useMemo(() => {
    let rows = tplsQ.data ?? [];
    if (filterApplies)
      rows = rows.filter((r) => r.applies_to === filterApplies);
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter(
        (r) =>
          r.name.toLowerCase().includes(q) ||
          (r.description ?? "").toLowerCase().includes(q),
      );
    }
    return rows;
  }, [tplsQ.data, filterApplies, search]);

  const createMut = useMutation({
    mutationFn: (body: IPAMTemplateCreate) => ipamApi.createTemplate(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ipam-templates"] });
      setEditor(null);
      setEditorErr("");
    },
    onError: (err: unknown) => {
      setEditorErr(formatApiError(err, String(err)));
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: IPAMTemplateUpdate }) =>
      ipamApi.updateTemplate(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ipam-templates"] });
      setEditor(null);
      setEditorErr("");
    },
    onError: (err: unknown) => {
      setEditorErr(formatApiError(err, String(err)));
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => ipamApi.deleteTemplate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["ipam-templates"] }),
  });

  const reapplyMut = useMutation({
    mutationFn: (id: string) => ipamApi.reapplyAllTemplate(id),
    onSuccess: () => {
      setReapplyTarget(null);
      qc.invalidateQueries({ queryKey: ["ipam-templates"] });
    },
  });

  function handleSave(form: TemplateForm) {
    setEditorErr("");
    let payload: IPAMTemplateCreate;
    try {
      payload = toCreatePayload(form);
    } catch (e) {
      setEditorErr(e instanceof Error ? e.message : String(e));
      return;
    }
    if (editor?.mode === "edit") {
      const { id } = editor.tpl;
      const update: IPAMTemplateUpdate = {
        name: payload.name,
        description: payload.description,
        tags: payload.tags,
        custom_fields: payload.custom_fields,
        dns_group_id: payload.dns_group_id ?? null,
        dns_zone_id: payload.dns_zone_id ?? null,
        dhcp_group_id: payload.dhcp_group_id ?? null,
        ddns_enabled: payload.ddns_enabled,
        ddns_hostname_policy: payload.ddns_hostname_policy,
        ddns_domain_override: payload.ddns_domain_override ?? null,
        ddns_ttl: payload.ddns_ttl ?? null,
        child_layout: payload.child_layout ?? null,
        clear_dns_group_id: payload.dns_group_id == null,
        clear_dhcp_group_id: payload.dhcp_group_id == null,
        clear_dns_zone_id: payload.dns_zone_id == null,
        clear_child_layout: payload.child_layout == null,
        clear_ddns_domain_override: payload.ddns_domain_override == null,
        clear_ddns_ttl: payload.ddns_ttl == null,
      };
      updateMut.mutate({ id, body: update });
      return;
    }
    createMut.mutate(payload);
  }

  return (
    <div className="h-full overflow-auto p-6">
      <div className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <LayoutTemplate className="h-5 w-5" /> IPAM Templates
            </h1>
            <p className="text-sm text-muted-foreground">
              Reusable stamp templates that pre-fill block / subnet defaults on
              create and let you reapply across instances when the template
              changes.
            </p>
          </div>
          <button
            onClick={() => {
              setEditorErr("");
              setEditor({ mode: "create", initial: { ...EMPTY } });
            }}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
            {...writeGate}
          >
            <Plus className="h-4 w-4" /> New template
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={filterApplies}
            onChange={(e) =>
              setFilterApplies(e.target.value as "" | IPAMTemplateAppliesTo)
            }
            className={`${inputCls} max-w-[12rem]`}
          >
            <option value="">All carriers</option>
            <option value="block">{APPLIES_TO_LABEL.block}</option>
            <option value="subnet">{APPLIES_TO_LABEL.subnet}</option>
          </select>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by name / description…"
            className={`${inputCls} max-w-md`}
          />
        </div>

        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/30 text-left text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Applies to</th>
                {dnsOn && <th className="px-3 py-2">DNS group</th>}
                {dhcpOn && <th className="px-3 py-2">DHCP group</th>}
                <th className="px-3 py-2">Children</th>
                <th className="px-3 py-2">Applied</th>
                <th className="px-3 py-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tplsQ.isLoading && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    Loading…
                  </td>
                </tr>
              )}
              {!tplsQ.isLoading && visible.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-3 py-8 text-center text-muted-foreground"
                  >
                    <ListEmpty
                      error={tplsQ.error}
                      what="templates"
                      filtered={filterApplies !== "" || search !== ""}
                      onClearFilters={() => {
                        setFilterApplies("");
                        setSearch("");
                      }}
                    >
                      No templates yet.
                    </ListEmpty>
                  </td>
                </tr>
              )}
              {visible.map((t) => (
                <tr key={t.id} className="border-b last:border-b-0">
                  <td className="px-3 py-2 align-top">
                    <div className="font-medium break-words">{t.name}</div>
                    {t.description && (
                      <div className="text-xs text-muted-foreground break-words">
                        {t.description}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {APPLIES_TO_LABEL[t.applies_to]}
                  </td>
                  {dnsOn && (
                    <td className="px-3 py-2 text-xs font-mono">
                      {t.dns_group_id ? t.dns_group_id.slice(0, 8) : "—"}
                    </td>
                  )}
                  {dhcpOn && (
                    <td className="px-3 py-2 text-xs font-mono">
                      {t.dhcp_group_id ? t.dhcp_group_id.slice(0, 8) : "—"}
                    </td>
                  )}
                  <td className="px-3 py-2 text-xs">
                    {t.child_layout?.children?.length ?? 0}
                  </td>
                  <td className="px-3 py-2 text-xs">{t.applied_count}</td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => setReapplyTarget(t)}
                      disabled={t.applied_count === 0}
                      className="mr-1 inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs text-muted-foreground hover:bg-accent disabled:opacity-40"
                      title="Reapply across all instances"
                      {...writeGate}
                    >
                      <RefreshCw className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() => {
                        setEditorErr("");
                        setEditor({
                          mode: "edit",
                          tpl: t,
                          initial: formFromTemplate(t),
                        });
                      }}
                      className="mr-1 rounded-md border px-2 py-1 text-xs text-muted-foreground hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                      {...writeGate}
                    >
                      <Pencil className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() => {
                        if (
                          confirm(
                            `Delete template "${t.name}"? Applied instances are not removed; their applied_template_id is cleared.`,
                          )
                        )
                          deleteMut.mutate(t.id);
                      }}
                      className="rounded-md border px-2 py-1 text-xs text-muted-foreground hover:text-destructive hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                      {...deleteGate}
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {editor && (
          <TemplateEditor
            mode={editor.mode}
            initial={editor.initial}
            error={editorErr}
            saving={createMut.isPending || updateMut.isPending}
            onClose={() => {
              setEditor(null);
              setEditorErr("");
            }}
            onSave={handleSave}
          />
        )}

        {reapplyTarget && (
          <ReapplyConfirmModal
            template={reapplyTarget}
            onClose={() => setReapplyTarget(null)}
            onConfirm={() => reapplyMut.mutate(reapplyTarget.id)}
            busy={reapplyMut.isPending}
          />
        )}
      </div>
    </div>
  );
}
