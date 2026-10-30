import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import {
  asnsApi,
  type ASNCreate,
  type ASNRead,
  type ASNUpdate,
} from "@/lib/api";
import { Modal } from "@/components/ui/modal";
import { CustomerPicker, ProviderPicker } from "@/components/ownership/pickers";
import { cn } from "@/lib/utils";

import { Field, errMsg } from "./_shared";

const inputCls =
  "w-full rounded-md border bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring";

// Both create + edit live in one modal — the only differences are the
// title, the (immutable-after-create) ``number`` field, and which API
// call the mutation fires. Mirrors the DeviceFormModal shape so the
// two ASN-related pages stay visually consistent.
export function AsnFormModal({
  asn,
  onClose,
}: {
  asn?: ASNRead | null;
  onClose: () => void;
}) {
  const isEdit = Boolean(asn);
  const qc = useQueryClient();
  const [number, setNumber] = useState<string>(asn ? String(asn.number) : "");
  const [name, setName] = useState(asn?.name ?? "");
  const [description, setDescription] = useState(asn?.description ?? "");
  const [holderOrg, setHolderOrg] = useState(asn?.holder_org ?? "");
  const [customerId, setCustomerId] = useState<string | null>(
    asn?.customer_id ?? null,
  );
  const [providerId, setProviderId] = useState<string | null>(
    asn?.provider_id ?? null,
  );
  const [tagsRaw, setTagsRaw] = useState(
    asn?.tags ? JSON.stringify(asn.tags, null, 2) : "{}",
  );
  const [error, setError] = useState<string | null>(null);

  // Lightweight client-side parse of the tags textarea — bad JSON
  // gets a friendly message instead of a 422 round-trip. Server
  // re-validates anyway so this is just UX.
  function parseTags(): Record<string, unknown> | null {
    if (!tagsRaw.trim()) return {};
    try {
      const parsed = JSON.parse(tagsRaw);
      if (
        parsed === null ||
        typeof parsed !== "object" ||
        Array.isArray(parsed)
      ) {
        setError('Tags must be a JSON object — e.g. {"region": "us-east"}');
        return null;
      }
      return parsed as Record<string, unknown>;
    } catch {
      setError("Tags isn't valid JSON.");
      return null;
    }
  }

  const mut = useMutation({
    mutationFn: async () => {
      setError(null);
      const tags = parseTags();
      if (tags === null) throw new Error("invalid tags");

      if (isEdit && asn) {
        const body: ASNUpdate = {
          name,
          description,
          holder_org: holderOrg || null,
          customer_id: customerId,
          provider_id: providerId,
          tags,
        };
        return asnsApi.update(asn.id, body);
      }
      const n = Number(number);
      if (!Number.isInteger(n) || n < 1 || n > 4_294_967_295) {
        throw new Error(
          "AS number must be an integer in 1..4_294_967_295 (32-bit range).",
        );
      }
      const body: ASNCreate = {
        number: n,
        name,
        description,
        holder_org: holderOrg || null,
        customer_id: customerId,
        provider_id: providerId,
        tags,
      };
      return asnsApi.create(body);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asns"] });
      onClose();
    },
    onError: (e: unknown) => {
      setError(errMsg(e, "Save failed"));
    },
  });

  return (
    <Modal
      title={isEdit ? `Edit AS${asn?.number}` : "New ASN"}
      onClose={onClose}
    >
      <div className="space-y-4">
        <Field
          label="AS Number"
          hint={
            isEdit
              ? "Number is immutable — delete + recreate to change it."
              : "1..4_294_967_295 (32-bit AS range). Private ranges (64512–65534, 4_200_000_000–4_294_967_294) are auto-detected."
          }
        >
          <input
            type="number"
            min={1}
            max={4_294_967_295}
            className={cn(inputCls, isEdit && "opacity-60")}
            value={number}
            onChange={(e) => setNumber(e.target.value)}
            disabled={isEdit}
            placeholder="e.g. 13335"
          />
        </Field>
        <Field
          label="Name"
          hint="Short label — usually the holder's network nickname."
        >
          <input
            className={inputCls}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Cloudflare"
          />
        </Field>
        <Field label="Description">
          <textarea
            className={cn(inputCls, "min-h-[60px]")}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Field>
        <Field
          label="Holder Org"
          hint="For a public ASN the RDAP refresh job fills this from WHOIS and replaces what you type here. Set it by hand for a private ASN."
        >
          <input
            className={inputCls}
            value={holderOrg}
            onChange={(e) => setHolderOrg(e.target.value)}
            placeholder="e.g. CLOUDFLARENET"
          />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Customer" hint="Operator owning this AS, if any.">
            <CustomerPicker
              className={inputCls}
              value={customerId}
              onChange={setCustomerId}
            />
          </Field>
          <Field
            label="Provider"
            hint="Upstream we lease / peer through, if any."
          >
            <ProviderPicker
              className={inputCls}
              value={providerId}
              onChange={setProviderId}
            />
          </Field>
        </div>
        <Field
          label="Tags (JSON)"
          hint='Free-form key/value object. Example: {"region": "us-east", "tier": "transit"}'
        >
          <textarea
            className={cn(inputCls, "min-h-[80px] font-mono text-xs")}
            value={tagsRaw}
            onChange={(e) => setTagsRaw(e.target.value)}
          />
        </Field>
        {error && <p className="text-xs text-red-600">{error}</p>}
        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border px-3 py-1.5 text-sm hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={mut.isPending}
            onClick={() => mut.mutate()}
            className={cn(
              "rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground",
              "hover:bg-primary/90 disabled:opacity-50",
            )}
          >
            {mut.isPending ? "Saving…" : isEdit ? "Save" : "Create"}
          </button>
        </div>
      </div>
    </Modal>
  );
}
