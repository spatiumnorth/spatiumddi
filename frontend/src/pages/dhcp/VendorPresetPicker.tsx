import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Plus, Trash2, Wand2 } from "lucide-react";

import { dhcpApi, formatApiError } from "@/lib/api";
import { inputCls } from "./_shared";

/**
 * "Add vendor preset…" (#4490): pick a vendor, enter the controller
 * address(es), see the option 43 bytes the server will send, then apply them.
 * The encoding is done server-side (one implementation, unit-tested against
 * each vendor's published example); this only previews and hands back the hex.
 */
export function VendorPresetPicker({
  onApply,
}: {
  onApply: (r: {
    value: string;
    vendor: string;
    vendorClassMatch: string | null;
  }) => void;
}) {
  const [open, setOpen] = useState(false);
  const [presetId, setPresetId] = useState("");
  const [ips, setIps] = useState<string[]>([""]);

  const { data: presets = [] } = useQuery({
    queryKey: ["dhcp-vendor-presets"],
    queryFn: () => dhcpApi.listVendorPresets(),
    staleTime: 5 * 60 * 1000,
    enabled: open,
  });
  const preset = presets.find((p) => p.id === presetId);
  const filled = ips.map((i) => i.trim()).filter(Boolean);

  const preview = useQuery({
    queryKey: ["dhcp-vendor-preset-encode", presetId, filled],
    queryFn: () => dhcpApi.encodeVendorPreset(presetId, filled),
    enabled: !!preset && filled.length >= preset.min_controllers,
    retry: false,
  });

  if (!open) {
    return (
      <div>
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] hover:bg-accent"
        >
          <Wand2 className="h-3 w-3" /> Add vendor preset…
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-2 rounded-md border bg-muted/20 p-3 text-xs">
      <div className="flex items-center justify-between">
        <span className="font-medium">Vendor preset (option 43)</span>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
      </div>
      <label className="block">
        <span className="mb-1 block text-muted-foreground">Vendor</span>
        <select
          className={inputCls}
          value={presetId}
          onChange={(e) => {
            setPresetId(e.target.value);
            setIps([""]);
          }}
        >
          <option value="">Select a vendor…</option>
          {presets.map((p) => (
            <option key={p.id} value={p.id}>
              {p.vendor} — {p.product}
            </option>
          ))}
        </select>
      </label>
      {preset && (
        <>
          <p className="text-muted-foreground">{preset.description}</p>
          {ips.map((ip, i) => (
            <div key={i} className="flex items-center gap-1">
              <input
                className={inputCls}
                aria-label={`${preset.controller_label} ${i + 1}`}
                placeholder={preset.controller_label}
                value={ip}
                onChange={(e) =>
                  setIps((prev) =>
                    prev.map((x, k) => (k === i ? e.target.value : x)),
                  )
                }
              />
              {ips.length > 1 && (
                <button
                  type="button"
                  aria-label="Remove address"
                  onClick={() =>
                    setIps((prev) => prev.filter((_, k) => k !== i))
                  }
                  className="rounded p-1 text-muted-foreground hover:text-destructive"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          ))}
          {ips.length < preset.max_controllers && (
            <button
              type="button"
              onClick={() => setIps((prev) => [...prev, ""])}
              className="inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] hover:bg-accent"
            >
              <Plus className="h-3 w-3" /> Add address
            </button>
          )}
          <div>
            <span className="text-muted-foreground">Encoded option 43: </span>
            {preview.data ? (
              <code data-testid="preset-hex" className="break-all font-mono">
                {preview.data.value}
              </code>
            ) : preview.error ? (
              <span className="text-destructive">
                {formatApiError(preview.error)}
              </span>
            ) : (
              <span className="text-muted-foreground">
                enter the address to preview
              </span>
            )}
          </div>
          <p className="text-muted-foreground">
            {preset.vendor_class_match
              ? `Fenced to option 60 "${preset.vendor_class_match}". `
              : ""}
            {preset.vendor_class_note} Source: {preset.source}.
          </p>
          <button
            type="button"
            disabled={!preview.data}
            onClick={() => {
              if (!preview.data) return;
              onApply({
                value: preview.data.value,
                vendor: preset.vendor,
                vendorClassMatch: preview.data.vendor_class_match,
              });
              setOpen(false);
              setPresetId("");
              setIps([""]);
            }}
            className="rounded-md bg-primary px-2 py-1 text-[11px] text-primary-foreground disabled:opacity-50"
          >
            Use this value
          </button>
        </>
      )}
    </div>
  );
}
