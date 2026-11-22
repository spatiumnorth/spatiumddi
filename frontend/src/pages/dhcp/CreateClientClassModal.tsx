import { useState } from "react";
import { FormError } from "@/components/ui/form-error";
import { useFreshRow, changedFields } from "@/hooks/useFreshRow";
import { FreshRowError } from "@/components/FreshRowError";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ConfirmModal } from "@/components/ui/confirm-modal";
import {
  dhcpApi,
  type DHCPClientClass,
  type DHCPOption,
  type RelayMatchSpec,
} from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";
import { EMPTY_RELAY_SPEC, RelayMatchBuilder } from "./RelayMatchBuilder";
import { optionsFromMap, optionsToMap } from "./dhcpOptionKeys";

type CreateClientClassModalProps = {
  klass?: DHCPClientClass;
  groupId: string;
  onClose: () => void;
};

// Edit reads the class fresh on open (#3091): the row the page holds comes
// from a cached list, and the form is seeded once. A class has no read of its
// own, so it is looked up in its group's list.
export function CreateClientClassModal(props: CreateClientClassModalProps) {
  const fresh = useFreshRow(props.klass, async () =>
    (await dhcpApi.listClientClasses(props.groupId)).find(
      (c) => c.id === props.klass!.id,
    ),
  );
  if (fresh.error)
    return (
      <FreshRowError
        title="Edit Client Class"
        error={fresh.error}
        onRetry={fresh.retry}
        onClose={props.onClose}
      />
    );
  if (!fresh.ready) return null;
  return <ClientClassModalForm {...props} klass={fresh.row} />;
}

function ClientClassModalForm({
  klass,
  groupId,
  onClose,
}: CreateClientClassModalProps) {
  const qc = useQueryClient();
  const editing = !!klass;
  const [name, setName] = useState(klass?.name ?? "");
  const [description, setDescription] = useState(klass?.description ?? "");
  const [matchExpr, setMatchExpr] = useState(klass?.match_expression ?? "");
  // #54 — how the class matches: a hand-written Kea expression, or the
  // structured relay agent (option 82) builder the server compiles.
  const [mode, setMode] = useState<"expression" | "relay">(
    klass?.match_spec ? "relay" : "expression",
  );
  const [spec, setSpec] = useState<RelayMatchSpec>(
    klass?.match_spec ?? EMPTY_RELAY_SPEC,
  );
  const [pendingMode, setPendingMode] = useState<"expression" | "relay" | null>(
    null,
  );
  const [family, setFamily] = useState<DHCPClientClass["address_family"]>(
    klass?.address_family ?? "ipv4",
  );
  const initialOptions: DHCPOption[] = optionsFromMap(klass?.options);
  const [options, setOptions] = useState<DHCPOption[]>(initialOptions);
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: async () => {
      const optionsDict = optionsToMap(options);
      // Builder mode never sends match_expression: the server compiles it.
      const data: Partial<DHCPClientClass> = {
        name,
        description,
        address_family: mode === "relay" ? "ipv4" : family,
        options: optionsDict,
        ...(mode === "relay"
          ? { match_spec: spec }
          : { match_expression: matchExpr, match_spec: null }),
      };
      if (mode === "expression" && !klass?.match_spec) delete data.match_spec;
      if (!editing) return dhcpApi.createClientClass(groupId, data);
      // Send only what changed (#3091), so a Save that touches nothing leaves
      // the class as it is. The options baseline goes through the editor's own
      // round trip, so an untouched map compares equal to what it shows.
      const diff = changedFields(
        {
          name: klass!.name,
          description: klass!.description ?? "",
          ...(mode === "relay"
            ? { match_spec: klass!.match_spec ?? null }
            : {
                match_expression: klass!.match_expression ?? "",
                match_spec: klass!.match_spec ?? null,
              }),
          address_family: klass!.address_family,
          options: optionsToMap(optionsFromMap(klass!.options)),
        },
        data,
      );
      if (Object.keys(diff).length === 0) return klass!;
      return dhcpApi.updateClientClass(groupId, klass!.id, diff);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-client-classes", groupId] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save client class")),
  });

  // Leaving the builder on a stored builder class sends match_spec: null (the
  // class becomes hand-written); leaving the expression box discards its text.
  // Both are confirmed when there is something to lose.
  const requestMode = (m: "expression" | "relay") => {
    if (m === mode) return;
    const loses =
      m === "expression" ? !!klass?.match_spec : matchExpr.trim() !== "";
    if (loses) setPendingMode(m);
    else applyMode(m);
  };
  const applyMode = (m: "expression" | "relay") => {
    if (m === "relay") {
      setSpec(klass?.match_spec ?? EMPTY_RELAY_SPEC);
    } else if (klass?.match_spec) {
      // Start the hand-written test from what the builder had compiled to.
      setMatchExpr(klass.match_expression);
    }
    setMode(m);
    setPendingMode(null);
  };

  return (
    <>
      <Modal
        title={editing ? "Edit Client Class" : "New Client Class"}
        onClose={onClose}
        wide
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            mut.mutate();
          }}
          className="space-y-3"
        >
          <Field label="Name">
            <input
              className={inputCls}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </Field>
          <Field label="Description">
            <input
              className={inputCls}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          <Field
            label="Address family"
            hint={
              mode === "relay"
                ? "Option 82 matching is IPv4 only."
                : "Which Kea daemons get this class. A test using pkt4 / relay4 is IPv4-only, pkt6 / relay6 IPv6-only. Both sends each option to whichever family it is valid in."
            }
          >
            <select
              className={inputCls}
              disabled={mode === "relay"}
              value={mode === "relay" ? "ipv4" : family}
              onChange={(e) =>
                setFamily(e.target.value as DHCPClientClass["address_family"])
              }
            >
              <option value="ipv4">IPv4 (kea-dhcp4)</option>
              <option value="ipv6">IPv6 (kea-dhcp6)</option>
              <option value="dual">Both</option>
            </select>
          </Field>
          <div
            role="group"
            aria-label="Match type"
            className="inline-flex overflow-hidden rounded-md border text-sm"
          >
            {(
              [
                ["expression", "Expression"],
                ["relay", "Relay agent (option 82)"],
              ] as const
            ).map(([m, label]) => (
              <button
                key={m}
                type="button"
                aria-pressed={mode === m}
                onClick={() => requestMode(m)}
                className={`px-3 py-1.5 ${
                  mode === m
                    ? "bg-primary text-primary-foreground"
                    : "hover:bg-accent"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
          {mode === "relay" ? (
            <RelayMatchBuilder value={spec} onChange={setSpec} />
          ) : (
            <Field
              label="Match Expression"
              hint="Driver-specific match (e.g. Kea: substring(option[60].hex,0,9) == 'MSFT 5.0')."
            >
              <textarea
                className={`${inputCls} font-mono text-xs`}
                rows={3}
                value={matchExpr}
                onChange={(e) => setMatchExpr(e.target.value)}
              />
            </Field>
          )}
          <div className="border-t pt-3">
            <h3 className="text-sm font-semibold mb-2">Options</h3>
            <DHCPOptionsEditor value={options} onChange={setOptions} />
          </div>
          <FormError>{error}</FormError>
          <Btns onClose={onClose} pending={mut.isPending} />
        </form>
      </Modal>
      <ConfirmModal
        open={pendingMode !== null}
        title="Change match type?"
        message={
          pendingMode === "expression"
            ? "This class is built from the option 82 builder. Switching to an expression saves it as a hand-written class, starting from the test the builder compiled to."
            : "Switching to the builder discards the expression you have written."
        }
        confirmLabel="Switch"
        onConfirm={() => pendingMode && applyMode(pendingMode)}
        onClose={() => setPendingMode(null)}
      />
    </>
  );
}

export const EditClientClassModal = CreateClientClassModal;
