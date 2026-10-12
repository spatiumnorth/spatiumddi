import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { dhcpApi, type DHCPClientClass, type DHCPOption } from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";
import { optionsFromMap, optionsToMap } from "./dhcpOptionKeys";

export function CreateClientClassModal({
  klass,
  groupId,
  onClose,
}: {
  klass?: DHCPClientClass;
  groupId: string;
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const editing = !!klass;
  const [name, setName] = useState(klass?.name ?? "");
  const [description, setDescription] = useState(klass?.description ?? "");
  const [matchExpr, setMatchExpr] = useState(klass?.match_expression ?? "");
  const [family, setFamily] = useState<DHCPClientClass["address_family"]>(
    klass?.address_family ?? "ipv4",
  );
  const initialOptions: DHCPOption[] = optionsFromMap(klass?.options);
  const [options, setOptions] = useState<DHCPOption[]>(initialOptions);
  const [error, setError] = useState("");

  const mut = useMutation({
    mutationFn: () => {
      const optionsDict = optionsToMap(options);
      const data: Partial<DHCPClientClass> = {
        name,
        description,
        match_expression: matchExpr,
        address_family: family,
        options: optionsDict,
      };
      return editing
        ? dhcpApi.updateClientClass(groupId, klass!.id, data)
        : dhcpApi.createClientClass(groupId, data);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-client-classes", groupId] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save client class")),
  });

  return (
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
          hint="Which Kea daemons get this class. A test using pkt4 / relay4 is IPv4-only, pkt6 / relay6 IPv6-only. Both sends each option to whichever family it is valid in."
        >
          <select
            className={inputCls}
            value={family}
            onChange={(e) =>
              setFamily(e.target.value as DHCPClientClass["address_family"])
            }
          >
            <option value="ipv4">IPv4 (kea-dhcp4)</option>
            <option value="ipv6">IPv6 (kea-dhcp6)</option>
            <option value="dual">Both</option>
          </select>
        </Field>
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
        <div className="border-t pt-3">
          <h3 className="text-sm font-semibold mb-2">Options</h3>
          <DHCPOptionsEditor value={options} onChange={setOptions} />
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}

export const EditClientClassModal = CreateClientClassModal;
