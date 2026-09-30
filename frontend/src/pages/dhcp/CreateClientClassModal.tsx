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
