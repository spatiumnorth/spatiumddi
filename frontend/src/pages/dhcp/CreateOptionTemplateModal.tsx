import { useState } from "react";
import { useFreshRow, changedFields } from "@/hooks/useFreshRow";
import { FreshRowError } from "@/components/FreshRowError";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  dhcpApi,
  type DHCPOption,
  type DHCPOptionTemplate,
  type DHCPOptionTemplateWrite,
} from "@/lib/api";
import { Modal, Field, Btns, inputCls, errMsg } from "./_shared";
import { DHCPOptionsEditor } from "./DHCPOptionsEditor";
import { optionsFromMap, optionsToMap, rawPrefixFor } from "./dhcpOptionKeys";

type CreateOptionTemplateModalProps = {
  template?: DHCPOptionTemplate;
  groupId: string;
  onClose: () => void;
};

// Edit reads the template fresh on open (#3091): the row the page holds comes
// from a cached list, and the form is seeded once. A template has no read of
// its own, so it is looked up in its group's list.
export function CreateOptionTemplateModal(
  props: CreateOptionTemplateModalProps,
) {
  const fresh = useFreshRow(props.template, async () =>
    (await dhcpApi.listOptionTemplates(props.groupId)).find(
      (t) => t.id === props.template!.id,
    ),
  );
  if (fresh.error)
    return (
      <FreshRowError
        title="Edit Option Template"
        error={fresh.error}
        onRetry={fresh.retry}
        onClose={props.onClose}
      />
    );
  if (!fresh.ready) return null;
  return <OptionTemplateModalForm {...props} template={fresh.row} />;
}

function OptionTemplateModalForm({
  template,
  groupId,
  onClose,
}: CreateOptionTemplateModalProps) {
  const qc = useQueryClient();
  const editing = !!template;
  const [name, setName] = useState(template?.name ?? "");
  const [description, setDescription] = useState(template?.description ?? "");
  const [addressFamily, setAddressFamily] = useState<"ipv4" | "ipv6">(
    template?.address_family ?? "ipv4",
  );
  const initialOptions: DHCPOption[] = optionsFromMap(template?.options);
  const [options, setOptions] = useState<DHCPOption[]>(initialOptions);
  const [error, setError] = useState("");
  // #1347 — a catalogue pick is keyed in the spelling the group's servers
  // read, so a Windows group gets `opt-43`, not a `code:43` it would refuse.
  const { data: groupServers = [] } = useQuery({
    queryKey: ["dhcp-servers", groupId],
    queryFn: () => dhcpApi.listServers(groupId),
    enabled: !!groupId,
  });
  const rawPrefix = rawPrefixFor(groupServers.map((s) => s.driver));

  const mut = useMutation({
    mutationFn: async () => {
      const optionsDict = optionsToMap(options, rawPrefix);
      const data: DHCPOptionTemplateWrite = {
        name,
        description,
        address_family: addressFamily,
        options: optionsDict,
      };
      if (!editing) return dhcpApi.createOptionTemplate(groupId, data);
      // Send only what changed (#3091), so a Save that touches nothing leaves
      // the template as it is. The options baseline goes through the editor's
      // own round trip, so an untouched map compares equal to what it shows.
      const diff = changedFields(
        {
          name: template!.name,
          description: template!.description ?? "",
          address_family: template!.address_family,
          options: optionsToMap(optionsFromMap(template!.options), rawPrefix),
        },
        { ...data },
      );
      if (Object.keys(diff).length === 0) return template!;
      return dhcpApi.updateOptionTemplate(groupId, template!.id, diff);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["dhcp-option-templates", groupId] });
      onClose();
    },
    onError: (e) => setError(errMsg(e, "Failed to save option template")),
  });

  return (
    <Modal
      title={editing ? "Edit Option Template" : "New Option Template"}
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
        <Field
          label="Name"
          hint="Short name shown in the apply dropdown (e.g. 'VoIP phones', 'PXE BIOS clients')."
        >
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
        <Field label="Address family">
          <select
            className={inputCls}
            value={addressFamily}
            onChange={(e) =>
              setAddressFamily(e.target.value as "ipv4" | "ipv6")
            }
          >
            <option value="ipv4">IPv4 (Dhcp4)</option>
            <option value="ipv6">IPv6 (Dhcp6)</option>
          </select>
        </Field>
        <div className="border-t pt-3">
          <h3 className="mb-2 text-sm font-semibold">Options</h3>
          <DHCPOptionsEditor value={options} onChange={setOptions} />
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <Btns onClose={onClose} pending={mut.isPending} />
      </form>
    </Modal>
  );
}
