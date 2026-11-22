/**
 * @vitest-environment jsdom
 *
 * #54 — the option 82 builder: it builds the spec the API expects, shows the
 * compiler's refusal inline, and switching a stored builder class to a
 * hand-written one is confirmed and sends match_spec: null.
 */
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { DHCPClientClass, RelayMatchSpec } from "@/lib/api";

const compile = vi.fn();
const updateClass = vi.fn();
const createClass = vi.fn();
const classes: DHCPClientClass[] = [];

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: {
      ...actual.dhcpApi,
      listClientClasses: () => Promise.resolve(classes),
      compileClientClassMatch: (s: RelayMatchSpec) => compile(s),
      updateClientClass: (...a: unknown[]) => updateClass(...a),
      createClientClass: (...a: unknown[]) => createClass(...a),
    },
  };
});

const { CreateClientClassModal } = await import("./CreateClientClassModal");
const { RelayMatchBuilder, EMPTY_RELAY_SPEC } =
  await import("./RelayMatchBuilder");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  classes.length = 0;
});

const wrap = (ui: React.ReactNode) =>
  render(
    <QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>,
  );

function Harness({ onSpec }: { onSpec: (s: RelayMatchSpec) => void }) {
  const [spec, setSpec] = useState(EMPTY_RELAY_SPEC);
  onSpec(spec);
  return <RelayMatchBuilder value={spec} onChange={setSpec} />;
}

describe("RelayMatchBuilder", () => {
  it("builds the spec for the API", async () => {
    compile.mockResolvedValue({
      expression: "relay4[1].hex == 0x41",
      warnings: [],
      windows: { supported: false, reason: "" },
    });
    let last: RelayMatchSpec = EMPTY_RELAY_SPEC;
    render(<Harness onSpec={(s) => (last = s)} />);
    fireEvent.change(screen.getByLabelText("Condition 1 value"), {
      target: { value: "A" },
    });
    fireEvent.change(screen.getByLabelText("Condition 1 operator"), {
      target: { value: "slice" },
    });
    fireEvent.change(screen.getByLabelText("Condition 1 offset"), {
      target: { value: "2" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add condition" }));
    fireEvent.change(screen.getByLabelText("Condition 2 sub-option"), {
      target: { value: "other" },
    });
    fireEvent.change(screen.getByLabelText("Condition 2 sub-option code"), {
      target: { value: "9" },
    });
    fireEvent.change(screen.getByLabelText("Condition 2 operator"), {
      target: { value: "exists" },
    });
    fireEvent.change(screen.getByLabelText("Combine conditions"), {
      target: { value: "any" },
    });
    expect(last).toEqual({
      kind: "relay_agent",
      combine: "any",
      conditions: [
        { sub_option: 1, op: "slice", encoding: "text", value: "A", offset: 2 },
        { sub_option: 9, op: "exists", encoding: "text" },
      ],
    });
    await waitFor(() =>
      expect(screen.getByTestId("relay-preview").textContent).toContain(
        "relay4[1]",
      ),
    );
  });

  it("shows the compiler's refusal inline", async () => {
    compile.mockRejectedValue({
      isAxiosError: true,
      response: { status: 422, data: { detail: "'equals' needs a value" } },
    });
    render(<RelayMatchBuilder value={EMPTY_RELAY_SPEC} onChange={() => {}} />);
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent",
      "'equals' needs a value",
    );
  });
});

describe("client class modal mode switch", () => {
  const builderClass = {
    id: "c1",
    group_id: "g1",
    name: "port7",
    description: "",
    match_expression: "relay4[1].hex == 0x41",
    match_spec: {
      kind: "relay_agent",
      combine: "all",
      conditions: [
        { sub_option: 1, op: "equals", encoding: "text", value: "A" },
      ],
    },
    address_family: "ipv4",
    options: {},
  } as unknown as DHCPClientClass;

  it("confirms, then saves match_spec: null", async () => {
    compile.mockResolvedValue({
      expression: "x",
      warnings: [],
      windows: { supported: false, reason: "" },
    });
    classes.push(builderClass);
    updateClass.mockResolvedValue(builderClass);
    wrap(
      <CreateClientClassModal
        klass={builderClass}
        groupId="g1"
        onClose={() => {}}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Expression" }));
    // Not switched yet: the builder is still there and a confirm is open.
    expect(await screen.findByText("Change match type?")).toBeTruthy();
    expect(screen.queryByLabelText("Match Expression")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Switch" }));
    fireEvent.click(await screen.findByRole("button", { name: "Save" }));
    await waitFor(() => expect(updateClass).toHaveBeenCalled());
    expect(updateClass.mock.calls[0][2]).toEqual({ match_spec: null });
  });
});
