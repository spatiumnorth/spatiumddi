/**
 * @vitest-environment jsdom
 *
 * The Subnet Planner's Node properties panel names only the fields a subnet
 * node really shows (#2626): Gateway IP, and no VLAN field.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

vi.mock("@/hooks/useFeatureModules", () => ({
  useFeatureModules: () => ({ ready: true, enabled: () => false }),
}));

const { PropertiesPanel } = await import("./SubnetPlannerEditorPage");

function node(kind: "block" | "subnet") {
  return {
    id: "n1",
    network: "10.0.0.0/24",
    name: "",
    description: "",
    kind,
    children: [],
  } as never;
}

function show(kind: "block" | "subnet") {
  const qc = new QueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PropertiesPanel
          node={node(kind)}
          isRoot={false}
          readOnly={false}
          onChange={() => {}}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(cleanup);

describe("Node properties copy", () => {
  it("a block says only Gateway IP appears on a subnet, not VLAN", () => {
    show("block");
    expect(screen.getByText(/Gateway IP appears when this node is a subnet/));
    expect(screen.queryByText(/VLAN/)).toBeNull();
  });

  it("a subnet node shows Gateway IP and no VLAN field", () => {
    show("subnet");
    expect(screen.getByText("Gateway IP")).toBeTruthy();
    expect(screen.queryByText(/VLAN/)).toBeNull();
  });
});
