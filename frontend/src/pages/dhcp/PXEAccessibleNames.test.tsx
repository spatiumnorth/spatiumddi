/**
 * @vitest-environment jsdom
 *
 * #2016: the scope dialog's PXE profile and "Apply template…" pickers have
 * names, the New PXE profile match rows name their controls per row, and
 * "Arch codes" names the checkbox SET.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async (orig) => ({
  ...(await orig<typeof import("@/lib/api")>()),
  dhcpApi: {
    listPxeProfiles: () => Promise.resolve([]),
    listOptionTemplates: () =>
      Promise.resolve([
        {
          id: "t1",
          name: "tpl",
          address_family: "ipv4",
          options: {},
        },
      ]),
  },
}));

import { PXEProfileSection, ApplyTemplateControl } from "./CreateScopeModal";
import { ProfileEditor } from "./PXEProfilesPage";

function wrap(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

afterEach(cleanup);

describe("scope dialog pickers", () => {
  it("names the PXE profile select", () => {
    wrap(<PXEProfileSection groupId="g" value="" onChange={() => {}} />);
    expect(
      screen.getAllByRole("combobox", { name: "PXE profile" }),
    ).toHaveLength(1);
  });

  it("names the Apply template select", async () => {
    wrap(
      <ApplyTemplateControl
        groupId="g"
        currentOptions={[]}
        onApply={() => {}}
      />,
    );
    expect(
      await screen.findAllByRole("combobox", { name: "Apply option template" }),
    ).toHaveLength(1);
  });
});

describe("New PXE profile match rows", () => {
  function open() {
    wrap(
      <ProfileEditor
        mode="create"
        groupId="g"
        onClose={() => {}}
        onSaved={() => {}}
      />,
    );
  }

  it("tells the two starter rows' controls apart", () => {
    open();
    for (const n of [1, 2]) {
      for (const l of [
        "Priority",
        "Match kind",
        "Vendor class (option 60 substring)",
        "Boot filename / URL",
      ])
        expect(screen.getAllByLabelText(`Match ${n}: ${l}`)).toHaveLength(1);
      expect(
        screen.getAllByRole("group", { name: `Match rule ${n}` }),
      ).toHaveLength(1);
      expect(
        screen.getAllByRole("checkbox", {
          name: new RegExp(`^Match ${n}: arch 0 `),
        }),
      ).toHaveLength(1);
    }
  });

  it("names Arch codes as a group of checkboxes, not the first one", () => {
    open();
    const row = screen.getByRole("group", { name: "Match rule 1" });
    const arch = within(row).getByRole("group", {
      name: "Match 1: Arch codes (option 93)",
    });
    expect(within(arch).getAllByRole("checkbox").length).toBeGreaterThan(2);
    // The first checkbox's name is its own, not the whole list.
    const first = within(arch).getAllByRole("checkbox")[0];
    expect(first.getAttribute("aria-label")).toMatch(/^Match 1: arch 0 · /);
  });
});
