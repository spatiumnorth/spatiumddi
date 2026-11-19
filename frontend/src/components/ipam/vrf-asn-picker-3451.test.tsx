/**
 * @vitest-environment jsdom
 *
 * VRF / ASN pickers for a user who cannot read the list (#3451): disabled
 * with a reason, the list never asked, an existing link shown as linked.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const answers: Record<
  string,
  Record<string, (...a: unknown[]) => unknown>
> = {};
const vrfList = vi.fn(() => Promise.resolve([]));
const asnList = vi.fn(() => Promise.resolve({ items: [] }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      myPermissions: () => answers.authApi.myPermissions(),
    },
    vrfsApi: { list: () => vrfList() },
    asnsApi: { list: () => asnList() },
  };
});

import { VrfPicker } from "./vrf-picker";
import { AsnPicker } from "./asn-picker";

function signInAs(grants: [string, string][]) {
  answers.authApi = {
    myPermissions: () =>
      Promise.resolve({
        is_superadmin: false,
        grants: grants.map(([action, resource_type]) => ({
          action,
          resource_type,
          resource_id: null,
        })),
      }),
  };
}

function wrap(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vrfList.mockClear();
  asnList.mockClear();
});

describe("VRF / ASN pickers without read (#3451)", () => {
  it("VRF: disabled, reasoned, shows the link, never asks", async () => {
    signInAs([["read", "ip_space"]]);
    wrap(<VrfPicker value="v1" onChange={() => {}} />);
    const sel = (await screen.findByRole("combobox")) as HTMLSelectElement;
    await waitFor(() => expect(sel.disabled).toBe(true));
    expect(sel.title).toContain("cannot read VRFs");
    expect(sel.selectedOptions[0].textContent).toBe(
      "Linked (not visible to your role)",
    );
    expect(vrfList).not.toHaveBeenCalled();
  });

  it("ASN: unlinked shows None, disabled", async () => {
    signInAs([["read", "ip_space"]]);
    wrap(<AsnPicker value={null} onChange={() => {}} />);
    const sel = (await screen.findByRole("combobox")) as HTMLSelectElement;
    await waitFor(() => expect(sel.disabled).toBe(true));
    expect(sel.selectedOptions[0].textContent).toBe("— None —");
    expect(asnList).not.toHaveBeenCalled();
  });

  it("with the grants the pickers are enabled and ask", async () => {
    signInAs([
      ["read", "vrf"],
      ["read", "manage_asns"],
    ]);
    wrap(
      <>
        <VrfPicker value={null} onChange={() => {}} />
        <AsnPicker value={null} onChange={() => {}} />
      </>,
    );
    await waitFor(() => {
      expect(vrfList).toHaveBeenCalled();
      expect(asnList).toHaveBeenCalled();
    });
    for (const s of screen.getAllByRole("combobox"))
      expect((s as HTMLSelectElement).disabled).toBe(false);
  });
});
