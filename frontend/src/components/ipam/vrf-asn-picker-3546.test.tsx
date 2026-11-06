/**
 * @vitest-environment jsdom
 *
 * VRF / ASN pickers when the permissions read failed (#3546): the control
 * says the permissions could not be read instead of reading as a role that
 * cannot read the list, and still sends the unchanged id (disabled).
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

const vrfList = vi.fn(() => Promise.resolve([]));
const asnList = vi.fn(() => Promise.resolve({ items: [] }));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    authApi: {
      myPermissions: () => Promise.reject(new Error("Network Error")),
    },
    vrfsApi: { list: () => vrfList() },
    asnsApi: { list: () => asnList() },
  };
});

import { VrfPicker } from "./vrf-picker";
import { AsnPicker } from "./asn-picker";

function wrap(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

afterEach(cleanup);

describe("pickers after a failed permissions read (#3546)", () => {
  it("VRF: disabled and says the permissions could not be read", async () => {
    wrap(<VrfPicker value="v1" onChange={() => {}} />);
    await waitFor(() =>
      expect(
        (screen.getByRole("combobox") as HTMLSelectElement).title,
      ).toContain("could not be read"),
    );
    const sel = screen.getByRole("combobox") as HTMLSelectElement;
    expect(sel.disabled).toBe(true);
    expect(sel.title).not.toContain("Your role");
    expect(sel.selectedOptions[0].textContent).toBe(
      "Linked (could not be read)",
    );
    expect(vrfList).not.toHaveBeenCalled();
  });

  it("ASN: unlinked shows the failure, not an empty None", async () => {
    wrap(<AsnPicker value={null} onChange={() => {}} />);
    await waitFor(() =>
      expect(
        (screen.getByRole("combobox") as HTMLSelectElement).title,
      ).toContain("could not be read"),
    );
    const sel = screen.getByRole("combobox") as HTMLSelectElement;
    expect(sel.title).toContain("could not be read");
    expect(sel.selectedOptions[0].textContent).toContain("could not be read");
    expect(asnList).not.toHaveBeenCalled();
  });
});
