/**
 * @vitest-environment jsdom
 *
 * The DHCP option editor's custom-option remove button has a name (#1950).
 * It drew only an X icon, so a screen reader announced it as "button".
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dhcpApi: { ...actual.dhcpApi, listOptionCodes: () => Promise.resolve([]) },
  };
});

const { DHCPOptionsEditor } = await import("@/pages/dhcp/DHCPOptionsEditor");

afterEach(() => cleanup());

describe("DHCPOptionsEditor", () => {
  it("names the remove button on a custom option row", async () => {
    const onChange = vi.fn();
    render(
      <QueryClientProvider client={new QueryClient()}>
        <DHCPOptionsEditor
          value={[{ code: 0, value: "" }]}
          onChange={onChange}
        />
      </QueryClientProvider>,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /Custom options/ }));
    await user.click(screen.getByRole("button", { name: "Remove option" }));
    expect(onChange).toHaveBeenCalledWith([]);
  });
});
