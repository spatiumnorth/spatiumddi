/**
 * @vitest-environment jsdom
 *
 * Typing a multi-digit code into the custom-option search box keeps every
 * digit (#1685). Each keystroke used to set the row's code, and an effect
 * then rewrote the box to "<code> —", so "43" became "4 —3" and option 4.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import type { DHCPOption } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  dhcpApi: {
    listOptionCodes: () =>
      Promise.resolve([
        { code: 4, name: "time-servers", kind: "ip", description: "Time" },
        {
          code: 43,
          name: "vendor-encapsulated-options",
          kind: "string",
          description: "Vendor specific",
        },
      ]),
  },
}));

import { DHCPOptionsEditor } from "./DHCPOptionsEditor";

let latest: DHCPOption[] = [];

function Harness() {
  const [v, setV] = useState<DHCPOption[]>([{ code: 0, value: "" }]);
  latest = v;
  return <DHCPOptionsEditor value={v} onChange={setV} />;
}

afterEach(cleanup);

describe("custom option search box", () => {
  it("keeps both digits when typing 43 key by key", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <Harness />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByText(/Custom options/));
    const box = (await screen.findByPlaceholderText(
      "Search code or name…",
    )) as HTMLInputElement;
    fireEvent.change(box, { target: { value: "4" } });
    fireEvent.change(box, { target: { value: box.value + "3" } });
    expect(box.value).toBe("43");
    expect(latest[0].code).toBe(43);
    expect(await screen.findByText("vendor-encapsulated-options")).toBeTruthy();
  });
});
