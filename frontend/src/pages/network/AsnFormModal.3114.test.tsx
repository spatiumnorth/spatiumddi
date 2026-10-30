/**
 * @vitest-environment jsdom
 *
 * The Holder Org hint describes the RDAP refresh job as it ships, not as a follow-up (#3114).
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AsnFormModal } from "./AsnFormModal";

afterEach(cleanup);

describe("AsnFormModal copy (#3114)", () => {
  it("does not call the shipped RDAP refresh job a follow-up", () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <AsnFormModal onClose={() => {}} />
      </QueryClientProvider>,
    );
    const hint = screen.getByText(/RDAP refresh job/);
    expect(hint.textContent).not.toMatch(/follow-up|roadmap|future/i);
    expect(hint.textContent).toMatch(/public ASN/);
  });
});
