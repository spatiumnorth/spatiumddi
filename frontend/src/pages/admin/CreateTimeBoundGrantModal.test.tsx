/**
 * @vitest-environment jsdom
 *
 * The time-bound grant dialog offers what the role editor offers (#1631).
 *
 * The role editor learned `approve` and `change_request` so a custom Change
 * Approver role can be saved; the grant dialog kept its own lists and offered
 * neither, so a temporary approver grant could only be made through the API.
 * Both now read one vocabulary.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { CreateTimeBoundGrantModal } from "./CreateTimeBoundGrantModal";
import {
  GRANT_ACTIONS,
  GRANT_RESOURCE_TYPES,
} from "@/lib/permissionVocabulary";

afterEach(cleanup);

function optionValues(select: HTMLElement): string[] {
  return Array.from(select.querySelectorAll("option")).map((o) => o.value);
}

describe("CreateTimeBoundGrantModal", () => {
  it("offers approve and change_request, like the role editor", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <CreateTimeBoundGrantModal
          groupId="g1"
          groupName="Approvers"
          onClose={() => {}}
        />
      </QueryClientProvider>,
    );
    const selects = screen.getAllByRole("combobox");
    const values = selects.map(optionValues);
    const actions = values.find(
      (v) => v.includes("read") && v.includes("write"),
    );
    const types = values.find((v) => v.includes("subnet"));
    expect(actions).toBeDefined();
    expect(types).toBeDefined();
    expect(actions).toContain("approve");
    expect(types).toContain("change_request");
    expect(actions).toEqual([...GRANT_ACTIONS]);
    expect(types).toEqual([...GRANT_RESOURCE_TYPES]);
  });
});
