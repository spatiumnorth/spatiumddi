/**
 * @vitest-environment jsdom
 *
 * ListEmpty is the one place a list page puts its empty-state copy (#1865).
 */

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ListEmpty } from "./list-read-error";

function httpError(status: number, detail: string) {
  return Object.assign(new Error(`Request failed with status code ${status}`), {
    isAxiosError: true,
    status,
    response: { status, data: { detail } },
  });
}

afterEach(cleanup);

describe("ListEmpty", () => {
  it("says the list is empty when the read succeeded", () => {
    render(
      <ListEmpty error={null} what="VRFs">
        No VRFs yet.
      </ListEmpty>,
    );
    expect(screen.getByText("No VRFs yet.")).toBeTruthy();
  });

  it("says the reader may not see it when the read was refused", () => {
    render(
      <ListEmpty
        error={httpError(403, "Permission denied: need 'read' on 'vrf'")}
        what="VRFs"
      >
        No VRFs yet.
      </ListEmpty>,
    );
    expect(screen.queryByText("No VRFs yet.")).toBeNull();
    expect(
      screen.getByText(
        "You don't have permission to see VRFs (Permission denied: need 'read' on 'vrf').",
      ),
    ).toBeTruthy();
  });

  it("says the list could not be loaded on any other failure", () => {
    render(
      <ListEmpty error={httpError(500, "boom")} what="VRFs">
        No VRFs yet.
      </ListEmpty>,
    );
    expect(screen.queryByText("No VRFs yet.")).toBeNull();
    expect(screen.getByText(/Couldn't load VRFs/)).toBeTruthy();
  });
});

describe("ListEmpty with a filter active (#2616)", () => {
  it("says the filter matches nothing, not that the list is empty", () => {
    render(
      <ListEmpty error={null} what="domains" filtered>
        No domains yet.
      </ListEmpty>,
    );
    expect(screen.queryByText(/No domains yet/)).toBeNull();
    expect(screen.getByText(/No domains match the current search or filter/));
  });

  it("offers to clear the filter", () => {
    const clear = vi.fn();
    render(
      <ListEmpty error={null} what="domains" filtered onClearFilters={clear}>
        No domains yet.
      </ListEmpty>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(clear).toHaveBeenCalledTimes(1);
  });

  it("keeps the yet copy when no filter is active", () => {
    render(
      <ListEmpty error={null} what="domains" filtered={false}>
        No domains yet.
      </ListEmpty>,
    );
    expect(screen.getByText("No domains yet.")).toBeTruthy();
  });
});
