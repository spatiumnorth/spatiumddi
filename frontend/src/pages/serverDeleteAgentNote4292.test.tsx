/** @vitest-environment jsdom */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { ConfirmDestroyModal } from "@/pages/dns/ConfirmDestroyModal";
import { DeleteConfirmModal } from "@/pages/dhcp/_shared";
import { deleteServerDescription } from "@/pages/dhcp/serverDeleteCopy";
import {
  SERVER_DELETE_RECIPE_URL,
  ServerDeleteAgentNote,
} from "@/pages/serverDeleteAgentNote";

const noop = () => {};
afterEach(cleanup);

describe("server delete dialogs say a running agent re-registers (#4292)", () => {
  it("DNS dialog carries the note and the recipe link", () => {
    render(
      <ConfirmDestroyModal
        title="Delete DNS Server"
        description={<ServerDeleteAgentNote />}
        checkLabel="x"
        onConfirm={noop}
        onClose={noop}
      />,
    );
    expect(
      screen.getByText(/registers the server again on its next heartbeat/),
    ).toBeTruthy();
    expect(screen.getByRole("link").getAttribute("href")).toBe(
      SERVER_DELETE_RECIPE_URL,
    );
  });
  it("DHCP dialog carries the note and keeps the scopes sentence", () => {
    render(
      <DeleteConfirmModal
        title="Delete DHCP Server"
        description={
          <>
            {deleteServerDescription("kea1")}
            <ServerDeleteAgentNote />
          </>
        }
        onConfirm={noop}
        onClose={noop}
      />,
    );
    expect(
      screen.getByText(/registers the server again on its next heartbeat/),
    ).toBeTruthy();
    expect(screen.getByText(/stay with the group/)).toBeTruthy();
  });
});
