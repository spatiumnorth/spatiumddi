/**
 * @vitest-environment jsdom
 *
 * Edit webhook: the Rotate secret field does what its hint says, and the
 * stored secret can be removed (#1397).
 *
 * The hint read "Leave blank to keep the stored secret. Type a new one to
 * rotate; clearing the field stores no secret (HMAC header omitted)." The
 * field always opens empty, and an empty field is sent as `secret: null`,
 * which the API reads as "keep" (only `""` clears; webhooks/router.py). So
 * clearing the field and leaving it alone sent the same request, and the
 * console had no way to store "no secret" at all.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import type { WebhookSubscription } from "@/lib/api";

const HOOK: WebhookSubscription = {
  id: "wh-1",
  name: "ops-automation",
  description: "",
  enabled: false,
  url: "https://192.0.2.1/hook",
  secret_set: true,
  event_types: null,
  header_names: [],
  headers_set: false,
  timeout_seconds: 5,
  max_attempts: 1,
  created_at: "2026-10-06T00:00:00Z",
  modified_at: "2026-10-06T00:00:00Z",
};

const update = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    // An administrator's page: the permissions self-check answers as a
    // superadmin, so write actions gated on it are offered.
    authApi: {
      ...actual.authApi,
      myPermissions: async () => ({ is_superadmin: true, grants: [] }),
    },
    webhooksApi: {
      ...actual.webhooksApi,
      list: async () => [HOOK],
      listEventTypes: async () => ["ip_address.created"],
      listDeliveries: () => new Promise(() => {}),
      update: (...args: unknown[]) => update(...args),
    },
  };
});

const { WebhooksPage } = await import("./WebhooksPage");

afterEach(() => {
  cleanup();
  update.mockReset();
});

async function openEdit(): Promise<HTMLElement> {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/admin/webhooks"]}>
        <WebhooksPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(await screen.findByRole("button", { name: /Edit/ }));
  return screen.getByRole("dialog", { name: /Edit webhook subscription/ });
}

/** Save the dialog; the body the PUT carried. */
async function save(dialog: HTMLElement): Promise<{ secret?: string | null }> {
  update.mockResolvedValue({ ...HOOK, secret_plaintext: null });
  fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
  await waitFor(() => expect(update).toHaveBeenCalled());
  const [id, body] = update.mock.calls[0] as [
    string,
    { secret?: string | null },
  ];
  expect(id).toBe("wh-1");
  return body;
}

const secretField = (dialog: HTMLElement) =>
  dialog.querySelector<HTMLInputElement>('input[type="password"]')!;

describe("Edit webhook: the stored secret", () => {
  it("an untouched Rotate secret field keeps it (control)", async () => {
    const body = await save(await openEdit());
    expect(body.secret, "an untouched field must keep the secret").toBeNull();
  });

  it("a typed secret rotates it (control)", async () => {
    const dialog = await openEdit();
    fireEvent.change(secretField(dialog), {
      target: { value: "rotated-0002" },
    });
    expect((await save(dialog)).secret).toBe("rotated-0002");
  });

  it("the hint is true of what clearing the field sends", async () => {
    const dialog = await openEdit();
    const hint = (dialog.textContent ?? "").replace(/\s+/g, " ");
    // The ddi-pg check's reading of the hint: does it promise that clearing
    // the field leaves the subscription with no secret?
    const promisesClear =
      /clear\w*[^.]*\b(stores? no secret|no secret|removes?|deletes?|unsigned|no (HMAC|signature))/i.test(
        hint,
      );
    fireEvent.change(secretField(dialog), { target: { value: "x" } });
    fireEvent.change(secretField(dialog), { target: { value: "" } });
    const body = await save(dialog);
    expect(
      body.secret,
      promisesClear
        ? `the hint says clearing the field stores no secret, but Save sent ${JSON.stringify(body.secret)}, which keeps it: "${hint}"`
        : "a cleared field is a blank field: the hint says blank keeps the secret",
    ).toBe(promisesClear ? "" : null);
  });

  it("the dialog can remove the stored secret", async () => {
    const dialog = await openEdit();
    const remove = within(dialog).queryByRole("checkbox", {
      name: /remove the stored secret/i,
    });
    expect(
      remove,
      "the Edit dialog offers no way to remove a webhook's secret: an empty " +
        "field keeps it, and the API clears it only on an empty string",
    ).not.toBeNull();
    fireEvent.click(remove!);
    expect(
      secretField(dialog).disabled,
      "while the secret is being removed, no new one can be typed",
    ).toBe(true);
    expect((await save(dialog)).secret).toBe("");
  });
});
