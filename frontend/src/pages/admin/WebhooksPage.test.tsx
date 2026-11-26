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
// What the server holds now; the page's list reads it.
let stored: WebhookSubscription = HOOK;

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
      list: async () => [stored],
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
  stored = HOOK;
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
  return screen.findByRole("dialog", { name: /Edit webhook subscription/ });
}

const maxAttemptsField = (dialog: HTMLElement) =>
  dialog.querySelector<HTMLInputElement>('input[type="number"][max="20"]')!;

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
    const dialog = await openEdit();
    fireEvent.change(maxAttemptsField(dialog), { target: { value: "4" } });
    const body = await save(dialog);
    expect(
      "secret" in body,
      "an untouched field must not send the secret",
    ).toBe(false);
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
    fireEvent.change(maxAttemptsField(dialog), { target: { value: "4" } });
    const body = await save(dialog);
    expect(
      body.secret ?? null,
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

describe("Edit webhook saves only what changed (#4236)", () => {
  it("sends only the changed field, not what another client stored since the list loaded", async () => {
    const dialog = await openEdit();
    // Another client changes the URL and description after the list loaded
    // and the dialog opened; the dialog still holds the old values.
    fireEvent.change(maxAttemptsField(dialog), { target: { value: "4" } });
    update.mockResolvedValue({ ...HOOK, secret_plaintext: null });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(update).toHaveBeenCalled());
    const [, body] = update.mock.calls[0] as [string, Record<string, unknown>];
    expect(body).toEqual({ max_attempts: 4 });
  });

  it("reads the subscription fresh when it opens", async () => {
    stored = { ...HOOK, url: "https://192.0.2.11/b", description: "newer" };
    const dialog = await openEdit();
    expect(
      dialog.querySelector<HTMLInputElement>(
        'input[value="https://192.0.2.11/b"]',
      ),
    ).not.toBeNull();
  });

  it("a Save with nothing changed sends no request and closes", async () => {
    const dialog = await openEdit();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() =>
      expect(
        screen.queryByRole("dialog", { name: /Edit webhook subscription/ }),
      ).toBeNull(),
    );
    expect(update).not.toHaveBeenCalled();
  });
});

describe("Webhooks header (#4373)", () => {
  it("does not promise a signature to every enabled subscription", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <WebhooksPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const p = (await screen.findByText(/Typed-event subscriptions/))
      .textContent as string;
    expect(p).toMatch(/HMAC-signed when the subscription has a secret/);
    expect(p).toMatch(/unsigned when it has none/);
    expect(p).not.toMatch(/receives one\s+HMAC-signed POST/);
  });

  it("does not say the audit-forward webhook ships every audit row (#4890)", async () => {
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <WebhooksPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    const p = (await screen.findByText(/Typed-event subscriptions/))
      .textContent as string;
    expect(p).not.toMatch(/ships every audit row/);
    expect(p).toMatch(/minimum severity and resource type filters/);
  });
});
