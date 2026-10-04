/**
 * @vitest-environment jsdom
 *
 * A webhook target's URL and Authorization header are write-only (#1502).
 *
 * The server never returns either (only ``url_set`` / ``url_display`` /
 * ``auth_header_set``), so the edit form always starts with both empty. An
 * empty field on save must therefore mean "keep what's stored": the form
 * used to send nothing for the header, which the server took as "clear",
 * so every edit of a generic target silently wiped it.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { AuditForwardTarget } from "@/lib/api";

const api = {
  list: vi.fn(),
  update: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      ...actual.settingsApi,
      listAuditTargets: () => api.list(),
      updateAuditTarget: (id: string, body: unknown) => api.update(id, body),
    },
  };
});

const { AuditForwardTargets } =
  await import("@/components/AuditForwardTargets");

const TARGET: AuditForwardTarget = {
  id: "t1",
  name: "collector",
  enabled: true,
  kind: "webhook",
  format: "rfc5424_json",
  host: "",
  port: 514,
  protocol: "udp",
  facility: 16,
  ca_cert_pem: null,
  url_set: true,
  url_display: "https://collector.example.test/…",
  auth_header_set: true,
  webhook_flavor: "generic",
  smtp_host: "",
  smtp_port: 587,
  smtp_security: "starttls",
  smtp_username: "",
  smtp_password_set: false,
  smtp_from_address: "",
  smtp_to_addresses: null,
  smtp_reply_to: "",
  min_severity: null,
  resource_types: null,
  created_at: "2026-10-01T00:00:00Z",
  modified_at: "2026-10-01T00:00:00Z",
};

async function openEdit() {
  api.list.mockResolvedValue([TARGET]);
  api.update.mockResolvedValue(TARGET);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <AuditForwardTargets isSuperadmin />
    </QueryClientProvider>,
  );
  // The table shows the host only.
  await screen.findByText("https://collector.example.test/…");
  fireEvent.click(screen.getByTitle("Edit"));
  await screen.findByText(/Stored: https:\/\/collector\.example\.test\/…/);
}

afterEach(() => {
  cleanup();
  api.list.mockReset();
  api.update.mockReset();
});

describe("webhook secrets in the target form", () => {
  it("keeps the stored URL and header when both are left blank", async () => {
    await openEdit();
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    expect(api.update).toHaveBeenCalledTimes(1);
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect("url" in body).toBe(false);
    expect("auth_header" in body).toBe(false);
  });

  it("clears the header only when asked to", async () => {
    await openEdit();
    fireEvent.click(screen.getByLabelText("Remove the stored header"));
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect(body.auth_header).toBe("");
    expect("url" in body).toBe(false);
  });
});
