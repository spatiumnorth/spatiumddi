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
  del: vi.fn(),
};

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    settingsApi: {
      ...actual.settingsApi,
      listAuditTargets: () => api.list(),
      updateAuditTarget: (id: string, body: unknown) => api.update(id, body),
      deleteAuditTarget: (id: string) => api.del(id),
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
  api.del.mockReset();
});

describe("webhook secrets in the target form", () => {
  it("keeps the stored URL and header when both are left blank", async () => {
    await openEdit();
    // Something else must change, or Save sends nothing at all (#3926).
    fireEvent.change(screen.getByDisplayValue("collector"), {
      target: { value: "collector2" },
    });
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

describe("Teams flavor", () => {
  // The Office 365 "Incoming Webhook" connector is retired (#1504); the
  // form must send operators to a Workflows webhook instead.
  it("points at a Workflows webhook, not the retired connector", async () => {
    await openEdit();
    fireEvent.change(screen.getByDisplayValue("Generic JSON"), {
      target: { value: "teams" },
    });
    expect(
      screen.getByRole("option", {
        name: "Microsoft Teams (Workflows / Adaptive Card)",
      }),
    ).toBeTruthy();
    expect(
      screen.getByText(/Workflows app .* “Send webhook alerts to a channel”/),
    ).toBeTruthy();
    expect(screen.queryByText(/MessageCard/)).toBeNull();
  });
});

describe("SMTP password in the target form (#3927)", () => {
  const SMTP = {
    ...TARGET,
    kind: "smtp",
    url_set: false,
    auth_header_set: false,
    smtp_host: "smtp.example.test",
    smtp_username: "u",
    smtp_password_set: true,
    smtp_from_address: "a@example.test",
    smtp_to_addresses: ["b@example.test"],
  };

  async function openSmtp() {
    api.list.mockResolvedValue([SMTP]);
    api.update.mockResolvedValue(SMTP);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <AuditForwardTargets isSuperadmin />
      </QueryClientProvider>,
    );
    await screen.findByText("collector");
    fireEvent.click(screen.getByTitle("Edit"));
    await screen.findByPlaceholderText(/stored — leave blank/);
  }

  it("does not send a blank password, even after typing and erasing", async () => {
    await openSmtp();
    const input = screen.getByPlaceholderText(/stored — leave blank/);
    fireEvent.change(input, { target: { value: "x" } });
    fireEvent.change(input, { target: { value: "" } });
    fireEvent.change(screen.getByDisplayValue("collector"), {
      target: { value: "collector2" },
    });
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect("smtp_password" in body).toBe(false);
  });

  it("clears the password only via the explicit checkbox", async () => {
    await openSmtp();
    fireEvent.click(screen.getByLabelText("Remove the stored password"));
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    const body = api.update.mock.calls[0][1] as Record<string, unknown>;
    expect(body.smtp_password).toBe("");
  });
});

describe("Edit saves only what changed (#3926)", () => {
  it("reads the target fresh and does not put back another client's change", async () => {
    api.list.mockResolvedValue([TARGET]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <AuditForwardTargets isSuperadmin />
      </QueryClientProvider>,
    );
    await screen.findByText("collector");
    // Another client renamed it and switched the flavor after the list loaded.
    const theirs = { ...TARGET, name: "renamed", webhook_flavor: "slack" };
    api.list.mockResolvedValue([theirs]);
    api.update.mockResolvedValue(theirs);
    fireEvent.click(screen.getByTitle("Edit"));
    await screen.findByDisplayValue("renamed");
    fireEvent.change(screen.getByDisplayValue("Enabled"), {
      target: { value: "0" },
    });
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    expect(api.update).toHaveBeenCalledWith("t1", { enabled: false });
  });

  it("sends nothing when nothing changed", async () => {
    await openEdit();
    await act(async () => {
      fireEvent.click(screen.getByText("Save"));
    });
    expect(api.update).not.toHaveBeenCalled();
  });
});

describe("a refused delete (#3822)", () => {
  it("says why in an alert and reads the list again", async () => {
    api.list.mockResolvedValue([TARGET]);
    const qc = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={qc}>
        <AuditForwardTargets isSuperadmin />
      </QueryClientProvider>,
    );
    await screen.findByText("collector");
    api.del.mockRejectedValue({
      response: { status: 404, data: { detail: "Target not found" } },
    });
    fireEvent.click(screen.getByTitle("Delete"));
    const before = api.list.mock.calls.length;
    await act(async () => {
      fireEvent.click(
        screen.getAllByRole("button", { name: "Delete" }).slice(-1)[0],
      );
    });
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("Target not found");
    expect(api.list.mock.calls.length).toBeGreaterThan(before);
  });
});
