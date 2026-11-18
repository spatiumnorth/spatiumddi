/**
 * @vitest-environment jsdom
 *
 * Apply a template to an existing zone (#2183): the preview is shown before
 * anything is written, and a conflict is applied only by an explicit
 * "leave alone" choice (skip_conflicts).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type {
  ApplyTemplatePreview,
  DNSZone,
  ZoneTemplateCatalog,
} from "@/lib/api";

const catalog: ZoneTemplateCatalog = {
  templates: [
    {
      id: "tls-rpt",
      name: "TLS-RPT reporting",
      category: "Mail",
      description: "d",
      record_count: 1,
      version: "1",
      source: "https://www.rfc-editor.org/rfc/rfc8460",
      parameters: [
        {
          key: "rua",
          label: "Report address",
          type: "string",
          required: true,
          default: null,
          placeholder: null,
          hint: null,
        },
      ],
    },
    {
      id: "k8s-external-dns",
      name: "Kubernetes external-dns target",
      category: "Kubernetes",
      description: "d",
      record_count: 0,
      parameters: [],
    },
  ],
};
const item = (status: "add" | "conflict") => ({
  name: "_smtp._tls",
  record_type: "TXT",
  value: "v=TLSRPTv1; rua=mailto:t@example.com",
  ttl: 3600,
  priority: null,
  weight: null,
  port: null,
  status,
  reason: status === "conflict" ? "already publishes v=tlsrptv1" : null,
  existing_id: null,
});
let nextPreview: ApplyTemplatePreview;
const previewFn = vi.fn((..._a: unknown[]) => Promise.resolve(nextPreview));
const applyFn = vi.fn((..._a: unknown[]) =>
  Promise.resolve({
    zone_id: "z1",
    template_id: "tls-rpt",
    created: 0,
    present: 0,
    skipped: [],
    target_serial: null,
  }),
);

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    dnsApi: {
      ...actual.dnsApi,
      listZoneTemplates: () => Promise.resolve(catalog),
      previewApplyTemplate: (...a: unknown[]) => previewFn(...a),
      applyTemplate: (...a: unknown[]) => applyFn(...a),
    },
  };
});

const { ApplyTemplateModal } = await import("./ApplyTemplateModal");

function open() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <ApplyTemplateModal
        groupId="g1"
        zone={{ id: "z1", name: "example.com." } as DNSZone}
        onClose={() => {}}
      />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  previewFn.mockClear();
  applyFn.mockClear();
});

describe("ApplyTemplateModal", { timeout: 30000 }, () => {
  it("hides record-less templates and previews before applying", async () => {
    nextPreview = {
      zone_id: "z1",
      zone_name: "example.com.",
      template_id: "tls-rpt",
      template_name: "TLS-RPT reporting",
      template_version: "1",
      source: null,
      items: [item("add")],
      add: 1,
      present: 0,
      conflict: 0,
      unsupported: 0,
    };
    open();
    expect(await screen.findByText("TLS-RPT reporting")).toBeTruthy();
    expect(screen.queryByText("Kubernetes external-dns target")).toBeNull();
    fireEvent.click(screen.getByText("TLS-RPT reporting"));
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const apply = await screen.findByRole(
      "button",
      { name: "Apply 1 record" },
      { timeout: 10000 },
    );
    expect(applyFn).not.toHaveBeenCalled();
    fireEvent.click(apply);
    await waitFor(() => expect(applyFn).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect((applyFn.mock.calls[0] as unknown[])[2]).toMatchObject({
      skip_conflicts: false,
    });
  });

  it("applies past a conflict only as 'leave alone'", async () => {
    nextPreview = {
      zone_id: "z1",
      zone_name: "example.com.",
      template_id: "tls-rpt",
      template_name: "TLS-RPT reporting",
      template_version: "1",
      source: null,
      items: [item("conflict"), { ...item("add"), name: "other" }],
      add: 1,
      present: 0,
      conflict: 1,
      unsupported: 0,
    };
    open();
    fireEvent.click(await screen.findByText("TLS-RPT reporting"));
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const apply = await screen.findByRole(
      "button",
      { name: "Apply 1, leave 1 alone" },
      { timeout: 10000 },
    );
    expect(screen.getByText("already publishes v=tlsrptv1")).toBeTruthy();
    fireEvent.click(apply);
    await waitFor(() => expect(applyFn).toHaveBeenCalledTimes(1), {
      timeout: 10000,
    });
    expect((applyFn.mock.calls[0] as unknown[])[2]).toMatchObject({
      skip_conflicts: true,
    });
  });
});
