/**
 * @vitest-environment jsdom
 *
 * The backup target form keeps a multi-line value's line breaks (#2199).
 *
 * Every config field used to be an `<input>`, and an input cannot hold a
 * line break: the browser folds each one into a space. So an SCP private
 * key reached paramiko as one line ("not a valid OPENSSH private key
 * file"), a two-host known_hosts became one entry, and a second HTTPS
 * header folded into the first header's value. A field the catalog marks
 * `multiline` is now a textarea, and what is typed is what is sent.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { BackupTarget, BackupTargetKind } from "@/lib/api";

const list = vi.fn<() => Promise<BackupTarget[]>>();
const listKinds = vi.fn<() => Promise<BackupTargetKind[]>>();
const create = vi.fn();
const update = vi.fn();

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return {
    formatApiError: actual.formatApiError,
    backupTargetsApi: { list, listKinds, create, update },
  };
});
vi.mock("./BackupSectionsPicker", () => ({ BackupSectionsPicker: () => null }));

const { BackupTargetsSection } = await import("./BackupTargetsSection");

function withClient(ui: ReactElement) {
  return render(
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: {
            queries: { retry: false },
            mutations: { retry: false },
          },
        })
      }
    >
      {ui}
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// The four fields the backend catalog marks multiline, as it sends them.
const KINDS: BackupTargetKind[] = [
  {
    kind: "scp",
    label: "SCP / SFTP",
    inherently_write_only: false,
    config_fields: [
      {
        name: "host",
        label: "Host",
        type: "text",
        required: true,
        description: null,
        secret: false,
      },
      {
        name: "private_key",
        label: "Private key (PEM)",
        type: "password",
        required: false,
        description: "Paste the entire PEM-encoded key.",
        secret: true,
        multiline: true,
      },
      {
        name: "known_hosts",
        label: "known_hosts content",
        type: "text",
        required: false,
        description: "OpenSSH known_hosts file content.",
        secret: false,
        multiline: true,
      },
    ],
  },
  {
    kind: "https_put",
    label: "HTTPS PUT / POST",
    inherently_write_only: true,
    config_fields: [
      {
        name: "extra_headers",
        label: "Extra headers",
        type: "text",
        required: false,
        description: "Optional, one 'Name: value' per line.",
        secret: false,
        multiline: true,
      },
    ],
  },
  {
    kind: "gcs",
    label: "Google Cloud Storage",
    inherently_write_only: false,
    config_fields: [
      {
        name: "service_account_json",
        label: "Service-account key JSON",
        type: "password",
        required: true,
        description: null,
        secret: true,
        multiline: true,
      },
    ],
  },
];

const PEM =
  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
  "QyNTUxOQAAACD0\n" +
  "-----END OPENSSH PRIVATE KEY-----\n";
const KNOWN_HOSTS =
  "a.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA\n" +
  "b.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB";
const HEADERS = "X-One: 1\nX-Two: 2";
const SA_JSON = '{\n  "type": "service_account",\n  "project_id": "p"\n}';

async function openCreate(kind: string) {
  list.mockResolvedValue([]);
  listKinds.mockResolvedValue(KINDS);
  create.mockResolvedValue({});
  const view = withClient(<BackupTargetsSection />);
  fireEvent.click(await screen.findByText("Add target"));
  const select = (await screen.findByDisplayValue(
    /\(scp\)|\(https_put\)|\(gcs\)/,
  )) as HTMLSelectElement;
  fireEvent.change(select, { target: { value: kind } });
  return view;
}

function field(container: HTMLElement, name: string): HTMLTextAreaElement {
  const el = container.querySelector(`[name="${name}"]`);
  expect(el, `${name} is rendered`).not.toBeNull();
  expect(el!.tagName, `${name} is a multi-line control`).toBe("TEXTAREA");
  return el as HTMLTextAreaElement;
}

async function submit(container: HTMLElement) {
  fireEvent.change(container.querySelector('input[type="text"]')!, {
    target: { value: "t1" },
  });
  const pass = Array.from(
    container.querySelectorAll('input[type="password"]'),
  ).at(-1) as HTMLInputElement;
  fireEvent.change(pass, { target: { value: "passphrase-123" } });
  fireEvent.submit(container.querySelector("form")!);
  await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
  return create.mock.calls[0][0] as { config: Record<string, string> };
}

describe("backup target form keeps line breaks (#2199)", () => {
  it("SCP private key and known_hosts are textareas and go out unchanged", async () => {
    const { container } = await openCreate("scp");
    await waitFor(() => field(container, "private_key"));
    const key = field(container, "private_key");
    const hosts = field(container, "known_hosts");
    fireEvent.change(key, { target: { value: PEM } });
    fireEvent.change(hosts, { target: { value: KNOWN_HOSTS } });
    // Read back with the line breaks.
    expect(key.value).toBe(PEM);
    expect(hosts.value).toBe(KNOWN_HOSTS);
    // The secret one is masked, and only the secret one.
    expect(key.dataset.masked).toBe("true");
    expect(hosts.dataset.masked).toBe("false");
    // Masked like a password input: copying it out is refused, and the
    // Show toggle reveals it (and copying is then allowed again).
    expect(fireEvent.copy(key)).toBe(false);
    expect(fireEvent.copy(hosts)).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Show" }));
    expect(key.dataset.masked).toBe("false");
    expect(fireEvent.copy(key)).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Hide" }));
    expect(key.dataset.masked).toBe("true");
    const body = await submit(container);
    expect(body.config.private_key).toBe(PEM);
    expect(body.config.known_hosts).toBe(KNOWN_HOSTS);
  });

  it("HTTPS extra headers keep one header per line", async () => {
    const { container } = await openCreate("https_put");
    await waitFor(() => field(container, "extra_headers"));
    const headers = field(container, "extra_headers");
    fireEvent.change(headers, { target: { value: HEADERS } });
    expect(headers.value).toBe(HEADERS);
    const body = await submit(container);
    expect(body.config.extra_headers).toBe(HEADERS);
  });

  it("GCS service-account JSON is a masked textarea", async () => {
    const { container } = await openCreate("gcs");
    await waitFor(() => field(container, "service_account_json"));
    const sa = field(container, "service_account_json");
    expect(sa.dataset.masked).toBe("true");
    fireEvent.change(sa, { target: { value: SA_JSON } });
    const body = await submit(container);
    expect(body.config.service_account_json).toBe(SA_JSON);
  });

  it("a one-line field stays an input", async () => {
    const { container } = await openCreate("scp");
    await waitFor(() => field(container, "private_key"));
    expect(container.querySelector("textarea[name=host]")).toBeNull();
  });

  it("editing without retyping keeps the stored key and the stored lines", async () => {
    // The API redacts a secret to "<set>"; the form blanks it so the merge
    // keeps the stored key. A non-secret multi-line value comes back with
    // its line breaks and must go out with them, not flattened by a save
    // that touched a different field.
    list.mockResolvedValue([
      {
        id: "t-1",
        name: "scp1",
        description: "",
        kind: "scp",
        enabled: true,
        config: {
          host: "h",
          private_key: "<set>",
          known_hosts: KNOWN_HOSTS,
        },
        passphrase_set: true,
        passphrase_hint: "",
        schedule_cron: null,
        retention_keep_last_n: null,
        retention_keep_days: null,
        write_only: false,
        last_run_status: null,
        last_run_at: null,
        last_run_filename: null,
        last_run_node: null,
        last_run_bytes: null,
        last_run_duration_ms: null,
        last_run_error: null,
        next_run_at: null,
        drill_enabled: false,
        drill_cron: null,
        drill_next_run_at: null,
        drill_last_status: "never",
        drill_last_at: null,
        created_at: "2026-10-13T00:00:00Z",
        modified_at: "2026-10-13T00:00:00Z",
      } as unknown as BackupTarget,
    ]);
    listKinds.mockResolvedValue(KINDS);
    update.mockResolvedValue({});
    const { container } = withClient(<BackupTargetsSection />);
    fireEvent.click(await screen.findByTitle("Edit"));
    await waitFor(() => field(container, "private_key"));
    await waitFor(() => expect(field(container, "private_key").value).toBe(""));
    expect(field(container, "known_hosts").value).toBe(KNOWN_HOSTS);
    fireEvent.change(container.querySelector('input[type="text"]')!, {
      target: { value: "scp1-renamed" },
    });
    fireEvent.submit(container.querySelector("form")!);
    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    const body = update.mock.calls[0][1] as { config: Record<string, string> };
    expect(body.config.private_key).toBe("");
    expect(body.config.known_hosts).toBe(KNOWN_HOSTS);
  });
});
