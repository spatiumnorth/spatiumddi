/**
 * @vitest-environment jsdom
 *
 * The BIND9 / Kea import tabs upload a file (#3038).
 *
 * The API client defaults to `Content-Type: application/json`, and axios
 * turns a FormData into JSON under that header (a File becomes `{}`), so
 * the preview reached a route that reads form fields and answered 422. The
 * page then rendered the 422's `detail` — an array of objects — as a React
 * child and the error boundary replaced it. These drive the real pages
 * through the real client with only the transport stubbed, so they see the
 * request as the server would.
 */
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { api } from "@/lib/api";
import { DNSImportPage } from "./DNSImportPage";
import { DHCPImportPage } from "./DHCPImportPage";

const GROUP_ID = "11111111-1111-4111-8111-111111111111";

let sent: InternalAxiosRequestConfig[] = [];
let previewStatus: 422 | 400 = 422;
let previewDetail: unknown;
const originalAdapter = api.defaults.adapter;

function respond(
  config: InternalAxiosRequestConfig,
  status: number,
  data: unknown,
) {
  const response = { data, status, statusText: "", headers: {}, config };
  if (status >= 400) {
    return Promise.reject(
      new AxiosError("failed", "ERR_BAD_REQUEST", config, null, response),
    );
  }
  return Promise.resolve(response);
}

beforeEach(() => {
  sent = [];
  previewStatus = 422;
  previewDetail = [
    {
      type: "missing",
      loc: ["body", "file"],
      msg: "Field required",
      input: null,
    },
    {
      type: "missing",
      loc: ["body", "target_group_id"],
      msg: "Field required",
      input: null,
    },
  ];
  api.defaults.adapter = (config) => {
    const url = config.url ?? "";
    sent.push(config);
    if (url.endsWith("/auth/me/permissions"))
      return respond(config, 200, { is_superadmin: true, grants: [] });
    if (url === "/dns/groups")
      return respond(config, 200, [{ id: GROUP_ID, name: "default" }]);
    if (url === "/dhcp/server-groups")
      return respond(config, 200, [{ id: GROUP_ID, name: "default" }]);
    if (url.endsWith("/preview"))
      return respond(config, previewStatus, { detail: previewDetail });
    return respond(config, 200, []);
  };
});

afterEach(() => {
  cleanup();
  api.defaults.adapter = originalAdapter;
});

async function show(page: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{page}</MemoryRouter>
    </QueryClientProvider>,
  );
  await act(async () => {});
  return view;
}

async function fillAndPreview(container: HTMLElement, fileName: string) {
  const file = new File(["{}"], fileName, { type: "application/octet-stream" });
  const input = container.querySelector(
    'input[type="file"]',
  ) as HTMLInputElement;
  fireEvent.change(input, { target: { files: [file] } });
  await waitFor(() =>
    expect(
      screen.getAllByRole("combobox")[0].querySelectorAll("option").length,
    ).toBeGreaterThan(1),
  );
  fireEvent.change(screen.getAllByRole("combobox")[0], {
    target: { value: GROUP_ID },
  });
  const button = screen.getByRole("button", { name: /Preview import/ });
  await waitFor(() =>
    expect((button as HTMLButtonElement).disabled).toBe(false),
  );
  fireEvent.click(button);
  await waitFor(() =>
    expect(sent.some((c) => c.url?.endsWith("/preview"))).toBe(true),
  );
  await act(async () => {});
  return file;
}

function previewRequest() {
  return sent.find((c) => c.url?.endsWith("/preview"))!;
}

describe("BIND9 tab (#3038)", () => {
  it("uploads the archive as multipart form fields", async () => {
    const { container } = await show(<DNSImportPage />);
    const file = await fillAndPreview(container, "named.zip");
    const req = previewRequest();
    expect(req.url).toBe("/dns/import/bind9/preview");
    expect(req.data).toBeInstanceOf(FormData);
    const fd = req.data as FormData;
    expect((fd.get("file") as File).name).toBe(file.name);
    expect(fd.get("target_group_id")).toBe(GROUP_ID);
    expect(String(req.headers.get("Content-Type"))).toContain(
      "multipart/form-data",
    );
  });

  it("shows a 422's array detail as words instead of crashing", async () => {
    const { container } = await show(<DNSImportPage />);
    await fillAndPreview(container, "named.zip");
    expect(await screen.findByText(/file: Field required/)).toBeTruthy();
    expect(screen.getByText(/target_group_id: Field required/)).toBeTruthy();
  });

  it("shows an object detail as words too", async () => {
    previewStatus = 400;
    previewDetail = { field: "file", message: "Archive is empty" };
    const { container } = await show(<DNSImportPage />);
    await fillAndPreview(container, "named.zip");
    expect(await screen.findByText("file: Archive is empty")).toBeTruthy();
  });
});

describe("Kea tab (#3038)", () => {
  it("uploads the config as multipart form fields", async () => {
    const { container } = await show(<DHCPImportPage />);
    const file = await fillAndPreview(container, "kea-dhcp4.conf");
    const req = previewRequest();
    expect(req.url).toBe("/dhcp/import/kea/preview");
    expect(req.data).toBeInstanceOf(FormData);
    const fd = req.data as FormData;
    expect((fd.get("file") as File).name).toBe(file.name);
    expect(fd.get("target_group_id")).toBe(GROUP_ID);
    expect(String(req.headers.get("Content-Type"))).toContain(
      "multipart/form-data",
    );
  });

  it("shows a 422's array detail as words instead of crashing", async () => {
    const { container } = await show(<DHCPImportPage />);
    await fillAndPreview(container, "kea-dhcp4.conf");
    expect(await screen.findByText(/file: Field required/)).toBeTruthy();
  });

  it("shows a plain string detail unchanged", async () => {
    previewStatus = 400;
    previewDetail = "Not valid Kea JSON";
    const { container } = await show(<DHCPImportPage />);
    await fillAndPreview(container, "kea-dhcp4.conf");
    expect(await screen.findByText("Not valid Kea JSON")).toBeTruthy();
  });
});
