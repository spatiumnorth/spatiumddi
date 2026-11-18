/**
 * @vitest-environment jsdom
 *
 * Editing an integration's address re-asks for its stored credential in the
 * form (#4135): the credential field is required, Save is held until it is
 * entered, editing a description does not ask, and changing the address back
 * restores "stored". The API's 422 stays the backstop.
 */
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type {
  BackupTarget,
  BackupTargetKind,
  DNSServer,
  NetworkDeviceRead,
  WebhookSubscription,
} from "@/lib/api";

const updateDevice = vi.fn();
const updateServer = vi.fn();
const updateSub = vi.fn();
const updateTarget = vi.fn();
const listTargets = vi.fn<() => Promise<BackupTarget[]>>();
const listKinds = vi.fn<() => Promise<BackupTargetKind[]>>();
const updateProvider = vi.fn();

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    networkApi: {
      ...actual.networkApi,
      updateDevice: (...a: unknown[]) => updateDevice(...a),
      listSpaces: () => Promise.resolve([]),
    },
    ipamApi: { ...actual.ipamApi, listSpaces: () => Promise.resolve([]) },
    dnsApi: {
      ...actual.dnsApi,
      listGroups: () => Promise.resolve([]),
      listServers: () => Promise.resolve([TECH]),
      updateServer: (...a: unknown[]) => updateServer(...a),
    },
    webhooksApi: {
      ...actual.webhooksApi,
      updateSubscription: (...a: unknown[]) => updateSub(...a),
    },
    authApi: {
      ...actual.authApi,
      me: () => Promise.resolve({ is_superadmin: true }),
      myPermissions: () => Promise.resolve({ is_superadmin: true, grants: [] }),
    },
    authProvidersApi: {
      ...actual.authProvidersApi,
      list: () => Promise.resolve([LDAP]),
      update: (...a: unknown[]) => updateProvider(...a),
      listMappings: () => Promise.resolve([]),
    },
    aiApi: {
      ...actual.aiApi,
      listProviders: () => Promise.resolve([AIP]),
      getDefaultSystemPrompt: async () => "",
    },
    backupTargetsApi: {
      list: () => listTargets(),
      listKinds: () => listKinds(),
      update: (...a: unknown[]) => updateTarget(...a),
    },
  };
});
vi.mock("./admin/BackupSectionsPicker", () => ({
  BackupSectionsPicker: () => null,
}));

const { DeviceFormModal } = await import("./network/DeviceFormModal");
const { ServerModal } = await import("./dns/DNSPage");
const { SubscriptionEditor } = await import("./admin/WebhooksPage");
const { BackupTargetsSection } = await import("./admin/BackupTargetsSection");
const { AuthProvidersPage } = await import("./admin/AuthProvidersPage");
const { AIProvidersPage } = await import("./admin/AIProvidersPage");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function wrap(node: React.ReactNode) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const type = (el: HTMLElement, value: string) =>
  fireEvent.change(el, { target: { value } });

const saveBtn = (name = "Save") =>
  screen.getByRole("button", { name }) as HTMLButtonElement;

describe("SNMP device (community)", () => {
  const DEVICE = {
    id: "d1",
    name: "sw1",
    hostname: "sw1",
    ip_address: "192.0.2.10",
    device_type: "switch",
    ip_space_id: "sp1",
    description: "",
    snmp_version: "v2c",
    snmp_port: 161,
    snmp_timeout_seconds: 5,
    snmp_retries: 1,
    has_community: true,
    has_auth_key: false,
    has_priv_key: false,
    v3_security_name: null,
    v3_security_level: null,
    v3_auth_protocol: null,
    v3_priv_protocol: null,
    v3_context_name: null,
    poll_interval_seconds: 300,
    poll_arp: true,
    poll_fdb: true,
    poll_interfaces: true,
    poll_lldp: true,
    auto_create_discovered: false,
    is_active: true,
  } as unknown as NetworkDeviceRead;

  const addr = () => screen.getByDisplayValue("192.0.2.10") as HTMLInputElement;
  const community = () =>
    screen.getByPlaceholderText(/unchanged|re-enter/) as HTMLInputElement;

  it("editing the address requires the community before Save", () => {
    wrap(<DeviceFormModal device={DEVICE} onClose={() => {}} />);
    expect(saveBtn().disabled).toBe(false);
    expect(community().placeholder).toMatch(/unchanged/);
    type(addr(), "192.0.2.99");
    expect(saveBtn().disabled).toBe(true);
    expect(community().placeholder).toMatch(/re-enter for the new address/);
    expect(community().required).toBe(true);
    expect(document.body.textContent).toMatch(/Re-enter the credential/);
    type(community(), "s3cret");
    expect(saveBtn().disabled).toBe(false);
  });

  it("changing the address back restores stored", () => {
    wrap(<DeviceFormModal device={DEVICE} onClose={() => {}} />);
    const a = addr();
    type(a, "192.0.2.99");
    type(community(), "typed-for-the-new-address");
    type(a, "192.0.2.10");
    expect(community().value).toBe("");
    expect(community().placeholder).toMatch(/unchanged/);
    expect(saveBtn().disabled).toBe(false);
  });

  it("editing only the description does not ask", () => {
    wrap(<DeviceFormModal device={DEVICE} onClose={() => {}} />);
    const desc = screen
      .getAllByRole("textbox")
      .find((e) => e.tagName === "TEXTAREA");
    if (desc) type(desc, "core switch");
    expect(saveBtn().disabled).toBe(false);
    expect(community().placeholder).toMatch(/unchanged/);
  });
});

describe("webhook subscription (custom headers)", () => {
  const SUB = {
    id: "w1",
    name: "ops",
    description: "",
    enabled: true,
    url: "https://hooks.example/a",
    secret_set: true,
    event_types: null,
    header_names: ["Authorization"],
    headers_set: true,
    timeout_seconds: 10,
    max_attempts: 8,
  } as unknown as WebhookSubscription;

  const url = () =>
    screen.getByDisplayValue("https://hooks.example/a") as HTMLInputElement;
  const headers = () =>
    screen.getByPlaceholderText(
      /stored — leave blank|re-enter/,
    ) as HTMLTextAreaElement;

  it("a new URL requires the headers (or removing them) before Save", () => {
    wrap(
      <SubscriptionEditor
        existing={SUB}
        eventTypeVocab={[]}
        onClose={() => {}}
      />,
    );
    expect(saveBtn().disabled).toBe(false);
    type(url(), "https://hooks.example/b");
    expect(saveBtn().disabled).toBe(true);
    expect(headers().required).toBe(true);
    type(headers(), "Authorization: Bearer new");
    expect(saveBtn().disabled).toBe(false);
    // Removing them is the other way through.
    type(headers(), "");
    expect(saveBtn().disabled).toBe(true);
    fireEvent.click(screen.getByLabelText("Remove all stored headers"));
    expect(saveBtn().disabled).toBe(false);
  });

  it("restoring the URL restores stored, and a description edit does not ask", () => {
    wrap(
      <SubscriptionEditor
        existing={SUB}
        eventTypeVocab={[]}
        onClose={() => {}}
      />,
    );
    type(screen.getByPlaceholderText(/What this receiver does/), "ops hook");
    expect(saveBtn().disabled).toBe(false);
    const u = url();
    type(u, "https://hooks.example/b");
    expect(saveBtn().disabled).toBe(true);
    type(u, "https://hooks.example/a");
    expect(saveBtn().disabled).toBe(false);
    expect(headers().placeholder).toMatch(/stored — leave blank/);
  });
});

const TECH = {
  id: "s1",
  group_id: "g1",
  name: "tech1",
  driver: "technitium_api",
  host: "tech.example",
  port: 5380,
  api_port: null,
  roles: [],
  notes: "",
  is_enabled: true,
  is_primary: false,
  has_credentials: true,
} as unknown as DNSServer;

describe("agentless DNS server (API token)", () => {
  const host = () =>
    screen.getByDisplayValue("tech.example") as HTMLInputElement;
  const token = () =>
    document.querySelector(
      'input[type="password"][placeholder*="unchanged"], input[type="password"][placeholder*="re-enter"]',
    ) as HTMLInputElement;

  it("a new host requires the token before Save; reverting restores stored", async () => {
    wrap(<ServerModal groupId="g1" server={TECH} onClose={() => {}} />);
    await screen.findByDisplayValue("tech.example");
    expect(saveBtn().disabled).toBe(false);
    const h = host();
    type(h, "tech2.example");
    expect(saveBtn().disabled).toBe(true);
    expect(token().placeholder).toMatch(/re-enter for the new address/);
    type(token(), "tok");
    expect(saveBtn().disabled).toBe(false);
    type(h, "tech.example");
    expect(token().value).toBe("");
    expect(token().placeholder).toMatch(/unchanged/);
    expect(saveBtn().disabled).toBe(false);
  });

  it("editing only the notes does not ask", async () => {
    wrap(<ServerModal groupId="g1" server={TECH} onClose={() => {}} />);
    await screen.findByDisplayValue("tech.example");
    type(screen.getByLabelText("Notes"), "lab box");
    expect(saveBtn().disabled).toBe(false);
  });
});

describe("backup target (password)", () => {
  const f = (name: string, label: string, secret = false) => ({
    name,
    label,
    type: secret ? "password" : "text",
    required: false,
    description: null,
    secret,
  });
  const KINDS: BackupTargetKind[] = [
    {
      kind: "ftp",
      label: "FTP",
      inherently_write_only: false,
      config_fields: [
        f("host", "Host"),
        f("port", "Port"),
        f("password", "Password", true),
      ],
    },
  ];
  const TARGET = {
    id: "t1",
    name: "nas",
    description: "",
    kind: "ftp",
    enabled: true,
    config: { host: "ftp.example", port: 21, password: "<set>" },
    passphrase_set: true,
    passphrase_hint: "",
    schedule_cron: null,
    retention_keep_last_n: null,
    retention_keep_days: null,
    write_only: false,
    last_run_status: "never",
    last_run_at: null,
  } as unknown as BackupTarget;

  async function openEdit() {
    listTargets.mockResolvedValue([TARGET]);
    listKinds.mockResolvedValue(KINDS);
    const { container } = wrap(<BackupTargetsSection />);
    fireEvent.click(await screen.findByTitle(/Edit/));
    await screen.findByDisplayValue("ftp.example");
    return container;
  }
  const pass = () =>
    document.querySelector(
      'input[type="password"][autocomplete="new-password"]',
    ) as HTMLInputElement;

  it("a new host requires the password before Save; reverting restores stored", async () => {
    await openEdit();
    const host = screen.getByDisplayValue("ftp.example") as HTMLInputElement;
    expect(saveBtn().disabled).toBe(false);
    expect(pass().placeholder).toMatch(/leave empty to keep/);
    type(host, "ftp2.example");
    expect(saveBtn().disabled).toBe(true);
    expect(pass().required).toBe(true);
    expect(pass().placeholder).toMatch(/re-enter for the new address/);
    type(pass(), "pw");
    expect(saveBtn().disabled).toBe(false);
    type(host, "ftp.example");
    expect(pass().value).toBe("");
    expect(pass().placeholder).toMatch(/leave empty to keep/);
    expect(saveBtn().disabled).toBe(false);
  });

  it("editing only the name does not ask", async () => {
    await openEdit();
    type(screen.getByDisplayValue("nas"), "nas2");
    expect(saveBtn().disabled).toBe(false);
    expect(pass().placeholder).toMatch(/leave empty to keep/);
  });
});

const LDAP = {
  id: "ap1",
  name: "Corp AD",
  type: "ldap",
  is_enabled: true,
  priority: 100,
  config: { host: "ldap.example", port: 636, backup_hosts: ["dc2.example"] },
  has_secrets: true,
  auto_create_users: true,
  auto_update_users: true,
  mapping_count: 0,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
};

describe("auth provider (bind password)", () => {
  async function openEdit() {
    wrap(<AuthProvidersPage />);
    fireEvent.click(await screen.findByTitle("Edit"));
    await screen.findByDisplayValue("ldap.example");
  }
  const bind = () =>
    document.querySelector(
      'input[type="password"][placeholder="••••••••"]',
    ) as HTMLInputElement | null;

  it("a new LDAP host requires the bind password before Save; reverting restores stored", async () => {
    await openEdit();
    expect(bind()).toBeNull();
    expect(document.body.textContent).toMatch(/Secrets are\s+stored/);
    type(screen.getByDisplayValue("ldap.example"), "ldap2.example");
    expect(bind()).not.toBeNull();
    expect(bind()!.required).toBe(true);
    expect(saveBtn().disabled).toBe(true);
    type(bind()!, "pw");
    expect(saveBtn().disabled).toBe(false);
    type(screen.getByDisplayValue("ldap2.example"), "ldap.example");
    expect(bind()).toBeNull();
    expect(document.body.textContent).toMatch(/Secrets are\s+stored/);
    expect(saveBtn().disabled).toBe(false);
  });

  it("changing only the port (not a destination key) does not ask", async () => {
    await openEdit();
    type(screen.getByDisplayValue("636"), "389");
    expect(bind()).toBeNull();
    expect(saveBtn().disabled).toBe(false);
  });
});

const AIP = {
  id: "p1",
  name: "local",
  kind: "openai_compat",
  base_url: "http://192.0.2.1:11434/v1",
  has_api_key: true,
  default_model: "m",
  is_enabled: false,
  priority: 100,
  options: {},
  system_prompt_override: null,
  enabled_tools: null,
  created_at: "2026-10-23T00:00:00Z",
  modified_at: "2026-10-23T00:00:00Z",
};

describe("AI provider (API key)", () => {
  async function openEdit() {
    wrap(<AIProvidersPage />);
    fireEvent.click(await screen.findByLabelText("Edit provider"));
    await screen.findByDisplayValue("http://192.0.2.1:11434/v1");
  }
  const key = () =>
    screen.getByPlaceholderText(
      /replace the stored key|re-enter/,
    ) as HTMLInputElement;

  it("a new base URL requires the key (or removing it) before Save", async () => {
    await openEdit();
    const url = screen.getByDisplayValue("http://192.0.2.1:11434/v1");
    expect(saveBtn().disabled).toBe(false);
    type(url, "http://192.0.2.2:11434/v1");
    expect(saveBtn().disabled).toBe(true);
    expect(key().required).toBe(true);
    type(key(), "sk-new");
    expect(saveBtn().disabled).toBe(false);
    type(key(), "");
    fireEvent.click(screen.getByLabelText("Remove the stored key"));
    expect(saveBtn().disabled).toBe(false);
    fireEvent.click(screen.getByLabelText("Remove the stored key"));
    type(url, "http://192.0.2.1:11434/v1");
    expect(saveBtn().disabled).toBe(false);
    expect(key().placeholder).toMatch(/replace the stored key/);
  });
});

void waitFor;
void updateDevice;
void updateServer;
void updateSub;
void updateTarget;
void updateProvider;
