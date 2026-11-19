/**
 * @vitest-environment jsdom
 *
 * "Delete pool" counts what the zone publishes, not the member total (#2603).
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render } from "@testing-library/react";
import type {
  DNSPool,
  DNSPoolListEntry,
  DNSPoolMember,
  DNSZone,
} from "@/lib/api";
import { ConfirmDeleteModal } from "./DNSPoolsPage";
import { ConfirmDelete } from "./PoolsView";

afterEach(cleanup);

const noop = () => {};

function listEntry(over: Partial<DNSPoolListEntry>): DNSPoolListEntry {
  return {
    name: "web",
    zone_name: "z.test.",
    record_name: "www",
    record_type: "A",
    enabled: true,
    member_count: 2,
    live_count: 2,
    ...over,
  } as DNSPoolListEntry;
}

function member(over: Partial<DNSPoolMember>): DNSPoolMember {
  return {
    enabled: true,
    last_check_state: "healthy",
    ...over,
  } as DNSPoolMember;
}

describe("Delete pool from the pool list", () => {
  it("does not call a disabled pool's members published", () => {
    const { container } = render(
      <ConfirmDeleteModal
        pool={listEntry({ enabled: false, live_count: 0 })}
        onConfirm={noop}
        onClose={noop}
        pending={false}
      />,
    );
    const t = container.ownerDocument.body.textContent ?? "";
    expect(t).not.toMatch(/currently published/);
    expect(t).toMatch(/its 2 members/);
    expect(t).toMatch(/the pool is disabled/);
    expect(t).toMatch(/nothing is removed from the zone/);
  });

  it("counts only the live members of an enabled pool", () => {
    const { container } = render(
      <ConfirmDeleteModal
        pool={listEntry({ live_count: 1 })}
        onConfirm={noop}
        onClose={noop}
        pending={false}
      />,
    );
    const t = container.ownerDocument.body.textContent ?? "";
    expect(t).toMatch(/publishes 1 record as www\.z\.test A/);
  });
});

describe("Delete pool from the zone's pool view", () => {
  const zone = { name: "z.test." } as DNSZone;
  function pool(over: Partial<DNSPool>): DNSPool {
    return {
      name: "web",
      record_name: "www",
      record_type: "A",
      enabled: true,
      members: [
        member({}),
        member({ last_check_state: "unknown" }),
        member({ enabled: false }),
      ],
      ...over,
    } as DNSPool;
  }

  it("counts enabled + healthy members only", () => {
    const { container } = render(
      <ConfirmDelete
        pool={pool({})}
        zone={zone}
        onConfirm={noop}
        onClose={noop}
        pending={false}
      />,
    );
    const t = container.ownerDocument.body.textContent ?? "";
    expect(t).toMatch(/its 3 members/);
    expect(t).toMatch(/publishes 1 record as www\.z\.test A/);
  });

  it("says nothing is published when no member is healthy", () => {
    const { container } = render(
      <ConfirmDelete
        pool={pool({ members: [member({ last_check_state: "unknown" })] })}
        zone={zone}
        onConfirm={noop}
        onClose={noop}
        pending={false}
      />,
    );
    const t = container.ownerDocument.body.textContent ?? "";
    expect(t).toMatch(/no enabled member is healthy/);
    expect(t).not.toMatch(/currently published/);
  });
});
