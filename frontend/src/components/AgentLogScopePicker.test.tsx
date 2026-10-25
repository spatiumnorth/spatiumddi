/**
 * @vitest-environment jsdom
 *
 * Grouped server picker for Logs → DNS Queries / DHCP Activity (#2120).
 *
 * Pins what review cannot see: the option order and labels an operator
 * reads, that a selection maps to the right request scope, and that a
 * name equal to the hostname is not printed twice.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { AgentLogSource } from "@/lib/api";
import {
  ALL_SERVERS,
  defaultSelection,
  groupSelection,
  selectionIsValid,
  selectionServerCount,
  selectionToScope,
  serverLabel,
  serverSelection,
} from "@/lib/agent-log-scope";
import { AgentLogScopePicker } from "./AgentLogScopePicker";

afterEach(cleanup);

const src = (over: Partial<AgentLogSource>): AgentLogSource => ({
  server_id: "s",
  server_name: "s",
  server_kind: "dns",
  driver: "bind9",
  host: "s",
  group_id: null,
  group_name: null,
  ...over,
});

const SOURCES: AgentLogSource[] = [
  src({
    server_id: "a2",
    server_name: "ns-a2",
    host: "ns-a2",
    group_id: "ga",
    group_name: "Edge",
  }),
  src({
    server_id: "a1",
    server_name: "ns-a1",
    host: "10.0.0.1",
    group_id: "ga",
    group_name: "Edge",
  }),
  src({
    server_id: "b1",
    server_name: "ns-b1",
    host: "ns-b1",
    group_id: "gb",
    group_name: "Core",
  }),
  src({ server_id: "x1", server_name: "kea-loose", host: "kea-loose" }),
];

describe("selection model", () => {
  it("maps each selection to its request scope", () => {
    expect(selectionToScope(ALL_SERVERS)).toEqual({});
    expect(selectionToScope(groupSelection("ga"))).toEqual({ group_id: "ga" });
    expect(selectionToScope(serverSelection("a1"))).toEqual({
      server_id: "a1",
    });
  });

  it("counts the servers a selection covers", () => {
    expect(selectionServerCount(ALL_SERVERS, SOURCES)).toBe(4);
    expect(selectionServerCount(groupSelection("ga"), SOURCES)).toBe(2);
    expect(selectionServerCount(serverSelection("b1"), SOURCES)).toBe(1);
    expect(selectionIsValid(groupSelection("gone"), SOURCES)).toBe(false);
  });

  it("opens on the first server, as before", () => {
    expect(defaultSelection(SOURCES)).toBe(serverSelection("a2"));
    expect(defaultSelection([])).toBeNull();
  });

  it("shows the hostname only when it differs from the name", () => {
    expect(serverLabel(SOURCES[0])).toBe("ns-a2");
    expect(serverLabel(SOURCES[1])).toBe("ns-a1 (10.0.0.1)");
  });
});

describe("AgentLogScopePicker", () => {
  it("lists all, then each group's entry followed by its servers", () => {
    render(
      <AgentLogScopePicker
        sources={SOURCES}
        value={ALL_SERVERS}
        onChange={() => {}}
      />,
    );
    const labels = Array.from(
      (screen.getByLabelText("Server") as HTMLSelectElement).options,
    ).map((o) => o.textContent);
    expect(labels).toEqual([
      "All servers (4)",
      // Core has one server, so no "all 1 servers" entry that would read
      // the same as the server below it.
      "ns-b1",
      "Edge (all 2 servers)",
      "ns-a1 (10.0.0.1)",
      "ns-a2",
      // Servers in no group get no group entry: the API cannot select
      // "no group", only "all" or the server itself.
      "kea-loose",
    ]);
    const groups = Array.from(document.querySelectorAll("optgroup")).map(
      (g) => g.label,
    );
    expect(groups).toEqual(["Core", "Edge", "No group"]);
  });

  it("reports the encoded selection", () => {
    const onChange = vi.fn();
    render(
      <AgentLogScopePicker
        sources={SOURCES}
        value={ALL_SERVERS}
        onChange={onChange}
      />,
    );
    fireEvent.change(screen.getByLabelText("Server"), {
      target: { value: groupSelection("ga") },
    });
    expect(onChange).toHaveBeenCalledWith("group:ga");
  });
});
