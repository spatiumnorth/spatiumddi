# Fleet Firewall — Declarative Per-Role Policy Compiled to nftables

> Expands [#285](https://github.com/spatiumnorth/spatiumddi/issues/285) (the four-port k3s-HA seed) into fine-grained, per-role, fleet-wide appliance firewall management. Closes the LAN-wide etcd/kubelet exposure as Phase 1; lands a structured policy engine as the larger arc.

---

## 1. Recommendation in one paragraph

We build a **first-class declarative firewall policy** authored on the control plane in three additive layers — a fleet baseline, per-role overlays keyed on the *same* role taxonomy as the #16 node labels, and per-appliance overrides — compiled **server-side** into the authoritative `spatium-role.nft` drop-in, riding the existing supervisor heartbeat → trigger-file → `spatium-firewall-reload` plane exactly as SNMP/NTP/LLDP do. The load-bearing primitive is a `source_kind` enum whose **derived** scopes (`cluster_peers` / `pod_cidr` / `mgmt` / `vip`) let an operator author "scope etcd to peers" *once* against the role abstraction while the compiler resolves each node's concrete, dynamically-changing `/32` peer set at that node's own render time — so promote/demote re-renders automatically and the firewall *tightens* on demote with zero per-appliance edits. This shape wins because it is simultaneously fleet-wide, HA-peer-dynamic, and injection-proof by construction (structured rules are rendered, never pasted), and because making the rendered drop-in authoritative is the *only* way to actually CLOSE the LAN-wide base ports (nftables is first-match-wins; the existing scoped peer rule is dead code stacked behind a base `accept` that already fired). The dangerous parts — closing base ports, the bootstrap join race, the connectivity-killing-but-valid push, and the **k3s data-plane ports (flannel VXLAN 8472/udp) that are opened nowhere today** — are bought back by an **un-removable SSH/management floor**, a **baked bootstrap sentinel** that retires only once the cluster is genuinely multi-node, a **bounded auto-narrowing 6443 join window**, an **asymmetric-on-leave peer set** that mirrors the cert-SAN only-grow safety, and a **state-file-driven, reboot-survivable, per-node-independent test-apply auto-revert**. Three verified prerequisites the proposals glossed are built explicitly *before* any port-closing ships: there is **no pod-CIDR mirror to the supervisor today**, **no flannel data-plane port is opened anywhere**, and **no base-conf-version signal exists** to tell a partially-upgraded fleet apart from a hardened one.

---

## 2. Data model

### 2.1 Three layers, one merge

```
effective_node_ruleset =
    MGMT_FLOOR                                   # ALWAYS, renderer-emitted + base-baked, un-removable (§6.1)
  ⊕ DATA_PLANE_FLOOR   (flannel VXLAN / wireguard, peer-scoped — emitted on EVERY pod-running node, §3.6)
  ⊕ FLEET_BASELINE     (FirewallPolicy scope_kind="fleet")
  ⊕ Σ ROLE_OVERLAY[r]  for r in node.assigned_roles ∪ ({"control-plane"} if node.cluster_role∈{primary,member})
  ⊕ CLUSTER_DERIVED    (peer-scoped etcd/kubelet/6443/memberlist; if CP node)
  ⊕ KUBEAPI_ALLOWLIST  (Appliance.kubeapi_expose_cidrs folded into a 6443 cidr rule)
  ⊕ APPLIANCE_OVERRIDE (FirewallPolicy scope_kind="appliance" structured rules)
  ⊕ RAW_EXTRA          (Appliance.firewall_extra, LINTED at write time, appended last)
```

`⊕` is the **explosion + deny-wins + source-union merge** defined concretely in §3.7 — not a loose "set union." The role taxonomy (`control-plane`, `dns-bind9`, `dns-powerdns`, `dns-technitium`, `dhcp`, `observer`, `custom`) is the *same* token set the chart uses for `spatium.io/role-*` node labels (#16), so firewall scope and pod scheduling share one source of truth.

### 2.2 New tables — `backend/app/models/firewall.py`

```python
class FirewallPolicy(Base):
    __tablename__ = "firewall_policy"
    id:            Mapped[uuid.UUID]   = mapped_column(primary_key=True, default=uuid.uuid4)
    name:          Mapped[str]         = mapped_column(String(120))
    description:   Mapped[str | None]  = mapped_column(Text)

    scope_kind:    Mapped[str]         = mapped_column(String(16))          # "fleet" | "role" | "appliance"
    scope_role:    Mapped[str | None]  = mapped_column(String(32))          # role token, iff scope_kind="role"
    scope_appliance_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("appliance.id", ondelete="CASCADE"))                     # iff scope_kind="appliance"

    enabled:       Mapped[bool]        = mapped_column(Boolean, default=True)
    is_builtin:    Mapped[bool]        = mapped_column(Boolean, default=False)  # seeded; non-deletable, editable
    priority:      Mapped[int]         = mapped_column(Integer, default=100)
    created_at / updated_at / updated_by_id

    rules: Mapped[list["FirewallRule"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="FirewallRule.seq")

    __table_args__ = (
        UniqueConstraint("scope_kind", "scope_role", name="uq_fw_policy_role"),   # one builtin per role; fleet singleton
        Index("ix_fw_policy_appliance", "scope_appliance_id"),
        CheckConstraint(
            "(scope_kind='fleet'     AND scope_role IS NULL    AND scope_appliance_id IS NULL) OR "
            "(scope_kind='role'      AND scope_role IS NOT NULL AND scope_appliance_id IS NULL) OR "
            "(scope_kind='appliance' AND scope_role IS NULL     AND scope_appliance_id IS NOT NULL)",
            name="ck_fw_policy_scope"),
    )

class FirewallRule(Base):
    __tablename__ = "firewall_rule"
    id:            Mapped[uuid.UUID]   = mapped_column(primary_key=True, default=uuid.uuid4)
    policy_id:     Mapped[uuid.UUID]   = mapped_column(ForeignKey("firewall_policy.id", ondelete="CASCADE"), index=True)
    seq:           Mapped[int]         = mapped_column(Integer)              # render order within policy

    action:        Mapped[str]         = mapped_column(String(8), default="accept")   # "accept" | "drop"
    protocol:      Mapped[str]         = mapped_column(String(8))           # "tcp" | "udp" | "icmp" | "icmpv6"
    ports:         Mapped[list]        = mapped_column(JSONB, default=list) # [53, "1024-2048"]; [] for icmp

    # ── source scoping: the heart of fine-grained control ──
    source_kind:   Mapped[str]         = mapped_column(String(16), default="any")
        # "any" | "cidr" | "alias" | "cluster_peers" | "pod_cidr" | "service_cidr" | "mgmt" | "vip"
    source_cidrs:  Mapped[list]        = mapped_column(JSONB, default=list) # for source_kind="cidr" (v4 + v6, family-split at render)
    source_alias:  Mapped[str | None]  = mapped_column(String(64))         # for source_kind="alias"

    family:        Mapped[str]         = mapped_column(String(6), default="both")  # "v4" | "v6" | "both"
    comment:       Mapped[str | None]  = mapped_column(String(120))
    enabled:       Mapped[bool]        = mapped_column(Boolean, default=True)
    policy: Mapped["FirewallPolicy"]   = relationship(back_populates="rules")
```

Validation rejects `protocol="tcp"|"udp"` with empty `ports`, and **rejects any rule whose resolved port atoms include 22 with `action="drop"`** (§6.1 — SSH/22 may never be closed by a rule).

```python
class FirewallAlias(Base):
    __tablename__ = "firewall_alias"
    id / name (unique String(64)) / kind ("port"|"cidr") / v4_members (JSONB) / v6_members (JSONB) / description / is_builtin
    # CIDR aliases are family-split AT REST (v4_members / v6_members) — closes the IPv6 lockout bug (§6.2)

class FirewallApplyState(Base):
    __tablename__ = "firewall_apply_state"
    appliance_id:    Mapped[uuid.UUID] = mapped_column(ForeignKey("appliance.id", ondelete="CASCADE"), primary_key=True)
    rendered_hash:   Mapped[str | None]= mapped_column(String(64))  # sha256 of the body the backend last rendered
    applied_hash:    Mapped[str | None]= mapped_column(String(64))  # echoed from the host runner sidecar
    applied_status:  Mapped[str | None]= mapped_column(String(48))  # "ok"|"error:dry-run-post"|"reverted-timeout"|"stalled"|...
    base_conf_marker:Mapped[str | None]= mapped_column(String(64))  # which base /etc/nftables.conf is live (§2.6)
    pending_commit:  Mapped[bool]      = mapped_column(Boolean, default=False)   # a test-apply is mid-countdown
    commit_deadline: Mapped[datetime | None]
    last_confirmed_hash: Mapped[str | None] = mapped_column(String(64))  # last hash the node CONFIRMED-good (drives stale-PASS compliance, §6.5)
    last_confirmed_at:   Mapped[datetime | None]
    last_rendered_at / last_applied_at
```

`FirewallApplyState` closes the verified gap that **nothing reads `firewall-applied-status` back today** — the host runner writes it but it dies on the box. Now it rides the heartbeat home and drives the Fleet UI status chip, drift detection (§3.4), the apply-lag alarm (§3.4b), and the stale-but-compliant conformity verdict (§6.5).

### 2.3 Fleet posture + floor knobs — `PlatformSettings` (singleton id=1)

These live on `PlatformSettings` (the fleet-wide channel SNMP/NTP/LLDP use) precisely so **no policy edit can touch them**:

```python
firewall_enabled:              Mapped[bool] = False        # master enforcement gate; false = floor-only (legacy posture)
firewall_default_input_action: Mapped[str]  = "drop"       # Talos NetworkDefaultActionConfig analog; drop-only in v1 (Q2)
firewall_posture:              Mapped[str]  = "balanced"
    # "open"     — k3s ports LAN-wide via policy (reproduces today; single-tenant lab)
    # "balanced" — DEFAULT-on-opt-in: 2379/2380/10250 peer-only, 6443 peer+pod+join-window, services LAN-wide
    # "locked"   — services also CIDR-scoped (requires per-role client allowlists)
firewall_mgmt_cidrs:           Mapped[list] = []           # SSH/mgmt floor source. [] = SSH LAN-wide (recovery)
firewall_mgmt_lockdown:        Mapped[bool] = False        # honour mgmt_cidrs for SSH ONLY when non-empty (§6.1 guard)
firewall_join_window_minutes:  Mapped[int]  = 30           # 6443 join-window duration after a promote
firewall_autorevert_seconds:   Mapped[int]  = 180          # test-apply revert timeout; clamped >= 2× heartbeat (§3.4a)
firewall_apply_lag_intervals:  Mapped[int]  = 5            # rendered≠applied for > N heartbeats → firewall.apply_stalled (§3.4b)
```

`firewall_enabled` defaults **false** so an upgrade is byte-identical to today (floor-only render + the still-present base accepts). Discovery (the feature module, §7) is on; *enforcement* is opt-in. Flipping it to `true` is additionally gated on a **fleet-wide base-conf confirmation** (§2.6) so hardening is never presented as live while a stale-base node is still LAN-wide.

### 2.4 What stays / migrates

- `Appliance.firewall_extra` (Text) — **kept**, becomes the bottom override tier. **Behavior changes on upgrade and must be called out:** today it is appended verbatim with no lint; under this design it is linted at **write time** (§6.3), and because the structured appliance-override tier now sits *above* it, a structured `drop` can precede a `firewall_extra` `accept` for the same port (effective-ruleset delta). A **one-time validation pass** lints every existing `firewall_extra` value on first upgrade and raises a Fleet banner + audit row for any value the new lint would reject — **without auto-clearing** — so operators get a fix window before enforcement. The lint never runs at compile time (no silent drops); only at save (422) and as the one-time advisory scan. Zero column-level data migration.
- `Appliance.kubeapi_expose_cidrs` (JSONB) — **kept**; the compiler folds it into a `{accept, tcp, [6443], source_kind:cidr}` rule. The existing `PUT /kubeapi-cidrs` editor keeps working as sugar.
- `_cluster_peer_cidrs(db, row)` (`supervisor.py:2820`) — **kept as the authoritative peer-set source** (already injection-validated #236) but **modified two ways**: (a) it is **family-split** so a v4 `node_ip` yields `/32` and a v6 `node_ip` yields `/128` (today it hardcodes `/32`, producing a garbage v6 network — §6.2); (b) it gains an **asymmetric-on-leave** mode so an in-flight leaver (`desired_cluster_role='none'`, not yet `left`) stays in every remaining peer's set, and the remaining peers stay in the leaver's set, until `cluster_join_state='left'` (§3a — mirrors the cert-SAN only-grow safety so the destructive etcd member-remove can complete).
- The supervisor's in-pod `firewall_renderer.py` `_ROLE_PORTS_*` dict → **replaced** by seeded builtin role policies (identical port sets, now editable). `firewall_renderer.py` is **retained one release as the cache-fallback renderer** (§3.5), then removed. The dead `expected_tcp_ports`/`expected_udp_ports` frozensets are dropped (verified: only the unit test reads them; drift now keys off the full-body hash, §3.4).

### 2.5 Seeded builtins (migration — idempotent data seed, split from schema; see Phase 3)

- One `fleet` policy (`is_builtin=True`, empty — operators add fleet-wide rules here).
- Six `role` policies: `control-plane` (80/443+vip; 2379/2380/10250 cluster_peers; 6443 peers∪pod∪svc; **10250 also pod∪svc** — `source_kind=kubelet`, seeded by `d4a9e37b2c15` for #993, so the api pod can reach its OWN node's kubelet, which the peer-scoped rule never covers and on a single node is not emitted at all; deliberately NOT the `kubeapi` union, whose operator `kubeapi_expose_cidrs` allowlist must not be extended from the RBAC-guarded apiserver to the kubelet's `/exec` and `/run`; memberlist 7946 **tcp+udp** cluster_peers), `dns-bind9`/`dns-powerdns`/`dns-technitium` (53 tcp+udp), `dhcp` (67 udp + 68 return; **547 udp** for DHCPv6, seeded by `e6b2f07a3c91` for #1139), `observer` (9100→scraper-CIDR, default-disabled rule), `custom` (empty). The three DNS-engine policies are byte-identical; `dns-technitium` ships in its own seed migration (`6a668dd451d5`) rather than as an edit to the already-shipped `f5b8d2c91a06`, per the append-only migration rule.
- Builtin aliases: `@k3s_peer_ports`, `@dns_ports`, `@dhcp_ports`, `@web_ports`.

### 2.6 Two new derived inputs the supervisor must report (verified absent today)

Both are collected by `appliance_state.collect()`, shipped on the heartbeat, persisted on `Appliance`, and consumed by the compiler. **Both gate Phase 1 port-closing** (§3.6):

1. **Cluster CIDRs + data-plane backend** — parse `cluster-cidr:`, `service-cidr:`, and `flannel-backend:` (default `vxlan`; may be `wireguard-native`) from the host `/etc/rancher/k3s/config.yaml.d/spatium-cidrs.yaml` drop-in (already bind-mounted to the supervisor). Fallback `10.42.0.0/16` / `10.43.0.0/16` / `vxlan` only if unreadable.
2. **Base-conf marker** — hash `/etc/nftables.conf` (or detect the absence of the `comment "k3s-ha"` line) and report it so the backend knows **per node** which base is live. This is what lets the UI refuse to claim "hardened" on a stale-base node and lets the conformity check be accurate during a rolling A/B upgrade (§6.5, §3.2).

`node_ip` collection is also extended to report **all** InternalIPs as `node_ips: list[str]` (k3s lists both families on a dual-stack cluster) so v6 peer scoping is derived from a real v6 address rather than a fabricated one (§6.2).

---

## 3. Render + apply pipeline

### 3.1 Compile server-side (mirror the `snmp_bundle` contract)

New `backend/app/services/appliance/firewall.py`:

```python
def compile_firewall(
    settings, appliance,
    fleet_policy, role_policies, appliance_policy,   # eager-loaded rules
    cluster_peer_cidrs_v4, cluster_peer_cidrs_v6,    # from family-split + asymmetric-on-leave _cluster_peer_cidrs
    pod_cidr_v4, pod_cidr_v6, service_cidr_v4,        # from the pod-CIDR mirror (§2.6 / §3.6 — PREREQUISITE)
    dataplane_backend, dataplane_peer_cidrs,          # flannel vxlan 8472 / wireguard 51820+51821 (§3.6)
    control_plane_vip, cp_member_count, vip_configured,
    join_window_active, aliases,
) -> str: ...

def firewall_bundle(...) -> dict:
    if not settings.firewall_enabled:
        return {"enabled": False, "config_hash": "", "firewall_conf": "", "default_action": "accept"}
    body = compile_firewall(...)
    return {
        "enabled": True,
        "config_hash": canonical_hash(body),          # sort+dedupe saddr sets BEFORE hashing (anti-flap, §3.4)
        "firewall_conf": body,
        "default_action": settings.firewall_default_input_action,
        "retire_bootstrap": cp_member_count >= 2 and not join_window_active and 'comment "kubeapi"' in body,  # §3.3
        "revert_seconds": settings.firewall_autorevert_seconds,
        "is_test_apply": <set true only on an operator Test action>,    # §3.4a
        "commit_deadline": <epoch, set only on a test-apply>,           # §3.4a
    }
```

Render order inside the drop-in (every fragment is a bare `proto dport N accept` since the include glob sits *inside* `chain input` — top-level `add rule` 422s on trixie):

```nft
# Auto-generated by SpatiumDDI control plane — do not hand-edit.
# profile: control-plane+dns-only | base: <marker> | layers: floor,dataplane,fleet,role:control-plane,role:dns-bind9,cluster
# ── MGMT FLOOR (immutable, FIRST — first-match-wins over any operator drop) ──
tcp dport 22 accept comment "ssh"                       # OR ip saddr {mgmt} when firewall_mgmt_lockdown (§6.1)
udp sport 67 udp dport 68 accept comment "dhcp-client-return"   # host's own lease renewal — kept even on DHCP-server nodes (§4)
icmp type echo-request accept
icmpv6 type echo-request accept
iif lo accept
# ── DATA-PLANE FLOOR (peer-scoped, on EVERY pod-running node — §3.6) ──
ip  saddr { 192.168.1.11/32, 192.168.1.12/32 } udp dport 8472 accept comment "flannel-vxlan-v4"
ip6 saddr { 2001:db8::12/128 }                 udp dport 8472 accept comment "flannel-vxlan-v6"
# (if flannel-backend=wireguard-native →) udp dport { 51820, 51821 } accept (peer-scoped)
# ── FLEET BASELINE ──
# ── ROLE: dns-bind9 ──
udp dport 53 accept comment "role:dns-bind9"
tcp dport 53 accept comment "role:dns-bind9"
# ── ROLE: control-plane (web) — matches ANY daddr so the MetalLB VIP passes ──
tcp dport { 80, 443 } accept comment "role:control-plane web"
# ── CLUSTER DERIVED (peer-scoped; etcd/kubelet NEVER LAN-wide) ──
ip  saddr @k3s_peers_v4  tcp dport { 2379, 2380, 10250 } accept comment "k3s-peer-v4"
ip6 saddr @k3s_peers_v6  tcp dport { 2379, 2380, 10250 } accept comment "k3s-peer-v6"
ip  saddr @kubelet_v4    tcp dport 10250 accept comment "kubelet-v4"   # #993, pod ∪ svc
ip6 saddr @kubelet_v6    tcp dport 10250 accept comment "kubelet-v6"   # #993, pod ∪ svc
ip  saddr @kubeapi_v4    tcp dport 6443 accept comment "kubeapi"        # peers ∪ pod ∪ svc ∪ kubeapi_expose
ip  saddr @k3s_peers_v4  tcp dport 7946 accept comment "metallb-memberlist-tcp"   # emitted iff cp_member_count>=2 && vip
ip  saddr @k3s_peers_v4  udp dport 7946 accept comment "metallb-memberlist-udp"
# (join window open →)  ip saddr @node_subnet tcp dport 6443 accept comment "join-window"   # node-subnet-scoped, §3a
# ── KUBEAPI ALLOWLIST (kubeapi_expose_cidrs) ──
# ── APPLIANCE OVERRIDE (structured) ──
# ── RAW_EXTRA (linted at write time, verbatim, last) ──
```

Three verified gaps closed here:

- **The peer rule is keyed off observed membership, never the row alone (#593).** The peer set is derived from the control plane's `cluster_role`, so a row that disagrees with reality renders an *agent* drop-in — with no `k3s-peer` rule — onto a node that is a live voting etcd member. Observed on a 3-node appliance: `ddi2`'s row had gone `cluster_role = NULL` after a failed re-join while its etcd was serving raft normally, and its own nftables dropped its peers' inbound `:2380`. The peers logged `dial tcp 192.168.0.133:2380: i/o timeout` every 5 s against a member that was up the whole time — a node partitioned from a cluster it belonged to, by its own firewall, on the strength of a stale database row.

  The triggering row bug is fixed, but the coupling is the hazard: a stuck heartbeat, a control plane restored from an older backup, a half-landed promote, or an operator clearing state all reproduce it. And it fails in the worst direction — dropping a voting member out of raft leaves a 3-node cluster one node from losing quorum. Three defences, in `firewall_peer_audit`:

  1. **Recover.** When the row supplies no peers but k3s labels this node `node-role.kubernetes.io/etcd`, re-derive the peer set from live kube-API membership and re-render. That label is managed by k3s from actual membership — `reconcile_node_labels` only ever touches `spatium.io/role-*` — so it is a statement about reality, not about the row.
  2. **Refuse.** Never write a drop-in that closes `2380` on a node k3s still calls an etcd member: log `supervisor.firewall.refused_self_partition`, record it on `appliance.firewall_state` (surfaced as a Fleet banner — a divergence only an operator can reconcile must not stay a log line), and leave the previous ruleset in place. A stale peer rule only over-permits to real cluster members; a self-inflicted partition does not degrade gracefully.
  3. **Fall back without the network.** The probe itself needs the network. The supervisor pod has **no `hostNetwork`**, so `k8s_api` reads the apiserver *ClusterIP* and kube-proxy may DNAT that to a **remote** apiserver — there is no local-apiserver path to use. A partitioned node therefore cannot probe, and a guard that treated "can't tell" as "not a member" would fail open exactly when it is needed, closing `2380` on itself with no way to ever read membership again and reopen it. When the probe comes back unreadable the supervisor falls back, in order, to a purely **local** cluster-member signal (the install variant, or the host runner's `cluster_join_state == ready` — the same two signals `_is_control_plane_member` uses, neither of which touches the network), and then to a previously **confirmed** membership persisted on disk.

  The asymmetry is load-bearing, and it runs through all three layers — the in-process TTL cache, the on-disk marker, and the fallbacks. **Only `True` is ever remembered.** A stale `True` merely delays narrowing the firewall after a real demote, and the peer rule only over-permits to real cluster members. A stale `False` *is* this bug on a slower timescale: a node promoted while its apiserver happens to be unreachable would read "not a member", pass the guard, and firewall its own raft port shut. So a confirmed `False` **clears** the marker instead of recording it, and no fallback can answer anything but `True` or "don't know". Membership genuinely unknown — never confirmed, no local signal — fails **open**, or the guard would freeze the firewall on every non-etcd appliance.

  The bundle-first path gets the same guard, but a refusal there **falls through to the in-pod renderer** rather than merely skipping the write: the control plane renders from the same stale row on every tick, and since Phase 1b removed the LAN-wide accept from the base config, a node that joined while its row was already wrong has no last-good ruleset to keep. Only the in-pod path can re-derive peers and heal it.

  `body_opens_etcd_peers` audits the rendered text, so it strips nftables' `comment "…"` clause *before* splitting on `#` (a `#` inside a comment otherwise leaks the comment's text — and its `2380` — into the code), and matches the port only in a `dport` position (`ip6 saddr { fd00:2380::/64 } … dport 6443` opens 6443, not 2380). Both would be *false positives*, the dangerous direction: they tell the guard a partitioning body is safe.
- **MetalLB memberlist 7946 on BOTH tcp+udp.** Native-L2 speakers (hostNetwork) gossip for leader election on tcp *and* udp 7946; their `127.0.0.1:7472`/`:17472` metrics+healthz are covered by the loopback floor. It is emitted on every CP node when `cp_member_count >= 2 AND vip_configured` — **derived from the membership model, not gated on a `metallb_enabled` flag the supervisor does not mirror.** Without it, VIP failover silently stops the moment Phase 1 closes the base accept, and the symptom looks like a node failure.
- **flannel VXLAN 8472/udp (the most likely Phase-1 outage).** The DATA-PLANE FLOOR opens the operator-configured inter-node data-plane port (`vxlan` → 8472/udp, `wireguard-native` → 51820+51821/udp) peer-scoped on **every pod-running node** — read from k3s config, never assumed. Removing the LAN-wide base accept without this drops cross-node pod networking and pod-to-apiserver.

**Named sets, not anonymous inline `{}` sets.** Peer/kubeapi CIDRs are emitted as named sets (`@k3s_peers_v4` …) so a peer-IP change updates one set via `nft add/delete element` without a full `nft -f` chain re-evaluation (anti-thrash, §3.4). The web rule stays `daddr`-agnostic so VIP traffic (which arrives `daddr=VIP`) passes on every CP node.

### 3.2 Compose with the baked base — reduce it to an immutable floor

`appliance/mkosi.extra/etc/nftables.conf` is reduced to a **floor**. The LAN-wide `k3s-ha` line (:79) is **removed**; the belt-and-braces 53 accept is removed, **but the DHCP client-return rule (`udp sport 67 dport 68`) is KEPT** (a DHCP-server appliance is itself frequently DHCP-addressed — removing it would break the host's own lease renewal):

```nft
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    meta l4proto icmp accept
    meta l4proto icmpv6 accept
    tcp dport 22 accept comment "ssh-floor"                  # un-removable recovery channel
    udp sport 67 udp dport 68 accept comment "dhcp-client-return-floor"
    include "/etc/nftables.d/00-spatium-k3s-bootstrap.nft"   # baked: 6443 LAN-wide; retired only when multi-node (§3.3)
    include "/etc/nftables.d/*.nft"                          # spatium-role.nft (AUTHORITATIVE) + SNMP/NTP/LLDP drop-ins
    counter
  }
  chain forward { type filter hook forward priority filter; policy accept; }   # UNCHANGED — flannel/kube-proxy
  chain output  { type filter hook output  priority filter; policy accept; }   # UNCHANGED — supervisor outbound
}
```

`FORWARD`/`OUTPUT` `accept` are **hard invariants** the standard surface cannot touch (pod networking + the supervisor's outbound heartbeat depend on them). The base SSH floor + the renderer-emitted SSH floor are belt-and-braces: a node whose drop-in never rendered (fresh boot, control-plane unreachable) is still SSH-reachable.

This is what lets the drop-in **CLOSE** ports: with the base no longer accepting 2379/2380/10250, the *only* accept comes from the scoped cluster-derived rule. The drop-in is the firewall, not decoration.

**Honest effective-view scope.** kube-proxy/flannel write their own iptables-nft chains (`KUBE-*`) in the `ip nat`/`ip filter` tables; a NodePort/LoadBalancer service can open a path our `inet filter` drop policy does not see. The server-rendered view (§5, §7) is therefore labeled **"SpatiumDDI-managed input rules"**, not "effective kernel ruleset." The supervisor additionally ships a periodic summary of NodePort/LoadBalancer service presence so the auditor knows pod-network paths exist outside our table; ClusterIP/pod traffic is governed by NetworkPolicy (out of scope).

### 3.3 Bootstrap sentinel + retire-on-multi-node (the flag-day-free migration)

The baked `00-spatium-k3s-bootstrap.nft` (`tcp dport 6443 accept`) keeps a fresh seed / out-of-band rejoin reachable before the supervisor renders. The runner deletes it **only** on a successful apply where the bundle's `retire_bootstrap=true` — and that flag is true **only when `cp_member_count >= 2 AND not join_window_active**`. On a single-node appliance (`cp_member_count == 1`) the bootstrap **stays indefinitely** — it is the only LAN path to 6443 for a future promote/join, and etcd is loopback-only so it is harmless. This closes the air-gap chicken-and-egg: a manual joiner that does not yet exist as a DB row (it pairs/approves *after* reaching the seed) still finds 6443 open via the un-retired sentinel. For deliberate hardening of a settled multi-node cluster, a Fleet **"allow LAN 6443 for join"** maintenance toggle (audited, auto-expiring) re-creates a bounded window without requiring the joiner to pre-exist (§3a).

### 3.4 Heartbeat wiring + apply + drift

- Add `firewall_settings: dict = Field(default_factory=dict)` to `SupervisorHeartbeatResponse`; build `firewall_block = firewall_bundle(...)` in the heartbeat handler (`supervisor.py` ~L1613, mirroring `snmp_settings`). The existing `role_assignment` + `cluster_peer_cidrs` stay (compiler inputs); the firewall body now arrives pre-rendered with a backend hash.
- Supervisor `maybe_fire_firewall_reload(block)` in `appliance_state.py` — **clones `maybe_fire_snmp_reload`**: appliance-gate, read `firewall-applied-hash` sidecar, short-circuit on match, atomic `.new`→rename to `firewall-pending`. Delete the in-pod `_maybe_apply_firewall` once the fallback (§3.5) sunsets.
- Host runner `spatium-firewall-reload` — **reused**, keeping the gold-standard validate-stage-validate-commit (`nft -c -f` pre → atomic rename → `nft -c -f` post → `nft -f` commit; bad drop-in removed on failure). It echoes `firewall-applied-status` + `applied-hash` + the **base-conf marker** → the heartbeat → `FirewallApplyState`. The runner **ignores-but-logs** unknown bundle fields (forward-compat so an old runner gracefully drops new fields, and a new runner survives an old bundle).
- **Drift** is the canonical-hash compare on every tick (60s): backend `rendered_hash` vs echoed `applied_hash`. The hash is computed over the body **after** each named saddr set is sorted + deduped + family-canonicalized, so a benign peer-IP reorder does not re-fire; a real out-of-band `nft flush` or a genuine peer-set change does. Backend **debounces** a peer-IP change for >1 heartbeat (anti-flap) before bumping the hash, and CP nodes on DHCP addressing raise a Fleet warning recommending static IPs (a DHCP renewal storm otherwise N-way-reloads the control plane and can wobble etcd quorum). Where only the saddr set changed, the supervisor prefers `nft add/delete element` on the named set over a full reload.

### 3.4a Test-apply with state-file-driven, reboot-survivable auto-revert

Re-specified away from the fragile "transient `systemd-run` timer fired from a oneshot runner" into a **persistent-timer + deadline-file** design:

- On a **test** apply, the `spatium-firewall-reload` runner: copies live `spatium-role.nft → .last-good` (the *currently committed* ruleset, never a pending one), applies the new drop-in, then writes `firewall-revert-deadline=<epoch>` to `/var/...` (survives reboot). It does **not** arm an inline timer.
- A separate **always-running** host timer `spatium-firewall-revert.timer` (`OnUnitActiveSec=15s`, enabled at install) checks every 15s: if `now() > deadline AND firewall-confirm absent` → restore `.last-good` + reload + clear the deadline. This is idempotent (one deadline file, last-write-wins — a second test-apply simply overwrites the deadline and re-saves `.last-good` against the current committed ruleset), survives a mid-window reboot (timer is persistent, deadline lives on `/var`), and has no stacked-timer hazard.
- `firewall_autorevert_seconds` is **clamped to ≥ 2× the heartbeat interval** so a good change always gets a confirm chance before the deadline.
- **Test-apply is forbidden on any change that triggers a reboot** (the bootstrap-retire + base-conf-swap cases). Those are permanent-apply only, protected by a separate health-gated rollback (the existing #296/A-B-slot health gate), since a transient timer cannot span a reboot meaningfully.

**Per-node-independent confirmation (decoupled from generic control-plane reachability).** The supervisor writes `firewall-confirm` only when BOTH (a) a fresh heartbeat succeeded AND (b) an explicit **post-apply self-probe** of its own critical inbound paths passes — a peer-originated or node-IP loopback TCP connect to 6443 (and, on a CP node, 10250 from a peer IP) confirming the new ruleset did not strand the node's own service ports. Because each node keys its timer off **its own** probe, a fleet-wide transient (CNPG failover / VIP re-home / etcd leader election / a 30s blip) can no longer mass-revert a healthy fleet. **Honest scope:** self-inflicted SSH lockout is *not* what auto-revert protects against (the heartbeat is outbound and OUTPUT stays accept, so a bad SSH-INPUT rule still confirms) — that is caught by the un-removable floor (§6.1) + the write-time lint that rejects any `drop` on port 22. Auto-revert's real job is the inter-node-partition case (a peer-CIDR typo breaks etcd quorum → the control plane itself goes unreachable AND the self-probe fails → revert). On a CP node, the revert restores `.last-good` which **retains the scoped peer rules as a floor** — it reverts only the operator's incremental change, never re-opening LAN-wide etcd.

### 3.4b Apply-lag alarm (control plane up, supervisor wedged)

If `rendered_hash != applied_hash` for more than `firewall_apply_lag_intervals` heartbeats, the backend raises a typed `firewall.apply_stalled` alert distinct from agent-offline, cross-referencing Wave E's external-watchdog state so "supervisor wedged" is shown as the cause. The Fleet drift chip differentiates `pending / applied-ok / applied-error / stalled / reverted` — a true status, not a bare hash mismatch.

### 3.5 Control-plane-loss survival (non-negotiable #5)

The rendered `spatium-role.nft` lives on the `/etc` overlay upper (`/var/persist/etc`); sidecars on `/var` — both survive reboots and A/B slot swaps. On a non-200 heartbeat, `heartbeat_once` returns early and `maybe_fire_firewall_reload` is never reached → **last-good stays loaded indefinitely**. Nothing tightens, nothing flushes. The supervisor retains `firewall_renderer.py` for **one release** as a cache-fallback: if a heartbeat arrives without a `firewall_settings` block (old control plane / transitional bundle), it re-renders from cached `role_assignment` as today. A node that reboots while the control plane is down loads its last-good drop-in from the overlay — fully functional, no control plane needed.

### 3.6 PREREQUISITES — pod-CIDR mirror + data-plane port (both verified absent today)

Three things the steady-state rules depend on are **not collected today** and are built **before any base port is closed**, gated as the first Phase-1 tasks:

1. **Pod / service CIDR** — the steady-state 6443 rule accepts from the operator-chosen pod/service CIDR (in-pod apiserver access traverses INPUT via the `10.43.0.1:443 → node:6443` DNAT with `saddr=pod-IP`; #302 lets operators change `10.42/10.43`). Built per §2.6.
2. **Data-plane port + backend** — cross-node pod networking depends on flannel VXLAN 8472/udp (default) or wireguard-native 51820+51821/udp. **Opened nowhere today**; removing the LAN-wide base accept without it breaks cross-node pod traffic. Built per §2.6, emitted as the DATA-PLANE FLOOR (§3.1).
3. **Base-conf marker** — per §2.6, so a partially-upgraded fleet is not silently split-brain.

Getting any of these wrong silently breaks cluster traffic the moment `firewall_enabled` flips on, so all three are hard Phase-1/Phase-2 gates with explicit cross-node pod-to-pod and pod-to-apiserver acceptance tests on a real 3-node appliance.

### 3.7 The merge algorithm (the load-bearing core of "fine-grained")

`⊕` is **not** loose set-union. Concretely:

1. **Explode** every enabled rule (from every layer) into per-individual-port atoms `(action, proto, port, resolved_source_set, family)` — a rule for ports `{80,443}` becomes two atoms.
2. **Resolve sources** to concrete CIDR sets per family (`cluster_peers`→peer set, `pod_cidr`→pod set, `alias`→alias members, `cidr`→literal, `any`→universe). The dedup key is `(action, proto, port, family, frozenset(resolved_source_set))` — two `accept/tcp/6443/cidr` atoms with *different* CIDR lists **union their sets into one** rule; identical atoms collapse to one.
3. **Deny-wins per port atom**: for each `(proto, port, family)`, emit every `drop` atom (each carrying its own `saddr` clause) **before** any `accept` atom for that same port. First-match-wins then does the rest. A blanket close is `source_kind=any` → bare `<proto> dport N drop`; a scoped close keeps its `ip saddr {…}` clause.
4. The MGMT floor + DATA-PLANE floor are emitted **first of all**, ahead of step 3's drops, so no operator `drop` can shadow SSH/22 or the data-plane port.

**Worked example.** Fleet `accept 443/any`; appliance-override `drop 443/any` + `accept 443/alias:@mgmt (10.0.0.0/24)`:

```nft
# floor first …
tcp dport 22 accept comment "ssh"
# … then deny-wins for the 443 atom:
ip saddr 10.0.0.0/24 tcp dport 443 accept comment "appliance:mgmt-web"   # narrower accept emitted…
tcp dport 443 drop comment "appliance:close-web"                          # …but the blanket drop is ALSO present;
                                                                          # first-match: mgmt CIDR hits accept, world hits drop
```

(Per first-match-wins, the scoped `accept` precedes the blanket `drop` so `10.0.0.0/24` is permitted and everything else is dropped — the design's emit order places narrower accepts ahead of blanket drops within a port atom; the fleet `accept 443/any` is shadowed and surfaced as a "this rule will never match" preview warning.) `firewall_extra` is strictly additive and last; the preview runs the merged ruleset through `nft --check` + a structural shadow-analysis so any shadowed rule is flagged before commit.

---

## 3a. #285 join bootstrap

**The constraint (verified against `spatium-cluster-join`):** a fresh joiner dials **seed:6443** to fetch `/cacerts` + validate the token *before* it is a settled member. `2379/2380/10250` are pure peer-to-peer — the seed already knows the joiner's `node_ip` (the promote API stamps `desired_cluster_role='member'` *before* telling the joiner to run the join runner, and `_cluster_peer_cidrs` already includes in-flight rows).

**Peer-set derivation (ranked):** `_cluster_peer_cidrs` (the control plane's own membership model) is the spine — available at heartbeat time, includes in-flight promotions, injection-validated. As a host-side *cross-check* against control-plane staleness, the supervisor compares its rendered peer set against the live `k3s etcd member list` and logs `supervisor.firewall.peer_drift` if a settled member is missing — **surfaced as a Fleet warning, never an auto-widen** (auto-widening would be a privilege-escalation vector). k3s node list / configured size are *not* used (over-broad / coarse).

**HA promote / leave reconciliation (asymmetric — the verified cert-SAN safety, applied here):**
- *Promote* adds a `/32`/`/128` to every CP node's set on the next heartbeat (the join window covers the propagation lag).
- *Leave* is the dangerous direction. A `spatium-cluster-join leave` does **destructive** etcd surgery (stop k3s, clear local etcd, flip cluster-init, restart single-node); during that window the leaver must still reach the remaining peers' 2379/2380 to gracefully remove itself, and the remaining peers must still accept *from* the leaver until it is fully out. So peer derivation is **asymmetric on leave**: when an appliance has `desired_cluster_role='none'` (in-flight leave), its `/32` is **kept** in every remaining peer's set AND the remaining peers are kept in the leaver's set, until `cluster_join_state` transitions to `left`. Only the *next* render after `left` drops it. This mirrors the cert-SAN only-grow safety exactly and is covered by an explicit test: 3 nodes → demote one → assert the leaver's 2379/2380 stays open to remaining peers until `cluster_join_state='left'`, then closes.

**Final posture per port:**

| Port | Steady-state scope | Bootstrap handling |
|---|---|---|
| **2379** (etcd client) | `cluster_peers` only; **no LAN fallback**, **no base accept**. Single-node → not emitted (etcd loopback-only). Asymmetric-on-leave (above). | None needed — never reached by a non-member. Ships in Phase 1. |
| **2380** (etcd peer) | `cluster_peers` only; asymmetric-on-leave. | None needed. Phase 1. |
| **10250** (kubelet) | `cluster_peers` only (metrics-server disabled). | None needed. Phase 1. |
| **8472/udp** (flannel VXLAN) or **51820/51821** (wireguard) | `cluster_peers` only, on **every pod-running node**. Read from k3s config (§2.6). | None — peer-to-peer only. **Phase 1 prerequisite.** |
| **7946 tcp+udp** (MetalLB memberlist) | `cluster_peers` only, emitted iff `cp_member_count>=2 AND vip_configured`. | None. Phase 1. |
| **6443** (apiserver) | `cluster_peers ∪ pod_cidr ∪ service_cidr ∪ kubeapi_expose_cidrs`. | **Two layers:** (a) baked `00-spatium-k3s-bootstrap.nft` keeps 6443 LAN-reachable until the cluster is genuinely multi-node + no join window (§3.3); (b) a **bounded auto-narrowing join window** — when any appliance is `cluster_join_state ∈ {pending, joining}`, the backend sets `firewall_join_window_until = now()+firewall_join_window_minutes` on the seed; the seed's drop-in adds `ip saddr @node_subnet tcp dport 6443 accept` (node subnet, never world) for the window; on `joined`/expiry it auto-narrows. For air-gap manual join (joiner not yet a DB row) the Fleet "allow LAN 6443 for join" maintenance toggle creates the same bounded window explicitly. |

---

## 4. Per-role scoping

A node's posture is the union of **two orthogonal axes** (verified roles-and-topologies model): cluster role (`Appliance.cluster_role ∈ {primary,member,None}` → `control-plane` overlay) and service roles (`Appliance.assigned_roles ⊆ {dns-bind9,dns-powerdns,dns-technitium,dhcp,observer,custom}`).

| Node shape (user vocabulary) | cluster_role | service roles | Inbound the compiler emits (balanced) |
|---|---|---|---|
| **Frontend / control node** | primary/member | — | floor + dataplane; 80/443 (+VIP daddr); 6443 (peers∪pod∪svc∪kubeapi, join-window); 2379/2380/10250 (peers); 7946 tcp+udp memberlist (peers, if ≥2+VIP) |
| **DNS worker** | None | dns-bind9 \| dns-powerdns \| dns-technitium | floor + dataplane; 53 tcp+udp. **No k3s ports** — the exact #16 misplacement risk, closed by absence (etcd/kubelet never opened here) |
| **DHCP worker** | None | dhcp | floor + dataplane; udp/67 broadcast (`any`); udp/68 return via floor; udp/547 DHCPv6 (`any`); relay-VIP (`daddr=relayVIP`, relay CIDRs) in bridged mode |
| **Combined DNS+DHCP worker** | None | dns-* ∪ dhcp | floor + dataplane; 53; 67/68/547 — union |
| **Promoted CP also serving DNS** | member | dns-bind9 | union of frontend-node + DNS-worker |
| **Observer** | any | observer | floor + dataplane; node-exporter 9100 scoped to scraper CIDR (default-disabled rule) |
| **Custom** | any | custom | floor + dataplane; custom role policy + `firewall_extra` |

Composition is the §3.7 merge, de-duplicated so two roles opening 53 emit it once. The DNS engines (`dns-bind9` XOR `dns-powerdns` XOR `dns-technitium`) map to the same 53 overlay. The drop-in header `profile:` reflects both axes.

**DHCP/67 honesty (verified Kea hostNetwork).** `udp/67` is opened from `any` because broadcast DISCOVER has no useful `saddr` to scope; relayed unicast from a giaddr is therefore *already* covered by the same `any` rule (no extra scoping needed). The `locked` posture **cannot** scope DHCP/67 — broadcast is unscopeable — and the UI says so explicitly so an operator does not believe they have locked it down. The host's own DHCP-client return (`udp sport 67 dport 68`) lives in the floor (§3.2) so a DHCP-server appliance that is itself DHCP-addressed keeps renewing its lease; this is verified by an explicit Phase-1 test.

**DHCPv6/547 (#1139).** `udp/547` is opened from `any` for the same reason: an on-link Solicit goes to the `ff02::1:2` multicast group, and a relay's Relay-Forward arrives unicast from whatever address the relay uses. Unlike v4, Kea's v6 server has no raw-socket mode, so without this rule every DHCPv6 packet dies on the drop policy, including the relayed case where Kea does bind the address (#1140). It is always open rather than gated on an IPv6 scope existing, because nothing in the role assignment carries scope families and an idle kea-dhcp6 answers nothing. The host's own DHCPv6-client return (`udp sport 547 dport 546`) sits in the floor next to the v4 one.

**#16 tie-in:** the firewall adds no workload (it's host config), so #16's chart-label clause doesn't directly fire — but keying the role overlays on the *same* tokens as `spatium.io/role-*` means the role assignment that schedules a pod (via label) *also* selects that node's firewall layer (via the compiler), so a workload can't land on a node without its firewall rendering there, and vice versa.

---

## 5. Operator UX

A new top-level **Firewall** surface under the Fleet sidebar **Services** group (alongside NTP/SNMP/LLDP), built as a `*Section` on `PlatformSettings` matching the established `{values, isSuperadmin, applianceMode, inputCls}` contract — master toggle = `firewall_enabled`, `!applianceMode` amber banner, Save/dirty/`✓ Saved`, superadmin-gated. **The `firewall_enabled` toggle is itself gated**: the UI refuses to present `posture=hardened` as fleet-wide and refuses to flip the master enable until every CP node reports the new base-conf marker (§2.6) — a "N of M nodes still on the legacy base" badge blocks the claim.

- **Posture preset cards** (three radios): `Lab / open`, `Hardened / balanced` *(recommended)*, `Hostile-LAN / locked`. Selecting **stages** a policy and drops the operator into preview — it doesn't apply.
- **Per-role accordion** with the **guided rule builder** (reusable `<FirewallRuleBuilder>`): each rule is dropdowns — `Action · Service/Port (DNS 53 / etcd 2379 / HTTPS 443 / Custom…) · Protocol · Source scope (Anywhere / Cluster peers (auto) / Pod CIDR (auto) / Management CIDRs / Alias… / Custom CIDRs…)`. No nft. The floor renders as locked, greyed rows with a lock tooltip ("Always open — cannot be removed"). The Source-scope dropdown reuses the SNMP/NTP CIDR `<input>` (split on `/[\s,]+/`, family-aware validation that 422s a v6 entry in a v4-only scope and any `drop` targeting port 22).
- **Alias manager** — define `@lan_clients` once, reference everywhere; CIDRs family-split at rest.
- **Server-rendered preview/diff** (`POST /firewall/preview`) — the *exact* "SpatiumDDI-managed input rules" body per affected node + an added/removed/changed diff + shadow-analysis warnings (rules that will never match). **Replaces the fragile client-side mirror** at `FleetTab.tsx:2998-3012` so UI and renderer can't drift.
- **Commit modal** (built on `ConfirmModal`) — affected-node count, SSH-floor-preserved chip, and **Apply permanently / Test for Ns** buttons. Test-mode copy is precise: *"Test mode auto-reverts only if the control plane becomes unreachable through the new ruleset (e.g. a peer-CIDR typo breaks etcd quorum). It does NOT protect your individual SSH session — the management floor (SSH/22 + ICMP) is always preserved and cannot be removed by any rule."* Any lockout-capable narrowing forces `tone="destructive"` + `requireCheckboxLabel="I understand this may close my SSH session to N appliances"`. A fleet-tier change offers a **canary → health-gate → fan-out** staged rollout reusing the #296 orchestrator shape and **holding the same coordination Lease** (§7). The fan-out enforces **confirm-before-advance**: do not advance to node N+1 until node N has held the new ruleset past the revert window AND re-confirmed on a fresh heartbeat, bounding any split-brain posture to one node. Test-apply is disabled for reboot-causing changes (§3.4a).
- **Per-appliance drilldown** keeps `firewall_extra` (now the **"Raw nftables (expert)"** `<details>`, write-time-lint-gated + acknowledgement-walled) + `kubeapi_expose_cidrs`, plus the server-rendered managed-rules block, the NodePort/LoadBalancer-presence note, a **base-conf badge** (new / legacy), and a **drift/apply-state table** modeled on `ApplianceRoleHealthSection` (`Node · Profile · Base · Rendered hash · Applied hash · Status chip (pending/ok/error/stalled/reverted) · Last confirmed`).
- Flip the stale `NetworkTab.tsx:49-53` "nftables firewall editor … deferred" copy to point at the new tab (the "needs a privileged host-side writer" caveat is obsolete — the supervisor trigger-file → runner plane *is* that writer).

---

## 6. Safety rails + IPv6 + injection-safety + audit/compliance

> **Shipped, partially, as [#1009](https://github.com/spatiumnorth/spatiumddi/issues/1009) — and one sentence below is wrong.**
> The SSH half of this section is now real, under the name `ssh_lockdown`
> rather than `firewall_mgmt_lockdown`, reusing the existing
> `ssh_allowed_source_networks` (#157) as its CIDR source rather than adding
> `firewall_mgmt_cidrs`. The floor moved from `/etc/nftables.conf` to the
> retireable sentinel `/etc/nftables.d/00-spatium-ssh.nft`, and all three
> renderers stamp `# spatium-ssh: retire|keep`.
>
> **"The base-conf floor stays LAN-wide regardless" cannot be true at the
> same time as line 192's `OR ip saddr {mgmt} when firewall_mgmt_lockdown`.**
> nftables is first-match-wins and the base conf is read before the include
> glob, so a floor that stays LAN-wide makes the scoped rule dead code — which
> is exactly the bug #1009 was filed for, designed in. The floor is therefore
> *retireable* rather than *un-removable*: present by default (so §6.1's
> guarantee holds for every install that has not opted in), retired only when
> the operator turns lockdown on. The belt-and-braces of line 266 survives in
> the form that matters — a node whose drop-in never rendered still has the
> baked sentinel.
>
> **What retiring the floor cost, and what paid for it —
> [#1013](https://github.com/spatiumnorth/spatiumddi/issues/1013).** §6.1's
> LAN-wide floor is named in the risk register (R1, and by implication
> everything below it) as the mitigation for *other* firewall mistakes,
> including a bad Web-UI scope from #285 Phase 6. Making it retireable removed
> that backstop for the one combination where both restrictions exclude the
> operator, and the two settings' guards could not see each other. Both write
> paths now resolve one shared question — after this change, does any remote
> door still admit the caller? — and escalate to a distinct 422 with its own
> acknowledgement when the answer is no. This section's guarantee therefore
> holds in the form the register relied on for every install that has not
> deliberately opted out of it *twice*, in writing.

**6.1 Un-removable management floor.** SSH/22 + ICMP v4/v6 + loopback are emitted **first**, outside any operator-controllable block, AND baked in the base conf (`ssh-floor`). No policy, no `firewall_extra`, no `default_action=drop` can remove them. `compile_firewall` **asserts** the body contains an SSH accept and refuses to ship a body lacking it (returns last-good / floor-only + logs). The write-time lint additionally **rejects any rule whose resolved port atoms include 22 with `action=drop`** so an operator can't even author a self-lockout. `firewall_mgmt_lockdown` is honoured only when `firewall_mgmt_cidrs` is non-empty AND yields a non-empty `ip saddr {…} tcp dport 22 accept`; the backend 422s `lockdown=true` with empty `mgmt_cidrs`. The base-conf floor stays LAN-wide regardless — the irreducible recovery channel.

**6.2 IPv6 (three confirmed bugs, fixed at the model layer).** (a) *Lockout-via-validation-gap*: aliases/rules family-split at rest (`v4_members`/`v6_members`, `family`); the renderer routes by family (`ip saddr` vs `ip6 saddr`) so a v6 entry can never leak into a v4 set and wipe the drop-in; the API 422s a v6 CIDR in a v4-only context. (b) *node_ip family*: `_cluster_peer_cidrs` is family-split so a v6 InternalIP yields `/128` (not a garbage `/32`); collection reports **all** InternalIPs as `node_ips: list` (k3s lists both families on dual-stack) so the v6 peer set is derived from a real v6 address. The compiler emits `ip6 saddr {…/128}` **only** when the v6 peer set is non-empty, and a **preflight check flags an asymmetric v6 peer set** (some CP nodes have a v6 InternalIP, the firewall set doesn't) before allowing the base-conf close — preventing a silent v6 etcd hole or v6 quorum outage on a dual-stack cluster. (c) *Silent bypass*: the base conf's family-agnostic k3s accept is gone (§3.2); the floor keeps `icmpv6` so v6 ND/ICMP is never stranded.

**6.3 Injection-safety.** Structured `FirewallRule` rows are the primary, **inject-proof-by-construction** surface (rendered, never pasted). `firewall_extra` is the linted expert hatch: an **allowlist grammar** (only `ip[6] saddr {cidrs} (tcp|udp|icmp[v6]) [dport {ports}] (accept|drop) [comment "…"]` shapes parse; everything else 422s) replaces a brittle deny-list — this closes the injection surface more durably *and* the lint runs at **write time** (never at compile time, no silent drops). `nft -c -f` on the host is the backstop. CIDR fields reuse the `_validated_cidrs` (#236) round-trip. The shadow-analysis in preview warns when an `extra` rule is shadowed by an earlier accept and will never match.

**6.4 Audit (gaps closed).** Every policy/rule/alias mutation writes `audit_log` with **both `old_value` and `new_value`** (closing today's gaps where `kubeapi_cidrs_updated` omits old_value and `role_assigned` omits `firewall_extra` entirely). New typed events (auto-appear in the webhook catalog): `firewall.policy.{created,updated,deleted}`, `firewall.rule.*`, `firewall.appliance_override.updated`, `firewall.posture.changed`, `firewall.auto_reverted`, `firewall.drift_repaired`, `firewall.apply_stalled`.

**6.5 Compliance (stale-PASS, not connectivity-FAIL).** A `conformity` check kind `no_lanwide_control_plane_ports` (PCI Req 1 / HIPAA §164.312). Because the conformity engine's `_TARGET_KINDS` has **no `appliance` target** today, this is implemented as a **`platform`-kind check whose evaluator iterates all appliances internally** (the less-invasive route — no engine/frontend target-enum surgery). The verdict is based on the **last CONFIRMED applied ruleset + base-conf marker** (`FirewallApplyState.last_confirmed_hash` / `base_conf_marker`), **not** heartbeat freshness — so a node that confirmed a hardened ruleset and then went silent reports **PASS-stale ("compliant as of T")**, honouring non-negotiable #5 instead of flipping the whole fleet to FAIL during a transient control-plane outage. A node fails only if it has *never* confirmed a hardened base, or its last confirmed state was LAN-wide, or it is still on the legacy base-conf marker. The expected-port set for CP nodes includes memberlist 7946 tcp+udp (a missing rule surfaces as a compliance fail, not a silent VIP outage). The report carries a staleness column so the auditor sees "compliant as of `<timestamp>`." Wired into the PCI/HIPAA seed frameworks; the read-only managed-rules view is the auditor artifact (honestly labeled per §3.2).

---

## 7. API + MCP + feature-module gating

**Feature module (#14).** New top-level surface → `ModuleSpec(key="appliance.firewall", name="Fleet Firewall", default_enabled=True)` in `feature_modules.MODULES`; migration seeds the `feature_module` row; `dependencies=[Depends(require_module("appliance.firewall"))]` on the new `firewall.py` router include in `router.py` (alphabetised); MCP tools tagged `module="appliance.firewall"`; the Firewall `NavItem` carries `module: "appliance.firewall"`. Default-enabled for *discovery* per #14 — `firewall_enabled` (the *enforcement* knob) defaults false.

**API** — `backend/app/api/v1/appliance/firewall.py` (new router): policy/rule/alias CRUD (write-time lint); `GET /appliances/{id}/firewall/effective` (server-rendered managed-rules body + layer breakdown + NodePort note + base-conf badge); `POST /firewall/preview` (staged-policy diff + shadow-analysis). Reuse `_validate_cidr`. Heartbeat `firewall_settings` block + the `firewall-confirm` round-trip live in `supervisor.py`. **A fleet-firewall coordination Lease** (`coordination.k8s.io`, `spatium-firewall-apply-lock`) is held for the duration of any fan-out OR any single-policy change affecting >1 node, mirroring #296; a new apply (operator OR copilot) is refused while that lock or the rolling-OS-upgrade Lease is held. Rule edits SAVE concurrently (just rows); only RENDER+APPLY fan-out is single-flight.

**MCP (#13)** — `backend/app/services/ai/tools/firewall.py`:
- Reads, **`default_enabled=True`**, superadmin-gated (firewall rules carry no secrets): `find_firewall_policies`, `count_firewall_rules`, `get_appliance_firewall_effective` (managed body + breakdown for a named appliance), `count_appliance_firewall_lanwide_ports` (compliance signal — CP nodes still on the legacy base).
- Writes, **`default_enabled=False`** (broad-blast-radius — can lock out a fleet; #13's explicit carve-out): `propose_set_firewall_policy`, `propose_set_appliance_firewall_override`. Each is an `Operation` returning the rendered-diff preview (§5) → operator Apply, **routed through the same Lease + test-apply/confirm path, never a fast-path**. `propose_assign_role`'s "handle firewall elsewhere" note now points here.

---

## 8. Phased implementation plan

Each phase independently shippable. Phase 1 is the minimal #285 close; later phases build the engine.

**Phase 1 — Close #285 (no new tables, no UI).** *Files:* `appliance/mkosi.extra/etc/nftables.conf`, `agent/supervisor/spatium_supervisor/firewall_renderer.py`, `appliance_state.py`, `heartbeat.py`, `backend/app/api/v1/appliance/supervisor.py`.
- **Build the three prerequisites first** (§2.6 / §3.6): `appliance_state.collect()` parses `spatium-cidrs.yaml` (pod/service CIDR + flannel-backend), hashes `/etc/nftables.conf` (base-conf marker), reports all `node_ips`; heartbeat ships them; backend persists on `Appliance`.
- **Thread the derived inputs into the heartbeat RESPONSE** so the still-in-pod renderer can use them in Phase 1: extend the response near `_build_role_assignment` with `pod_cidr_v4/v6`, `service_cidr_v4`, `dataplane_backend` + `dataplane_peer_cidrs`, `join_window_active`. (Render stays in-pod this phase; Phase 2 hoists the whole body.)
- Family-split `_cluster_peer_cidrs` → v4 (`/32`) + v6 (`/128`) from `node_ips`; add **asymmetric-on-leave** behavior (§3a); fix the IPv6 family-split in the renderer (§6.2 a/b).
- Renderer: emit the **DATA-PLANE FLOOR** (flannel/wireguard, peer-scoped, every node); scope 2379/2380/10250 to peers **authoritatively**; 6443 → peers∪pod∪svc + the join-window flag (derived from `cluster_join_state`); add memberlist **7946 tcp+udp** (iff ≥2 members + VIP).
- Base conf: delete the LAN-wide `k3s-ha` line, **keep** the DHCP-client-return floor; add the baked `00-spatium-k3s-bootstrap.nft`; runner gains bootstrap-retire **gated on multi-node + no-join-window** (§3.3) + base-conf-marker echo.
- **Tests (real 3-node appliance):** cross-node pod-to-pod + pod-to-apiserver survive; VIP re-homes after killing the holder; demote keeps 2379/2380 open to peers until `left`; a DHCP-addressed DHCP-server node keeps its lease; old-base+new-drop-in and new-base+old-drop-in both stay reachable.
- *(Ships via A/B slot OS image — the scoped rules are additive/harmless on the old base; the base-conf marker is the per-node "which base is live" signal that gates the UI/compliance claim.)*

**Phase 2 — Server-side render + auto-revert safety.** *Files:* new `backend/app/services/appliance/firewall.py`, `supervisor.py` (heartbeat `firewall_settings` block, `firewall-confirm` + self-probe), `appliance_state.py` (`maybe_fire_firewall_reload`), `usr/local/bin/spatium-firewall-reload` + new `spatium-firewall-revert.timer/.service` + deadline-file wiring.
- Move render server-side (`firewall_bundle` with canonical backend hash + named saddr sets); supervisor becomes a pipe; keep `firewall_renderer.py` as the one-release fallback.
- State-file-driven test-apply + persistent-timer auto-revert + per-node self-probe + reboot-survival + `revert_seconds ≥ 2×heartbeat` clamp + reboot-causing-change forbiddance (§3.4a); surface `firewall-applied-status` + base marker → `FirewallApplyState`; apply-lag alarm (§3.4b).

**Phase 3 — Policy data model + merge + preview API + feature module.** *Files:* new `backend/app/models/firewall.py`, migration, new `backend/app/api/v1/appliance/firewall.py`, `feature_modules.py`, `app/api/v1/router.py`.
- **Migration discipline:** the tree has **six concurrent alembic heads** today — emit an `alembic merge` collapsing them first (run `alembic heads`/`get_heads()` at authoring time; never trust a date-sorted filename), then chain the firewall revision off that single head. **Split** into (1) schema (tables + `platform_settings` columns) and (2) an idempotent data seed (module row + builtin policies/aliases) so a seed bug can't block schema and the seed is re-runnable.
- Implement the §3.7 explosion + deny-wins + source-union merge; allowlist-grammar `firewall_extra` lint + the one-time existing-value advisory scan; CRUD + effective + preview (shadow-analysis) endpoints behind `require_module`; coordination Lease; full audit + typed events. `firewall_enabled` still defaults false (ships dark).

**Phase 4 — Fleet UX.** *Files:* new `frontend/src/components/FirewallSection.tsx`, `frontend/src/components/FirewallRuleBuilder.tsx`, new `frontend/src/pages/appliance/FirewallTab.tsx`, `FleetTab.tsx` (effective view + drift table + base badge + linted override), `NetworkTab.tsx` (fulfil the deferral), `lib/api.ts`.
- Posture presets, per-role accordion + rule builder, alias manager, server-rendered preview/diff, commit modal + precise test-mode copy + confirm-before-advance canary rollout + base-conf gate on the master enable.

**Phase 5 — MCP + compliance + drift hardening + docs.** *Files:* new `backend/app/services/ai/tools/firewall.py`, conformity `platform`-kind check, host-side etcd-member-list cross-check, docs.
- Reads (default-on) + `propose_*` (default-off, Lease-routed) with rendered-diff previews; `no_lanwide_control_plane_ports` stale-PASS check + PCI/HIPAA seeds; host-side peer-drift cross-check (warn-only); APPLIANCE.md firewall section + TOPOLOGIES.md per-role posture table + the air-gap manual-join runbook. Retire the supervisor fallback renderer.

---

## 9. Open questions / decisions for the maintainer

1. **Pod-CIDR + base-conf authority.** §2.6 has the supervisor parse `spatium-cidrs.yaml` + hash `/etc/nftables.conf` and report them (operator-chosen #302 stays authoritative on the owning box, survives control-plane loss). Alternative: the backend reads cluster CIDRs from `kubectl get cm`. Supervisor-reported is simpler and #5-safe — confirm that's the call.
2. **`firewall_default_input_action`.** Ship `drop`-only first (keep base `policy drop` + floor-first). Defer the Talos-style `accept` default posture. Confirm.
3. **Web/443 closure.** `balanced` keeps 80/443 LAN-wide (daddr-agnostic for the VIP). True LAN-lockdown of web (`locked` posture) needs the base 80/443 to also leave the base conf — a second base-conf cut. Ship `locked` web-scoping in Phase 4 or defer to a later base cut?
4. **Auto-revert default-on for narrowing?** Recommendation: yes — fleet-tier *narrowing* forces a test-apply (no permanent button) until one node confirms via self-probe; widening is optional-test. Confirm.
5. **Static IPs for CP nodes.** Recommendation: surface a Fleet warning when a `cluster_role!=None` appliance is DHCP-addressed (peer-IP churn thrashes drift + can wobble etcd). Make it a hard preflight before base-conf close, or warn-only?
6. **memberlist 7946 derivation.** Shipped derived from `cp_member_count>=2 AND vip_configured` rather than a `metallb_enabled` flag the supervisor doesn't mirror. Confirm that's acceptable, or do we add the flag to the heartbeat?
7. **Phase-1 ship vehicle + rolling-upgrade sequencing.** The base-conf cut only lands via A/B slot upgrade. Confirm Phase 1 ships in a release that bumps the slot image, that the rolling OS upgrade sequences so firewall posture "counts" only after every CP node reports the new base marker, and that the conformity check (stale-PASS) is the operator's per-node signal for which fleet nodes are still on the legacy base.

---

## 10. Risk register (residual risks after the fixes above)

| # | Residual risk | Likelihood × impact | Mitigation in this design |
|---|---|---|---|
| R1 | **Self-inflicted SSH lockout** via a typo'd `mgmt` alias or a bad source-scoped accept on 22's neighbours. | Low × High | Un-removable SSH floor emitted first + baked (§6.1); write-time lint rejects any `drop` on 22; base-conf floor stays LAN-wide as the irreducible recovery channel. Auto-revert explicitly does **not** cover this (honest UX copy, §5). |
| R2 | **Mid-rolling-upgrade split-brain** (new-slot hardened nodes vs legacy-base LAN-wide nodes) misreported as fully hardened. | Medium × Medium | Per-node base-conf marker (§2.6) gates the UI "hardened" claim + the conformity verdict; master `firewall_enabled` flip blocked until all CP nodes report the new base; additive scoped rules are harmless on the legacy base. |
| R3 | **flannel/data-plane port still wrong** if an operator runs a non-default backend the parser doesn't recognise. | Low × High | `flannel-backend` is *read* from k3s config, not assumed; unknown backend → fall back to leaving the data-plane LAN-reachable (fail-open for the data plane) + raise a Fleet warning rather than silently dropping pod traffic. |
| R4 | **etcd quorum wobble** from an `nft -f` reload dropping conntrack-new etcd connections during a peer-set change on a busy cluster. | Low × Medium | Named saddr sets + `nft add/delete element` (not full reload) for peer-set-only changes; canonical-hash debounce; static-IP recommendation for CP nodes (R-adjacent: DHCP churn warning). |
| R5 | **Air-gap manual join** when the cluster is already multi-node and the bootstrap sentinel has retired. | Low × Medium | Bootstrap retires only at `cp_member_count>=2 AND no join window`; Fleet "allow LAN 6443 for join" audited auto-expiring toggle re-opens a bounded window without a pre-existing DB row; documented runbook (Phase 5). |
| R6 | **Effective-view misread as the true kernel ruleset** when kube-proxy NodePort/LoadBalancer paths exist outside our `inet filter` table. | Medium × Low | View labeled "SpatiumDDI-managed input rules"; supervisor ships NodePort/LB-presence summary; docs scope the firewall to host + hostNetwork-pod inbound, NetworkPolicy for pod traffic. |
| R7 | **Dual-stack v6 etcd hole/outage** if some CP nodes have a v6 InternalIP and the firewall set is asymmetric. | Low × High | `node_ips` reports all families; v6 rules emitted only when the v6 peer set is non-empty; preflight check flags asymmetric v6 peer sets before the base-conf close. |
| R8 | **Concurrent writers** (operator + copilot + rolling OS upgrade) racing renders/reverts. | Low × Medium | Fleet-firewall coordination Lease for any >1-node apply; refuse new apply while that or the OS-upgrade Lease is held; confirm-before-advance fan-out bounds split-brain to one node. |
| R9 | **Supervisor wedged** (control plane up) so a critical lockdown never lands on a node. | Low × Medium | `firewall.apply_stalled` typed alert after N stale heartbeats, cross-referenced with Wave E external-watchdog state; differentiated apply-state chip. |
| R10 | **`firewall_extra` shadowed rule** an expert expects to take effect but never matches. | Medium × Low | Allowlist grammar (write-time 422 on malformed); `nft --check` + structural shadow-analysis in preview surfaces "will never match"; documented as strictly additive/last. |
| R11 | **Demote/leave strands** if `cluster_join_state` never reaches `left` (e.g. a force-removed node). | Low × Medium | Asymmetric-on-leave keeps peer ports open until `left`; the existing leave runbook + a Fleet warning if a `desired_cluster_role='none'` row stays non-`left` past a timeout. |

---

## 11. Expanded issue #285 text (ready-to-paste GitHub issue body)

> **Title:** Appliance: fine-grained, per-role, fleet-wide firewall (declarative policy → nftables); close LAN-wide k3s-HA ports as Phase 1

### Context

The appliance base firewall (`appliance/mkosi.extra/etc/nftables.conf`) unconditionally accepts the k3s control-plane/etcd/kubelet ports from **any** source:

```nft
tcp dport { 6443, 2379, 2380, 10250 } accept comment "k3s-ha"
```

This is intentional today — a joining node must reach these *before* the supervisor can render a peer-scoped drop-in (a bootstrap chicken-and-egg), and it matches k3s's own posture (token + mTLS on 6443, client-cert on etcd). But it exposes etcd and the kubelet LAN-wide. The supervisor *already* renders a peer-scoped drop-in for these ports (`firewall_renderer.py`, #272 Phase 7b) — except nftables is **first-match-wins**, so that scoped rule is **dead code stacked behind the base `accept` that already fired**. The only way to actually *close* these ports is to make the rendered drop-in authoritative and reduce the base conf to a floor.

The broader operator ask: **fine-grained firewall control per node role** — a frontend/control node, a DNS-only worker, and a DHCP-only worker should each expose only what that role needs, authored once and rolled fleet-wide.

### Goal

A first-class **declarative firewall policy** authored on the control plane in three additive layers (fleet baseline → per-role overlay keyed on the same taxonomy as the `spatium.io/role-*` node labels → per-appliance override), **compiled server-side** into the authoritative `spatium-role.nft` drop-in, riding the existing supervisor heartbeat → trigger-file → `spatium-firewall-reload` plane (the SNMP/NTP/LLDP pattern). Source scoping is a `source_kind` enum whose *derived* scopes (`cluster_peers` / `pod_cidr` / `mgmt` / `vip`) resolve per-node at render time, so promote/demote re-renders automatically and the firewall tightens on demote with zero per-appliance edits. Injection-proof by construction (rules are rendered, never pasted); honours #5 (last-good cache survives control-plane loss), #13 (MCP), #14 (feature module), #16 (role taxonomy).

### Verified prerequisites (must land before any port is closed)

- [ ] **pod/service CIDR mirror** — the supervisor does **not** report pod/service CIDR today; parse it from `spatium-cidrs.yaml` and ship it (6443 must accept from pod/service CIDR for in-cluster apiserver access).
- [ ] **flannel data-plane port** — VXLAN `8472/udp` (or wireguard `51820/51821` if configured) is opened **nowhere** today; closing the LAN-wide base accept without it **breaks cross-node pod networking**. Read `flannel-backend` from k3s config; emit peer-scoped on every pod-running node.
- [ ] **base-conf-version marker** — the supervisor must report which base `/etc/nftables.conf` is live so a partially A/B-upgraded fleet isn't silently split-brain (hardened new-slot vs LAN-wide old-slot).
- [ ] **all-family node IPs** — report all InternalIPs (`node_ips: list`) and family-split peer derivation (`/32` v4, `/128` v6) — today `_cluster_peer_cidrs` hardcodes `/32`, producing a garbage v6 network.

### Phased deliverables

**Phase 1 — close #285 (no new tables, no UI)**
- [ ] Build the four prerequisites above; thread derived inputs into the heartbeat **response** so the still-in-pod renderer can use them.
- [ ] Emit the **data-plane floor** (flannel/wireguard, peer-scoped, every node).
- [ ] Scope `2379/2380/10250` to peers **authoritatively**; `6443` → peers ∪ pod ∪ service ∪ kubeapi_expose + bounded auto-narrowing **join window**.
- [ ] Add **MetalLB memberlist `7946` tcp+udp** (peer-scoped, iff ≥2 CP members + VIP).
- [ ] **Asymmetric-on-leave** peer set — keep a demoting node's etcd ports open to peers until `cluster_join_state='left'` (mirrors cert-SAN only-grow).
- [ ] Base conf → floor: remove the LAN-wide `k3s-ha` line; **keep** the DHCP-client-return rule; add baked `00-spatium-k3s-bootstrap.nft`; retire it **only** when multi-node + no join window.
- [ ] Real 3-node tests: cross-node pod + pod-to-apiserver, VIP re-home, demote-grace, DHCP-server lease renewal, old/new base × old/new drop-in reachability.

**Phase 2 — server-side render + auto-revert safety**
- [ ] Hoist render server-side (`firewall_bundle`, canonical hash, named saddr sets); supervisor becomes a pipe; keep in-pod renderer one release as the #5 fallback.
- [ ] **State-file + persistent-timer auto-revert** (reboot-survivable, idempotent), **per-node self-probe** confirmation (no fleet-wide mass-revert on a transient), `revert_seconds ≥ 2× heartbeat`, forbid test-apply on reboot-causing changes.
- [ ] Surface `firewall-applied-status` + base marker → `FirewallApplyState`; `firewall.apply_stalled` alarm.

**Phase 3 — policy data model + merge + preview API + feature module**
- [ ] `firewall_policy` / `firewall_rule` / `firewall_alias` / `firewall_apply_state` + `platform_settings` posture columns. **Merge the six current alembic heads first**; split schema migration from idempotent seed.
- [ ] Concrete **explode → deny-wins → source-union** merge (§3.7); allowlist-grammar `firewall_extra` lint (write-time) + one-time advisory scan of existing values.
- [ ] CRUD + `GET …/firewall/effective` + `POST /firewall/preview` (shadow-analysis) behind `require_module("appliance.firewall")`; coordination **Lease** for any >1-node apply; full audit (old+new value) + typed events. Ships dark (`firewall_enabled=false`).

**Phase 4 — Fleet UX**
- [ ] Posture preset cards (open/balanced/locked); per-role accordion + guided rule builder (no nft); alias manager; server-rendered preview/diff; commit modal (precise test-mode copy, destructive-checkbox on narrowing, confirm-before-advance canary rollout); base-conf gate on the master enable; fulfil the deferred `NetworkTab` editor.

**Phase 5 — MCP + compliance + docs**
- [ ] Read tools (default-on, superadmin) + `propose_*` writes (default-off, Lease-routed); `no_lanwide_control_plane_ports` **stale-PASS** conformity check (PCI Req 1 / HIPAA) via a `platform`-kind iterator; host-side etcd-member-list peer-drift cross-check (warn-only); APPLIANCE.md + TOPOLOGIES.md + air-gap manual-join runbook; retire the fallback renderer.

### Key design decisions

- [ ] **Authoritative drop-in, base = floor.** The only way to *close* a base port (first-match-wins). FORWARD/OUTPUT stay `accept` (pod networking + outbound heartbeat); SSH/22 + ICMP + loopback are an **un-removable floor** (renderer-first + baked), and no rule may `drop` 22.
- [ ] **Derived source scopes** (`cluster_peers`/`pod_cidr`/`mgmt`/`vip`) resolved per-node so promote/demote auto-re-renders; **asymmetric on leave** for the destructive etcd surgery window.
- [ ] **#5 first:** last-good cache on the `/etc` overlay; nothing tightens or flushes on control-plane loss; compliance reports **PASS-stale**, never connectivity-FAIL.
- [ ] **Auto-revert** catches inter-node partition (per-node self-probe), **not** self-inflicted SSH lockout (the floor + lint do that) — and says so in the UI.
- [ ] **IPv6 correctness** at the model layer (family-split aliases/peers, v6-only-when-non-empty, asymmetric-v6 preflight).
- [ ] **Injection-proof** structured rules; `firewall_extra` = allowlist-grammar expert hatch, additive + last.

*Supersedes the original "scope 6443/2379/2380/10250 to peer CIDRs" framing — that is now Phase 1.*
