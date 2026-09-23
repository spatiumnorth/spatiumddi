# Appliance host-script tests (#395)

Host-portable pytest suite for the appliance host scripts — and for the
CI gates that guard the appliance's Helm charts, which have nowhere else
hermetic to live.  These tests run on any developer machine or CI runner
with Python 3 and do NOT require a database, Docker, an appliance ISO,
helm or a cluster.

## Files

| File | What it tests |
|---|---|
| `test_chart_pod_posture.py` | `.github/scripts/chart-pod-posture.py` — the seccomp + PriorityClass gate on both charts (#983) |
| `test_cluster_join_failure_reason.py` | `spatium-cluster-join`'s failure-reason classifier (#590) |
| `test_cluster_join_identity.py` | `spatium-cluster-join`'s cluster-identity wipe (#590) |
| `test_firewall_webui_sentinel.py` | Web UI reachability before the supervisor exists (#769) |
| `test_firstboot_member_guard.py` | `spatiumddi-firstboot` not re-seeding manifests on a joined member (#590) |
| `test_firstboot_priority_class_reassert.py` | `spatiumddi-firstboot` having spatium-bootstrap re-create a missing `spatium-control-plane` before the control chart is released, and every guard around it, driven against a stub apiserver (#1123) |
| `test_firstboot_pod_posture.py` | `spatiumddi-firstboot`'s PSA namespace labels, the control-plane PriorityClass overlay, and the release-time gate that strips it when the class is absent (#983) |
| `test_frontend_boot_gate.py` | SPA fallback landing on the initialising page (#767) |
| `test_grub_render.py` | `spatium-grub-render` renderer via `--print` (DRY-RUN) |
| `test_host_migrate.py` | `spatium-host-migrate` orchestrator via a patched subprocess |
| `test_host_runner_stdin_programs.py` | The three runners that piped data into a `python3 -` whose program came from a heredoc — the SSH source-CIDR allowlist failing OPEN, TLS-syslog CAs, image pruning (#1001) |
| `test_install_done_gate.py` | The headless-install Done-screen gate |
| `test_install_ntp_decline.py` | Blanking the installer's **Time source** really disabling NTP — the rendered on-target `chrony.conf` plus firstboot's explicit-decline sentinel (#1002) |
| `test_preseed_lint.py` | `spatium-install --check-preseed` linter |
| `test_preseed_security.py` | The #549 preseed installer's security guards (#581) |
| `test_slot_status_active_version.py` | `spatium-upgrade-slot status` reading the active slot's version without a mount (#788) |
| `test_slot_upgrade_runner.py` | `spatiumddi-slot-upgrade` dead/stalled-apply guards (#421) |

## How to run

```sh
# from the repo root:
python3 -m pytest appliance/tests/ -v

# or from this directory:
cd appliance/tests
pytest -v
```

`grub-script-check` tests are automatically skipped when the binary is not
on PATH (install `grub2-common` / `grub-common` to enable them).

The `test_install_ntp_decline.py` cases that execute the installer's
`sed -i -E` skip on macOS: BSD sed takes `-i`'s backup suffix as the next
argument and swallows the `-E`, so it would measure a different program
than the Debian appliance runs. CI is ubuntu-latest, where they always run.

## Notes

The orchestrator (`spatium-host-migrate`) hardcodes its working paths as
unconditional shell variable assignments rather than `${VAR:-/default}`
env-overridable forms.  Tests work around this by dynamically patching the
script text before running it in a subprocess (a safe, read-only rewrite of
just the path declarations + the appliance-gate check).  If the orchestrator
is ever refactored to support env-var overrides, the `_run_migrate()` helper
in `test_host_migrate.py` can be simplified accordingly.
