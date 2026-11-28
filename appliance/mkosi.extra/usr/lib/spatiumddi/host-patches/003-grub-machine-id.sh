#!/bin/sh
# Patch 003 — re-render grub.cfg so it carries systemd.machine_id= (#4954).
#
# spatium-host-migrate runs each patch once (ledger host-patches-applied.json),
# so boxes that already applied 001 would never pick up the renderer's new
# machine-id cmdline argument. The renderer reads the persisted id from
# /var/lib/spatium-state/machine-id (or /etc/machine-id) and emits it on every
# linux line; journald then opens the journal under the persisted id instead of
# the DMI UUID.
#
# Idempotent: the output is deterministic from live state. Exit 0 = success;
# non-zero propagates (same contract as 001).

set -eu
exec /usr/local/bin/spatium-grub-render
