#!/bin/sh
# Reload nginx in place when the mounted TLS certificate changes (spatiumddi #1173).
#
# The appliance mounts the ``spatium-appliance-tls`` Secret at /etc/nginx/tls as
# a directory (no subPath), so the kubelet replaces tls.crt / tls.key inside the
# running pod whenever the api deploys a certificate: an uploaded, CSR-signed or
# Let's Encrypt one being activated, or the self-signed one the api re-mints when
# a control-plane member joins. nginx reads those files only at start and on a
# reload, so this watcher reloads it when they change. ``nginx -s reload`` keeps
# the listening sockets: the web ports never stop accepting, requests in flight
# finish on the old workers, and new connections get the new certificate.
#
# Before #1173 the api rolled the frontend Deployment instead. The frontend is
# hostNetwork with host ports 80/443, so that roll is terminate-first: each
# node's web port refused connections until its replacement pod had started.
#
# The nginx image's entrypoint runs this (/docker-entrypoint.d/*.sh) before it
# starts nginx. It forks the watcher and returns at once. The watcher takes its
# first reading before nginx loads the files, so a change between the two gets a
# reload rather than going unnoticed. Each change is checked with ``nginx -t``
# first. A pair nginx refuses (a key that does not match its certificate) is not
# sent: nginx keeps serving the certificate it has, the refusal is logged once,
# and the watcher tests again on every tick until the files change or nginx
# accepts them. A reload that finds no nginx running yet is retried too.
#
# No certificate mounted (Docker Compose, or the chart's frontend.tls.enabled
# off): nothing to watch, so it exits.
#
# SPATIUM_TLS_DIR and SPATIUM_TLS_RELOAD_INTERVAL (seconds) exist for
# backend/tests/test_frontend_tls_reload_1173.py; the defaults are the image's.

set -eu

_me="40-tls-reload-watch"
_dir="${SPATIUM_TLS_DIR:-/etc/nginx/tls}"
_every="${SPATIUM_TLS_RELOAD_INTERVAL:-5}"

_log() {
    if [ -z "${NGINX_ENTRYPOINT_QUIET_LOGS:-}" ]; then
        echo "$_me: $*"
    fi
}

if [ ! -f "$_dir/tls.crt" ] || [ ! -f "$_dir/tls.key" ]; then
    _log "no certificate in $_dir; not watching"
    exit 0
fi

if command -v sha256sum >/dev/null 2>&1; then
    _sum="sha256sum"
else
    _sum="cksum"
fi

# What nginx would load, as one line. The kubelet swaps both files at once (a
# rename of the ..data symlink), so a reading never mixes two certificates for
# longer than one tick.
_stamp() {
    cat -- "$_dir/tls.crt" "$_dir/tls.key" 2>/dev/null | $_sum
}

_watch() {
    set +e
    _last=$(_stamp)
    _refused=""
    while sleep "$_every"; do
        _now=$(_stamp)
        [ "$_now" != "$_last" ] || continue
        if ! _why=$(nginx -t 2>&1); then
            if [ "$_now" != "$_refused" ]; then
                echo "$_me: the certificate in $_dir changed, but nginx -t refused it; still serving the previous one" >&2
                printf '%s\n' "$_why" >&2
                _refused=$_now
            fi
            continue
        fi
        if nginx -s reload; then
            echo "$_me: the certificate in $_dir changed; nginx reload sent"
            _last=$_now
            _refused=""
        fi
    done
}

_log "watching $_dir every ${_every}s; nginx reloads when the certificate changes"
_watch </dev/null &
