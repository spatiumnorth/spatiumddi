#!/bin/sh
# #4192 -- apply SPATIUM_MALLOC_CONF to named's jemalloc.
#
# jemalloc reads its options from the target of the /etc/malloc.conf symlink.
# (The MALLOC_CONF environment variable is ignored by a binary with a file
# capability, which named is.) Unset or empty keeps the value the image ships.
# Replacing a symlink needs write access to /etc, so a container started as a
# random uid (OpenShift's restricted SCC) cannot override it: say so and keep
# the shipped value rather than failing to start.
set -u
link="${MALLOC_CONF_LINK:-/etc/malloc.conf}"
conf="${SPATIUM_MALLOC_CONF:-}"
[ -n "$conf" ] || exit 0
if ln -sfn "$conf" "$link" 2>/dev/null; then
    echo "spatium-malloc-conf: jemalloc options set to: $conf" >&2
else
    echo "spatium-malloc-conf: cannot write $link as uid $(id -u); SPATIUM_MALLOC_CONF ignored, image default kept" >&2
fi
exit 0
