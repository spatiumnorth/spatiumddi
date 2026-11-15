#!/bin/sh
# su-exec compatible shim for the UBI image (#3913). UBI has no su-exec
# package; the entrypoint's root-start path calls ``su-exec user:group cmd``.
# setpriv (util-linux) does the same thing: switch uid/gid, set supplementary
# groups, exec. Only the ``user[:group]`` form the entrypoints use is supported.
set -eu
spec="${1:?usage: su-exec user[:group] command [args...]}"
shift
user="${spec%%:*}"
group="${spec#*:}"
[ "$group" = "$spec" ] && group="$user"
uid=$(id -u "$user")
gid=$(getent group "$group" | cut -d: -f3)
exec setpriv --reuid="$uid" --regid="$gid" --init-groups -- "$@"
