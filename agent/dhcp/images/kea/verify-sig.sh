#!/bin/sh
# verify-sig FILE SIGNATURE KEY-URL FINGERPRINT
#
# Build-time check (#3913) that FILE was signed by exactly the OpenPGP key whose
# fingerprint the Dockerfile pins, in addition to the sha256 it also pins. The key
# is fetched from KEY-URL into a throwaway GNUPGHOME; the pinned fingerprint, not
# the URL, is what is trusted, so a swapped key file fails here. FINGERPRINT may
# be the signing (sub)key or its primary key: gpg's VALIDSIG status carries both.
set -eu
file=$1; sig=$2; url=$3; fpr=$4
home=$(mktemp -d); chmod 700 "$home"; trap 'rm -rf "$home"' EXIT
curl -fsSL --retry 3 -o "$home/key" "$url"
gpg --homedir "$home" --batch --quiet --import "$home/key" 2>/dev/null || true  # exits non-zero on expired subkeys; the fingerprint check below decides
gpg --homedir "$home" --batch --status-fd 1 --verify "$sig" "$file" 2>/dev/null \
  | awk -v f="$fpr" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == f || $NF == f) { ok = 1 } END { exit !ok }' \
  || { echo "verify-sig: $file is NOT signed by $fpr" >&2; exit 1; }
echo "verify-sig: $file signed by $fpr"
