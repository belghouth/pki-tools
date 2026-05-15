#!/bin/bash
# refresh_root_crl.sh — Re-signs the RSA and ECC Root ARLs (365-day validity)
#
# Recommended cron (1st of each month, 05:00 UTC):
#   0 5 1 * * /bin/bash /var/www/thameur.org/scripts/refresh_root_crl.sh
#
# The openssl.cnf files are written by gen_test_pki.php on each rotation.
# Run that script first if the configs do not exist yet.

set -euo pipefail

LOGFILE="/var/log/pki-crl-refresh.log"
exec >> "$LOGFILE" 2>&1

echo "===== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===== refresh_root_crl"

prune_expired_revoked() {
    local INDEX="$1"
    local now
    now=$(date -u '+%y%m%d%H%M%SZ')
    awk -v now="$now" 'BEGIN{FS="\t"} !($1=="R" && $2<=now)' "$INDEX" > "${INDEX}.tmp" \
        && mv "${INDEX}.tmp" "$INDEX"
}

refresh_arl() {
    local CONFIG="$1"
    local OUT="$2"

    if [ ! -f "$CONFIG" ]; then
        echo "SKIP: $CONFIG not found — run gen_test_pki.php first"
        return 0
    fi

    local DB
    DB="$(dirname "$CONFIG")"
    prune_expired_revoked "$DB/index.txt"

    TMP="$(mktemp)"
    /usr/bin/openssl ca \
        -config  "$CONFIG" \
        -gencrl \
        -crlexts crl_ext \
        -out     "$TMP" \
        -batch

    /usr/bin/openssl crl -in "$TMP" -outform DER -out "$OUT"
    rm -f "$TMP"

    /usr/bin/openssl crl -in "$OUT" -inform DER -noout -nextupdate
    echo "Root ARL updated → $OUT"
}

# RSA Root ARL
refresh_arl \
    "/var/www/thameur.org/pki-ca/root-db/openssl.cnf" \
    "/var/www/pki.thameur.org/meerkat-root.crl"

# ECC Root ARL
refresh_arl \
    "/var/www/thameur.org/pki-ca/ecc-root-db/openssl.cnf" \
    "/var/www/pki.thameur.org/meerkat-ecc-root.crl"

# MPCA Root ARL (365-day validity)
refresh_arl \
    "/var/www/thameur.org/pki-ca/mpca/root/openssl.cnf" \
    "/var/www/pki.thameur.org/mpca/root.crl"
