#!/bin/bash
# refresh_issuing_crl.sh — Re-signs the RSA and ECC Issuing CA CRLs (7-day validity)
#
# Recommended cron (every 6 days, 05:00 UTC — 1-day buffer before expiry):
#   0 5 */6 * * /bin/bash /var/www/thameur.org/scripts/refresh_issuing_crl.sh
#
# The openssl.cnf files are written by gen_test_pki.php on each rotation.
# Run that script first if the configs do not exist yet.

set -euo pipefail

LOGFILE="/var/log/pki-crl-refresh.log"
exec >> "$LOGFILE" 2>&1

echo "===== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===== refresh_issuing_crl"

prune_expired_revoked() {
    local INDEX="$1"
    local now
    now=$(date -u '+%y%m%d%H%M%SZ')
    awk -v now="$now" 'BEGIN{FS="\t"} !($1=="R" && $2<=now)' "$INDEX" > "${INDEX}.tmp" \
        && mv "${INDEX}.tmp" "$INDEX"
}

refresh_crl() {
    local CONFIG="$1"
    local OUT="$2"
    local DB="$3"

    if [ ! -f "$CONFIG" ]; then
        echo "SKIP: $CONFIG not found — run gen_test_pki.php first"
        return 0
    fi

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
    echo "Issuing CRL updated → $OUT"

    # Restore group permissions in case openssl recreated any db files as root-only
    chgrp www-data "$DB/crlnumber" "$DB/index.txt" "$DB/cert.srl" 2>/dev/null || true
    chmod 660      "$DB/crlnumber" "$DB/index.txt" "$DB/cert.srl" 2>/dev/null || true
}

# RSA Issuing CA CRL
refresh_crl \
    "/var/www/thameur.org/pki-ca/issuing-db/openssl.cnf" \
    "/var/www/pki.thameur.org/meerkat-issuing.crl" \
    "/var/www/thameur.org/pki-ca/issuing-db"

# ECC Issuing CA CRL
refresh_crl \
    "/var/www/thameur.org/pki-ca/ecc-issuing-db/openssl.cnf" \
    "/var/www/pki.thameur.org/meerkat-ecc-issuing.crl" \
    "/var/www/thameur.org/pki-ca/ecc-issuing-db"
