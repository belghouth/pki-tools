#!/bin/bash
# refresh_root_crl.sh — Re-signs the Meerkat Root ARL (365-day validity)
#
# Recommended cron (1st of each month, 05:00 UTC):
#   0 5 1 * * /bin/bash /var/www/thameur.org/scripts/refresh_root_crl.sh
#
# The openssl.cnf used here is written by gen_test_pki.php on each rotation.
# Run that script first if the config does not exist yet.

set -euo pipefail

LOGFILE="/var/log/pki-crl-refresh.log"
exec >> "$LOGFILE" 2>&1

echo "===== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===== refresh_root_crl"

CONFIG="/var/www/thameur.org/pki-ca/root-db/openssl.cnf"
OUT="/var/www/pki.thameur.org/meerkat-root.crl"

if [ ! -f "$CONFIG" ]; then
    echo "ERROR: $CONFIG not found — run gen_test_pki.php first"
    exit 1
fi

TMP="$(mktemp)"
/usr/bin/openssl ca \
    -config  "$CONFIG" \
    -gencrl \
    -out     "$TMP" \
    -batch

/usr/bin/openssl crl -in "$TMP" -outform DER -out "$OUT"
rm -f "$TMP"

# Log next update date
/usr/bin/openssl crl -in "$OUT" -inform DER -noout -nextupdate
echo "Root ARL updated → $OUT"
