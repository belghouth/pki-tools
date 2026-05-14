#!/bin/bash
# refresh_issuing_crl.sh — Re-signs the Meerkat Issuing CA CRL (7-day validity)
#
# Recommended cron (every 6 days, 05:00 UTC — 1-day buffer before expiry):
#   0 5 */6 * * /bin/bash /var/www/thameur.org/scripts/refresh_issuing_crl.sh
#
# The openssl.cnf used here is written by gen_test_pki.php on each rotation.
# Run that script first if the config does not exist yet.

set -euo pipefail

LOGFILE="/var/log/pki-crl-refresh.log"
exec >> "$LOGFILE" 2>&1

echo "===== $(date -u '+%Y-%m-%d %H:%M:%S UTC') ===== refresh_issuing_crl"

CONFIG="/var/www/thameur.org/pki-ca/issuing-db/openssl.cnf"
OUT="/var/www/pki.thameur.org/meerkat-issuing.crl"

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
echo "Issuing CRL updated → $OUT"

# Restore group permissions in case openssl recreated any db files as root-only
DB="/var/www/thameur.org/pki-ca/issuing-db"
chgrp www-data "$DB/crlnumber" "$DB/index.txt" "$DB/cert.srl" 2>/dev/null || true
chmod 660      "$DB/crlnumber" "$DB/index.txt" "$DB/cert.srl" 2>/dev/null || true
