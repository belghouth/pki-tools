#!/usr/bin/env bash
# cron/prune_tmp.sh — remove stale temp files left by pki-tools PHP scripts.
#
# Normal PHP cleanup (finally / register_shutdown_function) covers the happy path.
# This script handles files orphaned by fatal errors, OOM kills, or server crashes.
# cert_factory.php is the highest-risk file: its cleanup is scattered @unlink calls
# rather than a single finally block.
#
# ── File locations ─────────────────────────────────────────────────────────────
#
#  /tmp/mkt_*                          modules/_base.php          (all OpenSSL helpers)
#  /tmp/x509lint_* zlint_* pkilint_*   linters/
#  /tmp/at_k_* at_c_* at_n_* …        acme_tester.php
#  /tmp/revoc_ee_* revoc_is_* …        revocation.php
#  /tmp/cf_csr_* cf_cert_* cf_ext_* …  cert_factory.php           (highest orphan risk)
#  /tmp/ct_iss_*                       ct_log.php
#  /tmp/tsa_tsq_* tsa_tsr_*           tsa.php                    (TSQ/TSR temp files)
#  /tmp/????????????????.pdf           cps_to_br_assessor.php     (URL fetch + upload)
#  /tmp/????????????????.upload        cps_to_br_assessor.php     (non-PDF upload)
#  /tmp/meerkat_csr_*/                 csr_generator.php          (subdirectory)
#  /tmp/meerkat_badcsr_*/              csr_generator.php          (subdirectory)
#  $PKI_APP/includes/br_cache.json.tmp.*  br_fetcher.php          (failed atomic write)
#
# ── Recommended cron ──────────────────────────────────────────────────────────
#
#   */15 * * * * /var/www/thameur.org/pki-tools/cron/prune_tmp.sh \
#                >> /var/log/pki-tools-prune.log 2>&1
#
# ── Configuration ─────────────────────────────────────────────────────────────
#
#   MAX_AGE_MIN  — delete files/dirs older than this many minutes (default: 60).
#                  Must be well above the longest PHP timeout; cert_factory uses
#                  90 s and acme_tester uses 120 s, so 60 min is safe.
#   PKI_APP      — absolute path to the deployed PHP app directory.

set -euo pipefail

PKI_APP="${PKI_APP:-/var/www/thameur.org/pki-tools}"
TMPDIR="${TMPDIR:-/tmp}"
MAX_AGE_MIN="${MAX_AGE_MIN:-60}"

total=0

log()  { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }

prune_flat() {
  local pat="$1"
  local n
  n=$(find "$TMPDIR" -maxdepth 1 -name "$pat" ! -type d -mmin +"$MAX_AGE_MIN" 2>/dev/null | wc -l)
  if [[ "$n" -gt 0 ]]; then
    find "$TMPDIR" -maxdepth 1 -name "$pat" ! -type d -mmin +"$MAX_AGE_MIN" -delete 2>/dev/null || true
    log "removed ${n} × ${pat}"
    total=$((total + n))
  fi
}

prune_dirs() {
  local pat="$1"
  local n
  n=$(find "$TMPDIR" -maxdepth 1 -type d -name "$pat" -mmin +"$MAX_AGE_MIN" 2>/dev/null | wc -l)
  if [[ "$n" -gt 0 ]]; then
    find "$TMPDIR" -maxdepth 1 -type d -name "$pat" -mmin +"$MAX_AGE_MIN" \
      -exec rm -rf -- {} + 2>/dev/null || true
    log "removed ${n} × ${pat}/"
    total=$((total + n))
  fi
}

log "=== pki-tools tmp prune start (MAX_AGE_MIN=${MAX_AGE_MIN}) ==="

# ── modules/_base.php ─────────────────────────────────────────────────────────
prune_flat 'mkt_*'

# ── linters ───────────────────────────────────────────────────────────────────
prune_flat 'x509lint_*'
prune_flat 'zlint_*'
prune_flat 'pkilint_*'

# ── acme_tester.php ───────────────────────────────────────────────────────────
prune_flat 'at_k_*'
prune_flat 'at_c_*'
prune_flat 'at_n_*'
prune_flat 'at_ci_*'
prune_flat 'at_co_*'
prune_flat 'at_cp_*'

# ── revocation.php ────────────────────────────────────────────────────────────
prune_flat 'revoc_ee_*'
prune_flat 'revoc_is_*'
prune_flat 'revoc_rsp_*'
prune_flat 'revoc_rq_*'
prune_flat 'revoc_crl_*'
prune_flat 'revoc_lcrl_*'
prune_flat 'revoc_locsp_*'

# ── cert_factory.php ──────────────────────────────────────────────────────────
prune_flat 'cf_csr_*'
prune_flat 'cf_crl_*'
prune_flat 'cf_gk_*'
prune_flat 'cf_gc_*'
prune_flat 'cf_gn_*'
prune_flat 'cf_ext_*'
prune_flat 'cf_cert_*'

# ── ct_log.php ────────────────────────────────────────────────────────────────
prune_flat 'ct_iss_*'

# ── tsa.php ───────────────────────────────────────────────────────────────────
prune_flat 'tsa_tsq_*'
prune_flat 'tsa_tsr_*'

# ── csr_generator.php — subdirectories created with mkdir() ──────────────────
prune_dirs 'meerkat_csr_*'
prune_dirs 'meerkat_badcsr_*'

# ── cps_to_br_assessor.php — uploaded and URL-fetched CP/CPS documents ───────
# Filenames are bin2hex(random_bytes(8)) = exactly 16 hex chars, then .pdf or .upload.
# '????????????????' matches exactly 16 single characters in glob syntax.
prune_flat '????????????????.pdf'
prune_flat '????????????????.upload'

# ── br_fetcher.php — failed atomic cache writes ───────────────────────────────
# Written as includes/br_cache.json.tmp.<pid> and renamed on success.
# Left behind only if the process is killed between write and rename.
includes_dir="${PKI_APP}/includes"
if [[ -d "$includes_dir" ]]; then
  n=$(find "$includes_dir" -maxdepth 1 -name 'br_cache.json.tmp.*' \
        -mmin +"$MAX_AGE_MIN" 2>/dev/null | wc -l)
  if [[ "$n" -gt 0 ]]; then
    find "$includes_dir" -maxdepth 1 -name 'br_cache.json.tmp.*' \
      -mmin +"$MAX_AGE_MIN" -delete 2>/dev/null || true
    log "removed ${n} × br_cache.json.tmp.*"
    total=$((total + n))
  fi
fi

log "=== done — ${total} item(s) pruned ==="
