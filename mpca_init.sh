#!/usr/bin/env bash
# mpca_init.sh — Initialize the Multi-Purpose CA hierarchy.
#
# Safe to re-run: each component asks before overwriting.
#
# Hierarchy:
#   MPCA Root CA          RSA-4096   25 yr   (offline)
#    ├── MPCA S/MIME CA   RSA-3072   10 yr
#    ├── MPCA Personal CA P-384      10 yr   (client auth + document signing)
#    ├── MPCA CS CA       RSA-4096   10 yr   (code signing)
#    └── MPCA TSA CA      P-384      10 yr
#         └── TSA Signing  P-256     3 yr    (RFC 3161 endpoint cert)
#
# OID arc: 2.16.788.1.99  (thameur.org test MPCA — Tunisia ISO 3166-1 numeric 788)
#
# Usage:
#   MPCA_DIR=/etc/mpca WEB_DIR=/var/www/html/mpca ./mpca_init.sh

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

MPCA_DIR="${MPCA_DIR:-/etc/mpca}"
WEB_DIR="${WEB_DIR:-/var/www/thameur.org/pki-tools/mpca}"

ROOT_DIR="$MPCA_DIR/root"
SMIME_DIR="$MPCA_DIR/smime"
PERSONAL_DIR="$MPCA_DIR/personal"
CS_DIR="$MPCA_DIR/codesign"
TSA_CA_DIR="$MPCA_DIR/tsa_ca"
TSA_SIGN_DIR="$MPCA_DIR/tsa_sign"

REPO_URL="https://pki.thameur.org/mpca"
TSA_URL="https://thameur.org/tsa"
# Set to live OCSP responder URL once deployed; leave empty to omit from AIA
OCSP_URL="${OCSP_URL:-}"

OID_ROOT_CP="2.16.788.1.99.1.1"
OID_SMIME_CA_CP="2.16.788.1.99.1.2"
OID_PERSONAL_CA_CP="2.16.788.1.99.1.3"
OID_CS_CA_CP="2.16.788.1.99.1.4"
OID_TSA_CA_CP="2.16.788.1.99.1.5"
OID_TSA_POLICY="2.16.788.1.99.1.40"

ROOT_DAYS=9131      # 25 yr
SUBCA_DAYS=3652     # 10 yr
TSA_SIGN_DAYS=1095  # 3 yr

DN_C="TN"
DN_O="thameur.org MPCA"

# ── Helpers ───────────────────────────────────────────────────────────────────

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
BLU='\033[1;34m'; DIM='\033[2m';   RST='\033[0m'

log()  { printf "${BLU}[mpca-init]${RST} %s\n" "$*"; }
ok()   { printf "  ${GRN}✓${RST} %s\n" "$*"; }
warn() { printf "  ${YEL}⚠${RST} %s\n" "$*"; }
die()  { printf "  ${RED}✗${RST} %s\n" "$*" >&2; exit 1; }
sep()  { printf "\n${DIM}────────────────────────────────────────────────────${RST}\n"; }

# ask_skip LABEL KEY_FILE — returns 0 (proceed) or 1 (skip).
ask_skip() {
  local label="$1" key="$2"
  [[ -f "$key" ]] || return 0
  warn "$label already initialized ($key exists)"
  local ans
  read -r -p "  Skip ${label}? [Y/n] " ans </dev/tty
  [[ "$ans" == [Nn]* ]] && return 0
  ok "Skipping $label"
  return 1
}

init_ca_db() {
  local dir="$1"
  mkdir -p "$dir"/{certs,crl,csr,private}
  chmod 700 "$dir/private"
  [[ -f "$dir/index.txt" ]]       || touch "$dir/index.txt"
  [[ -f "$dir/index.txt.attr" ]]  || printf 'unique_subject = no\n' > "$dir/index.txt.attr"
  [[ -f "$dir/serial" ]]          || openssl rand -hex 8 \
                                       | tr '[:lower:]' '[:upper:]' > "$dir/serial"
  [[ -f "$dir/crlnumber" ]]       || printf '01\n' > "$dir/crlnumber"
}

# aia CDP_URL ISSUERS_URL — prints the authorityInfoAccess value string
aia_value() {
  local issuers="$2"
  if [[ -n "$OCSP_URL" ]]; then
    printf 'OCSP;URI:%s,caIssuers;URI:%s' "$OCSP_URL" "$issuers"
  else
    printf 'caIssuers;URI:%s' "$issuers"
  fi
}

# ── OpenSSL config writers ─────────────────────────────────────────────────────

write_root_cnf() {
  cat > "$ROOT_DIR/openssl.cnf" <<CONF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $ROOT_DIR
certs             = \$dir/certs
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/root.key
certificate       = \$dir/root.crt
crl_dir           = \$dir/crl
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/root.crl
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = $SUBCA_DAYS
default_crl_days  = 365
preserve          = no
copy_extensions   = none
policy            = policy_match

[ policy_match ]
countryName      = match
organizationName = match
commonName       = supplied

[ req ]
default_bits       = 4096
distinguished_name = req_dn
string_mask        = utf8only
default_md         = sha256
x509_extensions    = v3_root
prompt             = no

[ req_dn ]
C  = $DN_C
O  = $DN_O
CN = $DN_O Root CA

[ v3_root ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true,pathlen:1
keyUsage               = critical,keyCertSign,cRLSign
certificatePolicies    = @cp_root

[ cp_root ]
policyIdentifier = $OID_ROOT_CP
CPS.1            = $REPO_URL/cps.html
CONF
}

# write_subca_ext FILE POLICY_OID CDP_URL ISSUERS_URL
write_subca_ext() {
  local file="$1" policy_oid="$2" cdp="$3" issuers="$4"
  local aia; aia=$(aia_value "" "$issuers")
  cat > "$file" <<EXT
[ subca_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:true,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
crlDistributionPoints  = URI:$cdp
authorityInfoAccess    = $aia
certificatePolicies    = @cp_subca

[ cp_subca ]
policyIdentifier = $policy_oid
CPS.1            = $REPO_URL/cps.html
EXT
}

write_subca_cnf() {
  local dir="$1" key_name="$2" cert_name="$3" cn="$4" bits="${5:-}" curve="${6:-}"
  local key_section
  if [[ -n "$bits" ]]; then
    key_section="default_bits = $bits"
  else
    key_section="# EC key — no default_bits"
  fi
  cat > "$dir/openssl.cnf" <<CONF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $dir
certs             = \$dir/certs
new_certs_dir     = \$dir/certs
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand
private_key       = \$dir/private/$key_name
certificate       = \$dir/$cert_name
crl_dir           = \$dir/crl
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/${cert_name%.crt}.crl
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_crl_days  = 7
preserve          = no
copy_extensions   = copy
policy            = policy_loose

[ policy_loose ]
countryName      = optional
organizationName = optional
commonName       = optional
emailAddress     = optional

[ req ]
$key_section
distinguished_name = req_dn
string_mask        = utf8only
default_md         = sha256
prompt             = no

[ req_dn ]
C  = $DN_C
O  = $DN_O
CN = $cn
CONF
}

write_tsa_sign_cnf() {
  cat > "$TSA_SIGN_DIR/tsa.cnf" <<CONF
[ tsa ]
default_tsa = tsa_config

[ tsa_config ]
dir                    = $TSA_SIGN_DIR
serial                 = \$dir/tsaserial
crypto_device          = builtin
signer_cert            = \$dir/tsa_signing.crt
certs                  = \$dir/chain.pem
signer_key             = \$dir/tsa_signing.key
signer_digest          = sha256
default_policy         = $OID_TSA_POLICY
other_policies         =
digests                = sha256, sha384, sha512
accuracy               = secs:1
clock_precision_digits = 0
ordering               = no
tsa_name               = yes
ess_cert_id_chain      = yes
CONF
}

# ── CA init functions ──────────────────────────────────────────────────────────

init_root() {
  sep; log "Root CA (RSA-4096, ${ROOT_DAYS}d)"
  ask_skip "Root CA" "$ROOT_DIR/private/root.key" || return 0

  init_ca_db "$ROOT_DIR"
  write_root_cnf

  log "Generating Root CA key (RSA-4096)…"
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$ROOT_DIR/private/root.key" 2>/dev/null
  chmod 400 "$ROOT_DIR/private/root.key"

  log "Self-signing Root CA certificate…"
  openssl req -new -x509 \
    -config "$ROOT_DIR/openssl.cnf" \
    -key    "$ROOT_DIR/private/root.key" \
    -out    "$ROOT_DIR/root.crt" \
    -days   "$ROOT_DAYS"

  log "Seeding Root CRL…"
  openssl ca -gencrl \
    -config "$ROOT_DIR/openssl.cnf" \
    -out    "$ROOT_DIR/crl/root.crl" 2>/dev/null

  ok "Root CA initialized"
  openssl x509 -noout -fingerprint -sha256 -in "$ROOT_DIR/root.crt"
}

# sign_subca LABEL CSR CERT EXTFILE
sign_subca() {
  local label="$1" csr="$2" cert="$3" extfile="$4"
  log "Root CA signs $label certificate…"
  openssl ca -batch -notext \
    -config     "$ROOT_DIR/openssl.cnf" \
    -in         "$csr" \
    -out        "$cert" \
    -days       "$SUBCA_DAYS" \
    -extfile    "$extfile" \
    -extensions subca_ext 2>/dev/null
  ok "$label certificate signed"
}

init_smime_ca() {
  sep; log "S/MIME CA (RSA-3072)"
  ask_skip "S/MIME CA" "$SMIME_DIR/private/smime_ca.key" || return 0

  init_ca_db "$SMIME_DIR"
  write_subca_cnf "$SMIME_DIR" smime_ca.key smime_ca.crt "$DN_O S/MIME CA" 3072

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$SMIME_DIR/private/smime_ca.key" 2>/dev/null
  chmod 400 "$SMIME_DIR/private/smime_ca.key"

  openssl req -new -config "$SMIME_DIR/openssl.cnf" \
    -key "$SMIME_DIR/private/smime_ca.key" \
    -out "$SMIME_DIR/csr/smime_ca.csr"

  local ext="$SMIME_DIR/csr/smime_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_SMIME_CA_CP" \
    "$REPO_URL/root.crl" "$REPO_URL/root.crt"

  sign_subca "S/MIME CA" "$SMIME_DIR/csr/smime_ca.csr" \
    "$SMIME_DIR/smime_ca.crt" "$ext"

  openssl ca -gencrl -config "$SMIME_DIR/openssl.cnf" \
    -out "$SMIME_DIR/crl/smime_ca.crl" 2>/dev/null
  ok "S/MIME CA initialized"
}

init_personal_ca() {
  sep; log "Personal CA (P-384)"
  ask_skip "Personal CA" "$PERSONAL_DIR/private/personal_ca.key" || return 0

  init_ca_db "$PERSONAL_DIR"
  write_subca_cnf "$PERSONAL_DIR" personal_ca.key personal_ca.crt "$DN_O Personal CA"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out "$PERSONAL_DIR/private/personal_ca.key" 2>/dev/null
  chmod 400 "$PERSONAL_DIR/private/personal_ca.key"

  openssl req -new -config "$PERSONAL_DIR/openssl.cnf" \
    -key "$PERSONAL_DIR/private/personal_ca.key" \
    -out "$PERSONAL_DIR/csr/personal_ca.csr"

  local ext="$PERSONAL_DIR/csr/personal_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_PERSONAL_CA_CP" \
    "$REPO_URL/root.crl" "$REPO_URL/root.crt"

  sign_subca "Personal CA" "$PERSONAL_DIR/csr/personal_ca.csr" \
    "$PERSONAL_DIR/personal_ca.crt" "$ext"

  openssl ca -gencrl -config "$PERSONAL_DIR/openssl.cnf" \
    -out "$PERSONAL_DIR/crl/personal_ca.crl" 2>/dev/null
  ok "Personal CA initialized"
}

init_cs_ca() {
  sep; log "Code Signing CA (RSA-4096)"
  ask_skip "Code Signing CA" "$CS_DIR/private/codesign_ca.key" || return 0

  init_ca_db "$CS_DIR"
  write_subca_cnf "$CS_DIR" codesign_ca.key codesign_ca.crt \
    "$DN_O Code Signing CA" 4096

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$CS_DIR/private/codesign_ca.key" 2>/dev/null
  chmod 400 "$CS_DIR/private/codesign_ca.key"

  openssl req -new -config "$CS_DIR/openssl.cnf" \
    -key "$CS_DIR/private/codesign_ca.key" \
    -out "$CS_DIR/csr/codesign_ca.csr"

  local ext="$CS_DIR/csr/codesign_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_CS_CA_CP" \
    "$REPO_URL/root.crl" "$REPO_URL/root.crt"

  sign_subca "Code Signing CA" "$CS_DIR/csr/codesign_ca.csr" \
    "$CS_DIR/codesign_ca.crt" "$ext"

  openssl ca -gencrl -config "$CS_DIR/openssl.cnf" \
    -out "$CS_DIR/crl/codesign_ca.crl" 2>/dev/null
  ok "Code Signing CA initialized"
}

init_tsa_ca() {
  sep; log "TSA CA (P-384)"
  ask_skip "TSA CA" "$TSA_CA_DIR/private/tsa_ca.key" || return 0

  init_ca_db "$TSA_CA_DIR"
  write_subca_cnf "$TSA_CA_DIR" tsa_ca.key tsa_ca.crt "$DN_O TSA CA"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
    -out "$TSA_CA_DIR/private/tsa_ca.key" 2>/dev/null
  chmod 400 "$TSA_CA_DIR/private/tsa_ca.key"

  openssl req -new -config "$TSA_CA_DIR/openssl.cnf" \
    -key "$TSA_CA_DIR/private/tsa_ca.key" \
    -out "$TSA_CA_DIR/csr/tsa_ca.csr"

  local ext="$TSA_CA_DIR/csr/tsa_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_TSA_CA_CP" \
    "$REPO_URL/root.crl" "$REPO_URL/root.crt"

  sign_subca "TSA CA" "$TSA_CA_DIR/csr/tsa_ca.csr" \
    "$TSA_CA_DIR/tsa_ca.crt" "$ext"

  openssl ca -gencrl -config "$TSA_CA_DIR/openssl.cnf" \
    -out "$TSA_CA_DIR/crl/tsa_ca.crl" 2>/dev/null
  ok "TSA CA initialized"
}

init_tsa_signing() {
  sep; log "TSA Signing Certificate (P-256)"
  ask_skip "TSA Signing cert" "$TSA_SIGN_DIR/tsa_signing.key" || return 0

  mkdir -p "$TSA_SIGN_DIR"
  chmod 700 "$TSA_SIGN_DIR"
  [[ -f "$TSA_SIGN_DIR/tsaserial" ]] || printf '01\n' > "$TSA_SIGN_DIR/tsaserial"

  write_tsa_sign_cnf

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TSA_SIGN_DIR/tsa_signing.key" 2>/dev/null
  chmod 400 "$TSA_SIGN_DIR/tsa_signing.key"

  openssl req -new \
    -key "$TSA_SIGN_DIR/tsa_signing.key" \
    -out "$TSA_SIGN_DIR/tsa_signing.csr" \
    -subj "/C=${DN_C}/O=${DN_O}/CN=${DN_O} TSA"

  # EKU timeStamping must be critical and appear alone — RFC 3161 §2.3
  local aia; aia=$(aia_value "" "$REPO_URL/tsa_ca.crt")
  cat > "$TSA_SIGN_DIR/tsa_signing_ext.cnf" <<EXT
[ tsa_sign_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature
extendedKeyUsage       = critical,timeStamping
crlDistributionPoints  = URI:${REPO_URL}/tsa_ca.crl
authorityInfoAccess    = $aia
certificatePolicies    = @cp_tsa_sign

[ cp_tsa_sign ]
policyIdentifier = $OID_TSA_POLICY
CPS.1            = $REPO_URL/cps.html
EXT

  log "TSA CA signs TSA signing certificate (${TSA_SIGN_DAYS}d)…"
  openssl ca -batch -notext \
    -config     "$TSA_CA_DIR/openssl.cnf" \
    -in         "$TSA_SIGN_DIR/tsa_signing.csr" \
    -out        "$TSA_SIGN_DIR/tsa_signing.crt" \
    -days       "$TSA_SIGN_DAYS" \
    -extfile    "$TSA_SIGN_DIR/tsa_signing_ext.cnf" \
    -extensions tsa_sign_ext 2>/dev/null

  # Full chain for openssl ts -reply
  cat "$TSA_SIGN_DIR/tsa_signing.crt" \
      "$TSA_CA_DIR/tsa_ca.crt" \
      "$ROOT_DIR/root.crt" \
    > "$TSA_SIGN_DIR/chain.pem"

  ok "TSA Signing certificate initialized"
  openssl x509 -noout -subject -enddate -in "$TSA_SIGN_DIR/tsa_signing.crt"
}

# ── Web publish ───────────────────────────────────────────────────────────────

publish_web() {
  sep; log "Publishing to $WEB_DIR"
  mkdir -p "$WEB_DIR"

  # DER copies for AIA caIssuers (browsers fetch these)
  for pair in \
    "$ROOT_DIR/root.crt:root" \
    "$SMIME_DIR/smime_ca.crt:smime_ca" \
    "$PERSONAL_DIR/personal_ca.crt:personal_ca" \
    "$CS_DIR/codesign_ca.crt:codesign_ca" \
    "$TSA_CA_DIR/tsa_ca.crt:tsa_ca"
  do
    local src="${pair%%:*}" base="${pair##*:}"
    cp "$src" "$WEB_DIR/${base}.crt"
    openssl x509 -in "$src" -outform DER -out "$WEB_DIR/${base}.der" 2>/dev/null
  done

  # CRLs
  for pair in \
    "$ROOT_DIR/crl/root.crl:root" \
    "$SMIME_DIR/crl/smime_ca.crl:smime_ca" \
    "$PERSONAL_DIR/crl/personal_ca.crl:personal_ca" \
    "$CS_DIR/crl/codesign_ca.crl:codesign_ca" \
    "$TSA_CA_DIR/crl/tsa_ca.crl:tsa_ca"
  do
    cp "${pair%%:*}" "$WEB_DIR/${pair##*:}.crl"
  done

  # Full chains (Sub CA + Root) — useful for cert downloads
  cat "$SMIME_DIR/smime_ca.crt"       "$ROOT_DIR/root.crt" > "$WEB_DIR/smime_chain.pem"
  cat "$PERSONAL_DIR/personal_ca.crt" "$ROOT_DIR/root.crt" > "$WEB_DIR/personal_chain.pem"
  cat "$CS_DIR/codesign_ca.crt"       "$ROOT_DIR/root.crt" > "$WEB_DIR/codesign_chain.pem"
  cat "$TSA_CA_DIR/tsa_ca.crt"        "$ROOT_DIR/root.crt" > "$WEB_DIR/tsa_chain.pem"

  ok "Web directory populated"
}

# ── Summary ───────────────────────────────────────────────────────────────────

print_summary() {
  sep; log "Hierarchy"
  printf '\n  %-42s  %-28s  %s\n' "CN" "Not After" "Algorithm"
  printf '  %-42s  %-28s  %s\n' "──" "─────────" "─────────"
  local certs=(
    "$ROOT_DIR/root.crt"
    "$SMIME_DIR/smime_ca.crt"
    "$PERSONAL_DIR/personal_ca.crt"
    "$CS_DIR/codesign_ca.crt"
    "$TSA_CA_DIR/tsa_ca.crt"
    "$TSA_SIGN_DIR/tsa_signing.crt"
  )
  for cert in "${certs[@]}"; do
    [[ -f "$cert" ]] || continue
    local cn notafter algo
    cn=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null \
           | sed 's/.*CN\s*=\s*//' | sed 's/,.*//')
    notafter=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
    algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null \
           | awk '/Public Key Algorithm/{print $NF; exit}')
    printf '  %-42s  %-28s  %s\n' "$cn" "$notafter" "$algo"
  done
  printf '\n'
  log "Cert/CRL repo : $REPO_URL/"
  log "TSA endpoint  : $TSA_URL"
  [[ -n "$OCSP_URL" ]] && log "OCSP          : $OCSP_URL" || \
    warn "OCSP_URL not set — AIA omits OCSP entry; set and re-run to add"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  log "MPCA hierarchy initialization"
  log "MPCA_DIR = $MPCA_DIR"
  log "WEB_DIR  = $WEB_DIR"
  printf '\n'
  command -v openssl >/dev/null || die "openssl not found in PATH"

  init_root
  init_smime_ca
  init_personal_ca
  init_cs_ca
  init_tsa_ca
  init_tsa_signing
  publish_web
  print_summary

  sep
  ok "Done. Next: run mpca_crl_refresh.sh to keep CRLs fresh."
}

main "$@"
