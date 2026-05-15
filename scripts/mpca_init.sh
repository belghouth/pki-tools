#!/usr/bin/env bash
# mpca_init.sh — Initialize the Multi-Purpose CA hierarchy.
#
# Safe to re-run: each component asks before overwriting.
#
# Hierarchy:
#   MPCA Root CA          RSA-4096   25 yr   (keep offline after init)
#    ├── MPCA S/MIME CA   RSA-3072   10 yr
#    ├── MPCA Personal CA P-384      10 yr   (client auth + document signing)
#    ├── MPCA CS CA       RSA-4096   10 yr   (code signing)
#    └── MPCA TSA CA      P-384      10 yr
#         └── TSA Signing  P-256     3 yr    (RFC 3161 endpoint cert)
#
# OID arc: 2.16.788.1.99  (thameur.org test MPCA — Tunisia ISO 3166-1 numeric 788)
#
# Paths (override via env):
#   MPCA_DIR  /var/www/thameur.org/pki-ca/mpca   private CA material, not web-served
#   WEB_DIR   /var/www/pki.thameur.org/mpca       public certs + CRLs
#   HTML_PAGE /var/www/pki.thameur.org/mpca.html  repository page

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

MPCA_DIR="${MPCA_DIR:-/var/www/thameur.org/pki-ca/mpca}"
WEB_DIR="${WEB_DIR:-/var/www/pki.thameur.org/mpca}"
HTML_PAGE="${HTML_PAGE:-/var/www/pki.thameur.org/mpca.html}"

ROOT_DIR="$MPCA_DIR/root"
SMIME_DIR="$MPCA_DIR/smime"
PERSONAL_DIR="$MPCA_DIR/personal"
CS_DIR="$MPCA_DIR/codesign"
TSA_CA_DIR="$MPCA_DIR/tsa_ca"
TSA_SIGN_DIR="$MPCA_DIR/tsa_sign"

REPO_URL="https://pki.thameur.org/mpca"
TSA_URL="https://thameur.org/tsa"
SITE_URL="https://thameur.org"
# Set to live OCSP responder URL once deployed; leave empty to omit AIA OCSP entry
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

# ask_skip LABEL KEY_FILE — returns 0 (proceed) or 1 (skip)
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
  [[ -f "$dir/index.txt" ]]      || touch "$dir/index.txt"
  [[ -f "$dir/index.txt.attr" ]] || printf 'unique_subject = no\n' > "$dir/index.txt.attr"
  [[ -f "$dir/serial" ]]         || openssl rand -hex 8 \
                                      | tr '[:lower:]' '[:upper:]' > "$dir/serial"
  [[ -f "$dir/crlnumber" ]]      || printf '01\n' > "$dir/crlnumber"
}

aia_value() {
  local issuers="$1"
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
  local aia; aia=$(aia_value "$issuers")
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
  local dir="$1" key_name="$2" cert_name="$3" cn="$4" bits="${5:-}"
  local key_section
  [[ -n "$bits" ]] && key_section="default_bits = $bits" \
                   || key_section="# EC key — no default_bits"
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

write_tsa_cnf() {
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
  log "Root CA signs $label…"
  openssl ca -batch -notext \
    -config     "$ROOT_DIR/openssl.cnf" \
    -in         "$csr" \
    -out        "$cert" \
    -days       "$SUBCA_DAYS" \
    -extfile    "$extfile" \
    -extensions subca_ext 2>/dev/null
  ok "$label signed"
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
    -key "$SMIME_DIR/private/smime_ca.key" -out "$SMIME_DIR/csr/smime_ca.csr"

  local ext="$SMIME_DIR/csr/smime_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_SMIME_CA_CP" "$REPO_URL/root.crl" "$REPO_URL/root.crt"
  sign_subca "S/MIME CA" "$SMIME_DIR/csr/smime_ca.csr" "$SMIME_DIR/smime_ca.crt" "$ext"

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
    -key "$PERSONAL_DIR/private/personal_ca.key" -out "$PERSONAL_DIR/csr/personal_ca.csr"

  local ext="$PERSONAL_DIR/csr/personal_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_PERSONAL_CA_CP" "$REPO_URL/root.crl" "$REPO_URL/root.crt"
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
  write_subca_cnf "$CS_DIR" codesign_ca.key codesign_ca.crt "$DN_O Code Signing CA" 4096

  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$CS_DIR/private/codesign_ca.key" 2>/dev/null
  chmod 400 "$CS_DIR/private/codesign_ca.key"

  openssl req -new -config "$CS_DIR/openssl.cnf" \
    -key "$CS_DIR/private/codesign_ca.key" -out "$CS_DIR/csr/codesign_ca.csr"

  local ext="$CS_DIR/csr/codesign_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_CS_CA_CP" "$REPO_URL/root.crl" "$REPO_URL/root.crt"
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
    -key "$TSA_CA_DIR/private/tsa_ca.key" -out "$TSA_CA_DIR/csr/tsa_ca.csr"

  local ext="$TSA_CA_DIR/csr/tsa_ca_ext.cnf"
  write_subca_ext "$ext" "$OID_TSA_CA_CP" "$REPO_URL/root.crl" "$REPO_URL/root.crt"
  sign_subca "TSA CA" "$TSA_CA_DIR/csr/tsa_ca.csr" "$TSA_CA_DIR/tsa_ca.crt" "$ext"

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

  write_tsa_cnf

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TSA_SIGN_DIR/tsa_signing.key" 2>/dev/null
  chmod 400 "$TSA_SIGN_DIR/tsa_signing.key"

  openssl req -new \
    -key "$TSA_SIGN_DIR/tsa_signing.key" \
    -out "$TSA_SIGN_DIR/tsa_signing.csr" \
    -subj "/C=${DN_C}/O=${DN_O}/CN=${DN_O} TSA"

  # EKU timeStamping must be critical and appear alone — RFC 3161 §2.3
  local aia; aia=$(aia_value "$REPO_URL/tsa_ca.crt")
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

  for pair in \
    "$ROOT_DIR/crl/root.crl:root" \
    "$SMIME_DIR/crl/smime_ca.crl:smime_ca" \
    "$PERSONAL_DIR/crl/personal_ca.crl:personal_ca" \
    "$CS_DIR/crl/codesign_ca.crl:codesign_ca" \
    "$TSA_CA_DIR/crl/tsa_ca.crl:tsa_ca"
  do
    cp "${pair%%:*}" "$WEB_DIR/${pair##*:}.crl"
  done

  cat "$SMIME_DIR/smime_ca.crt"       "$ROOT_DIR/root.crt" > "$WEB_DIR/smime_chain.pem"
  cat "$PERSONAL_DIR/personal_ca.crt" "$ROOT_DIR/root.crt" > "$WEB_DIR/personal_chain.pem"
  cat "$CS_DIR/codesign_ca.crt"       "$ROOT_DIR/root.crt" > "$WEB_DIR/codesign_chain.pem"
  cat "$TSA_CA_DIR/tsa_ca.crt"        "$ROOT_DIR/root.crt" > "$WEB_DIR/tsa_chain.pem"

  ok "Web directory populated"
  write_html
}

# ── HTML repository page ──────────────────────────────────────────────────────

# cert_card TITLE CERT_FILE CRL_FILENAME CERT_FILENAME [CHAIN_FILENAME]
# Echoes the HTML card for one CA. Called in a subshell via $(...).
cert_card() {
  local title="$1" cert="$2" crl_name="$3" cert_name="$4" chain_name="${5:-}"

  if [[ ! -f "$cert" ]]; then
    printf '<div class="card"><div class="card-title">%s</div><p class="chain-pending">Not yet initialized.</p></div>\n' \
      "$title"
    return
  fi

  local cn algo notafter fp pem uid
  cn=$(openssl x509 -noout -subject -in "$cert" 2>/dev/null \
         | sed -E 's/.*CN\s*=\s*//' | sed 's/,.*//')
  algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null \
           | awk '/Public Key Algorithm/{print $NF; exit}')
  notafter=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
  fp=$(openssl x509 -noout -fingerprint -sha256 -in "$cert" 2>/dev/null \
         | sed 's/.*=//' | tr -d ':')
  pem=$(openssl x509 -in "$cert" 2>/dev/null)
  uid="pem_$(basename "$cert" .crt | tr '-' '_')"

  local chain_btn=""
  [[ -n "$chain_name" ]] && \
    chain_btn="<a class=\"dl-btn\" href=\"${REPO_URL}/${chain_name}\">Chain PEM</a>"

  cat <<CARD
  <div class="card">
    <div class="card-title">${title}</div>
    <div class="card-meta">
      CN: <span>${cn}</span><br>
      Algorithm: <span>${algo}</span><br>
      Not After: <span>${notafter}</span><br>
      SHA-256: <span>${fp}</span>
    </div>
    <div class="pem-wrap">
      <textarea class="pem-field" id="${uid}" rows="5" readonly spellcheck="false">${pem}</textarea>
      <div class="pem-actions">
        <a class="dl-btn" href="${REPO_URL}/${cert_name}">CRT</a>
        <a class="dl-btn" href="${REPO_URL}/${crl_name}">CRL</a>
        ${chain_btn}
        <button class="pem-btn" onclick="copyPem('${uid}',this)">Copy PEM</button>
        <button class="pem-btn" onclick="dlPem('${uid}','${cert_name}')">Save PEM</button>
      </div>
    </div>
  </div>
CARD
}

write_html() {
  local generated; generated=$(date -u '+%Y-%m-%d %H:%M UTC')

  local root_card smime_card personal_card cs_card tsa_ca_card tsa_sign_card
  root_card=$(cert_card     "MPCA Root CA"            "$ROOT_DIR/root.crt"             "root.crl"        "root.crt")
  smime_card=$(cert_card    "MPCA S/MIME CA"           "$SMIME_DIR/smime_ca.crt"        "smime_ca.crl"    "smime_ca.crt"    "smime_chain.pem")
  personal_card=$(cert_card "MPCA Personal CA"         "$PERSONAL_DIR/personal_ca.crt"  "personal_ca.crl" "personal_ca.crt" "personal_chain.pem")
  cs_card=$(cert_card       "MPCA Code Signing CA"     "$CS_DIR/codesign_ca.crt"        "codesign_ca.crl" "codesign_ca.crt" "codesign_chain.pem")
  tsa_ca_card=$(cert_card   "MPCA TSA CA"              "$TSA_CA_DIR/tsa_ca.crt"         "tsa_ca.crl"      "tsa_ca.crt"      "tsa_chain.pem")
  tsa_sign_card=$(cert_card "TSA Signing Certificate"  "$TSA_SIGN_DIR/tsa_signing.crt"  "tsa_ca.crl"      "tsa_ca.crt")

  cat > "$HTML_PAGE" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MPCA — pki.thameur.org</title>
  <style>
    :root {
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --mono: 'IBM Plex Mono', 'Fira Mono', monospace;
      --sans: 'IBM Plex Sans', system-ui, sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans);
           font-weight: 300; line-height: 1.75; padding: 3rem 1.5rem 5rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; }
    .wrap { max-width: 760px; margin: 0 auto; }

    h1 { font-size: 1.6rem; font-weight: 600; color: #fff; margin-bottom: 0.25rem; }
    .sub { font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
           letter-spacing: 0.05em; margin-bottom: 2.5rem; }

    .warning {
      border: 1px solid #7c2d12; background: rgba(124,45,18,0.12);
      border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 2.5rem;
      font-size: 0.83rem; color: #fca5a5;
    }
    .warning strong { color: #f87171; }

    h2 { font-size: 0.72rem; font-family: var(--mono); text-transform: uppercase;
         letter-spacing: 0.1em; color: var(--muted); margin: 2rem 0 1rem; }

    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 1.2rem 1.4rem; margin-bottom: 1rem;
    }
    .card-title { font-weight: 600; color: #fff; margin-bottom: 0.6rem; }
    .card-meta { font-family: var(--mono); font-size: 0.7rem; color: var(--muted);
                 line-height: 1.9; word-break: break-all; }
    .card-meta span { color: var(--text); }

    .dl-btn {
      display: inline-block; margin-top: 0.9rem;
      font-family: var(--mono); font-size: 0.7rem; letter-spacing: 0.06em;
      text-transform: uppercase; border: 1px solid var(--accent);
      color: var(--accent); border-radius: 4px; padding: 0.3em 0.85em;
      transition: background 0.15s;
    }
    .dl-btn:hover { background: rgba(0,212,170,0.1); color: #fff; border-color: #fff; }

    .pem-wrap { margin-top: 0.9rem; }
    .pem-field {
      width: 100%; background: var(--bg); border: 1px solid var(--border);
      border-radius: 6px; color: var(--muted); font-family: var(--mono);
      font-size: 0.65rem; line-height: 1.55; padding: 0.7rem 0.9rem;
      resize: vertical; min-height: 96px; cursor: default;
    }
    .pem-field:focus { outline: none; }
    .pem-actions {
      display: flex; gap: 0.5rem; margin-top: 0.55rem;
      flex-wrap: wrap; align-items: center;
    }
    .pem-actions .dl-btn { margin-top: 0; }
    .pem-btn {
      font-family: var(--mono); font-size: 0.68rem; letter-spacing: 0.06em;
      text-transform: uppercase; border: 1px solid var(--border);
      background: none; color: var(--muted); border-radius: 4px;
      padding: 0.3em 0.85em; cursor: pointer;
      transition: border-color 0.15s, color 0.15s;
    }
    .pem-btn:hover { border-color: var(--accent); color: var(--accent); }

    .oid-table { width: 100%; border-collapse: collapse; margin-top: 0.3rem; }
    .oid-table td { font-family: var(--mono); font-size: 0.68rem; padding: 0.25rem 0;
                    color: var(--muted); vertical-align: top; }
    .oid-table td:first-child { color: var(--text); padding-right: 1.5rem;
                                 white-space: nowrap; }
    .oid-table tr.section td { padding-top: 0.75rem; color: var(--accent);
                                font-size: 0.62rem; text-transform: uppercase;
                                letter-spacing: 0.08em; }

    .footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid var(--border);
              font-family: var(--mono); font-size: 0.68rem; color: var(--muted); }
    .footer a { color: var(--muted); }
    .footer a:hover { color: var(--accent); }
    .chain-pending { color: var(--muted); font-size: 0.8rem; padding: 1rem 0; font-style: italic; }
  </style>
</head>
<body>
<div class="wrap">

  <h1>Multi-Purpose CA</h1>
  <p class="sub">pki.thameur.org/mpca &nbsp;·&nbsp; Generated ${generated}</p>

  <div class="warning">
    <strong>Test infrastructure.</strong> This hierarchy exists to validate certificate
    profiles and linter behaviour on <a href="${SITE_URL}">${SITE_URL}</a>.
    Certificates issued here are not trusted by browsers or operating systems.
  </div>

  <h2>Certificate Hierarchy</h2>

${root_card}
${smime_card}
${personal_card}
${cs_card}
${tsa_ca_card}

  <h2>Timestamp Authority</h2>

${tsa_sign_card}

  <div class="card">
    <div class="card-title">RFC 3161 Endpoint</div>
    <div class="card-meta">
      URL: <span><a href="${TSA_URL}">${TSA_URL}</a></span><br>
      Protocol: <span>HTTP POST  application/timestamp-query → application/timestamp-reply</span><br>
      Policy OID: <span>${OID_TSA_POLICY}</span><br>
      Digests: <span>SHA-256, SHA-384, SHA-512</span>
    </div>
  </div>

  <h2>OID Arc — 2.16.788.1.99</h2>

  <div class="card">
    <table class="oid-table">
      <tr class="section"><td colspan="2">CA Policies</td></tr>
      <tr><td>${OID_ROOT_CP}</td><td>MPCA Root CA CP</td></tr>
      <tr><td>${OID_SMIME_CA_CP}</td><td>S/MIME CA CP</td></tr>
      <tr><td>${OID_PERSONAL_CA_CP}</td><td>Personal CA CP</td></tr>
      <tr><td>${OID_CS_CA_CP}</td><td>Code Signing CA CP</td></tr>
      <tr><td>${OID_TSA_CA_CP}</td><td>TSA CA CP</td></tr>
      <tr class="section"><td colspan="2">Leaf Certificate Policies</td></tr>
      <tr><td>2.16.788.1.99.1.10</td><td>S/MIME MV — Multipurpose  &nbsp;+&nbsp; 2.23.140.1.5.1.1 (CA/B Forum)</td></tr>
      <tr><td>2.16.788.1.99.1.11</td><td>S/MIME MV — Signing only  &nbsp;+&nbsp; 2.23.140.1.5.1.2 (CA/B Forum)</td></tr>
      <tr><td>2.16.788.1.99.1.20</td><td>Client Authentication</td></tr>
      <tr><td>2.16.788.1.99.1.21</td><td>Document Signing (AdES / RFC 9336)</td></tr>
      <tr><td>2.16.788.1.99.1.30</td><td>Code Signing OV  &nbsp;+&nbsp; 2.23.140.1.4.1 (CA/B Forum)</td></tr>
      <tr><td>${OID_TSA_POLICY}</td><td>TSA Policy</td></tr>
    </table>
  </div>

  <div class="footer">
    <a href="${SITE_URL}">${SITE_URL}</a> &nbsp;·&nbsp;
    <a href="${SITE_URL}/mpca.html">MPCA Factory</a> &nbsp;·&nbsp;
    <a href="/">pki.thameur.org</a>
  </div>

</div>
<script>
function copyPem(id, btn) {
  var t = document.getElementById(id);
  if (!t) return;
  navigator.clipboard.writeText(t.value).then(function() {
    var o = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = o; }, 1800);
  });
}
function dlPem(id, filename) {
  var t = document.getElementById(id);
  if (!t) return;
  var blob = new Blob([t.value], { type: 'application/x-x509-ca-cert' });
  var url = URL.createObjectURL(blob);
  var a = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
</script>
</body>
</html>
HTML

  ok "mpca.html written → $HTML_PAGE"
}

# ── Terminal summary ──────────────────────────────────────────────────────────

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
           | sed -E 's/.*CN\s*=\s*//' | sed 's/,.*//')
    notafter=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
    algo=$(openssl x509 -noout -text -in "$cert" 2>/dev/null \
             | awk '/Public Key Algorithm/{print $NF; exit}')
    printf '  %-42s  %-28s  %s\n' "$cn" "$notafter" "$algo"
  done
  printf '\n'
  log "Private material : $MPCA_DIR"
  log "Cert/CRL repo    : $REPO_URL/"
  log "Repo page        : $HTML_PAGE"
  log "TSA endpoint     : $TSA_URL"
  [[ -n "$OCSP_URL" ]] \
    && log "OCSP             : $OCSP_URL" \
    || warn "OCSP_URL not set — AIA omits OCSP entry; set env var and re-run to add"
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
  log "MPCA hierarchy initialization"
  log "MPCA_DIR   = $MPCA_DIR"
  log "WEB_DIR    = $WEB_DIR"
  log "HTML_PAGE  = $HTML_PAGE"
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
  ok "Done. Next: add scripts/mpca_crl_refresh.sh to cron."
}

main "$@"
