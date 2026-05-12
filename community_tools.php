<?php
$navLabel = 'Community Tools';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'Community PKI Tools — Free Online Testing Tools for WebPKI Practitioners | thameur.org',
    'description' => 'A curated index of free, open-source community tools for PKI testing: ASN.1 decoders, TLS analysers, digital signature validators, CT log search, DNSSEC visualisers, and more.',
    'url'         => 'https://thameur.org/community_tools.php',
  ]);
  ?>
  <link rel="icon" type="image/x-icon" href="/favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
  <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg:      #0e1014;
      --surface: #13171e;
      --border:  #2a3040;
      --accent:  #00d4aa;
      --text:    #d4dae6;
      --muted:   #6b7a90;
      --sans:    'IBM Plex Sans', sans-serif;
      --mono:    'IBM Plex Mono', monospace;
      --radius:  8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; text-decoration: underline; }

    /* ── Page layout ── */
    .ct-page { max-width: 1060px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    .ct-page h1 { font-size: 2rem; font-weight: 600; color: #fff; margin-bottom: .4rem; }
    .ct-page .page-sub {
      font-family: var(--mono); font-size: .75rem; color: var(--muted);
      letter-spacing: .05em; margin-bottom: 1.5rem;
    }

    /* ── Disclaimer ── */
    .ct-disclaimer {
      background: rgba(59,130,246,.06);
      border: 1px solid rgba(59,130,246,.2);
      border-radius: var(--radius);
      padding: .9rem 1.2rem;
      font-size: .82rem; color: #93c5fd; line-height: 1.6;
      margin-bottom: 3rem;
    }
    .ct-disclaimer strong { color: #bfdbfe; }

    /* ── TOC ── */
    .toc {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.2rem 1.6rem;
      margin-bottom: 3rem; display: inline-block; min-width: 260px;
    }
    .toc-title {
      font-family: var(--mono); font-size: .72rem; text-transform: uppercase;
      letter-spacing: .08em; color: var(--muted); margin-bottom: .7rem;
    }
    .toc ol { list-style: decimal; padding-left: 1.2rem; }
    .toc li { margin-bottom: .25rem; }
    .toc a { font-size: .85rem; color: var(--muted); }
    .toc a:hover { color: var(--accent); text-decoration: none; }

    /* ── Section ── */
    .ct-section { margin-bottom: 3.5rem; }
    .ct-section-header {
      display: flex; align-items: center; gap: .75rem;
      border-bottom: 1px solid var(--border); padding-bottom: .6rem; margin-bottom: 1.2rem;
    }
    .ct-section-icon { font-size: 1.15rem; line-height: 1; }
    .ct-section-header h2 { font-size: 1.05rem; font-weight: 600; color: #fff; }

    /* ── Cards ── */
    .ct-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
      gap: 1rem;
    }
    .ct-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.15rem 1.3rem;
      display: flex; flex-direction: column; gap: .45rem;
      transition: border-color .15s, transform .15s;
    }
    .ct-card:hover { border-color: #3a4458; transform: translateY(-1px); }

    .ct-card-top { display: flex; align-items: flex-start; justify-content: space-between; gap: .5rem; }
    .ct-card-name { font-weight: 600; font-size: .92rem; color: #fff; line-height: 1.3; }
    .ct-card-oss {
      font-family: var(--mono); font-size: .6rem; letter-spacing: .06em;
      padding: .15em .45em; border-radius: 3px; white-space: nowrap; flex-shrink: 0;
      background: rgba(0,212,170,.08); color: var(--accent); border: 1px solid rgba(0,212,170,.2);
      text-transform: uppercase;
    }

    .ct-card-desc { font-size: .82rem; color: var(--muted); line-height: 1.55; flex: 1; }

    /* input type tags */
    .ct-tags { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .15rem; }
    .ct-tag {
      font-family: var(--mono); font-size: .63rem; letter-spacing: .05em; text-transform: uppercase;
      padding: .12em .5em; border-radius: 3px; border: 1px solid;
    }
    .ct-tag-paste   { background: rgba(0,212,170,.07);  color: #5eead4; border-color: rgba(0,212,170,.2); }
    .ct-tag-domain  { background: rgba(99,102,241,.08); color: #a5b4fc; border-color: rgba(99,102,241,.2); }
    .ct-tag-file    { background: rgba(168,85,247,.08); color: #d8b4fe; border-color: rgba(168,85,247,.2); }
    .ct-tag-browser { background: rgba(245,158,11,.07); color: #fcd34d; border-color: rgba(245,158,11,.2); }
    .ct-tag-search  { background: rgba(236,72,153,.07); color: #f9a8d4; border-color: rgba(236,72,153,.2); }

    .ct-card-link {
      font-family: var(--mono); font-size: .72rem; color: var(--accent);
      display: inline-flex; align-items: center; gap: .3rem; margin-top: .3rem;
    }
    .ct-card-link:hover { color: #fff; text-decoration: none; }
    .ct-card-link::after { content: '↗'; font-size: .7rem; }

    /* ── Footer ── */
    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: .72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .ct-grid { grid-template-columns: 1fr; }
      .toc { width: 100%; }
    }
  </style>
  <?php require __DIR__ . '/includes/adsense_head.php'; ?>
</head>
<body>

<?php require __DIR__ . '/includes/site_nav.php'; ?>

<main class="ct-page">
  <h1>Community PKI Tools</h1>
  <p class="page-sub">Free, open-source online testing tools from the WebPKI community — paste, upload, or enter a domain and get instant results.</p>

  <div class="ct-disclaimer">
    <strong>Curation policy:</strong> only free, community-driven or openly-licensed tools are listed here. No commercial products, no sponsored entries. Links and status of third-party tools may change — if you spot a dead link or a worthy addition, <a href="mailto:me@thameur.org">let me know</a>.
  </div>

  <nav class="toc" aria-label="Table of contents">
    <p class="toc-title">Contents</p>
    <ol>
      <li><a href="#asn1">ASN.1 &amp; Certificate Parsing</a></li>
      <li><a href="#linting">Certificate Linting</a></li>
      <li><a href="#tls">TLS &amp; HTTPS Analysis</a></li>
      <li><a href="#signatures">Digital Signature Validation</a></li>
      <li><a href="#ct">Certificate Transparency</a></li>
      <li><a href="#acme">ACME &amp; Issuance</a></li>
      <li><a href="#dns">DNS, DNSSEC &amp; CAA</a></li>
      <li><a href="#oid">OID &amp; Standards Lookup</a></li>
    </ol>
  </nav>

  <!-- ── 1. ASN.1 & Certificate Parsing ─────────────────────────────────── -->
  <section class="ct-section" id="asn1">
    <div class="ct-section-header">
      <span class="ct-section-icon">🔬</span>
      <h2>ASN.1 &amp; Certificate Parsing</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">ASN.1 JavaScript Decoder</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Interactive ASN.1 tree viewer by Lapo Luchini. Paste a PEM or base64/hex DER blob and explore every field of the structure — offsets, lengths, and raw hex included. The gold standard for ad-hoc ASN.1 inspection.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-paste">Paste PEM</span>
          <span class="ct-tag ct-tag-file">File upload</span>
        </div>
        <a href="https://lapo.it/asn1js/" class="ct-card-link" target="_blank" rel="noopener">lapo.it/asn1js</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">Certificate Decoder — CertLogik</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">Parses X.509 certificates into human-readable fields: subject, issuer, SANs, extensions, and validity. Useful as a quick sanity-check before deeper linting. No account required.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-paste">Paste PEM</span>
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://certlogik.com/decoder/" class="ct-card-link" target="_blank" rel="noopener">certlogik.com/decoder</a>
      </div>

    </div>
  </section>

  <!-- ── 2. Certificate Linting ──────────────────────────────────────────── -->
  <section class="ct-section" id="linting">
    <div class="ct-section-header">
      <span class="ct-section-icon">🧾</span>
      <h2>Certificate Linting</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">pkimetal — pkilint Web UI</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Web front-end for pkilint, the CA/Browser Forum–aligned certificate linter by Paul van Brouwershaven (DigiCert). Checks CABF TLS, S/MIME, and CS profiles. Returns structured findings with requirement references. Code on GitHub (digicert/pkilint).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-paste">Paste PEM</span>
        </div>
        <a href="https://pkimet.al/" class="ct-card-link" target="_blank" rel="noopener">pkimet.al</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">Certificate Linters — thameur.org</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Run zlint, pkilint, and x509lint simultaneously on the same certificate, or pull a live cert from any domain. Flags CABF BR violations and RFC 5280 issues with direct requirement references. Includes OCSP and CRL revocation checks.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-paste">Paste PEM</span>
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="/linters.php" class="ct-card-link">linters.php</a>
      </div>

    </div>
  </section>

  <!-- ── 3. TLS & HTTPS Analysis ────────────────────────────────────────── -->
  <section class="ct-section" id="tls">
    <div class="ct-section-header">
      <span class="ct-section-icon">🔒</span>
      <h2>TLS &amp; HTTPS Analysis</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">Mozilla Observatory</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Analyses HTTP security headers, CSP, HSTS, subresource integrity, cookies, and X-Frame-Options. Gives a grade and actionable recommendations. Operated by Mozilla Foundation; source on GitHub (mozilla/http-observatory).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://observatory.mozilla.org/" class="ct-card-link" target="_blank" rel="noopener">observatory.mozilla.org</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">badssl.com</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Reference site from the Google Chrome team. Each subdomain deliberately misconfigures TLS in a specific way — expired cert, self-signed, wrong host, RC4, SHA-1, etc. — letting you test how your browser or HTTP client handles each case. Code on GitHub (chromium/badssl.com).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-browser">Browser test</span>
        </div>
        <a href="https://badssl.com/" class="ct-card-link" target="_blank" rel="noopener">badssl.com</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">testssl.sh</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">The most comprehensive open-source TLS analysis tool, written in bash. Tests protocol support, cipher suites, key exchange, certificate chain, OCSP stapling, HSTS, vulnerabilities (POODLE, BEAST, ROBOT …), and more. Primarily a CLI tool; community-hosted web front-ends exist.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://testssl.sh/" class="ct-card-link" target="_blank" rel="noopener">testssl.sh</a>
      </div>

    </div>
  </section>

  <!-- ── 4. Digital Signature Validation ────────────────────────────────── -->
  <section class="ct-section" id="signatures">
    <div class="ct-section-header">
      <span class="ct-section-icon">✍️</span>
      <h2>Digital Signature Validation</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">EU DSS Demonstration WebApp</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Reference implementation of the EU's DSS (Digital Signature Service) library (LGPL). Validates and creates AdES-compliant signatures: CAdES, XAdES, PAdES (PDF), and JAdES. Accepts signed documents, returns a detailed conformance report. Source on GitHub (esig/dss).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-file">File upload</span>
        </div>
        <a href="https://github.com/esig/dss" class="ct-card-link" target="_blank" rel="noopener">github.com/esig/dss</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">ETSI Signature Conformance Checker</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">ETSI's own conformance checking service for AdES digital signatures (CAdES, XAdES, PAdES). Tests compliance against ETSI EN 319 100-series standards. Particularly useful for eIDAS qualified signature validation.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-file">File upload</span>
        </div>
        <a href="https://signatures-conformance-checker.etsi.org/" class="ct-card-link" target="_blank" rel="noopener">signatures-conformance-checker.etsi.org</a>
      </div>

    </div>
  </section>

  <!-- ── 5. Certificate Transparency ────────────────────────────────────── -->
  <section class="ct-section" id="ct">
    <div class="ct-section-header">
      <span class="ct-section-icon">🌲</span>
      <h2>Certificate Transparency</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">crt.sh</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">Sectigo's CT log search engine — the most widely used public interface to the Certificate Transparency ecosystem. Search by domain, organisation, certificate fingerprint, or serial. Surfaces all logged certificates and precertificates, and renders full parsed certificate details.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-search">Search</span>
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://crt.sh/" class="ct-card-link" target="_blank" rel="noopener">crt.sh</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">Google Transparency Report — CT</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">Google's Certificate Transparency monitoring and reporting tool. Check whether a certificate has been logged, view recent CT log additions, and access the authoritative Chrome CT log list. Essential for verifying that your certificates are CT-compliant.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-search">Search</span>
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://transparencyreport.google.com/https/certificates" class="ct-card-link" target="_blank" rel="noopener">transparencyreport.google.com</a>
      </div>

    </div>
  </section>

  <!-- ── 6. ACME & Issuance ─────────────────────────────────────────────── -->
  <section class="ct-section" id="acme">
    <div class="ct-section-header">
      <span class="ct-section-icon">⚡</span>
      <h2>ACME &amp; Certificate Issuance</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">Let's Debug</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Diagnoses why Let's Encrypt or any ACME CA might fail to validate a domain. Simulates HTTP-01 and DNS-01 challenges, checks CAA records, firewall behaviour, and multi-perspective reachability. By Andrew Ayer (SSLMate). Source on GitHub (letsdebug/letsdebug).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://letsdebug.net/" class="ct-card-link" target="_blank" rel="noopener">letsdebug.net</a>
      </div>

    </div>
  </section>

  <!-- ── 7. DNS, DNSSEC & CAA ───────────────────────────────────────────── -->
  <section class="ct-section" id="dns">
    <div class="ct-section-header">
      <span class="ct-section-icon">🌐</span>
      <h2>DNS, DNSSEC &amp; CAA</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">DNSViz</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Visual analysis and debugging of the DNSSEC chain of trust for any domain. Renders the entire delegation path from root → TLD → zone with coloured status indicators for each signature, key, and DS record. Source on GitHub (dnsviz/dnsviz).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://dnsviz.net/" class="ct-card-link" target="_blank" rel="noopener">dnsviz.net</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">HSTS Preload</div>
          <span class="ct-card-oss">Open Source</span>
        </div>
        <div class="ct-card-desc">Chrome/Firefox HSTS preload list submission and eligibility checker. Verifies that your domain meets the strict requirements (valid HTTPS, max-age ≥ 1 year, includeSubDomains, preload directive) before applying for preloading. Source on GitHub (chromium/hstspreload).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://hstspreload.org/" class="ct-card-link" target="_blank" rel="noopener">hstspreload.org</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">CAA Test</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">Checks CAA (Certification Authority Authorization) DNS records for any domain. Shows which CAs are authorised to issue, which issuewild / iodef properties are set, and whether the record is valid. By Rob Stradling (Sectigo researcher).</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-domain">Domain</span>
        </div>
        <a href="https://caatest.co.uk/" class="ct-card-link" target="_blank" rel="noopener">caatest.co.uk</a>
      </div>

    </div>
  </section>

  <!-- ── 8. OID & Standards Lookup ──────────────────────────────────────── -->
  <section class="ct-section" id="oid">
    <div class="ct-section-header">
      <span class="ct-section-icon">🔖</span>
      <h2>OID &amp; Standards Lookup</h2>
    </div>
    <div class="ct-grid">

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">OID Repository (oid-info.com)</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">Community-maintained OID registry. Paste any OID in dotted notation and get its name, description, owning organisation, and the standards that define it. Covers the full arc tree including PKIX, PKCS, ETSI, CAB Forum, and vendor arcs.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-search">Search</span>
        </div>
        <a href="http://oid-info.com/" class="ct-card-link" target="_blank" rel="noopener">oid-info.com</a>
      </div>

      <div class="ct-card">
        <div class="ct-card-top">
          <div class="ct-card-name">RFC Editor</div>
          <span class="ct-card-oss">Free</span>
        </div>
        <div class="ct-card-desc">The authoritative source for all IETF RFCs. Full-text search, cross-references between documents, errata tracking, and machine-readable formats. Operated by the IETF/IASA. Indispensable for reading the specifications behind every PKI standard.</div>
        <div class="ct-tags">
          <span class="ct-tag ct-tag-search">Search</span>
        </div>
        <a href="https://www.rfc-editor.org/" class="ct-card-link" target="_blank" rel="noopener">rfc-editor.org</a>
      </div>

    </div>
  </section>

</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/feed.php">PKI News</a>
    <a href="/references.php">References</a>
    <a href="/privacy.php">Privacy</a>
    <a href="mailto:me@thameur.org">me@thameur.org</a>
  </div>
</footer>

<?php require __DIR__ . '/includes/cookie_banner.php'; ?>

</body>
</html>
