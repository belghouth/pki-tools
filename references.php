<?php
$navLabel = 'PKI References';
?><!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <?php
  require_once __DIR__ . '/includes/seo.php';
  seo_head([
    'title'       => 'PKI References — Essential Links for CA/Browser Forum & WebPKI Practitioners | ' . SITE_DOMAIN,
    'description' => 'Curated essential references for PKI practitioners: CABF Baseline Requirements, Apple & Chrome & Mozilla root programs, ETSI & WebTrust audit standards, CCADB, CT logs, key RFCs, and community resources.',
    'url'         => SITE_BASE_URL . '/references.php',
    'jsonld'      => json_encode([
      '@context'    => 'https://schema.org',
      '@type'       => 'CollectionPage',
      'name'        => 'PKI References',
      'url'         => SITE_BASE_URL . '/references.php',
      'description' => 'Curated essential references for PKI practitioners: CABF Baseline Requirements, root programs, ETSI & WebTrust audit standards, CCADB, CT logs, and key RFCs.',
      'keywords'    => 'PKI references, CA/Browser Forum, Baseline Requirements, root programs, WebTrust, ETSI, CCADB, RFC 5280, X.509',
      'author'      => ['@id' => SITE_BASE_URL . '/#person', 'name' => 'Thameur Belghith'],
    ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT),
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
      --bg: #0e1014; --surface: #13171e; --border: #2a3040;
      --accent: #00d4aa; --text: #d4dae6; --muted: #6b7a90;
      --sans: 'IBM Plex Sans', sans-serif; --mono: 'IBM Plex Mono', monospace;
      --radius: 8px;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { font-size: 15px; scroll-behavior: smooth; }
    body { background: var(--bg); color: var(--text); font-family: var(--sans); font-weight: 300; line-height: 1.75; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { color: #fff; text-decoration: underline; }

    /* ── Page layout ── */
    .ref-page { max-width: 1040px; margin: 0 auto; padding: 3.5rem 2rem 6rem; }

    .ref-page h1 {
      font-size: 2rem; font-weight: 600; color: #fff; margin-bottom: 0.4rem;
    }
    .ref-page .page-sub {
      font-family: var(--mono); font-size: 0.75rem; color: var(--muted);
      letter-spacing: 0.05em; margin-bottom: 3rem;
    }

    /* ── TOC ── */
    .toc {
      background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
      padding: 1.2rem 1.6rem; margin-bottom: 3rem; display: inline-block; min-width: 260px;
    }
    .toc-title {
      font-family: var(--mono); font-size: 0.72rem; text-transform: uppercase;
      letter-spacing: 0.08em; color: var(--muted); margin-bottom: 0.7rem;
    }
    .toc ol { list-style: decimal; padding-left: 1.2rem; }
    .toc li { margin-bottom: 0.25rem; }
    .toc a { font-size: 0.85rem; color: var(--muted); }
    .toc a:hover { color: var(--accent); text-decoration: none; }

    /* ── Section ── */
    .ref-section { margin-bottom: 3.5rem; }
    .ref-section-header {
      display: flex; align-items: center; gap: 0.75rem;
      border-bottom: 1px solid var(--border); padding-bottom: 0.6rem; margin-bottom: 1.2rem;
    }
    .ref-section-header h2 {
      font-size: 1.05rem; font-weight: 600; color: #fff;
    }
    .ref-section-icon {
      font-size: 1.1rem; line-height: 1;
    }

    /* ── Cards ── */
    .ref-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));
      gap: 1rem;
    }
    .ref-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.1rem 1.3rem;
      transition: border-color 0.15s;
      display: flex; flex-direction: column; gap: 0.45rem;
    }
    .ref-card:hover { border-color: var(--accent); }
    .ref-card-name {
      font-weight: 600; font-size: 0.9rem; color: #fff;
    }
    .ref-card-desc {
      font-size: 0.82rem; color: var(--muted); line-height: 1.55; flex: 1;
    }
    .ref-card-link {
      font-family: var(--mono); font-size: 0.72rem; color: var(--accent);
      display: inline-flex; align-items: center; gap: 0.3rem; margin-top: 0.2rem;
    }
    .ref-card-link:hover { color: #fff; text-decoration: none; }
    .ref-card-link::after { content: '↗'; font-size: 0.7rem; }
    .ref-tag {
      display: inline-block; font-family: var(--mono); font-size: 0.65rem;
      background: rgba(0,212,170,0.08); color: var(--accent); border: 1px solid rgba(0,212,170,0.2);
      border-radius: 3px; padding: 0.1em 0.45em; text-transform: uppercase; letter-spacing: 0.05em;
      align-self: flex-start;
    }
    .ref-tag.tag-rfc { background: rgba(59,130,246,0.08); color: #60a5fa; border-color: rgba(59,130,246,0.2); }
    .ref-tag.tag-policy { background: rgba(245,158,11,0.08); color: #fbbf24; border-color: rgba(245,158,11,0.2); }
    .ref-tag.tag-community { background: rgba(168,85,247,0.08); color: #c084fc; border-color: rgba(168,85,247,0.2); }
    .ref-tag.tag-db { background: rgba(236,72,153,0.08); color: #f472b6; border-color: rgba(236,72,153,0.2); }

    /* ── Footer ── */
    .site-footer {
      border-top: 1px solid var(--border); padding: 1.4rem 2rem;
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem;
      font-family: var(--mono); font-size: 0.72rem; color: var(--muted);
    }
    .site-footer a { color: var(--muted); text-decoration: none; }
    .site-footer a:hover { color: var(--accent); }
    .site-footer-links { display: flex; gap: 1.5rem; }

    @media (max-width: 600px) {
      .ref-grid { grid-template-columns: 1fr; }
      .toc { width: 100%; }
    }
  </style>
  <?php require_once __DIR__ . '/includes/adsense_head.php'; ?>
</head>
<body>

<?php require_once __DIR__ . '/includes/site_nav.php'; ?>

<main class="ref-page">
  <h1>PKI References</h1>
  <p class="page-sub">Curated resources for PKI & Trust Services practitioners — policies, standards, databases, and community.</p>

  <nav class="toc" aria-label="Table of contents">
    <p class="toc-title">Contents</p>
    <ol>
      <li><a href="#cabf">CA/Browser Forum</a></li>
      <li><a href="#root-programs">Root Programs</a></li>
      <li><a href="#audit">Audit Standards</a></li>
      <li><a href="#databases">Databases &amp; Platforms</a></li>
      <li><a href="#ct">Certificate Transparency</a></li>
      <li><a href="#rfcs">Key RFCs</a></li>
      <li><a href="#community">Community &amp; Mailing Lists</a></li>
    </ol>
  </nav>

  <?php require_once __DIR__ . '/includes/adsense_unit.php'; ?>

  <!-- ── 1. CA/Browser Forum ── -->
  <section class="ref-section" id="cabf">
    <div class="ref-section-header">
      <span class="ref-section-icon">⚖️</span>
      <h2>CA/Browser Forum</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-policy">Website</span>
        <p class="ref-card-name">CA/Browser Forum</p>
        <p class="ref-card-desc">The governing body that produces the Baseline Requirements, EV Guidelines, and Code Signing requirements for publicly trusted CAs.</p>
        <a class="ref-card-link" href="https://cabforum.org/" target="_blank" rel="noopener">cabforum.org</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">TLS BR</span>
        <p class="ref-card-name">Baseline Requirements for TLS</p>
        <p class="ref-card-desc">The primary standard governing issuance of publicly trusted TLS/SSL certificates. Covers validation, certificate profiles, and CA operational requirements.</p>
        <a class="ref-card-link" href="https://cabforum.org/working-groups/server/baseline-requirements/documents/" target="_blank" rel="noopener">Latest version</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">S/MIME BR</span>
        <p class="ref-card-name">S/MIME Baseline Requirements</p>
        <p class="ref-card-desc">Baseline Requirements for the issuance and management of publicly-trusted S/MIME certificates for email signing and encryption.</p>
        <a class="ref-card-link" href="https://cabforum.org/working-groups/smime/requirements/" target="_blank" rel="noopener">Latest version</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">CS BR</span>
        <p class="ref-card-name">Code Signing Baseline Requirements</p>
        <p class="ref-card-desc">Requirements for the issuance and management of publicly-trusted Code Signing certificates, covering subscriber validation and key protection.</p>
        <a class="ref-card-link" href="https://cabforum.org/working-groups/code-signing/documents/" target="_blank" rel="noopener">Latest version</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">EV</span>
        <p class="ref-card-name">Extended Validation (EV) Guidelines</p>
        <p class="ref-card-desc">Guidelines for issuing EV TLS and EV Code Signing certificates, detailing enhanced identity validation requirements for organizations.</p>
        <a class="ref-card-link" href="https://cabforum.org/working-groups/server/extended-validation/" target="_blank" rel="noopener">Latest version</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">NCSSR</span>
        <p class="ref-card-name">Network &amp; Certificate System Security Requirements</p>
        <p class="ref-card-desc">Security requirements for CA network infrastructure, system configuration, and operational security practices.</p>
        <a class="ref-card-link" href="https://cabforum.org/working-groups/server/network-security/" target="_blank" rel="noopener">Latest version</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">Mailing List</span>
        <p class="ref-card-name">CABF Public Mailing List</p>
        <p class="ref-card-desc">The public mailing list for CA/Browser Forum discussions. Open for observation; membership required to participate in ballots.</p>
        <a class="ref-card-link" href="https://lists.cabforum.org/mailman/listinfo/public" target="_blank" rel="noopener">Subscribe / Archive</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag">GitHub</span>
        <p class="ref-card-name">CABF GitHub Organization</p>
        <p class="ref-card-desc">Source repository for all CABF documents. Track ballot pull requests and diffs between versions of the Baseline Requirements and other guidelines.</p>
        <a class="ref-card-link" href="https://github.com/cabforum" target="_blank" rel="noopener">github.com/cabforum</a>
      </div>

    </div>
  </section>

  <!-- ── 2. Root Programs ── -->
  <section class="ref-section" id="root-programs">
    <div class="ref-section-header">
      <span class="ref-section-icon">🏛️</span>
      <h2>Root Programs</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-policy">Google</span>
        <p class="ref-card-name">Chrome Root Program</p>
        <p class="ref-card-desc">Policy governing the Chrome Root Store, Chrome Root Program requirements, and Moving Forward Together initiative for the web PKI ecosystem.</p>
        <a class="ref-card-link" href="https://googlechrome.github.io/chromerootprogram/" target="_blank" rel="noopener">Policy &amp; requirements</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Mozilla</span>
        <p class="ref-card-name">Mozilla Root Store Policy</p>
        <p class="ref-card-desc">Mozilla's policy for inclusion in the NSS root store, which underpins Firefox and many Linux distributions. Includes incident response expectations.</p>
        <a class="ref-card-link" href="https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/" target="_blank" rel="noopener">Policy</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Apple</span>
        <p class="ref-card-name">Apple Root Certificate Program</p>
        <p class="ref-card-desc">Requirements for CAs to participate in the Apple Root Certificate Program, covering iOS, macOS, Safari, and other Apple platforms.</p>
        <a class="ref-card-link" href="https://www.apple.com/certificateauthority/ca_program.html" target="_blank" rel="noopener">Program page</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Microsoft</span>
        <p class="ref-card-name">Microsoft Trusted Root Program</p>
        <p class="ref-card-desc">Requirements and technical constraints for inclusion in the Microsoft Root Certificate Program used by Windows and Edge. The former Learn page has been superseded — canonical requirements are now on GitHub.</p>
        <a class="ref-card-link" href="https://github.com/TrustedRootProgram/Program-Requirements" target="_blank" rel="noopener">Requirements (GitHub)</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Mozilla</span>
        <p class="ref-card-name">Mozilla Included CAs List</p>
        <p class="ref-card-desc">Spreadsheet of all CAs included in the Mozilla root store with their constraints, audit information, and contact details.</p>
        <a class="ref-card-link" href="https://wiki.mozilla.org/CA/Included_Certificates" target="_blank" rel="noopener">Included certificates</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Google</span>
        <p class="ref-card-name">Chrome Root Store</p>
        <p class="ref-card-desc">The actual root store used by Chrome, published as a human-readable list with constraints. Separate from the OS root store.</p>
        <a class="ref-card-link" href="https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.md" target="_blank" rel="noopener">Root store list</a>
      </div>

    </div>
  </section>

  <!-- ── 3. Audit Standards ── -->
  <section class="ref-section" id="audit">
    <div class="ref-section-header">
      <span class="ref-section-icon">📋</span>
      <h2>Audit Standards</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-policy">WebTrust</span>
        <p class="ref-card-name">WebTrust for Certification Authorities</p>
        <p class="ref-card-desc">The foundational WebTrust audit criteria for public CAs, covering CA management and operations, certificate issuance, and revocation.</p>
        <a class="ref-card-link" href="https://www.cpacanada.ca/en/business-and-accounting-resources/audit-and-assurance/overview-of-webtrust-services/standards-and-guidance" target="_blank" rel="noopener">CPA Canada — standards</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">WebTrust</span>
        <p class="ref-card-name">WebTrust for CAs — EV SSL</p>
        <p class="ref-card-desc">Supplemental WebTrust criteria for Extended Validation certificate issuance, aligned with the CABF EV Guidelines.</p>
        <a class="ref-card-link" href="https://www.cpacanada.ca/en/business-and-accounting-resources/audit-and-assurance/overview-of-webtrust-services/standards-and-guidance" target="_blank" rel="noopener">CPA Canada — standards</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">WebTrust</span>
        <p class="ref-card-name">WebTrust for CAs — Baseline Requirements</p>
        <p class="ref-card-desc">WebTrust audit criteria specifically tied to the CABF TLS Baseline Requirements. Required for most root program inclusion.</p>
        <a class="ref-card-link" href="https://www.cpacanada.ca/en/business-and-accounting-resources/audit-and-assurance/overview-of-webtrust-services/standards-and-guidance" target="_blank" rel="noopener">CPA Canada — standards</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">ETSI</span>
        <p class="ref-card-name">ETSI EN 319 411-1</p>
        <p class="ref-card-desc">European standard for policy and security requirements for Trust Service Providers issuing certificates, applicable in EU/eIDAS contexts.</p>
        <a class="ref-card-link" href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941101/" target="_blank" rel="noopener">ETSI — EN 319 411-1</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">ETSI</span>
        <p class="ref-card-name">ETSI EN 319 411-2</p>
        <p class="ref-card-desc">Policy and security requirements for TSPs issuing EU Qualified Certificates under eIDAS regulation, including QCP-l and QCP-n profiles.</p>
        <a class="ref-card-link" href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/" target="_blank" rel="noopener">ETSI — EN 319 411-2</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">ETSI</span>
        <p class="ref-card-name">ETSI EN 319 401</p>
        <p class="ref-card-desc">General Policy Requirements for Trust Service Providers — the base standard from which the 411-1 and 411-2 certificate-specific requirements derive.</p>
        <a class="ref-card-link" href="https://www.etsi.org/deliver/etsi_en/319400_319499/319401/" target="_blank" rel="noopener">ETSI — EN 319 401</a>
      </div>

    </div>
  </section>

  <!-- ── 4. Databases & Platforms ── -->
  <section class="ref-section" id="databases">
    <div class="ref-section-header">
      <span class="ref-section-icon">🗄️</span>
      <h2>Databases &amp; Platforms</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-db">CCADB</span>
        <p class="ref-card-name">Common CA Database (CCADB)</p>
        <p class="ref-card-desc">Shared repository used by Mozilla, Microsoft, Apple, and Google to store information about CAs, root certificates, and audit reports.</p>
        <a class="ref-card-link" href="https://www.ccadb.org/" target="_blank" rel="noopener">ccadb.org</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-db">CCADB</span>
        <p class="ref-card-name">CCADB Policy</p>
        <p class="ref-card-desc">Policy governing CA participation in CCADB — audit report submission timelines, CP/CPS update requirements, and incident disclosure obligations.</p>
        <a class="ref-card-link" href="https://www.ccadb.org/policy" target="_blank" rel="noopener">CCADB Policy</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-db">Search</span>
        <p class="ref-card-name">crt.sh</p>
        <p class="ref-card-desc">Certificate Transparency log aggregator and search engine by Sectigo. Search by domain, organization, or SHA fingerprint. Essential for CT monitoring.</p>
        <a class="ref-card-link" href="https://crt.sh/" target="_blank" rel="noopener">crt.sh</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-db">Bugzilla</span>
        <p class="ref-card-name">Mozilla Bugzilla — CA Program</p>
        <p class="ref-card-desc">Mozilla's bug tracker for CA inclusion requests, incident reports, and policy discussions. The authoritative record of CA compliance actions.</p>
        <a class="ref-card-link" href="https://bugzilla.mozilla.org/describecomponents.cgi?product=CA%20Program" target="_blank" rel="noopener">CA Program component</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-db">Search</span>
        <p class="ref-card-name">Censys Certificate Search</p>
        <p class="ref-card-desc">Internet-wide certificate scanner providing structured search over CT logs and active scan data. Useful for certificate profiling and CA research.</p>
        <a class="ref-card-link" href="https://search.censys.io/certificates" target="_blank" rel="noopener">search.censys.io</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-db">Lint</span>
        <p class="ref-card-name">zlint (GoDaddy / ZmapTeam)</p>
        <p class="ref-card-desc">Open-source X.509 certificate linter implementing CABF Baseline Requirements, RFC 5280, and root program checks. Used by CAs pre-issuance.</p>
        <a class="ref-card-link" href="https://github.com/zmap/zlint" target="_blank" rel="noopener">github.com/zmap/zlint</a>
      </div>

    </div>
  </section>

  <!-- ── 5. Certificate Transparency ── -->
  <section class="ref-section" id="ct">
    <div class="ref-section-header">
      <span class="ref-section-icon">🔍</span>
      <h2>Certificate Transparency</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-policy">Google</span>
        <p class="ref-card-name">Chrome CT Log Policy</p>
        <p class="ref-card-desc">Requirements for CT logs to be accepted by Chrome, including inclusion, temporal shard requirements, and the qualification process.</p>
        <a class="ref-card-link" href="https://googlechrome.github.io/CertificateTransparency/log_policy.html" target="_blank" rel="noopener">CT Log Policy</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-policy">Google</span>
        <p class="ref-card-name">Known/Qualified CT Log List</p>
        <p class="ref-card-desc">The JSON list of CT logs recognized by Chrome — the canonical source for which logs' SCTs are accepted by the browser.</p>
        <a class="ref-card-link" href="https://www.gstatic.com/ct/log_list/v3/log_list.json" target="_blank" rel="noopener">log_list.json (v3)</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 9162</span>
        <p class="ref-card-name">RFC 9162 — Certificate Transparency v2</p>
        <p class="ref-card-desc">The current CT specification (CT v2), superseding RFC 6962. Defines the Merkle tree structure, signed list, and submission API used by modern CT logs.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc9162" target="_blank" rel="noopener">RFC 9162</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 6962</span>
        <p class="ref-card-name">RFC 6962 — Certificate Transparency v1</p>
        <p class="ref-card-desc">The original CT specification. Still referenced for backward compatibility and historical context, though CT v2 (RFC 9162) is the current standard.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc6962" target="_blank" rel="noopener">RFC 6962</a>
      </div>

    </div>
  </section>

  <!-- ── 6. Key RFCs ── -->
  <section class="ref-section" id="rfcs">
    <div class="ref-section-header">
      <span class="ref-section-icon">📄</span>
      <h2>Key RFCs</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 5280</span>
        <p class="ref-card-name">RFC 5280 — Internet X.509 PKI</p>
        <p class="ref-card-desc">The foundational RFC defining the X.509 certificate and CRL profile for the Internet. Defines field syntax, extensions, path validation, and name constraints.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc5280" target="_blank" rel="noopener">RFC 5280</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 6960</span>
        <p class="ref-card-name">RFC 6960 — OCSP</p>
        <p class="ref-card-desc">Online Certificate Status Protocol — the standard for real-time certificate revocation checking, defining the request/response format and signing requirements.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc6960" target="_blank" rel="noopener">RFC 6960</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 5652</span>
        <p class="ref-card-name">RFC 5652 — Cryptographic Message Syntax (CMS)</p>
        <p class="ref-card-desc">Defines the CMS format (based on PKCS #7) used for signed and enveloped data in S/MIME, code signing, and timestamping.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc5652" target="_blank" rel="noopener">RFC 5652</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 8555</span>
        <p class="ref-card-name">RFC 8555 — ACME Protocol</p>
        <p class="ref-card-desc">Automatic Certificate Management Environment — the protocol enabling automated certificate issuance and renewal, as implemented by Let's Encrypt and others.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc8555" target="_blank" rel="noopener">RFC 8555</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 5912</span>
        <p class="ref-card-name">RFC 5912 — New ASN.1 for PKIX</p>
        <p class="ref-card-desc">ASN.1 module definitions for PKIX structures (certificates, CRLs, OCSP) using 2002 ASN.1 syntax. Reference for implementers parsing X.509 structures.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc5912" target="_blank" rel="noopener">RFC 5912</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 3647</span>
        <p class="ref-card-name">RFC 3647 — CP &amp; CPS Framework</p>
        <p class="ref-card-desc">The standard framework and outline for writing Certificate Policies (CP) and Certification Practice Statements (CPS), with a 9-section structure widely adopted by CAs.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc3647" target="_blank" rel="noopener">RFC 3647</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 5019</span>
        <p class="ref-card-name">RFC 5019 — Lightweight OCSP Profile</p>
        <p class="ref-card-desc">Simplified OCSP profile for large-scale deployments, defining GET-based requests, caching headers, and pre-produced response requirements.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc5019" target="_blank" rel="noopener">RFC 5019</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-rfc">RFC 6818</span>
        <p class="ref-card-name">RFC 6818 — Updates to RFC 5280</p>
        <p class="ref-card-desc">Clarifications and corrections to RFC 5280 path validation and certificate/CRL profile. Should be read alongside RFC 5280.</p>
        <a class="ref-card-link" href="https://www.rfc-editor.org/rfc/rfc6818" target="_blank" rel="noopener">RFC 6818</a>
      </div>

    </div>
  </section>

  <!-- ── 7. Community & Mailing Lists ── -->
  <section class="ref-section" id="community">
    <div class="ref-section-header">
      <span class="ref-section-icon">💬</span>
      <h2>Community &amp; Mailing Lists</h2>
    </div>
    <div class="ref-grid">

      <div class="ref-card">
        <span class="ref-tag tag-community">Mozilla</span>
        <p class="ref-card-name">mozilla.dev.security.policy</p>
        <p class="ref-card-desc">The primary public forum for CA-related policy discussions in the Mozilla ecosystem. Incident disclosures, inclusion requests, and policy debates happen here.</p>
        <a class="ref-card-link" href="https://groups.google.com/a/mozilla.org/g/dev-security-policy" target="_blank" rel="noopener">Google Groups archive</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">CABF</span>
        <p class="ref-card-name">CABF SCWG (Server Cert Working Group)</p>
        <p class="ref-card-desc">The working group list where TLS Baseline Requirements ballots, discussions, and proposals are developed before going to the full Forum.</p>
        <a class="ref-card-link" href="https://lists.cabforum.org/mailman/listinfo/servercert-wg" target="_blank" rel="noopener">SCWG list</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">CABF</span>
        <p class="ref-card-name">CABF S/MIME Working Group</p>
        <p class="ref-card-desc">Working group responsible for the S/MIME Baseline Requirements and related ballots.</p>
        <a class="ref-card-link" href="https://lists.cabforum.org/mailman/listinfo/smime-wg" target="_blank" rel="noopener">S/MIME WG list</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">IETF</span>
        <p class="ref-card-name">IETF PKIX Working Group Archive</p>
        <p class="ref-card-desc">Historical archive of the IETF PKIX WG, which produced RFC 5280 and related PKI standards. Now concluded; active work continues in LAMPS WG.</p>
        <a class="ref-card-link" href="https://datatracker.ietf.org/wg/pkix/about/" target="_blank" rel="noopener">IETF Datatracker</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">IETF</span>
        <p class="ref-card-name">IETF LAMPS Working Group</p>
        <p class="ref-card-desc">Limited Additional Mechanisms for PKIX and SMIME — the active IETF WG producing updates to X.509, CMS, and related PKI specifications.</p>
        <a class="ref-card-link" href="https://datatracker.ietf.org/wg/lamps/about/" target="_blank" rel="noopener">IETF Datatracker</a>
      </div>

      <div class="ref-card">
        <span class="ref-tag tag-community">Mozilla</span>
        <p class="ref-card-name">Mozilla CA Incident Dashboard</p>
        <p class="ref-card-desc">Consolidated view of open and closed CA incidents tracked in Bugzilla. A critical resource for monitoring CA compliance trends.</p>
        <a class="ref-card-link" href="https://wiki.mozilla.org/CA/Incident_Dashboard" target="_blank" rel="noopener">Incident Dashboard</a>
      </div>

    </div>
  </section>

  <div style="border-top:1px solid var(--border);margin-top:2rem;padding-top:1.5rem;font-family:var(--mono);font-size:0.72rem;color:var(--muted);">
    Links checked <?= date('F Y') ?>. Policies and standards are maintained by their respective organizations — always verify you are reading the current version.
    &nbsp;·&nbsp; <a href="<?= 'mailto:' . CONTACT_EMAIL ?>">Suggest a resource</a>
  </div>
</main>

<footer class="site-footer">
  <span>&copy; <?= date('Y') ?> Thameur Belghith</span>
  <div class="site-footer-links">
    <a href="/">Home</a>
    <a href="/references.php">PKI References</a>
    <a href="/privacy.php">Privacy Policy</a>
    <a href="<?= 'mailto:' . CONTACT_EMAIL ?>"><?= CONTACT_EMAIL ?></a>
  </div>
</footer>

<?php require_once __DIR__ . '/includes/cookie_banner.php'; ?>
</body>
</html>
