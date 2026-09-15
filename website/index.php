<?php
/**
 * =============================================================================
 *  TRIDENT :: Showcase Landing Page
 * =============================================================================
 *  Pure display — no scanning logic, no execution, no external requests.
 * =============================================================================
 */

$config       = require __DIR__ . '/config.php';
$meta         = $config['meta'];
$funding      = $config['funding'];
$aiProviders  = $config['ai_providers'];

$php_ver      = phpversion();
$server_time  = gmdate('Y-m-d H:i:s') . ' UTC';
$server_agent = $_SERVER['SERVER_SOFTWARE'] ?? 'unknown';

// Helper: format dollars
$usd = fn($n) => '$' . number_format($n, 0);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="TRIDENT — AI-powered bug bounty automation. Recon, audit, and report generation for HackerOne and Bugcrowd. SQLi, XSS, SSRF, Open Redirect, Path Traversal.">
<meta name="theme-color" content="#050810">
<title>TRIDENT — Three Prongs. One Strike.</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@300;400;500;600;700&family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="stylesheet" href="assets/css/main.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" defer></script>
<script src="assets/js/main.js" defer></script>
</head>
<body>

<canvas id="matrix"></canvas>
<div id="crt-overlay"></div>

<!-- ======================================================================
     HERO
     ====================================================================== -->
<header id="hero">
    <div class="scan-line"></div>

    <div class="hero-content">
        <div class="hero-eyebrow">AI-Powered Bug Bounty Automation</div>

        <h1 class="hero-title" data-text="TRIDENT">TRIDENT</h1>

        <div class="hero-tagline" id="typing-line">
            <span class="cursor"></span>
        </div>

        <p class="hero-description">
            Three prongs. One strike. TRIDENT ingests your Burp Suite URLs,
            triages every page with AI, audits each parameter with verified
            payloads, and writes submission-ready reports — <strong>all in a
            single pipeline</strong>.
        </p>

        <div class="hero-actions">
            <a class="btn btn-primary" href="#prongs">
                <i class="fa-solid fa-bolt"></i> Explore
            </a>
            <a class="btn" href="<?= htmlspecialchars($meta['repo']) ?>" target="_blank" rel="noopener">
                <i class="fa-brands fa-github"></i> Source
            </a>
            <a class="btn" href="<?= htmlspecialchars($meta['hackerone']) ?>" target="_blank" rel="noopener">
                <i class="fa-solid fa-user-shield"></i> HackerOne
            </a>
        </div>
    </div>

    <div class="scroll-hint">
        SCROLL
        <i class="fa-solid fa-chevron-down"></i>
    </div>
</header>


<!-- ======================================================================
     STATUS TICKER
     ====================================================================== -->
<div class="status-bar">
    <div class="status-ticker">
        <?php for ($i = 0; $i < 3; $i++): ?>
            <span><span class="dot"></span><span class="tag">Systems</span> Operational</span>
            <span><span class="dot"></span><span class="tag">Version</span> v<?= htmlspecialchars($meta['version']) ?></span>
            <span><span class="dot"></span><span class="tag">Payloads</span> <?= number_format($meta['payloads']) ?> Loaded</span>
            <span><span class="dot"></span><span class="tag">AI Providers</span> <?= (int)$meta['providers'] ?> Online</span>
            <span><span class="dot"></span><span class="tag">Vectors</span> <?= number_format($meta['vectors']) ?> Indexed</span>
            <span><span class="dot"></span><span class="tag">Updated</span> <?= htmlspecialchars($meta['updated']) ?></span>
        <?php endfor; ?>
    </div>
</div>


<!-- ======================================================================
     QUICK STATS
     ====================================================================== -->
<section id="stats">
    <div class="container">
        <h2 class="section-title reveal">By The Numbers</h2>
        <div class="section-subtitle reveal">Live telemetry from the trident core</div>

        <div class="server-status reveal">
            <div class="server-status-item">
                <span class="k">Server</span>
                <span class="v"><span class="pulse-dot"></span><?= htmlspecialchars($server_agent) ?></span>
            </div>
            <div class="server-status-item">
                <span class="k">PHP Runtime</span>
                <span class="v"><?= htmlspecialchars($php_ver) ?></span>
            </div>
            <div class="server-status-item">
                <span class="k">UTC Time</span>
                <span class="v"><?= htmlspecialchars($server_time) ?></span>
            </div>
            <div class="server-status-item">
                <span class="k">TRIDENT Core</span>
                <span class="v">v<?= htmlspecialchars($meta['version']) ?></span>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card reveal">
                <i class="fa-solid fa-crosshairs stat-icon"></i>
                <div class="stat-number" data-target="<?= (int)$meta['scanners'] ?>">0</div>
                <div class="stat-label">Active Scanners</div>
            </div>
            <div class="stat-card reveal">
                <i class="fa-solid fa-vial-circle-check stat-icon"></i>
                <div class="stat-number" data-target="<?= (int)$meta['payloads'] ?>">0</div>
                <div class="stat-label">Payload Templates</div>
            </div>
            <div class="stat-card reveal">
                <i class="fa-solid fa-bug stat-icon"></i>
                <div class="stat-number" data-target="<?= (int)$meta['vectors'] ?>">0</div>
                <div class="stat-label">Injection Vectors</div>
            </div>
            <div class="stat-card reveal">
                <i class="fa-solid fa-brain stat-icon"></i>
                <div class="stat-number" data-target="<?= (int)$meta['providers'] ?>">0</div>
                <div class="stat-label">AI Providers</div>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     THE THREE PRONGS
     ====================================================================== -->
<section id="prongs">
    <div class="container">
        <h2 class="section-title reveal">The Three Prongs</h2>
        <div class="section-subtitle reveal">Recon &nbsp;·&nbsp; Audit &nbsp;·&nbsp; Report</div>

        <div class="prong-grid">
            <div class="prong-card reveal">
                <div class="prong-num">01</div>
                <div class="prong-icon"><i class="fa-solid fa-satellite-dish"></i></div>
                <h3>Recon &amp; Triage</h3>
                <p>
                    Paste your Burp Suite URL dump into <code>urls.txt</code>.
                    TRIDENT fetches every page, extracts forms, endpoints, and
                    parameters, then asks an LLM to score each one for potential
                    risk and business-logic weight.
                </p>
                <code class="prong-cli">python cli.py ingest urls.txt</code>
            </div>

            <div class="prong-card reveal">
                <div class="prong-num">02</div>
                <div class="prong-icon"><i class="fa-solid fa-syringe"></i></div>
                <h3>Audit &amp; Verify</h3>
                <p>
                    Each scanner loads its <code>payloads/&lt;script&gt;.yaml</code>,
                    injects every payload into every parameter, and matches
                    responses against <code>responses/&lt;script&gt;.yaml</code>
                    signatures. Only reproducible hits survive.
                </p>
                <code class="prong-cli">python cli.py audit --modules sqli,ssrf</code>
            </div>

            <div class="prong-card reveal">
                <div class="prong-num">03</div>
                <div class="prong-icon"><i class="fa-solid fa-file-lines"></i></div>
                <h3>Report &amp; Submit</h3>
                <p>
                    Every verified finding is rendered through
                    <code>templates/default_&lt;script&gt;.md</code> — severity,
                    reproduction cURL, response snippet, remediation guidance.
                    Copy, paste, submit to HackerOne or Bugcrowd.
                </p>
                <code class="prong-cli">python cli.py report --out reports/</code>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     SCANNERS
     ====================================================================== -->
<section id="scanners">
    <div class="container">
        <h2 class="section-title reveal">The Arsenal</h2>
        <div class="section-subtitle reveal">Five verified scanners · one unified pipeline</div>

        <div class="scanner-grid">
            <div class="scanner-card reveal" data-sev="critical">
                <i class="fa-solid fa-database scanner-icon"></i>
                <h3>SQL Injection</h3>
                <p>Error-based, blind boolean, blind time, UNION, and stacked queries across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, MongoDB, and Redis.</p>
                <div class="scanner-tags">
                    <span class="tag">Error-Based</span>
                    <span class="tag">Blind Time</span>
                    <span class="tag">UNION</span>
                    <span class="tag">NoSQL</span>
                </div>
            </div>

            <div class="scanner-card reveal" data-sev="high">
                <i class="fa-solid fa-code scanner-icon"></i>
                <h3>Cross-Site Scripting</h3>
                <p>Context-aware routing across HTML body, attributes, JS strings, template literals. Includes mXSS, CSP bypass, and DOM clobbering.</p>
                <div class="scanner-tags">
                    <span class="tag">Reflected</span>
                    <span class="tag">Stored</span>
                    <span class="tag">DOM</span>
                    <span class="tag">mXSS</span>
                </div>
            </div>

            <div class="scanner-card reveal" data-sev="critical">
                <i class="fa-solid fa-network-wired scanner-icon"></i>
                <h3>Server-Side Request Forgery</h3>
                <p>Cloud metadata extraction, protocol abuse (gopher, dict, file, ldap, smb), IPv6 transition addresses, and blind OOB confirmation.</p>
                <div class="scanner-tags">
                    <span class="tag">AWS IMDS</span>
                    <span class="tag">GCP</span>
                    <span class="tag">Azure</span>
                    <span class="tag">gopher</span>
                </div>
            </div>

            <div class="scanner-card reveal" data-sev="medium">
                <i class="fa-solid fa-arrow-up-right-from-square scanner-icon"></i>
                <h3>Open Redirect</h3>
                <p>Protocol-relative, backslash, userinfo, encoding, scheme abuse, CRLF, HPP, and OAuth <code>redirect_uri</code> chains.</p>
                <div class="scanner-tags">
                    <span class="tag">OAuth</span>
                    <span class="tag">CRLF</span>
                    <span class="tag">Scheme Abuse</span>
                </div>
            </div>

            <div class="scanner-card reveal" data-sev="high">
                <i class="fa-solid fa-folder-tree scanner-icon"></i>
                <h3>Path Traversal</h3>
                <p>Traversal via <code>../</code>, encoded, unicode, overlong UTF-8, and PHP stream wrappers. Detects <code>/etc/passwd</code>, <code>.env</code>, AWS creds, and K8s tokens.</p>
                <div class="scanner-tags">
                    <span class="tag">LFI</span>
                    <span class="tag">Wrappers</span>
                    <span class="tag">Credentials</span>
                </div>
            </div>

            <div class="scanner-card reveal" data-sev="info">
                <i class="fa-solid fa-file-import scanner-icon"></i>
                <h3>Burp Import</h3>
                <p>Convert Burp Suite URL exports into curated workspaces. Filter by host, exclude CDNs, build clean scan targets in one command.</p>
                <div class="scanner-tags">
                    <span class="tag">Burp</span>
                    <span class="tag">Curated</span>
                    <span class="tag">In-Scope</span>
                </div>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     AI LAYER
     ====================================================================== -->
<section id="ai">
    <div class="container">
        <h2 class="section-title reveal">The AI Layer</h2>
        <div class="section-subtitle reveal">Multi-provider intelligence · local-first tomorrow</div>

        <p class="section-lede reveal">
            TRIDENT doesn't lock you to one brain. Six hosted providers today,
            a self-hosted <strong>Ollama</strong> rack tomorrow. Fall through
            the chain automatically — if Gemini runs out of tokens, Claude picks
            up the context. If every cloud is down, the local model takes over.
        </p>

        <div class="ai-grid">
            <?php foreach ($aiProviders as $p): ?>
                <div class="ai-card reveal" data-status="<?= htmlspecialchars($p['status']) ?>">
                    <i class="fa-solid <?= htmlspecialchars($p['icon']) ?>"></i>
                    <span class="ai-name"><?= htmlspecialchars($p['name']) ?></span>
                    <span class="ai-status">
                        <?= $p['status'] === 'active' ? '● Active' : '◌ Planned' ?>
                    </span>
                </div>
            <?php endforeach; ?>
        </div>

        <div class="ai-uses reveal">
            <h3>What the AI actually does</h3>
            <div class="ai-uses-grid">
                <div class="ai-use">
                    <i class="fa-solid fa-magnifying-glass-chart"></i>
                    <h4>Risk Scoring</h4>
                    <p>Reads each crawled page and assigns a 0–100 exploitability score based on parameters, auth state, and reflected content.</p>
                </div>
                <div class="ai-use">
                    <i class="fa-solid fa-diagram-project"></i>
                    <h4>Attack Chain Suggestion</h4>
                    <p>Identifies multi-step flows — "this IDOR feeds that SSRF" — that a signature scanner would miss entirely.</p>
                </div>
                <div class="ai-use">
                    <i class="fa-solid fa-wand-magic-sparkles"></i>
                    <h4>Payload Mutation</h4>
                    <p>Rewrites a near-miss payload for the specific WAF and backend it just observed. Adapts instead of giving up.</p>
                </div>
                <div class="ai-use">
                    <i class="fa-solid fa-pen-fancy"></i>
                    <h4>Report Drafting</h4>
                    <p>Turns raw request/response pairs into a professional HackerOne submission — impact narrative, CVSS vector, remediation.</p>
                </div>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     INCOME JOURNEY
     ====================================================================== -->
<section id="journey">
    <div class="container">
        <h2 class="section-title reveal">The 12-Month Journey</h2>
        <div class="section-subtitle reveal">From first $100 to a full-time income</div>

        <p class="section-lede reveal">
            This is the story we're building TRIDENT for: the solo hunter
            grinding through HackerOne with nothing but Burp and patience,
            who plugs in TRIDENT and watches the trajectory bend.
        </p>

        <div class="chart-card reveal">
            <div class="chart-header">
                <i class="fa-solid fa-chart-line"></i> Monthly Bug Bounty Income — Manual vs. TRIDENT-Powered
            </div>
            <div class="chart-container chart-tall">
                <canvas id="chart-income"></canvas>
            </div>
            <div class="chart-footnote">
                Illustrative. Assumes consistent weekly hunting on mid-tier programs, a mix of low/medium/high severity findings, and the 12-month income curve achievable with verified, reproducible reports.
            </div>
        </div>

        <div class="journey-stats">
            <div class="journey-stat reveal">
                <div class="js-label">Year 1 — Manual</div>
                <div class="js-value" data-target="2400" data-prefix="$">$0</div>
                <div class="js-sub">~$200 / mo average</div>
            </div>
            <div class="journey-stat reveal">
                <div class="js-label">Year 1 — TRIDENT</div>
                <div class="js-value accent" data-target="58400" data-prefix="$">$0</div>
                <div class="js-sub">~$4,867 / mo average</div>
            </div>
            <div class="journey-stat reveal">
                <div class="js-label">Delta</div>
                <div class="js-value cyan" data-target="56000" data-prefix="$">$0</div>
                <div class="js-sub">Incremental Year 1 revenue</div>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     IMPACT & PAYOUT
     ====================================================================== -->
<section id="impact">
    <div class="container">
        <h2 class="section-title reveal">The Impact</h2>
        <div class="section-subtitle reveal">What each verified class is worth</div>

        <div class="charts-grid">
            <div class="chart-card reveal">
                <div class="chart-header">
                    <i class="fa-solid fa-sack-dollar"></i> Typical Payout Range by Class
                </div>
                <div class="chart-container">
                    <canvas id="chart-payout"></canvas>
                </div>
                <div class="chart-footnote">Median low-to-high payout ranges across HackerOne &amp; Bugcrowd public disclosures.</div>
            </div>

            <div class="chart-card reveal">
                <div class="chart-header">
                    <i class="fa-solid fa-shield-halved"></i> Detection Coverage
                </div>
                <div class="chart-container">
                    <canvas id="chart-coverage"></canvas>
                </div>
                <div class="chart-footnote">How TRIDENT confirms a hit — no single signal is trusted alone.</div>
            </div>
        </div>

        <div class="impact-grid">
            <div class="impact-card reveal">
                <i class="fa-solid fa-server"></i>
                <h4>Critical Infrastructure</h4>
                <p>SSRF chained into cloud metadata → IAM credential theft → full account takeover. This is the bug class that pays <strong>$10K–$50K+</strong> on mature programs.</p>
            </div>
            <div class="impact-card reveal">
                <i class="fa-solid fa-user-secret"></i>
                <h4>Privacy &amp; PII</h4>
                <p>SQLi and path traversal exposing user records, tokens, and config files. Regulatory exposure for the target — <strong>$5K–$25K</strong> typical range.</p>
            </div>
            <div class="impact-card reveal">
                <i class="fa-solid fa-globe"></i>
                <h4>Session &amp; Account</h4>
                <p>Stored XSS in an authenticated context, OAuth redirect abuse. <strong>$500–$5K</strong> per verified finding, stacked with chain amplification.</p>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     COMPARISON
     ====================================================================== -->
<section id="compare">
    <div class="container">
        <h2 class="section-title reveal">Why TRIDENT</h2>
        <div class="section-subtitle reveal">Manual grind vs. pipeline power</div>

        <div class="compare-table reveal">
            <div class="compare-row compare-header">
                <div>Capability</div>
                <div>Manual</div>
                <div class="col-trident">TRIDENT</div>
            </div>
            <div class="compare-row">
                <div>URL Ingestion</div>
                <div class="no">Copy/paste, notes app</div>
                <div class="yes">Single-file ingest → JSON</div>
            </div>
            <div class="compare-row">
                <div>Page Triage</div>
                <div class="no">Eyeball 400 tabs</div>
                <div class="yes">AI risk-scored &amp; ranked</div>
            </div>
            <div class="compare-row">
                <div>Payload Injection</div>
                <div class="no">Manual, per-parameter</div>
                <div class="yes">YAML-driven, every param</div>
            </div>
            <div class="compare-row">
                <div>Response Matching</div>
                <div class="no">Gut feel</div>
                <div class="yes">Signature-verified</div>
            </div>
            <div class="compare-row">
                <div>False Positives</div>
                <div class="no">High</div>
                <div class="yes">Filtered before write</div>
            </div>
            <div class="compare-row">
                <div>Report Generation</div>
                <div class="no">1–2 hrs per finding</div>
                <div class="yes">Auto-rendered Markdown</div>
            </div>
            <div class="compare-row">
                <div>Time to First Valid Bug</div>
                <div class="no">Weeks</div>
                <div class="yes">Same day</div>
            </div>
        </div>
    </div>
</section>


<!-- ======================================================================
     ROADMAP & FUNDING
     ====================================================================== -->
<section id="roadmap">
    <div class="container">
        <h2 class="section-title reveal">Roadmap &amp; Funding</h2>
        <div class="section-subtitle reveal">Where TRIDENT is going, and what it takes to get there</div>

        <div class="roadmap">
            <div class="roadmap-item done reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge done">Shipped</span>
                    <h4>Core Scanner Suite</h4>
                </div>
                <p>Five verified scanners, 896 payload templates, JSON workspace output, Markdown reporting.</p>
            </div>

            <div class="roadmap-item done reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge done">Shipped</span>
                    <h4>Multi-Provider AI Layer</h4>
                </div>
                <p>Gemini, ChatGPT, DeepSeek, Claude, Groq, Hugging Face. Automatic fallback chain.</p>
            </div>

            <div class="roadmap-item active reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge active">In Progress</span>
                    <h4>Public Launch &amp; Community</h4>
                </div>
                <p>Open-source release on GitHub, public landing page, documentation site, and issue tracker.</p>
            </div>

            <div class="roadmap-item future reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge future">Funded — $50K</span>
                    <h4>Relocation to Texas</h4>
                </div>
                <p>Return to home base. Stable footing is the prerequisite for everything that follows.</p>
            </div>

            <div class="roadmap-item future reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge future">Funded — $35K</span>
                    <h4>AI Workstation Rack</h4>
                </div>
                <p>Local <strong>Ollama</strong> inference. 32GB+ VRAM. Zero API costs. Full offline capability. Context windows measured in hundreds of thousands of tokens, not per-request budgets.</p>
            </div>

            <div class="roadmap-item future reveal">
                <div class="roadmap-header">
                    <span class="roadmap-badge future">Next</span>
                    <h4>SaaS / PTaaS Rebuild</h4>
                </div>
                <p>Turn the CLI into a hosted service. Subscription tiers, private scan workspaces, org accounts, direct report export to HackerOne and Bugcrowd.</p>
            </div>
        </div>

        <div class="funding-grid">
            <?php foreach ($funding as $key => $item): ?>
                <?php
                    $pct = $item['goal'] > 0 ? min(100, round(($item['raised'] / $item['goal']) * 100)) : 0;
                ?>
                <div class="funding-card reveal">
                    <div class="funding-label"><?= htmlspecialchars($item['label']) ?></div>
                    <div class="funding-bar">
                        <div class="funding-bar-fill" style="width: <?= $pct ?>%"></div>
                    </div>
                    <div class="funding-meta">
                        <span><?= $usd((int)$item['raised']) ?> raised</span>
                        <span>Goal: <?= $item['goal'] > 0 ? $usd((int)$item['goal']) : 'Build-ready' ?></span>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
</section>


<!-- ======================================================================
     SAFETY
     ====================================================================== -->
<section id="safety">
    <div class="container">
        <h2 class="section-title reveal">Safety &amp; Ethics</h2>
        <div class="section-subtitle reveal">Authorized testing only</div>

        <div class="safety-box reveal">
            <h3><i class="fa-solid fa-triangle-exclamation"></i> Authorization Required</h3>
            <ul class="safety-list">
                <li>
                    <i class="fa-solid fa-circle-xmark"></i>
                    <div><strong>Never run TRIDENT against a target you do not have explicit written permission to test.</strong> Even reconnaissance generates observable traffic.</div>
                </li>
                <li>
                    <i class="fa-solid fa-circle-xmark"></i>
                    <div><strong>Respect scope boundaries.</strong> If a host or path is excluded in the program's rules of engagement, exclude it in your workspace.</div>
                </li>
                <li>
                    <i class="fa-solid fa-circle-xmark"></i>
                    <div><strong>Never scan CDN infrastructure.</strong> Cloudflare, Akamai, CloudFront, Fastly endpoints — useless traffic, real ToS violations.</div>
                </li>
                <li>
                    <i class="fa-solid fa-circle-xmark"></i>
                    <div><strong>Disclose responsibly.</strong> Report through official programs. Do not sell, publish, or exploit findings for personal gain.</div>
                </li>
                <li>
                    <i class="fa-solid fa-circle-xmark"></i>
                    <div><strong>Rate-limit aggressively.</strong> Unsolicited flooding is a DoS attack, authorized or not. Slow down.</div>
                </li>
            </ul>
        </div>
    </div>
</section>


<!-- ======================================================================
     FOOTER
     ====================================================================== -->
<footer>
    <div class="container">
        <div class="footer-quote">"Three prongs forward. No false positives."</div>
        <div class="footer-sub">TRIDENT v<?= htmlspecialchars($meta['version']) ?> &middot; Updated <?= htmlspecialchars($meta['updated']) ?></div>

        <div class="footer-links">
            <a href="<?= htmlspecialchars($meta['repo']) ?>" target="_blank" rel="noopener">
                <i class="fa-brands fa-github"></i> GitHub
            </a>
            <a href="<?= htmlspecialchars($meta['hackerone']) ?>" target="_blank" rel="noopener">
                <i class="fa-solid fa-user-shield"></i> HackerOne
            </a>
            <a href="<?= htmlspecialchars($meta['site']) ?>" target="_blank" rel="noopener">
                <i class="fa-solid fa-globe"></i> BeardedViking.org
            </a>
        </div>

        <div class="footer-sig">
            Forged by <span class="accent">BeardedVikingTX</span> &middot;
            Three prongs. One strike.
        </div>
    </div>
</footer>

</body>
</html>
