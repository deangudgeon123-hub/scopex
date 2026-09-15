"use client";

import { useMemo, useState } from "react";

type Severity = "Critical" | "High" | "Medium" | "Low";

type Finding = {
  severity: Severity;
  title: string;
  description: string;
  asset: string;
  status: string;
};

const findings: Finding[] = [
  {
    severity: "Critical",
    title: "Outdated component with a known security issue",
    description: "A public-facing component appears to be behind on security updates and should be reviewed urgently.",
    asset: "shop.example.com",
    status: "Needs attention",
  },
  {
    severity: "High",
    title: "Admin area is publicly discoverable",
    description: "Your administration login is exposed to the public internet. Restricting access can reduce unnecessary attack surface.",
    asset: "example.com",
    status: "Open",
  },
  {
    severity: "Medium",
    title: "Browser security policy could be stronger",
    description: "Your current browser protection settings leave more room than recommended for untrusted scripts.",
    asset: "app.example.com",
    status: "Open",
  },
  {
    severity: "Low",
    title: "Security headers can be improved",
    description: "A few recommended response headers are missing. This is a hardening opportunity rather than an emergency.",
    asset: "example.com",
    status: "Recommendation",
  },
];

const navItems = ["Overview", "Assets", "Scans", "Findings", "Reports"];

function BrandMark() {
  return (
    <div className="brand-mark" aria-hidden="true">
      <span className="brand-mark-inner" />
    </div>
  );
}

function Chevron() {
  return <span className="chevron">›</span>;
}

function AppIcon({ label }: { label: string }) {
  const symbols: Record<string, string> = {
    Overview: "⌂",
    Assets: "◇",
    Scans: "⌁",
    Findings: "!",
    Reports: "▤",
  };
  return <span className="nav-icon">{symbols[label] ?? "•"}</span>;
}

export default function Home() {
  const [activeNav, setActiveNav] = useState("Overview");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanTarget, setScanTarget] = useState("https://example.com");
  const [severityFilter, setSeverityFilter] = useState<string>("All");

  const filteredFindings = useMemo(() => {
    if (severityFilter === "All") return findings;
    return findings.filter((finding) => finding.severity === severityFilter);
  }, [severityFilter]);

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row">
          <BrandMark />
          <span className="brand-name">SCOPEX</span>
        </div>

        <div className="workspace-pill">
          <div className="workspace-avatar">S</div>
          <div>
            <strong>Scopex workspace</strong>
            <span>Security overview</span>
          </div>
          <span className="workspace-caret">⌄</span>
        </div>

        <nav className="nav-list" aria-label="Primary navigation">
          {navItems.map((item) => (
            <button
              className={`nav-item ${activeNav === item ? "active" : ""}`}
              key={item}
              onClick={() => setActiveNav(item)}
            >
              <AppIcon label={item} />
              <span>{item}</span>
              {item === "Findings" && <span className="nav-count">4</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="plan-card">
            <div className="plan-card-top">
              <span>Free plan</span>
              <strong>1 / 1 site</strong>
            </div>
            <div className="plan-track"><span /></div>
            <button>View plans</button>
          </div>

          <button className="account-row">
            <span className="account-avatar">DG</span>
            <span>
              <strong>Your account</strong>
              <small>Settings & billing</small>
            </span>
            <span className="account-menu">•••</span>
          </button>
        </div>
      </aside>

      <section className="content-area">
        <header className="topbar">
          <div>
            <span className="eyebrow">SECURITY OVERVIEW</span>
            <h1>{activeNav}</h1>
          </div>
          <div className="topbar-actions">
            <button className="icon-button" aria-label="Notifications">○</button>
            <button className="primary-button" onClick={() => setScanOpen(true)}>
              <span className="button-plus">＋</span>
              Run security scan
            </button>
          </div>
        </header>

        <div className="dashboard-grid">
          <section className="posture-card panel">
            <div className="panel-heading">
              <div>
                <span className="section-kicker">OVERALL POSTURE</span>
                <h2>Your website is looking good.</h2>
                <p>There are a few things worth fixing, including one issue that needs urgent attention.</p>
              </div>
              <button className="subtle-button">View full report <Chevron /></button>
            </div>

            <div className="posture-content">
              <div className="score-ring" aria-label="Security score 82 out of 100">
                <div className="score-ring-inner">
                  <strong>82</strong>
                  <span>/ 100</span>
                </div>
              </div>
              <div className="score-copy">
                <div className="status-chip"><span /> GOOD</div>
                <h3>Strong foundation</h3>
                <p>Your current setup is stronger than most first scans. Fixing the urgent finding could improve your score further.</p>
                <div className="score-meta">
                  <span>Last scanned <strong>12 mins ago</strong></span>
                  <span>•</span>
                  <span>1 verified website</span>
                </div>
              </div>
            </div>
          </section>

          <section className="risk-card panel">
            <span className="section-kicker">OPEN FINDINGS</span>
            <div className="risk-total-row">
              <div>
                <strong className="risk-total">4</strong>
                <span>things to review</span>
              </div>
              <div className="mini-pulse">↗</div>
            </div>
            <div className="severity-stack">
              <div className="severity-row"><span className="severity-dot critical" /><span>Critical</span><strong>1</strong></div>
              <div className="severity-row"><span className="severity-dot high" /><span>High</span><strong>1</strong></div>
              <div className="severity-row"><span className="severity-dot medium" /><span>Medium</span><strong>1</strong></div>
              <div className="severity-row"><span className="severity-dot low" /><span>Low</span><strong>1</strong></div>
            </div>
          </section>

          <section className="asset-panel panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">YOUR WEBSITE</span>
                <h2>Protected assets</h2>
              </div>
              <button className="text-button">Manage assets <Chevron /></button>
            </div>

            <div className="asset-row">
              <div className="asset-icon">e</div>
              <div className="asset-main">
                <div className="asset-name-line">
                  <strong>example.com</strong>
                  <span className="verified-chip">✓ Verified</span>
                </div>
                <span>HTTPS • Website • Continuous monitoring</span>
              </div>
              <div className="asset-score">
                <span>Security score</span>
                <strong>82</strong>
              </div>
              <div className="asset-state"><span /> Monitoring</div>
              <button className="more-button">•••</button>
            </div>
          </section>

          <section className="findings-panel panel">
            <div className="panel-title-row findings-heading">
              <div>
                <span className="section-kicker">WHAT NEEDS YOUR ATTENTION</span>
                <h2>Latest findings</h2>
              </div>
              <div className="filters">
                {["All", "Critical", "High", "Medium", "Low"].map((filter) => (
                  <button
                    key={filter}
                    className={severityFilter === filter ? "selected" : ""}
                    onClick={() => setSeverityFilter(filter)}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            <div className="finding-list">
              {filteredFindings.map((finding) => (
                <button className="finding-row" key={finding.title}>
                  <div className={`finding-severity severity-${finding.severity.toLowerCase()}`}>
                    <span>{finding.severity === "Critical" ? "!" : finding.severity.charAt(0)}</span>
                  </div>
                  <div className="finding-copy">
                    <div className="finding-title-line">
                      <span className={`severity-label severity-label-${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                      <strong>{finding.title}</strong>
                    </div>
                    <p>{finding.description}</p>
                    <span className="finding-asset">{finding.asset} • {finding.status}</span>
                  </div>
                  <Chevron />
                </button>
              ))}
            </div>
          </section>

          <section className="activity-panel panel">
            <div className="panel-title-row">
              <div>
                <span className="section-kicker">SCAN HISTORY</span>
                <h2>Security trend</h2>
              </div>
              <span className="trend-chip">+8 pts this month</span>
            </div>
            <div className="chart-wrap">
              <div className="chart-ylabels"><span>100</span><span>75</span><span>50</span><span>25</span></div>
              <div className="chart">
                <div className="grid-line line-1" /><div className="grid-line line-2" /><div className="grid-line line-3" />
                <div className="chart-fill" />
                <svg className="chart-line" viewBox="0 0 600 140" preserveAspectRatio="none" aria-label="Security score trend">
                  <path d="M0,102 C75,101 85,90 145,92 C205,94 232,67 290,70 C350,72 390,50 440,56 C500,63 520,36 600,30" fill="none" stroke="currentColor" strokeWidth="3" vectorEffect="non-scaling-stroke" />
                </svg>
                <span className="chart-point" />
              </div>
            </div>
            <div className="chart-labels"><span>Aug 19</span><span>Aug 26</span><span>Sep 02</span><span>Sep 09</span><span>Today</span></div>
          </section>

          <section className="recent-panel panel">
            <span className="section-kicker">RECENT ACTIVITY</span>
            <h2>Latest scan</h2>
            <div className="scan-status-line">
              <div className="scan-status-icon">✓</div>
              <div>
                <strong>Scan completed</strong>
                <span>example.com</span>
              </div>
              <span className="scan-time">12m ago</span>
            </div>
            <div className="scan-stats">
              <div><span>Pages checked</span><strong>148</strong></div>
              <div><span>Checks run</span><strong>326</strong></div>
              <div><span>Duration</span><strong>4m 18s</strong></div>
            </div>
            <button className="secondary-button">Open scan results <Chevron /></button>
          </section>
        </div>
      </section>

      {scanOpen && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setScanOpen(false)}>
          <section className="scan-modal" role="dialog" aria-modal="true" aria-labelledby="scan-title" onMouseDown={(event) => event.stopPropagation()}>
            <button className="modal-close" onClick={() => setScanOpen(false)} aria-label="Close">×</button>
            <div className="modal-icon"><BrandMark /></div>
            <span className="section-kicker">NEW SECURITY SCAN</span>
            <h2 id="scan-title">Check your website</h2>
            <p>SCOPEX will inspect your verified website and turn technical security signals into clear, prioritised actions.</p>

            <label htmlFor="target">Website</label>
            <div className="target-field">
              <span>◉</span>
              <input id="target" value={scanTarget} onChange={(event) => setScanTarget(event.target.value)} />
              <span className="field-verified">✓ Verified</span>
            </div>

            <div className="scan-type-grid">
              <button className="scan-type selected">
                <span className="scan-type-icon">⌁</span>
                <strong>Standard check</strong>
                <small>Recommended • Safe website assessment</small>
                <span className="radio-dot" />
              </button>
              <button className="scan-type disabled" title="Coming later">
                <span className="scan-type-icon">◎</span>
                <strong>Deep assessment</strong>
                <small>Coming soon</small>
              </button>
            </div>

            <div className="safety-note">
              <span>✓</span>
              <p><strong>Authorised target only.</strong> Scans should only run against websites you own or have explicit permission to assess.</p>
            </div>

            <button className="primary-button modal-primary" onClick={() => setScanOpen(false)}>
              Start security scan <span>→</span>
            </button>
            <small className="modal-footnote">Frontend demo only — scanning is not connected yet.</small>
          </section>
        </div>
      )}
    </main>
  );
}
