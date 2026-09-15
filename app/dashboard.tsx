"use client";

import { useMemo, useState } from "react";

import type { DashboardData } from "@/lib/data/contracts";

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

export default function Dashboard({ data }: { data: DashboardData }) {
  const { findings } = data;
  const [activeNav, setActiveNav] = useState("Overview");
  const [scanOpen, setScanOpen] = useState(false);
  const [scanTarget, setScanTarget] = useState(data.assets[0]?.origin ?? "");
  const [severityFilter, setSeverityFilter] = useState<string>("All");

  const filteredFindings = useMemo(() => {
    if (severityFilter === "All") return findings;
    return findings.filter((finding) => finding.severity === severityFilter);
  }, [severityFilter, findings]);

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
            <strong>{data.workspaceName}</strong>
            <span>Security overview</span>
          </div>
          <span className="workspace-caret">⌄</span>
        </div>

        <nav className="nav-list" aria-label="Primary navigation">
          {navItems.map((item) => (
            <button
              className={`nav-item ${activeNav === item ? "active" : ""}`}
              key={item}
              aria-current={activeNav === item ? "page" : undefined}
              onClick={() => setActiveNav(item)}
            >
              <AppIcon label={item} />
              <span>{item}</span>
              {item === "Findings" && <span className="nav-count">{findings.length}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="plan-card">
            <div className="plan-card-top">
              <span>{data.mode === "demo" ? "Free plan" : "Workspace"}</span>
              <strong>{data.mode === "demo" ? "1 / 1 site" : `${data.assets.length} websites`}</strong>
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
            {data.mode === "demo" && <span className="demo-label">DEMO — sample data, not a security assessment</span>}
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
                <h2>{data.posture.title}</h2>
                <p>{data.posture.description}</p>
              </div>
              <button className="subtle-button">View full report <Chevron /></button>
            </div>

            <div className="posture-content">
              <div className={`score-ring ${data.score.kind === "unavailable" ? "unscored" : ""}`} aria-label={data.score.kind === "demo" ? `Demo security score ${data.score.value} out of 100` : "Security score unavailable"}>
                <div className="score-ring-inner">
                  <strong>{data.score.value ?? "—"}</strong>
                  <span>{data.score.kind === "demo" ? "/ 100 · DEMO" : "Not scored"}</span>
                </div>
              </div>
              <div className="score-copy">
                <div className="status-chip"><span /> {data.posture.label}</div>
                <h3>{data.posture.heading}</h3>
                <p>{data.posture.detail}</p>
                <div className="score-meta">
                  <span>Last scanned <strong>{data.lastScanned}</strong></span>
                  <span>•</span>
                  <span>{data.verifiedCount} verified website{data.verifiedCount === 1 ? "" : "s"}</span>
                </div>
              </div>
            </div>
          </section>

          <section className="risk-card panel">
            <span className="section-kicker">OPEN FINDINGS</span>
            <div className="risk-total-row">
              <div>
                <strong className="risk-total">{findings.length}</strong>
                <span>things to review</span>
              </div>
              <div className="mini-pulse">↗</div>
            </div>
            <div className="severity-stack">
              {findings.some(f => f.severity === "Informational") && <div className="severity-row"><span className="severity-dot low" /><span>Informational</span><strong>{findings.filter(f => f.severity === "Informational").length}</strong></div>}
              <div className="severity-row"><span className="severity-dot critical" /><span>Critical</span><strong>{findings.filter(f => f.severity === "Critical").length}</strong></div>
              <div className="severity-row"><span className="severity-dot high" /><span>High</span><strong>{findings.filter(f => f.severity === "High").length}</strong></div>
              <div className="severity-row"><span className="severity-dot medium" /><span>Medium</span><strong>{findings.filter(f => f.severity === "Medium").length}</strong></div>
              <div className="severity-row"><span className="severity-dot low" /><span>Low</span><strong>{findings.filter(f => f.severity === "Low").length}</strong></div>
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

            {data.assets.length === 0 && <p className="empty-state">No websites added yet. Add a website record to your project to get started.</p>}
            {data.assets.map(asset => <div className="asset-row" key={asset.id}>
              <div className="asset-icon">{asset.hostname.charAt(0)}</div>
              <div className="asset-main">
                <div className="asset-name-line">
                  <strong>{asset.hostname}</strong>
                  <span className="verified-chip">{asset.verified ? "✓ Verified" : "Verification required"}</span>
                </div>
                <span>{asset.detail}</span>
              </div>
              <div className="asset-score">
                <span>Security score</span>
                <strong>{data.score.value ?? "—"}</strong>
              </div>
              <div className="asset-state"><span /> {asset.state}</div>
              <button className="more-button" aria-label={`Options for ${asset.hostname}`}>•••</button>
            </div>)}
          </section>

          <section className="findings-panel panel">
            <div className="panel-title-row findings-heading">
              <div>
                <span className="section-kicker">WHAT NEEDS YOUR ATTENTION</span>
                <h2>Latest findings</h2>
              </div>
              <div className="filters">
                {["All", "Critical", "High", "Medium", "Low", ...(findings.some(f => f.severity === "Informational") ? ["Informational"] : [])].map((filter) => (
                  <button
                    key={filter}
                    aria-pressed={severityFilter === filter}
                    className={severityFilter === filter ? "selected" : ""}
                    onClick={() => setSeverityFilter(filter)}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            <div className="finding-list">
              {filteredFindings.length === 0 && <p className="empty-state">{findings.length ? "No findings match this severity." : "No findings recorded yet. This does not mean your website has been assessed."}</p>}
              {filteredFindings.map((finding) => (
                <button className="finding-row" key={finding.id}>
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
              <span className="trend-chip">{data.trend?.change ?? "Not available"}</span>
            </div>
            {data.trend ? <><div className="chart-wrap">
              <div className="chart-ylabels"><span>100</span><span>75</span><span>50</span><span>25</span></div>
              <div className="chart">
                <div className="grid-line line-1" /><div className="grid-line line-2" /><div className="grid-line line-3" />
                <div className="chart-fill" />
                <svg className="chart-line" viewBox="0 0 600 140" preserveAspectRatio="none" aria-label="Security score trend">
                  <path d={data.trend.path} fill="none" stroke="currentColor" strokeWidth="3" vectorEffect="non-scaling-stroke" />
                </svg>
                <span className="chart-point" />
              </div>
            </div>
            <div className="chart-labels">{data.trend.labels.map(label => <span key={label}>{label}</span>)}</div></> : <p className="empty-state">Security trends will appear when evidence-backed scoring is available.</p>}
          </section>

          <section className="recent-panel panel">
            <span className="section-kicker">RECENT ACTIVITY</span>
            <h2>Latest scan</h2>
            {data.latestScan ? <><div className="scan-status-line">
              <div className="scan-status-icon">✓</div>
              <div>
                <strong>{data.latestScan.status}</strong>
                <span>{data.latestScan.asset}</span>
              </div>
              <span className="scan-time">{data.latestScan.time}</span>
            </div>
            <div className="scan-stats">
              <div><span>Pages checked</span><strong>{data.latestScan.pages}</strong></div>
              <div><span>Checks run</span><strong>{data.latestScan.checks}</strong></div>
              <div><span>Duration</span><strong>{data.latestScan.duration}</strong></div>
            </div>
            <button className="secondary-button">Open scan results <Chevron /></button></> : <p className="empty-state">No scans have run. Live scanning is not enabled.</p>}
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
              <span className="field-verified">{data.mode === "demo" ? "Demo target" : "Not checked"}</span>
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

            <button className="primary-button modal-primary" disabled aria-disabled="true">
              Start security scan <span>→</span>
            </button>
            <small className="modal-footnote">Scanning is not enabled — no security tests will be run.</small>
          </section>
        </div>
      )}
    </main>
  );
}
