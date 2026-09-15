import type { DashboardData, DashboardFinding, DashboardRepository } from './contracts';
const findings: Omit<DashboardFinding, "id">[] = [
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

export const demoDashboard: DashboardData = {
 mode: 'demo', workspaceName: 'Scopex workspace', projectName: 'Example website',
 findings: findings.map((finding, i) => ({ ...finding, id: `demo-${i}` })),
 assets: [{ id: 'demo-asset', hostname: 'example.com', origin: 'https://example.com', verified: true, detail: 'HTTPS • Website • Continuous monitoring', state: 'Monitoring' }],
 score: { kind: 'demo', value: 82 },
 posture: { title: 'Your website is looking good.', description: 'There are a few things worth fixing, including one issue that needs urgent attention.', label: 'GOOD', heading: 'Strong foundation', detail: 'Your current setup is stronger than most first scans. Fixing the urgent finding could improve your score further.' },
 lastScanned: '12 mins ago', verifiedCount: 1,
 latestScan: { status: 'Scan completed', asset: 'example.com', time: '12m ago', pages: '148', checks: '326', duration: '4m 18s' },
 trend: { change: '+8 pts this month', labels: ['Aug 19','Aug 26','Sep 02','Sep 09','Today'], path: 'M0,102 C75,101 85,90 145,92 C205,94 232,67 290,70 C350,72 390,50 440,56 C500,63 520,36 600,30' },
};
export class DemoDashboardRepository implements DashboardRepository {
 async getDashboard(): Promise<DashboardData> { return structuredClone(demoDashboard); }
}
