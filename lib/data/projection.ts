import type { Asset, Finding, Organization, Project, Scan, Severity } from '@/lib/domain';
import type { DashboardData, DisplaySeverity } from './contracts';
const severityNames: Record<Severity, DisplaySeverity> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational' };
export function projectDashboard(workspace: Organization | null, project: Project | null, assets: Asset[], findings: Finding[], scans: Scan[], now = Date.now()): DashboardData {
 const assetMap = new Map(assets.map(a => [a.id, a]));
 const verified = (a: Asset) => a.verification_status === 'verified' && a.verification_expires_at !== null && Date.parse(a.verification_expires_at) > now;
 const scan = scans[0];
 const date = (value: string) => new Date(value).toLocaleString('en-GB', { timeZone: 'UTC' }) + ' UTC';
 return {
  mode: 'supabase', workspaceName: workspace?.name ?? 'Your workspace', projectName: project?.name ?? null,
  score: { kind: 'unavailable', value: null },
  findings: findings.map(f => ({ id: f.id, severity: severityNames[f.severity], title: f.title, description: f.explanation, asset: assetMap.get(f.asset_id)?.hostname ?? 'Unavailable asset', status: f.state === 'open' ? 'Open' : f.state })),
  assets: assets.map(a => ({ id: a.id, hostname: a.hostname, origin: a.origin, verified: verified(a), detail: `${a.origin.startsWith('https:') ? 'HTTPS' : 'HTTP'} • Website`, state: 'Scanning not enabled' })),
  verifiedCount: assets.filter(verified).length,
  posture: { title: 'Your security overview.', description: project ? 'Review your website records and available findings.' : 'Your workspace is ready for its first project.', label: 'NOT SCORED', heading: 'Assessment pending', detail: 'A real security score is not available yet. No rating is inferred from missing results.' },
  lastScanned: scan?.completed_at ? date(scan.completed_at) : 'Not yet',
  latestScan: scan ? { status: `Scan ${scan.status}`, asset: assetMap.get(scan.asset_id)?.hostname ?? 'Unavailable asset', time: date(scan.created_at), pages: scan.pages_checked?.toString() ?? '—', checks: scan.checks_run?.toString() ?? '—', duration: scan.started_at && scan.completed_at ? `${Math.max(0, Math.round((Date.parse(scan.completed_at) - Date.parse(scan.started_at)) / 1000))}s` : '—' } : null,
  trend: null,
 };
}
