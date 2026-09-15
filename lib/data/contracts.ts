export type DisplaySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export interface DashboardFinding { id: string; severity: DisplaySeverity; title: string; description: string; asset: string; status: string }
export interface DashboardAsset { id: string; hostname: string; origin: string; verified: boolean; detail: string; state: string }
export interface DashboardData {
 mode: 'demo' | 'supabase'; workspaceName: string; projectName: string | null;
 findings: DashboardFinding[]; assets: DashboardAsset[];
 score: { kind: 'demo'; value: number } | { kind: 'unavailable'; value: null };
 posture: { title: string; description: string; label: string; heading: string; detail: string };
 lastScanned: string; verifiedCount: number;
 latestScan: { status: string; asset: string; time: string; pages: string; checks: string; duration: string } | null;
 trend: { change: string; labels: string[]; path: string } | null;
}
export interface DashboardRepository { getDashboard(projectId?: string): Promise<DashboardData> }
