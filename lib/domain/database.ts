import type * as D from './index';
type Table<Row, Insert = Partial<Row>> = { Row: { [K in keyof Row]: Row[K] }; Insert: { [K in keyof Insert]: Insert[K] }; Update: Partial<Row>; Relationships: [] };
type OperatorScanStatus = {
 scan_id: string;
 hostname: string;
 status: string;
 created_at: string;
 started_at: string | null;
 completed_at: string | null;
 failure_code: string | null;
};
type NativeScanLease = {
 scan_id: string;
 hostname: string;
 origin: string;
 max_requests: number;
 requests_per_second: number;
 timeout_seconds: number;
};
type ScanObservationRow = {
 id: string;
 organization_id: string;
 scan_id: string;
 asset_id: string;
 observation_key: string;
 kind: 'http' | 'tls' | 'header' | 'redirect' | 'network';
 status: 'pass' | 'warn' | 'info' | 'error';
 summary: string;
 observed_url: string | null;
 data: D.Json;
 observed_at: string;
};
/** Schema contract maintained alongside migrations; replace with CLI generated types when linked. */
export type Database = { public: {
 Tables: {
 organizations: Table<D.Organization, Pick<D.Organization, 'owner_id' | 'name'>>;
 organization_members: Table<D.OrganizationMember>;
 projects: Table<D.Project, Pick<D.Project, 'organization_id' | 'name'>>;
 assets: Table<D.Asset, Pick<D.Asset, 'organization_id' | 'project_id' | 'hostname' | 'origin'>>;
 asset_verifications: Table<D.AssetVerification>;
 scopes: Table<D.Scope>; scan_policies: Table<D.ScanPolicy>; scans: Table<D.Scan>;
 scan_jobs: Table<D.ScanJob>; scan_events: Table<D.ScanEvent>; scan_observations: Table<ScanObservationRow>;
 findings: Table<D.Finding>; finding_instances: Table<D.FindingInstance>; evidence: Table<D.Evidence>;
 retests: Table<D.Retest>; audit_logs: Table<D.AuditLog>;
 };
 Views: Record<string, never>;
 Functions: {
  can_read_workspace: { Args: { workspace: string }; Returns: boolean };
  can_manage_workspace: { Args: { workspace: string }; Returns: boolean };
  request_operator_scan: { Args: { p_hostname: string; p_token: string }; Returns: string };
  get_operator_scan_status: { Args: { p_scan_id: string; p_token: string }; Returns: OperatorScanStatus[] };
  lease_next_operator_scan: { Args: { p_token: string; p_worker_id: string }; Returns: NativeScanLease[] };
  complete_operator_scan_native: { Args: { p_scan_id: string; p_token: string; p_observations: D.Json; p_pages_checked?: number }; Returns: boolean };
  fail_operator_scan_native: { Args: { p_scan_id: string; p_token: string; p_failure_code: string }; Returns: boolean };
 };
 Enums: Record<string, never>; CompositeTypes: Record<string, never>;
} };
