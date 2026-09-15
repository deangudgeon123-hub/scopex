import type * as D from './index';
type Table<Row, Insert = Partial<Row>> = { Row: { [K in keyof Row]: Row[K] }; Insert: { [K in keyof Insert]: Insert[K] }; Update: Partial<Row>; Relationships: [] };
/** Schema contract maintained alongside migrations; replace with CLI generated types when linked. */
export type Database = { public: {
 Tables: {
 organizations: Table<D.Organization, Pick<D.Organization, 'owner_id' | 'name'>>;
 organization_members: Table<D.OrganizationMember>;
 projects: Table<D.Project, Pick<D.Project, 'organization_id' | 'name'>>;
 assets: Table<D.Asset, Pick<D.Asset, 'organization_id' | 'project_id' | 'hostname' | 'origin'>>;
 asset_verifications: Table<D.AssetVerification>;
 scopes: Table<D.Scope>; scan_policies: Table<D.ScanPolicy>; scans: Table<D.Scan>;
 scan_jobs: Table<D.ScanJob>; scan_events: Table<D.ScanEvent>; findings: Table<D.Finding>;
 finding_instances: Table<D.FindingInstance>; evidence: Table<D.Evidence>; retests: Table<D.Retest>; audit_logs: Table<D.AuditLog>;
 };
 Views: Record<string, never>;
 Functions: { can_read_workspace: { Args: { workspace: string }; Returns: boolean }; can_manage_workspace: { Args: { workspace: string }; Returns: boolean } };
 Enums: Record<string, never>; CompositeTypes: Record<string, never>;
} };
