/** Domain rows use database naming; UI projections live in lib/data/contracts.ts. */
export type UUID = string;
export type Timestamp = string;
export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Confidence = 'confirmed' | 'high' | 'possible' | 'informational';
export type FindingState = 'open' | 'fixed' | 'accepted' | 'false_positive';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export interface Organization { id: UUID; owner_id: UUID; name: string; created_at: Timestamp }
export interface OrganizationMember { organization_id: UUID; user_id: UUID; role: 'admin' | 'member' | 'viewer'; created_at: Timestamp }
export interface WorkspaceRow { id: UUID; organization_id: UUID; created_at: Timestamp }
export interface Project extends WorkspaceRow { name: string }
export interface Asset extends WorkspaceRow {
 project_id: UUID; hostname: string; origin: string;
 verification_status: 'pending' | 'verified' | 'expired' | 'revoked';
 verified_at: Timestamp | null; verification_expires_at: Timestamp | null;
}
export interface AssetVerification extends WorkspaceRow {
 asset_id: UUID; method: 'dns_txt'; challenge: string;
 status: 'pending' | 'verified' | 'expired' | 'failed'; expires_at: Timestamp;
 checked_at: Timestamp | null; verified_at: Timestamp | null;
}
export interface Scope extends WorkspaceRow { project_id: UUID; asset_id: UUID; allowed_paths: string[]; include_subdomains: false; authorized_by: UUID; expires_at: Timestamp }
export interface ScanPolicy extends WorkspaceRow { name: string; scan_type: 'configuration'; max_requests: number; requests_per_second: number; timeout_seconds: number; enabled: boolean }
export interface Scan extends WorkspaceRow {
 project_id: UUID; asset_id: UUID; scope_id: UUID; policy_id: UUID; requested_by: UUID;
 status: ScanStatus; started_at: Timestamp | null; completed_at: Timestamp | null;
 failure_code: string | null; pages_checked: number | null; checks_run: number | null;
}
export interface ScanJob extends WorkspaceRow { scan_id: UUID; status: 'queued' | 'leased' | 'completed' | 'failed' | 'cancelled'; attempts: number; available_at: Timestamp; lease_expires_at: Timestamp | null; worker_id: string | null }
export interface ScanEvent extends WorkspaceRow { scan_id: UUID; event_type: string; message: string }
export interface Finding extends WorkspaceRow {
 project_id: UUID; asset_id: UUID; fingerprint: string; title: string; severity: Severity; confidence: Confidence;
 category: string; affected_url: string | null; explanation: string; technical_explanation: string | null;
 remediation: string; cwe: string[] | null; cve: string[] | null; cvss: number | null;
 state: FindingState; first_seen: Timestamp; last_seen: Timestamp;
}
export interface FindingInstance extends WorkspaceRow { asset_id: UUID; finding_id: UUID; scan_id: UUID; source: string; source_rule_id: string }
export interface Evidence extends WorkspaceRow { finding_instance_id: UUID; kind: 'http_header' | 'tls' | 'redirect' | 'metadata' | 'note'; summary: string; redacted_data: Json; collected_at: Timestamp }
export interface Retest extends WorkspaceRow { asset_id: UUID; finding_id: UUID; scan_id: UUID | null; requested_by: UUID; status: 'requested' | 'running' | 'passed' | 'failed' | 'inconclusive' | 'cancelled'; completed_at: Timestamp | null }
export interface AuditLog extends WorkspaceRow { actor_id: UUID | null; action: string; entity_type: string; entity_id: UUID | null; metadata: Json }
