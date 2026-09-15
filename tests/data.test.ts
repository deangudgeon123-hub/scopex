import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DemoDashboardRepository } from '../lib/data/demo';
import { projectDashboard } from '../lib/data/projection';
import type { Asset } from '../lib/domain';
test('demo fixture is labelled and isolated between requests', async () => {
 const repository = new DemoDashboardRepository();
 const first = await repository.getDashboard();
 assert.deepEqual(first.score, { kind: 'demo', value: 82 });
 assert.equal(first.mode, 'demo');
 first.findings.pop();
 assert.equal((await repository.getDashboard()).findings.length, 4);
});
test('empty real dashboard never invents a score, scan or positive assessment', () => {
 const data = projectDashboard(null, null, [], [], []);
 assert.deepEqual(data.score, { kind: 'unavailable', value: null });
 assert.equal(data.mode, 'supabase');
 assert.equal(data.trend, null);
 assert.equal(data.latestScan, null);
 assert.equal(data.verifiedCount, 0);
});
test('expired verification cannot appear verified in the dashboard', () => {
 const asset: Asset = { id:'a', organization_id:'o', project_id:'p', created_at:'2026-01-01', hostname:'example.com', origin:'https://example.com', verification_status:'verified', verified_at:'2026-01-01', verification_expires_at:'2026-01-02' };
 const expired = projectDashboard(null, null, [asset], [], [], Date.parse('2026-01-03'));
 assert.equal(expired.assets[0].verified, false);
 assert.equal(expired.verifiedCount, 0);
 assert.equal(projectDashboard(null, null, [asset], [], [], Date.parse('2026-01-01T12:00Z')).verifiedCount, 1);
});
