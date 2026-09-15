# SCOPEX

Website security made understandable for business owners.

## Run

```sh
npm install
npm run dev
```

The existing dark dashboard runs in **demo mode** without credentials. All displayed demo findings, scores and verification badges are sample data. Live scanning is disabled.

## App foundation

- Supabase migrations for workspaces, projects, assets, verification, scopes/policies, scans/jobs/events, canonical findings, scanner instances, evidence, retests and audit logs.
- Workspace RLS, constrained client writes and composite tenant foreign keys.
- Shared TypeScript domain contracts and separate demo/Supabase data providers.
- Cookie-based Supabase clients, server-only services and a read-only dashboard API.
- Loading, empty and error states; no real security scoring yet.

See [foundation setup and architecture](docs/foundation.md) for database activation, the permissions model, current limitations and remaining integrations. Sign-in/onboarding and ownership verification execution are future work.

```sh
npm test
npm run build
```
