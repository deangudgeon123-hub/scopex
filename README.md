# SCOPEX

SCOPEX is a website-security product concept focused on making security findings understandable to non-security users.

## Current state

This branch contains the **frontend/UX shell only**. Scanner integrations, authentication, persistence, verification, billing and backend jobs are intentionally not implemented yet.

### Included

- Responsive Next.js dashboard shell
- Security posture score UI
- Plain-English findings view
- Severity filters
- Protected website / asset card
- Scan history and recent activity panels
- Interactive "Run security scan" modal
- Authorised-target UX messaging
- Mock/demo data that can be replaced with API data later

## Run locally

```bash
npm install
npm run dev
```

Then open `http://localhost:3000`.

## Backend handoff

The primary integration points are in `app/page.tsx`:

- Replace the `findings` mock array with persisted findings/API data.
- Replace the posture score and counters with calculated backend values.
- Wire `Run security scan` to verified assets and a scan-job API.
- Replace the example asset with real user assets.
- Connect scan history/activity to persisted scan runs.
- Add authentication and workspace/account state.

The current UI deliberately does **not** execute security tests.
