# PROJECT CONTEXT

## What this project is
Hands-Off is a beginner-friendly launch-readiness API for AI-built applications.
It scans GitHub repositories (or local sample repositories) for exposed secrets
and dependency issues, then returns a prioritised findings report.

## Tech and tools
- Languages/framework: Node.js and Express
- Where it runs: Local Node.js server (or any Node-capable host)
- AI tools I'm using: GitHub Copilot in VS Code

## How the files are organized
- server.js: Starts the Express server. Validates required env vars in production.
- src/app.js: Defines the API routes, authentication, rate limiting, and scan coordination.
- src/scanner.js: Non-executing secret-pattern and dependency-manifest checks. 1 MB file cap, 30 s timeout.
- src/scan-store.js: Persists scan records in a SQLite database via node:sqlite.
- src/auth.js: Issues and verifies HMAC-SHA256 signed bearer tokens.
- src/rate-limit.js: In-memory per-IP rate limiter middleware.
- src/github-app.js: GitHub App JWT signing, installation token exchange, and safe tarball download/extraction.
- src/github-source.js: Validates GitHub repository and ref inputs.
- sample-repositories/harmless: Safe sample repository used in tests.
- sample-repositories/missing-lockfile: Sample with no lockfile, used in tests.
- test/app.test.js: Full integration test suite (13 tests).
- .env.example: Template for all required and optional environment variables.

## What works right now
- `GET /api/v1/health`
- `POST /api/v1/auth/token` — issues signed bearer tokens
- `POST /api/v1/scans` — local sample repos and GitHub repos (via GitHub App)
- `GET /api/v1/scans/:scanId` — scan status
- `GET /api/v1/scans/:scanId/report` — sanitised findings report with limitations
- Secret-pattern detection (AWS keys, generic API key assignments)
- Dependency lockfile check
- Files > 1 MB are skipped and listed in report limitations
- Scan timeout: 30 seconds
- Per-user scan cap: 100 scans
- In-memory per-IP rate limiter: 60 requests per minute
- Scan ownership enforced; scans are not cross-user accessible
- SQLite persistence via node:sqlite (no race conditions on save)
- GitHub App: RS256 JWT signing, installation token exchange, tarball download with size limits (50 MB total, 5 MB per file), symlink blocking, path traversal protection
- Fail-fast startup check for required secrets when NODE_ENV=production

## What is not yet implemented
- Real user accounts / login UI — token issuance still uses an API key
- GitHub webhook support for automatic re-scans on push
- Scan deletion endpoint
- Deployed HTTPS — use a reverse proxy (Caddy, nginx) or a platform that provides TLS

## Rules for the AI
- Give me the complete replacement file, not snippets.
- Tell me exactly which file to edit.
- Don't change files I didn't mention.
- Explain each step briefly.

## Last session summary
- What we changed: Upgraded prototype to launch-ready state:
  - Wired rate limiter into app.js
  - Added per-user scan cap (100 scans)
  - Replaced JSON file store with SQLite (node:sqlite)
  - Added file size cap (1 MB) and scan timeout (30 s) in scanner
  - Implemented full GitHub App integration (JWT, token exchange, safe tarball extraction)
  - Added fail-fast env var check in server.js for production
  - Added .env.example
  - Updated tests to 13, all passing
- What we were about to do next: Set up a production deployment (reverse proxy for HTTPS, choose a hosting platform).
