Hands-Off API --- Initial Reference (Proposed Contract)
Document status: Draft for discussion
Important: This is a proposed starting contract, not an existing
deployed API or finalized specification. Confirm the MVP and
architecture before implementing it.
1. Purpose
The Hands-Off API will eventually accept an authorized
application/repository assessment request, coordinate selected checks,
and return a report containing prioritized findings.

The API should not claim that an application is completely secure or
bug-free.
2. Proposed first workflow
1. Client submits a scan request for an authorized GitHub repository.
2. API validates the request and authorization.
3. API creates a scan job and returns a job identifier.
4. A worker retrieves the permitted repository snapshot safely.
5. The worker performs only the checks enabled for the MVP.
6. API stores scan status and sanitized results.
7. Client fetches the report.
For an early local prototype, this can be implemented synchronously or
with a simple background worker. Do not introduce a complex queue or
paid infrastructure until justified.
3. Proposed endpoints
Base path: /api/v1
GET /health
Purpose: basic service health check.

Example response:
{
  "status": "ok"
}
This endpoint must not reveal environment variables, secrets, internal
paths, or infrastructure details.
POST /scans
Purpose: request a scan of a repository the caller owns or is authorized
to assess.

Illustrative request:
{
  "source": {
    "type": "github",
    "repository": "owner/repository",
    "ref": "main"
  },
  "checks": [
    "secret_patterns",
    "dependency_audit",
    "configuration_review"
  ]
}
Notes: - The repository identifier and ref must be validated. -
Authentication and repository authorization are required before
accessing private repositories. - Do not accept arbitrary clone URLs in
the initial MVP. - Do not accept arbitrary shell commands, scripts, or
user-supplied scanner arguments. - Check names must be selected from a
server-side allowlist.

Illustrative response:
{
  "scan_id": "scan_example_id",
  "status": "queued",
  "created_at": "2026-01-01T12:00:00Z"
}
Use a real generated identifier and timestamp in implementation; the
values above are examples only.
GET /scans/{scan_id}
Purpose: retrieve scan status.

Illustrative response:
{
  "scan_id": "scan_example_id",
  "status": "running",
  "progress": {
    "completed_checks": 1,
    "total_checks": 3
  }
}
Allowed statuses should be defined consistently, for example: -
queued - running - completed - failed - cancelled

Progress is optional. Do not expose internal worker details.
GET /scans/{scan_id}/report
Purpose: retrieve a completed scan report.

Illustrative response:
{
  "scan_id": "scan_example_id",
  "status": "completed",
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1,
    "info": 3
  },
  "findings": [
    {
      "id": "finding_example_id",
      "check": "configuration_review",
      "severity": "high",
      "title": "Example configuration issue",
      "description": "A concise explanation of the observed issue.",
      "location": {
        "file": "path/to/file",
        "line": 12
      },
      "evidence": "Redacted, minimal evidence supporting the finding.",
      "confidence": "medium",
      "recommendation": "A practical remediation suggestion."
    }
  ],
  "limitations": [
    "Only the checks listed in this report were performed."
  ]
}
Never include secret values in evidence, logs, or API responses.
Redact sensitive material.
4. Finding model
Each finding should contain: - Stable finding ID. - Check name. -
Severity: critical, high, medium, low, or info. -
Human-readable title and explanation. - Location when available (file,
line, URL, or endpoint). - Minimal sanitized evidence. - Confidence
level. - Recommended next step.

Severity and confidence are different: severity describes potential
impact; confidence describes how certain the scanner is that the finding
is real.
5. Error response shape
Use a consistent error format:
{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "The scan request is invalid."
  }
}
Do not return stack traces, tokens, secrets, private file paths, or raw
internal exceptions to clients.

Potential error codes: - INVALID_REQUEST - UNAUTHORIZED -
FORBIDDEN - NOT_FOUND - RATE_LIMITED - SCAN_FAILED -
INTERNAL_ERROR
6. Security requirements
These are design requirements, not optional polish.
Repository access
- Require authentication for scan creation and report access.
- Verify the caller is authorized to scan the repository.
- Prefer short-lived, narrowly scoped, read-only credentials.
- Never ask users to paste personal access tokens into source code or
  logs.
- Do not expose credentials to scanner subprocesses unless strictly
  required.
Untrusted source code
- Treat every repository as hostile input.
- Do not execute repository scripts, package lifecycle hooks, build
  steps, or tests by default.
- If execution becomes necessary, use a disposable isolated
  environment with no host filesystem access, no privileged mode,
  restricted network egress, CPU/memory/process limits, and hard
  timeouts.
- Never mount Docker sockets or sensitive host directories into a scan
  environment.
- Validate archive paths and defend against path traversal, symlinks,
  oversized archives, and decompression bombs.
API and data protection
- Enforce ownership checks on every scan and report request.
- Add request size limits, rate limits, timeouts, and concurrency
  limits.
- Store only the minimum source material needed and define
  deletion/retention behavior.
- Redact secrets from findings and logs.
- Use HTTPS in deployed environments.
- Keep credentials in a secrets manager or protected environment
  configuration, never in Git.
7. Initial MVP scope recommendation
A sensible first prototype could include: 1. GET /health 2.
POST /scans for a local sample repository or a tightly controlled
GitHub integration. 3. GET /scans/{scan_id} 4.
GET /scans/{scan_id}/report 5. One or two non-executing checks, such
as secret-pattern detection and dependency manifest review.

Do not start with arbitrary website scanning, active penetration
testing, automatic code fixes, or broad AI-agent execution. Those add
significant safety and reliability complexity.
8. Not yet decided
Do not silently choose these without discussing them: - Backend
language/framework. - Database. - GitHub App versus another repository
authorization method. - Synchronous versus background job processing. -
Which scanner tools and licenses are suitable. - Whether the first
deliverable is a local prototype or hosted service. - Pricing, tiers,
and retention policy.
9. Definition of a successful first technical milestone
Given a harmless test repository: - The API accepts a valid scan
request. - It rejects malformed or unauthorized requests. - It runs the
explicitly enabled safe checks without executing repository code. - It
returns a scan ID and status. - It produces a structured report with
reproducible findings. - Tests verify error handling, authorization
boundaries, redaction, and path/archive safety.