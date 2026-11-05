Hands-Off --- Startup & Product Brief
Status: Early-stage concept / validation-to-prototype
Working product name: Hands-Off (name not finalized)
Audience: Solo developers and indie hackers building applications
with AI coding tools.
1. The problem
People building with AI coding tools can ship quickly, but may not fully
understand the code changes, security posture, or whether important user
workflows still work. They need a practical way to identify
launch-blocking risks before making an app public.

Our founder has experienced the difficulty of understanding AI-generated
changes and knowing whether an app is safe and reliable enough to
launch.
2. Product vision
Hands-Off is intended to become an automated launch-readiness system for
AI-built applications.

A developer provides a project for assessment. Hands-Off runs a set of
automated checks, explains meaningful findings in plain language,
prioritizes risks, and produces an actionable report.

Core promise: Help indie developers find important security,
reliability, and workflow problems before launch.

This is an intended product direction, not a claim that the system
already detects every vulnerability or can certify an application as
safe.
3. Initial target users
- Solo developers and indie hackers.
- First-time founders shipping an MVP.
- Developers using Cursor, Claude Code, Lovable, Bolt, and similar
  AI-assisted tools.
- Small teams without dedicated security or QA engineers.
4. Initial product direction
Start narrow. The first prototype should accept a GitHub repository
(preferably a repository the user owns or is authorized to test),
inspect its structure, identify its stack, and run a small, transparent
set of checks.

Potential first checks: 1. Exposed secrets and suspicious credential
patterns. 2. Risky configuration and common security misconfigurations.
3. Dependency and known-vulnerability checks using established tools. 4.
Basic build/test execution where safe and practical. 5. A clear report
with evidence, severity, confidence, and suggested remediation.

Later possibilities: - Browser-based workflow tests using Playwright. -
API endpoint and authorization testing. - Deployed-site assessments. -
Tracking risky changes between commits. - Re-testing after fixes.

These are roadmap ideas, not MVP commitments.
5. Differentiation hypothesis
Do not position Hands-Off as merely another generic vulnerability
scanner.

The hypothesis to validate is that AI-built-app creators need a
beginner-friendly, integrated launch-readiness workflow that combines
security, QA, understandable explanations, and prioritized next steps.

We must validate whether customers will use and pay for this before
building a large platform.
6. Existing tools to evaluate
Use established tools where appropriate instead of reimplementing
scanners: - OWASP ZAP: web application security testing. - Playwright:
browser automation and end-to-end testing. - GitHub repository and
workflow features: source access and CI integration. -
Dependency/security audit tools appropriate to the detected ecosystem.

Evaluate each tool's license, maintenance status, safety model, and fit
before integrating it. Do not assume a tool covers every risk.
7. Product principles
- Safe by default: never run untrusted repository code on the
  developer's machine or on an unrestricted host.
- Explicit authorization: only assess repositories and deployed
  targets the user owns or has permission to test.
- Least privilege: request the minimum access required; prefer
  read-only repository access initially.
- No false guarantees: a clean scan does not prove an app is secure or
  bug-free.
- Explain findings: include evidence, affected file/route, impact,
  confidence, and practical remediation.
- Protect customer data: avoid storing source code or secrets longer
  than necessary; never expose secrets in reports or logs.
- Be transparent about limitations and skipped checks.
8. Founder constraints and working style
- Founder is working on Windows with VS Code.
- Beginner-friendly, precise instructions are important.
- Explain exactly which file to create or replace and where.
- Prefer complete files over scattered snippets when making code
  changes.
- Build incrementally and verify each step before moving on.
- Do not introduce paid infrastructure or services without discussing
  cost first. The initial budget is extremely limited.
- Do not rush into implementation before the architecture and MVP
  scope are clear.
9. Current development status
At handoff: - No repository has been created for this project yet. -
Development environment: Windows + VS Code. - GitHub Copilot is intended
to assist with implementation. - The product is still a
concept/prototype; no functioning Hands-Off API should be assumed to
exist.
10. Immediate next milestone
Before writing application code: 1. Confirm the smallest useful MVP. 2.
Choose a simple architecture and language/framework based on the
founder's environment and ability to maintain it. 3. Define a safe
repository-ingestion approach. 4. Write an API contract for the first
scan workflow. 5. Create a minimal project skeleton. 6. Implement one
safe check end-to-end and test it with a deliberately harmless sample
repository.
11. Instructions for an AI coding assistant
Act as a careful senior engineer and technical partner.
- First inspect the existing folder and files. Do not overwrite or
  delete anything without explaining why and obtaining confirmation.
- Read this brief and HANDSOFF_API_REFERENCE.md before proposing
  implementation.
- Do not assume decisions that are marked as hypotheses or future
  possibilities are finalized.
- Before coding, summarize the proposed MVP, architecture, security
  boundaries, and files to be created.
- Work in small steps. Ask for approval before major architectural
  choices or destructive changes.
- Give exact Windows/VS Code instructions.
- Prefer secure, maintainable, understandable code over clever
  shortcuts.
- Add tests for every meaningful behavior.
- Never execute untrusted repository code with host privileges. Use
  isolation, strict resource limits, and timeouts if execution is
  necessary.
- Never print, persist, or return discovered secrets.
- Do not claim a scan guarantees security.