const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const tar = require('tar');
const test = require('node:test');
const app = require('../src/app');
const { downloadRepository, getGitHubAppConfig } = require('../src/github-app');
const { createScanStore } = require('../src/scan-store');
const { createRateLimiter } = require('../src/rate-limit');

let server;
let baseUrl;
let userAToken;
let userBToken;

test.before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  userAToken = await getToken('user-a');
  userBToken = await getToken('user-b');
});

test.after(() => server.close());

async function getToken(userId) {
  const response = await fetch(`${baseUrl}/api/v1/auth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key' },
    body: JSON.stringify({ user_id: userId })
  });
  return (await response.json()).access_token;
}

test('health endpoint is public', async () => {
  const response = await fetch(`${baseUrl}/api/v1/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok' });
});

test('accepts valid feedback without authentication', async () => {
  const response = await fetch(`${baseUrl}/api/v1/feedback`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: 'The scan was easy to understand.', rating: 5, category: 'Usability' })
  });
  assert.equal(response.status, 201);
  assert.equal((await response.json()).status, 'received');
});

test('rejects invalid feedback', async () => {
  const response = await fetch(`${baseUrl}/api/v1/feedback`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ message: '', rating: 6 })
  });
  assert.equal(response.status, 400);
});

test('scan request requires authentication', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ source: { type: 'local', path: 'harmless' }, checks: ['secret_patterns'] })
  });

  assert.equal(response.status, 401);
});

test('rejects protected requests without a bearer token', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key' },
    body: JSON.stringify({ source: { type: 'local', path: 'harmless' }, checks: ['secret_patterns'] })
  });
  assert.equal(response.status, 401);
});

test('rejects local paths outside the sample repository root', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({ source: { type: 'local', path: '..' }, checks: ['secret_patterns'] })
  });
  assert.equal(response.status, 404);
});

test('validates GitHub sources before integration is enabled', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({
      source: { type: 'github', repository: 'owner/repository', ref: 'main' },
      checks: ['secret_patterns']
    })
  });
  assert.equal(response.status, 501);
  assert.equal((await response.json()).error.code, 'NOT_IMPLEMENTED');
});

test('rejects unsafe GitHub refs', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({
      source: { type: 'github', repository: 'owner/repository', ref: '../main' },
      checks: ['secret_patterns']
    })
  });
  assert.equal(response.status, 400);
});

test('requires complete GitHub App configuration', () => {
  assert.equal(getGitHubAppConfig({ GITHUB_APP_ID: '123' }), null);
  assert.deepEqual(getGitHubAppConfig({
    GITHUB_APP_ID: '123',
    GITHUB_APP_INSTALLATION_ID: '456',
    GITHUB_APP_PRIVATE_KEY: 'line one\\nline two'
  }), {
    appId: '123',
    installationId: '456',
    privateKey: 'line one\nline two'
  });
});

test('rate limiter rejects requests over its configured limit', () => {
  const limiter = createRateLimiter({ maxRequests: 1, windowMs: 60 * 1000 });
  const responses = [];
  const createResponse = () => ({
    status(code) {
      responses.push(code);
      return this;
    },
    set() {},
    json() {}
  });
  const request = { socket: { remoteAddress: 'test-client' } };

  limiter(request, createResponse(), () => {});
  limiter(request, createResponse(), () => {});

  assert.deepEqual(responses, [429]);
});

test('creates a scan and returns a report without secrets', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({ source: { type: 'local', path: 'harmless' }, checks: ['secret_patterns'] })
  });
  assert.equal(response.status, 201);
  const scan = await response.json();

  const reportResponse = await fetch(`${baseUrl}/api/v1/scans/${scan.scan_id}/report`, {
    headers: { 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` }
  });
  const report = await reportResponse.json();
  assert.equal(report.status, 'completed');
  assert.deepEqual(report.summary, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  assert.equal(JSON.stringify(report).includes('local-development-key'), false);
});

test('reports a missing dependency lockfile when requested', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({ source: { type: 'local', path: 'missing-lockfile' }, checks: ['dependency_audit'] })
  });
  assert.equal(response.status, 201);
  const scan = await response.json();

  const reportResponse = await fetch(`${baseUrl}/api/v1/scans/${scan.scan_id}/report`, {
    headers: { 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` }
  });
  const report = await reportResponse.json();
  assert.equal(report.findings[0].check, 'dependency_audit');
  assert.equal(report.findings[0].severity, 'medium');
});

test('does not expose a scan to another user', async () => {
  const createResponse = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({ source: { type: 'local', path: 'harmless' }, checks: ['secret_patterns'] })
  });
  const scan = await createResponse.json();

  const reportResponse = await fetch(`${baseUrl}/api/v1/scans/${scan.scan_id}/report`, {
    headers: { 'x-api-key': 'local-development-key', authorization: `Bearer ${userBToken}` }
  });
  assert.equal(reportResponse.status, 404);
});

test('loads saved scans after a store is recreated', () => {
  const dbPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'handsoff-store-')), 'scans.db');
  const scan = { scan_id: 'scan_persisted', owner_id: 'user-x', status: 'completed', checks: [], findings: [], limitations: [], created_at: new Date().toISOString() };

  createScanStore(dbPath).save(scan);

  assert.deepEqual(createScanStore(dbPath).get(scan.scan_id), scan);
});

test('report includes limitations listing skipped files', async () => {
  const response = await fetch(`${baseUrl}/api/v1/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` },
    body: JSON.stringify({ source: { type: 'local', path: 'harmless' }, checks: ['secret_patterns'] })
  });
  const scan = await response.json();
  const report = await (await fetch(`${baseUrl}/api/v1/scans/${scan.scan_id}/report`, {
    headers: { 'x-api-key': 'local-development-key', authorization: `Bearer ${userAToken}` }
  })).json();
  assert.ok(Array.isArray(report.limitations));
  assert.ok(report.limitations.length > 0);
});

async function createArchive(sourceDir, entries) {
  const archivePath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'handsoff-archive-')), 'repo.tar');
  await tar.create({ cwd: sourceDir, file: archivePath, portable: true }, entries);
  return fs.readFileSync(archivePath);
}

function mockGitHubArchive(archive) {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(Readable.toWeb(Readable.from(archive)), {
    status: 200,
    headers: { 'content-type': 'application/x-tar' }
  });
  return () => {
    global.fetch = originalFetch;
  };
}

test('extracts a GitHub archive into a temporary directory', async () => {
  const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'handsoff-repo-'));
  fs.writeFileSync(path.join(sourceDir, 'README.md'), 'safe');
  const restoreFetch = mockGitHubArchive(await createArchive(sourceDir, ['README.md']));

  let extractedDir;
  try {
    extractedDir = await downloadRepository('owner', 'repo', 'main', 'test-token');
    assert.equal(fs.readFileSync(path.join(extractedDir, 'README.md'), 'utf8'), 'safe');
  } finally {
    restoreFetch();
    if (extractedDir) fs.rmSync(extractedDir, { recursive: true, force: true });
  }
});

test('rejects symlinks in a GitHub archive', async () => {
  const sourceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'handsoff-repo-'));
  fs.writeFileSync(path.join(sourceDir, 'safe.txt'), 'safe');
  fs.symlinkSync('safe.txt', path.join(sourceDir, 'link.txt'));
  const restoreFetch = mockGitHubArchive(await createArchive(sourceDir, ['safe.txt', 'link.txt']));

  let extractedDir;
  try {
    extractedDir = await downloadRepository('owner', 'repo', 'main', 'test-token');
    assert.equal(fs.existsSync(path.join(extractedDir, 'link.txt')), false);
  } finally {
    restoreFetch();
    if (extractedDir) fs.rmSync(extractedDir, { recursive: true, force: true });
  }
});
