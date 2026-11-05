const crypto = require('node:crypto');
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const { scanLocalRepository } = require('./scanner');
const { createScanStore } = require('./scan-store');
const { createToken, verifyToken } = require('./auth');
const { isValidGitHubSource } = require('./github-source');
const { getGitHubAppConfig, getInstallationToken, downloadRepository } = require('./github-app');
const { createRateLimiter } = require('./rate-limit');

const app = express();
const scanStore = createScanStore();
const sampleRoot = path.resolve(process.env.SAMPLE_REPOSITORIES_ROOT || path.join(__dirname, '..', 'sample-repositories'));
const apiKey = process.env.HANDSOFF_API_KEY || 'local-development-key';
const allowedChecks = new Set(['secret_patterns', 'dependency_audit']);
const MAX_SCANS_PER_USER = 100; // shortcut: in-DB count; add a cleanup job when this matters

app.use(express.json({ limit: '32kb' }));
app.use(createRateLimiter({ maxRequests: 60, windowMs: 60_000 }));
app.use(express.static(path.join(__dirname, '..', 'public')));

function errorResponse(res, status, code, message) {
  return res.status(status).json({ error: { code, message } });
}

function requireApiKey(req, res, next) {
  if (req.get('x-api-key') !== apiKey) {
    return errorResponse(res, 401, 'UNAUTHORIZED', 'A valid API key is required.');
  }
  const authorization = req.get('authorization') || '';
  if (!authorization.startsWith('Bearer ')) {
    return errorResponse(res, 401, 'UNAUTHORIZED', 'A valid bearer token is required.');
  }
  const payload = verifyToken(authorization.slice('Bearer '.length));
  if (!payload) return errorResponse(res, 401, 'UNAUTHORIZED', 'The bearer token is invalid or expired.');
  req.userId = payload.sub;
  next();
}

function getOwnedScan(req, res) {
  const scan = scanStore.get(req.params.scanId);
  if (!scan || scan.owner_id !== req.userId) {
    errorResponse(res, 404, 'NOT_FOUND', 'The scan was not found.');
    return null;
  }
  return scan;
}

function resolveLocalRepository(relativePath) {
  if (path.isAbsolute(relativePath)) return null;
  const resolvedPath = path.resolve(sampleRoot, relativePath);
  const relativeToRoot = path.relative(sampleRoot, resolvedPath);
  if (!relativeToRoot || relativeToRoot.startsWith('..') || path.isAbsolute(relativeToRoot)) return null;
  return resolvedPath;
}

function buildScan(scanId, userId, source, checks, findings, skippedFiles) {
  return {
    scan_id: scanId,
    owner_id: userId,
    status: 'completed',
    source,
    checks,
    findings,
    limitations: [
      `Only these checks were performed: ${checks.join(', ')}.`,
      'This scan does not certify that an application is secure.',
      ...(skippedFiles.length > 0 ? [`${skippedFiles.length} file(s) were skipped because they exceeded the size limit.`] : [])
    ],
    created_at: new Date().toISOString()
  };
}

app.get('/api/v1/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/api/v1/feedback', (req, res) => {
  const { message, email, rating, category } = req.body || {};
  if (typeof message !== 'string' || message.trim().length < 1 || message.length > 2000) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'Feedback message must be between 1 and 2000 characters.');
  }
  if (email !== undefined && (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'A valid email address is required when provided.');
  }
  if (rating !== undefined && (!Number.isInteger(rating) || rating < 1 || rating > 5)) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'Rating must be an integer from 1 to 5.');
  }
  if (category !== undefined && (typeof category !== 'string' || category.length > 50)) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'Feedback category is invalid.');
  }

  const feedback = {
    feedback_id: crypto.randomUUID(),
    message: message.trim(),
    ...(email ? { email } : {}),
    ...(rating !== undefined ? { rating } : {}),
    ...(category ? { category } : {}),
    created_at: new Date().toISOString()
  };
  try {
    scanStore.saveFeedback(feedback);
  } catch {
    return errorResponse(res, 500, 'INTERNAL_ERROR', 'The feedback could not be saved.');
  }
  res.status(201).json({ feedback_id: feedback.feedback_id, status: 'received' });
});

app.post('/api/v1/auth/token', (req, res) => {
  if (req.get('x-api-key') !== apiKey) {
    return errorResponse(res, 401, 'UNAUTHORIZED', 'A valid API key is required.');
  }
  const { user_id: userId } = req.body || {};
  if (typeof userId !== 'string' || userId.length === 0 || userId.length > 100) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'A valid user_id is required.');
  }
  res.json({ access_token: createToken(userId), token_type: 'Bearer', expires_in: 3600 });
});

app.post('/api/v1/scans', requireApiKey, async (req, res) => {
  const { source, checks } = req.body || {};

  if (!Array.isArray(checks) || checks.length === 0 || checks.some((c) => !allowedChecks.has(c))) {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'The scan request is invalid.');
  }

  if (scanStore.countByOwner(req.userId) >= MAX_SCANS_PER_USER) {
    return errorResponse(res, 429, 'RATE_LIMITED', 'Scan limit reached. Delete old scans or contact support.');
  }

  const scanId = crypto.randomUUID();

  // --- GitHub source ---
  if (source && source.type === 'github') {
    if (!isValidGitHubSource(source)) {
      return errorResponse(res, 400, 'INVALID_REQUEST', 'The GitHub repository or ref is invalid.');
    }
    const config = getGitHubAppConfig();
    if (!config) {
      return errorResponse(res, 501, 'NOT_IMPLEMENTED', 'GitHub App repository access is not configured yet.');
    }

    let repoDir;
    try {
      const [owner, repo] = source.repository.split('/');
      const token = await getInstallationToken(config);
      repoDir = await downloadRepository(owner, repo, source.ref, token);

      // scan inside a synthetic "root" that is the temp dir itself
      const { findings, skippedFiles } = scanLocalRepository(repoDir, path.dirname(repoDir), checks);
      const scan = buildScan(scanId, req.userId, { type: 'github', repository: source.repository, ref: source.ref }, checks, findings, skippedFiles);
      try { scanStore.save(scan); } catch { return errorResponse(res, 500, 'INTERNAL_ERROR', 'The scan could not be stored.'); }
      return res.status(201).json({ scan_id: scanId, status: scan.status, created_at: scan.created_at });
    } catch (error) {
      return errorResponse(res, 422, 'SCAN_FAILED', error.message);
    } finally {
      if (repoDir) {
        const { rmSync } = require('node:fs');
        rmSync(repoDir, { recursive: true, force: true });
      }
    }
  }

  // --- Local source ---
  if (!source || source.type !== 'local' || typeof source.path !== 'string') {
    return errorResponse(res, 400, 'INVALID_REQUEST', 'The scan request is invalid.');
  }

  const repositoryPath = resolveLocalRepository(source.path);
  if (!repositoryPath || !fs.existsSync(repositoryPath) || !fs.statSync(repositoryPath).isDirectory()) {
    return errorResponse(res, 404, 'NOT_FOUND', 'The requested local repository was not found.');
  }

  try {
    const { findings, skippedFiles } = scanLocalRepository(repositoryPath, sampleRoot, checks);
    const scan = buildScan(scanId, req.userId, { type: 'local' }, checks, findings, skippedFiles);
    try { scanStore.save(scan); } catch { return errorResponse(res, 500, 'INTERNAL_ERROR', 'The scan could not be stored.'); }
    return res.status(201).json({ scan_id: scanId, status: scan.status, created_at: scan.created_at });
  } catch (error) {
    return errorResponse(res, 422, 'SCAN_FAILED', error.message);
  }
});

app.get('/api/v1/scans/:scanId', requireApiKey, (req, res) => {
  const scan = getOwnedScan(req, res);
  if (!scan) return;

  res.json({
    scan_id: scan.scan_id,
    status: scan.status,
    progress: { completed_checks: scan.checks.length, total_checks: scan.checks.length }
  });
});

app.get('/api/v1/scans/:scanId/report', requireApiKey, (req, res) => {
  const scan = getOwnedScan(req, res);
  if (!scan) return;

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of scan.findings) summary[finding.severity] += 1;
  res.json({
    scan_id: scan.scan_id,
    status: scan.status,
    summary,
    findings: scan.findings,
    limitations: scan.limitations
  });
});

module.exports = app;
