const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const tar = require('tar');

function getGitHubAppConfig(env = process.env) {
  const appId = env.GITHUB_APP_ID;
  const installationId = env.GITHUB_APP_INSTALLATION_ID;
  const privateKey = env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, '\n');

  if (!appId || !/^\d+$/.test(appId) || !installationId || !/^\d+$/.test(installationId) || !privateKey) {
    return null;
  }

  return { appId, installationId, privateKey };
}

// Build a GitHub App JWT (RS256). Valid for 10 minutes max per GitHub docs.
function buildAppJwt({ appId, privateKey }) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ iat: now - 60, exp: now + 540, iss: appId })).toString('base64url');
  const data = `${header}.${payload}`;
  const signature = crypto.createSign('RSA-SHA256').update(data).sign(privateKey, 'base64url');
  return `${data}.${signature}`;
}

// Exchange the App JWT for a short-lived installation token.
async function getInstallationToken(config) {
  const jwt = buildAppJwt(config);
  const response = await fetch(
    `https://api.github.com/app/installations/${config.installationId}/access_tokens`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'handsoff-api'
      }
    }
  );
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`GitHub token exchange failed (${response.status}): ${body.slice(0, 200)}`);
  }
  return (await response.json()).token;
}

const MAX_ARCHIVE_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_ENTRY_BYTES = 5 * 1024 * 1024;    // 5 MB per file
const GITHUB_TIMEOUT_MS = 30_000;

// Download and safely extract a GitHub repo tarball into a temp directory.
// Returns the temp directory path; caller must remove it.
async function downloadRepository(owner, repo, ref, token) {
  const url = `https://api.github.com/repos/${owner}/${repo}/tarball/${ref}`;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), GITHUB_TIMEOUT_MS);

  let response;
  try {
    response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'handsoff-api'
      },
      signal: ac.signal,
      redirect: 'follow'
    });
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new Error(`GitHub tarball fetch failed (${response.status}): ${body.slice(0, 200)}`);
  }

  const destDir = fs.mkdtempSync(path.join(os.tmpdir(), 'handsoff-repo-'));

  let totalBytes = 0;
  try {
    // Extract via streaming tar with strict safety guards
    await pipeline(
      response.body,
      tar.extract({
        cwd: destDir,
        strip: 1, // GitHub tarballs have a single top-level directory; strip it
        filter(entryPath) {
          // Block absolute paths and traversal
          if (path.isAbsolute(entryPath) || entryPath.includes('..')) return false;
          // Block symlinks — tar's 'filter' only filters regular entries, so we also use onentry
          return true;
        },
        onentry(entry) {
          if (entry.type === 'SymbolicLink' || entry.type === 'Link') {
            entry.resume(); // discard
            return;
          }
          let entryBytes = 0;
          entry.on('data', (chunk) => {
            entryBytes += chunk.length;
            totalBytes += chunk.length;
            if (entryBytes > MAX_ENTRY_BYTES || totalBytes > MAX_ARCHIVE_BYTES) {
              entry.destroy(new Error('Archive entry or total size limit exceeded.'));
            }
          });
        }
      })
    );
  } catch (err) {
    fs.rmSync(destDir, { recursive: true, force: true });
    throw err;
  }

  return destDir;
}

module.exports = { getGitHubAppConfig, getInstallationToken, downloadRepository };
