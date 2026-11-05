const fs = require('node:fs');
const path = require('node:path');

const SECRET_PATTERNS = [
  { check: 'secret_patterns', name: 'AWS access key', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { check: 'secret_patterns', name: 'Generic API key assignment', pattern: /\b(api[_-]?key|secret[_-]?key)\s*[:=]\s*["'][^"']{8,}["']/i }
];

const MAX_FILE_BYTES = 1 * 1024 * 1024; // 1 MB — skip larger files
const SCAN_TIMEOUT_MS = 30_000;

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative);
}

function collectFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;

    const entryPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error('Symbolic links are not allowed in local scan sources.');
    }
    if (entry.isDirectory()) {
      files.push(...collectFiles(entryPath));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

function addFinding(findings, finding) {
  findings.push({ id: `finding_${findings.length + 1}`, ...finding });
}

function scanSecretPatterns(repositoryPath, findings, skippedFiles, deadline) {
  for (const filePath of collectFiles(repositoryPath)) {
    if (Date.now() >= deadline) throw new Error('Scan timed out.');

    const { size } = fs.statSync(filePath);
    if (size > MAX_FILE_BYTES) {
      skippedFiles.push(path.relative(repositoryPath, filePath));
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    for (const secret of SECRET_PATTERNS) {
      const match = content.match(secret.pattern);
      if (!match) continue;

      const line = content.slice(0, match.index).split(/\r?\n/).length;
      addFinding(findings, {
        check: secret.check,
        severity: 'high',
        title: `Possible ${secret.name} found`,
        description: 'A credential-like value appears to be stored in source code.',
        location: { file: path.relative(repositoryPath, filePath), line },
        evidence: 'Credential-like content was detected and redacted.',
        confidence: 'medium',
        recommendation: 'Remove the value, rotate it if real, and use protected environment configuration.'
      });
    }
  }
}

function scanDependencyManifest(repositoryPath, findings) {
  const packageJsonPath = path.join(repositoryPath, 'package.json');
  if (!fs.existsSync(packageJsonPath)) return;

  let packageJson;
  try {
    packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  } catch {
    addFinding(findings, {
      check: 'dependency_audit',
      severity: 'medium',
      title: 'Invalid package manifest',
      description: 'The package.json file could not be parsed.',
      location: { file: 'package.json' },
      evidence: 'The manifest contains invalid JSON.',
      confidence: 'high',
      recommendation: 'Fix the manifest and run the dependency manager validation command.'
    });
    return;
  }

  const hasDependencies = Object.keys({
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {})
  }).length > 0;
  const hasLockfile = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml']
    .some((name) => fs.existsSync(path.join(repositoryPath, name)));

  if (hasDependencies && !hasLockfile) {
    addFinding(findings, {
      check: 'dependency_audit',
      severity: 'medium',
      title: 'Dependency lockfile is missing',
      description: 'The project declares dependencies but does not include a recognized lockfile.',
      location: { file: 'package.json' },
      evidence: 'Dependencies are declared without a package lockfile.',
      confidence: 'high',
      recommendation: 'Generate and commit the lockfile so dependency versions are reproducible.'
    });
  }
}

function scanLocalRepository(repositoryPath, rootPath, checks) {
  const resolvedRoot = path.resolve(rootPath);
  const resolvedRepository = path.resolve(repositoryPath);
  if (!isInside(resolvedRoot, resolvedRepository)) {
    throw new Error('The scan source must be inside the configured sample repository directory.');
  }

  const findings = [];
  const skippedFiles = [];
  const deadline = Date.now() + SCAN_TIMEOUT_MS;

  if (checks.includes('secret_patterns')) scanSecretPatterns(resolvedRepository, findings, skippedFiles, deadline);
  if (checks.includes('dependency_audit')) scanDependencyManifest(resolvedRepository, findings);

  return { findings, skippedFiles };
}

module.exports = { scanLocalRepository };
