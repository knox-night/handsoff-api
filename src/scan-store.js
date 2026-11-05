const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

// shortcut: single-process SQLite; upgrade to libsql/Turso for multi-process deployments
function createScanStore(dbPath = process.env.SCANS_STORE_PATH || path.join(__dirname, '..', '.data', 'scans.db')) {
  const resolvedPath = path.resolve(dbPath);
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

  const db = new DatabaseSync(resolvedPath);
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      scan_id TEXT PRIMARY KEY,
      owner_id TEXT,
      status TEXT NOT NULL,
      data TEXT NOT NULL
    )
  `);

  const stmtGet = db.prepare('SELECT data FROM scans WHERE scan_id = ?');
  const stmtCountByOwner = db.prepare('SELECT COUNT(*) AS n FROM scans WHERE owner_id = ?');
  const stmtUpsert = db.prepare(
    'INSERT INTO scans (scan_id, owner_id, status, data) VALUES (?, ?, ?, ?) ON CONFLICT(scan_id) DO UPDATE SET owner_id=excluded.owner_id, status=excluded.status, data=excluded.data'
  );

  return {
    get(scanId) {
      const row = stmtGet.get(scanId);
      return row ? JSON.parse(row.data) : undefined;
    },
    save(scan) {
      stmtUpsert.run(scan.scan_id, scan.owner_id ?? null, scan.status, JSON.stringify(scan));
    },
    countByOwner(ownerId) {
      return stmtCountByOwner.get(ownerId).n;
    }
  };
}

module.exports = { createScanStore };
