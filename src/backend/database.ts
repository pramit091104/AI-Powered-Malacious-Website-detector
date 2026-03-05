import Database from 'better-sqlite3';
import path from 'path';

const dbPath = path.resolve(process.cwd(), 'scans.db');
const db = new Database(dbPath);

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    prediction TEXT NOT NULL,
    confidence REAL NOT NULL,
    report TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

export interface ScanResult {
  id?: number;
  url: string;
  prediction: string;
  confidence: number;
  report: string;
  timestamp?: string;
}

export const saveScan = (result: ScanResult) => {
  const stmt = db.prepare(`
    INSERT INTO scans (url, prediction, confidence, report)
    VALUES (?, ?, ?, ?)
  `);
  return stmt.run(result.url, result.prediction, result.confidence, result.report);
};

export const getScanHistory = (): ScanResult[] => {
  const stmt = db.prepare('SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50');
  return stmt.all() as ScanResult[];
};

export default db;
