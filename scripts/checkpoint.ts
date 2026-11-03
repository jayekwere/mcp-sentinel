import { Store } from '../src/store.js';
import { writeCheckpoint } from '../src/checkpoint.js';
const { DB_PATH, AUDIT_KEY, CHECKPOINT_KEY, CHECKPOINT_FILE } = process.env;
if (!DB_PATH || !AUDIT_KEY || !CHECKPOINT_KEY || !CHECKPOINT_FILE)
  throw new Error('DB_PATH, AUDIT_KEY, CHECKPOINT_KEY and CHECKPOINT_FILE are required');
// A first checkpoint has no existing file to verify. Later checkpoints verify the retained one.
const { existsSync } = await import('node:fs');
const store = new Store(
  DB_PATH,
  AUDIT_KEY,
  undefined,
  existsSync(CHECKPOINT_FILE)
    ? { file: CHECKPOINT_FILE, key: process.env.CHECKPOINT_PUBLIC_KEY ?? CHECKPOINT_KEY }
    : {},
);
try {
  if (!store.verify(true)) throw new Error('Audit integrity check failed');
  console.log(JSON.stringify(writeCheckpoint(store.db, CHECKPOINT_KEY, CHECKPOINT_FILE)));
} finally {
  store.close();
}
