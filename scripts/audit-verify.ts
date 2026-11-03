import { Store } from '../src/store.js';
if (!process.env.DB_PATH || !process.env.AUDIT_KEY)
  throw new Error('DB_PATH and AUDIT_KEY are required');
const store = new Store(process.env.DB_PATH, process.env.AUDIT_KEY);
try {
  if (!store.verify(true)) throw new Error('Audit integrity check failed');
  console.log('PASS: full audit verification');
} finally {
  store.close();
}
