import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { canonical } from './security.js';
import type { DatabaseSync } from 'node:sqlite';
const Payload = z
  .object({
    seq: z.number().int().nonnegative().safe(),
    hash: z.string().regex(/^(genesis|[0-9a-f]{64})$/),
    at: z.iso.datetime(),
  })
  .strict();
const Signed = Payload.extend({ signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/) }).strict();
export function verifyCheckpoint(db: DatabaseSync, file: string, publicKeyPath: string) {
  try {
    const { signature, ...payload } = Signed.parse(JSON.parse(readFileSync(file, 'utf8')));
    const key = createPublicKey(readFileSync(publicKeyPath));
    if (
      key.asymmetricKeyType !== 'ed25519' ||
      !verify(null, Buffer.from(canonical(payload)), key, Buffer.from(signature, 'base64'))
    )
      throw new Error('Invalid signature');
    const row = db.prepare('SELECT hash FROM audit WHERE seq=?').get(payload.seq) as
      { hash: string } | undefined;
    if (payload.hash !== (payload.seq === 0 ? 'genesis' : row?.hash))
      throw new Error('Audit rollback');
  } catch {
    throw new Error('Checkpoint signature or chain verification failed');
  }
}
export function writeCheckpoint(db: DatabaseSync, keyPath: string, file: string) {
  const key = createPrivateKey(readFileSync(keyPath));
  if (key.asymmetricKeyType !== 'ed25519')
    throw new Error('CHECKPOINT_KEY must be Ed25519 PKCS8 PEM');
  const head = db.prepare('SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1').get() as
    { seq: number; hash: string } | undefined;
  const payload = Payload.parse({
    ...head,
    seq: head?.seq ?? 0,
    hash: head?.hash ?? 'genesis',
    at: new Date().toISOString(),
  });
  const checkpoint = {
    ...payload,
    signature: sign(null, Buffer.from(canonical(payload)), key).toString('base64'),
  };
  const temporary = file + '.' + randomUUID() + '.tmp';
  const fd = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify(checkpoint, null, 2) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, file);
  const dir = openSync(dirname(file), 'r');
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
  return checkpoint;
}
