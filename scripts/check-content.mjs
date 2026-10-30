import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
const paths = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' })
  .split('\0')
  .filter(Boolean);
for (const path of paths) {
  if (/\.(png|jpg|zip)$/.test(path)) continue;
  const text = readFileSync(path, 'utf8');
  if (text.includes(String.fromCodePoint(0x2014)))
    throw new Error('Disallowed punctuation in ' + path);
}
console.log('PASS: tracked text content policy');
