import { pinUpstream } from '../src/upstream.js';
if (!process.argv[2]) throw new Error('Usage: npm run pin:upstream -- <url>');
console.log(
  JSON.stringify(await pinUpstream(process.argv[2], process.env.UPSTREAM_TOKEN), null, 2),
);
