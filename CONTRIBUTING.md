# Contributing

Use Node 24 and `npm ci --ignore-scripts`. Run `npm run verify`, `npm run test:browser` after installing the browser with `npx playwright install chromium`, and the container smoke test after building the image. Include a failure-inducing test for changes to a trust boundary or detection rule. Keep fixtures synthetic and use reserved network addresses and example domains.

Explain the behavior change, why the input can occur, how authorization or correlation is affected, and the checks performed. Keep documentation consistent with actual capabilities. Do not introduce live credentials, personal data, unrelated organization references, or long dash punctuation. Update detection labels and explain the reason for changed expectations. Do not lower security checks just to make CI pass.
