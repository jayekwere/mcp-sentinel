# Release validation

Recorded on 2026-10-30. These are executed checks, not proposed acceptance criteria. Host validation used Node 26.3.0, and the pinned Alpine image independently ran the suite on Node 24. Browser workflows used a locally installed compatible browser through Playwright. Hosted CI uses the Playwright Chromium build and is visible in the repository Actions tab.

| Check | Observed result | Evidence |
| --- | --- | --- |
| Formatter, strict types, build and demo | Passed | [verify.txt](verify.txt) |
| Automated tests | 39 passed, zero failed or skipped | [coverage.txt](coverage.txt) |
| V8 coverage, exercised source modules | 97.68% lines, 91.27% branches | [coverage.txt](coverage.txt) |
| Browser workflow | Passed at 1440px desktop and 390px mobile widths, no page errors | [browser.txt](browser.txt), [desktop](../docs/dashboard.png), [mobile](../docs/dashboard-mobile.png) |
| Container build | Passed, includes Node 24 type and test checks | [container-build.txt](container-build.txt) |
| Restricted runtime | Passed with non-root user, read-only root, dropped capabilities and process/memory limits | [container-smoke.txt](container-smoke.txt) |
| Locked dependency advisory query | Zero reported advisories at validation time | [dependencies.json](dependencies.json) |
| Tracked text policy and credential-pattern inspection | Passed | `node scripts/check-content.mjs` and local tracked-file inspection |

The coverage report includes modules loaded by the automated tests. Startup configuration, the main entrypoint, and browser source are not included in those percentages. Browser and container checks exercise those paths separately. Coverage is evidence of execution, not proof that all security properties hold. Dependency advisory results change over time and do not cover every vulnerability in a container base.

[Source manifest](source-manifest.json) fingerprints the implementation, tests, build scripts, workflow, and dependency lockfile. The full test output records case names and actual outcomes. Disposable tokens are intentionally absent from committed logs. Demo timestamps, request IDs, approval IDs, audit hashes, and measured durations vary per run.

The MCP test uses a real official SDK client over local HTTP for initialization, discovery, tool execution, independent approval metadata, and replay rejection. A separate real SDK server tests the optional fixed upstream adapter's descriptor pin and dedicated credential. Concurrency tests race twelve calls against one approval and observe one successful execution. Persistence tests reopen SQLite before trying reuse. Failure tests confirm an upstream error does not restore approval or expose its error text.

Cloud summary adapters are tested against synthetic AWS, Azure, and GCP field projections. No live cloud account, external issuer, production reverse proxy, or external MCP service was tested. The evidence export tool returns a complete synthetic payload and never claims to create absent files or resources.
