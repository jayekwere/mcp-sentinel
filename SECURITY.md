# Security policy

Version 1.x receives fixes. This project is a reference implementation with a documented deployment boundary, not a managed security service.

Report vulnerabilities through the repository's private vulnerability reporting form when available: `https://github.com/jayekwere/mcp-sentinel/security/advisories/new`. If that form is unavailable, open an issue requesting a private reporting channel without exploit details or sensitive data.

Include the affected commit, the trust boundary crossed, minimal synthetic reproduction, expected and observed behavior, and practical impact. Never send live tokens, personal data, or cloud credentials. Please allow a fix to be prepared before public disclosure.

Read [the threat model](docs/THREAT-MODEL.md) and [deployment guide](docs/OPERATIONS.md) before evaluating a report. Controls claimed by the project must remain enforced on REST and other exposed execution paths. Synthetic fixture quality and performance limits matter, but a detector failing on an undocumented event shape is not automatically an authorization vulnerability.
