# Security policy

Version 1.x receives fixes. This project is a reference implementation with a documented deployment boundary, not a managed security service.

Report vulnerabilities through the repository's private vulnerability reporting form when available: `https://github.com/jayekwere/mcp-sentinel/security/advisories/new`. If that form is unavailable, open an issue requesting a private reporting channel without exploit details or sensitive data.

Include the affected commit, the trust boundary crossed, minimal synthetic reproduction, expected and observed behavior, and practical impact. Never send live tokens, personal data, or cloud credentials. Please allow a fix to be prepared before public disclosure.

Read [the threat model](docs/THREAT-MODEL.md) and [deployment guide](docs/OPERATIONS.md) before evaluating a report. Controls claimed by the project must remain enforced on REST and other exposed execution paths. Synthetic fixture quality and performance limits matter, but a detector failing on an undocumented event shape is not automatically an authorization vulnerability.

## Release image verification

The tag-triggered release workflow builds `ghcr.io/jayekwere/mcp-sentinel:<tag>`, creates an SPDX JSON SBOM with Syft, signs the image and SBOM attestation keylessly with Cosign, and attaches GitHub build provenance to the image digest. OIDC write access exists only in the release signing job within that workflow. Tags remain an operator release action. New workflow configuration isn't evidence that a release has already been published or verified.

Resolve the intended tag to its immutable digest and verify the exact repository, workflow and tag identity. Replace `sha256:...` with the published digest:

```sh
IMAGE='ghcr.io/jayekwere/mcp-sentinel@sha256:...'
IDENTITY='https://github.com/jayekwere/mcp-sentinel/.github/workflows/release.yml@refs/tags/v1.1.0'
cosign verify --certificate-identity "$IDENTITY" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE"
cosign verify-attestation --type spdxjson --certificate-identity "$IDENTITY" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE"
gh attestation verify "oci://$IMAGE" --repo jayekwere/mcp-sentinel --signer-workflow jayekwere/mcp-sentinel/.github/workflows/release.yml
```

Inspect the verified SBOM predicate and provenance subject digest before deployment. The SBOM is also retained as a workflow artifact. A signature proves the workflow identity and artifact integrity; it doesn't prove absence of vulnerabilities. Keep GHCR package visibility and retention configured for the intended consumers.
