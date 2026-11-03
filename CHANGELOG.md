# Changelog

## 1.1.0 - 2026-11-03

Breaking: upstream pins now cover the complete descriptor, including annotations, output schemas, and extension fields. Re-run `npm run pin:upstream -- <url>`, review every descriptor, and replace all old hashes before restarting. Outstanding approvals become invalid when execution configuration changes.

Breaking: `GET /api/overview` now returns `totals.pending` as an integer. Replace `totals.pending.n` with `totals.pending` in API clients. Startup migrates the database and invalidates legacy pending or approved requests without reviewer arguments; request fresh approval after upgrading. Back up the stopped database before migration.

Added bounded authentication-denial aggregates, incremental audit verification and `audit:verify`, policy-driven approval visibility, same-tenant jti/subject revocations, validated SIGHUP auth reload, text-only upstream output, pinned output-schema validation, deterministic secret redaction with detections, private SQLite sidecars, atomic audit writes, exclusive single-writer enforcement, signed external Ed25519 checkpoints, deduplicated OCSF detection export, and optional persistent denial-burst suspension with operator release. Encoded API/MCP routes share authentication and containment checks. Suspensions re-arm after expiry or release.

Added SHA-pinned CodeQL, gitleaks and OpenSSF Scorecard workflows, keyless signed image releases with SPDX SBOMs and provenance, a digest-pinned Node 24 distroless runtime, attack coverage and reproducible evidence collection. Security workflows and releases require actual hosted runs before claiming hosted scan findings or a signed published release. New containment defaults off outside demo mode. Existing pins must be regenerated, and offline maintenance requires stopping the single writer.

## 1.0.0 - 2026-10-30

Initial reference implementation with signed access-token verification, server-owned identity and tenant boundaries, auditable state transitions, local synthetic demonstration, responsive evidence dashboard, immutable workflow references, dependency review, browser checks, and restricted container validation.

MCP Sentinel adds default-deny per-tool policy, exact independently reviewed one-time approvals, official SDK Streamable HTTP, fixed schema-pinned upstream routing, three cloud export projections, and deterministic audit-based signals.
