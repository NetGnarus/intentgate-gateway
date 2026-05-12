# Security Policy

## Reporting a vulnerability

Email **security@netgnarus.com** with subject line starting `Security disclosure`.

We confirm receipt within one business day. Embargo: **90 days from confirmed receipt**, or earlier if a patch is available and rolled out to known users, or if the reporter requests it.

PGP fingerprint will be published alongside the documentation site once live; until then, send unencrypted reports to the email above. Do **not** open a public GitHub issue for security reports.

## What we run on this repository

- **Dependabot** alerts on every push, scanning Go modules + Docker base images + GitHub Actions for known CVEs. Security updates are auto-proposed as PRs.
- **CodeQL** + **gosec** static analysis on every push and pull request, plus a weekly scheduled scan.
- **Secret scanning** and **push protection** at the GitHub platform level — committed secrets are detected, and pushes that contain them are blocked.

## Supply chain

Each release artifact is:

- Built reproducibly from a tagged commit via GitHub Actions
- Signed with [Sigstore cosign](https://github.com/sigstore/cosign) (`cosign verify` confirms provenance)
- Accompanied by an [SBOM (SPDX 2.3)](https://spdx.dev/) and an [SLSA build provenance attestation](https://slsa.dev/)

Container images are pulled from `ghcr.io/netgnarus/`; the registry enforces TLS and HTTPS-only pulls.

## Supported versions

The most recent released minor version is supported. Older versions receive security patches at our discretion for **six months** past the next minor release.

## Coordinated disclosure window

We follow a standard 90-day responsible disclosure model. Earlier disclosure happens when:

- A patch is available and rolled out to known users
- The issue is actively exploited in the wild
- The reporter requests earlier publication

## Out of scope

The following are explicitly out of scope for this disclosure program:

- Social engineering of NetGnarus staff or customers
- Physical attacks on infrastructure
- Denial-of-service / volumetric attacks (these are operational concerns, not vulnerabilities)
- Issues in third-party dependencies — please file those with the upstream project. We track upstream advisories via Dependabot and remediate from there.

---

Maintained by **NetGnarus B.V.**, Ijsselstein, The Netherlands (KvK 63319578). Commercial inquiries: <https://intentgate.app/contact>.
