# IntentGate Governance

This document captures NetGnarus's commitment to the IntentGate open-source community: what stays Apache 2.0 in perpetuity, what's reserved for the commercial Pro tier, and the principle that decides which side new features land on. It exists so contributors, customers, and prospective customers can verify what they're depending on before they invest in it.

## The principle

> **Anything required to operate IntentGate as an authorization control point stays Apache 2.0. The commercial tier adds enterprise operator experience, not capability gates.**

Restated: any organization should be able to run IntentGate as a security control in their environment using the open-source components alone. The Pro tier exists for organizations that need an *enterprise operator console* — multiple operator roles, single sign-on, lifecycle management, polished workflows on top of the same authorization core.

Every new feature decision NetGnarus makes is run against this principle. If a small deployment can't operate without the feature, it ships as Apache 2.0. If it's an operator-experience layer on top, it ships as Pro.

## What stays Apache 2.0, forever

The components listed below remain Apache 2.0 in perpetuity. NetGnarus will not relicense them, will not restrict their use, will not change their license to BSL, SSPL, AGPL, or any non-permissive form. This commitment is permanent.

| Repository | What it provides |
| --- | --- |
| [`intentgate-gateway`](https://github.com/NetGnarus/intentgate-gateway) | The authorization control point. Four-check pipeline (capability, intent, policy, budget), capability token issuance and attenuation, multi-tenant scoping, tamper-evident audit chain, audit query / export / verify endpoints, webhook emitter, SIEM forwarders. |
| [`intentgate-extractor`](https://github.com/NetGnarus/intentgate-extractor) | Intent classifier microservice. Stub backend (heuristic) and Anthropic backend (Claude Haiku). |
| [`intentgate-sdk-python`](https://github.com/NetGnarus/intentgate-sdk-python) | Agent-side SDK. Capability attenuation, transport, typed client. |
| [`intentgate-sdk-typescript`](https://github.com/NetGnarus/intentgate-sdk-typescript) | Agent-side SDK for Node 18+. Byte-compatible attenuation with the Python SDK. |
| [`intentgate-helm`](https://github.com/NetGnarus/intentgate-helm) | Kubernetes packaging. Gateway + extractor in one chart. |
| [`intentgate-console`](https://github.com/NetGnarus/intentgate-console) | Basic operator UI. Full token lifecycle (mint, revoke, audit query), live `/metrics` dashboard. |

These repositories are sufficient to deploy IntentGate as a complete authorization control point for AI agents.

## What's reserved for the commercial Pro tier

The commercial console (`intentgate-console-pro`, private repository, licensed) adds the enterprise *operator experience* layer:

- OIDC SSO + viewer / operator / admin RBAC
- SCIM 2.0 provisioning with active-state-driven off-boarding
- TOTP step-up authentication for destructive operations
- Per-tenant notification channels (Slack, Microsoft Teams, PagerDuty)
- JIT admin elevation lifecycle (request, approval, auto-expiry, audit linkage)
- `/audit/verify` operator dashboard with chain-head freshness
- Audit export download UI (CSV / NDJSON)
- Approvals queue with step-up-gated decisions
- AI-assisted Rego policy authoring with dry-run, promote, rollback

These features add *how operators run the gateway day-to-day at enterprise scale*, not *whether the gateway can authorize requests*. A small team can authorize agent calls, write Rego policies, query the audit log, and respond to security incidents using the OSS components alone.

## The rule that will never be broken

NetGnarus commits that:

1. **No feature currently in the Apache 2.0 components will ever move to the commercial tier.** The current OSS feature surface is the floor, not the ceiling.
2. **The Apache 2.0 components will not be relicensed.** No BSL, SSPL, AGPL, source-available, or any other non-permissive license will ever apply to the repositories listed above.
3. **New features will be categorized against the principle, not commercial pressure.** If a security control fits the principle's OSS criterion, it ships Apache 2.0 even if NetGnarus could plausibly monetize it.

If NetGnarus ever fails to honor these commitments, the community is entitled to fork the existing Apache 2.0 codebase under its existing license and continue development independently. The Apache 2.0 license guarantees this in writing; this document acknowledges it as an explicit expectation.

## Decision making

Day-to-day product decisions (roadmap, feature prioritization, release timing) sit with NetGnarus. The OSS / Pro categorization is constrained by the principle above and is not a unilateral discretionary call.

Contributors influence direction through:

- Issues and pull requests on the public repositories.
- A public roadmap discussion (planned for `docs.intentgate.app` once the documentation site is live).
- Direct conversation with maintainers via the public GitHub Discussions board (planned).

Material changes to this document — to the principle, to the OSS / Pro split, or to the commitments above — will be announced publicly, with rationale, and with reasonable notice before taking effect.

## Trademark

"IntentGate" is a trademark application by NetGnarus (filings in progress in the EU). The trademark exists to protect users and customers from confusing forks or imitations; it does not restrict the use of the Apache 2.0 code itself.

Use of the IntentGate name in forks, derivative products, or commercial offerings should follow NetGnarus's trademark policy (to be published alongside the trademark registration). Forking the code under Apache 2.0 is unconditionally permitted; naming a fork "IntentGate Plus" or similar requires permission.

## Security disclosure

Coordinated vulnerability disclosure: `security@netgnarus.com`. PGP fingerprint published with the documentation site. Embargo policy: 90 days from confirmed receipt or earlier if a patch is available and customer-deployed.

## Contact

Inquiries about IntentGate Pro, partnerships, or commercial terms: <https://intentgate.app/contact>.

General OSS issues: GitHub issues on the relevant repository.

---

This document is part of NetGnarus's commitment to open-source-first development of authorization infrastructure for AI agents. Last updated: May 2026.
