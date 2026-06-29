# rnv-mcp-identity

*Working name. An identity-and-authorization layer for MCP servers, built on one rule: resolve or refuse, never guess.*

> **Status: early, in active development.** The spec comes before the code, and this will change as the work teaches us.

## What this is

Most MCP servers running in the wild have no way to say who is calling them, or what that caller is allowed to do. A recent survey of roughly 2,000 servers found every one lacked authentication. This is a small, deterministic reference implementation for the missing layer: an MCP server (or middleware) that attaches a verifiable agent identity, checks it, and authorizes what the agent may do, refusing cleanly when it can't.

It's the running-code half of a larger proposal, **AIII (the Artificial Intelligence Identification Initiative)**. The narrative front door lives here: https://rnvizion.dev/aiii

## The rule

Resolve or refuse, never guess. The layer returns an answer it can prove, or it declines with an explicit deny or unknown. The one move it must never make is faking a confidence it hasn't earned. A false yes travels further than an honest blank.

## Scope

This covers the layers a single deployment can actually resolve:

- **L1, identity provenance:** who issued this agent, and who controls it.
- **L2, verification:** is the identity claim cryptographically real.
- **L3, authorization:** what the agent is scoped to do, enforced per call.

## Non-goals, on purpose

- **L4, structural enforcement:** holding an agent to its scope across systems.
- **L5, cross-organizational behavioral trust:** trusting an agent beyond the deployment that made it.

These are out of scope, and that's the honest part. No single deployment can operate cross-organizational trust, so this code doesn't pretend to; it marks exactly where L4 begins and stops there. Closing that gap is the longer AIII argument, not this repo.

## Grounding

This doesn't invent new protocols. It maps proven ones onto the MCP surface: OAuth 2.0 for authorization, WIMSE-style workload identity, and HTTP Message Signatures (RFC 9421) for verification. Where the active IETF agent-identity drafts already specify a piece, this aligns with them rather than competing.

## Eval gates

Correctness is measured, not asserted. CI holds three gates, a pattern carried over from a prior retrieval project:

- **Correct-resolution:** valid identities and in-scope calls succeed.
- **Correct-refusal:** invalid identities and out-of-scope calls are denied.
- **False-refusal:** valid identities and scopes are never wrongly denied.

## Roadmap

The build runs in phases, from spec to a credible proposal. See [ROADMAP.md](ROADMAP.md).

## Where this is headed

The goal is to get this to working level and submit it as a project proposal to the **Agentic AI Foundation (AAIF)**, the Linux Foundation directed fund that now hosts MCP. To be clear about status: this is an independent build that *aspires* to that proposal. It is not affiliated with, endorsed by, or currently a project of the AAIF.

## License

Apache-2.0, to match MCP and AAIF norms.

## Feedback

Comments, holes, and prior art are welcome. Open an issue.
