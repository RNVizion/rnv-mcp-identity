# OpenSSF Best Practices: passing-badge self-assessment

A working sheet for filling the badge form at bestpractices.dev for
**rnv-mcp-identity**. Passing requires every MUST met, every SHOULD met or
justified, and every SUGGESTED rated. Status as of 2026-06-29.

Legend: ✅ met · ➖ N/A (justified) · ⚠ unmet (SUGGESTED, allowed) · ⏳ earned on/after submission

## Basics
| Criterion [id] | Level | Status | Evidence / note |
|---|---|---|---|
| Describe what it does [description_good] | MUST | ✅ | README opening + the three-outcome rule |
| How to obtain / feedback / contribute [interact] | MUST | ✅ | README, CONTRIBUTING, GitHub Issues |
| Explain contribution process [contribution] | MUST | ✅ | CONTRIBUTING (fork, branch, PR, DCO) |
| Requirements for contributions [contribution_requirements] | SHOULD | ✅ | CONTRIBUTING (tests required, dep-free core, sign-off) |
| Released as FLOSS [floss_license] | MUST | ✅ | Apache-2.0 |
| OSI-approved license [floss_license_osi] | SUGGESTED | ✅ | Apache-2.0 |
| License in standard location [license_location] | MUST | ✅ | `LICENSE` at repo root |
| Basic documentation [documentation_basics] | MUST | ✅ | README, SPEC, examples/ |
| Interface/reference docs [documentation_interface] | MUST | ✅ | SPEC, docstrings, examples/README |
| Sites use HTTPS [sites_https] | MUST | ✅ | GitHub + rnvizion.dev/aiii/ |
| Discussion mechanism [discussion] | MUST | ✅ | GitHub Issues / Discussions |
| English [english] | SUGGESTED | ✅ | — |
| Maintained [maintained] | MUST | ✅ | Active; v0.1.0 just cut |

## Change control
| Criterion | Level | Status | Evidence / note |
|---|---|---|---|
| Public version-controlled repo [repo_public] | MUST | ✅ | github.com/RNVizion/rnv-mcp-identity |
| Tracks changes [repo_track] | MUST | ✅ | git |
| Interim versions between releases [repo_interim] | MUST | ✅ | commit history |
| Distributed VCS [repo_distributed] | SUGGESTED | ✅ | git |
| Unique version numbering [version_unique] | MUST | ✅ | SemVer |
| Semantic versioning [version_semver] | SUGGESTED | ✅ | SemVer, pre-1.0 |
| Release tags [version_tags] | SUGGESTED | ✅ | `v0.1.0` |
| Release notes [release_notes] | MUST | ✅ | CHANGELOG.md |
| Release notes list fixed vulns [release_notes_vulns] | MUST (N/A allowed) | ➖ | No fixed vulnerabilities to date |

## Reporting
| Criterion | Level | Status | Evidence / note |
|---|---|---|---|
| Bug-report process [report_process] | MUST | ✅ | GitHub Issues + CONTRIBUTING |
| Issue tracker [report_tracker] | SHOULD | ✅ | GitHub Issues |
| Respond to reports [report_responses] | MUST | ✅ | Maintainer-committed |
| Respond to enhancements [enhancement_responses] | SHOULD | ✅ | — |
| Archive of reports [report_archive] | MUST | ✅ | GitHub Issues |
| Vulnerability report process [vulnerability_report_process] | MUST | ✅ | SECURITY.md |
| Private vuln reporting [vulnerability_report_private] | MUST (N/A allowed) | ✅ | GitHub private vulnerability reporting (SECURITY.md) |
| Vuln response time [vulnerability_report_response] | MUST | ✅ | SECURITY.md: acknowledge within ~1 week |

## Quality
| Criterion | Level | Status | Evidence / note |
|---|---|---|---|
| Working build [build] | MUST (N/A allowed) | ✅ | `pip install -e .` (hatchling) |
| Common build tools [build_common_tools] | SUGGESTED | ✅ | pip / hatchling |
| FLOSS build tools [build_floss_tools] | SUGGESTED | ✅ | — |
| Automated test suite [test] | MUST | ✅ | pytest, 46 tests |
| Documented test invocation [test_invocation] | SHOULD | ✅ | README + CONTRIBUTING |
| Tests cover most code [test_most] | SUGGESTED | ✅ | unit + property tests + 3 eval gates |
| Continuous integration [test_continuous_integration] | SUGGESTED | ✅ | GitHub Actions matrix + demo job |
| Policy: tests for new functionality [test_policy] | MUST | ✅ | CONTRIBUTING states it |
| Evidence tests are added [tests_are_added] | MUST | ✅ | commit history |
| Test policy documented [tests_documented_added] | SUGGESTED | ✅ | CONTRIBUTING |
| Enable warnings/lint [warnings] | MUST (N/A allowed) | ✅ | ruff in CI (lint job) |
| Fix warnings [warnings_fixed] | MUST | ✅ | `ruff check .` clean |
| Strict warnings [warnings_strict] | SUGGESTED | ⚠ | ruff E/F/W enabled; rule set can be widened |

## Security
| Criterion | Level | Status | Evidence / note |
|---|---|---|---|
| Primary dev knows secure design [know_secure_design] | MUST | ✅ | SPEC threat model + holder-of-key design; OpenSSF LFD courses available if reviewers want a formal basis |
| Knows common errors [know_common_errors] | MUST | ✅ | Threat model covers spoofing, theft/replay, scope escalation, audit evasion |
| Published crypto only [crypto_published] | MUST (N/A allowed) | ✅ | Ed25519/EdDSA, SHA-256, JWS/JWT, RFC 7800/7638 |
| Call existing crypto, don't reimplement [crypto_call] | MUST (N/A allowed) | ✅ | Uses `cryptography` and `pyjwt`; no homegrown primitives |
| FLOSS crypto [crypto_floss] | MUST (N/A allowed) | ✅ | `cryptography` (Apache-2.0/BSD) |
| Default key lengths [crypto_keylength] | MUST (N/A allowed) | ✅ | Ed25519 |
| No broken crypto [crypto_working] | MUST (N/A allowed) | ✅ | No MD5/SHA-1/DES in security paths |
| Avoid known-weak crypto [crypto_weaknesses] | SHOULD (N/A allowed) | ✅ | — |
| Perfect forward secrecy [crypto_pfs] | SHOULD (N/A allowed) | ➖ | Not a transport protocol |
| Password storage hashing [crypto_password_storage] | MUST (N/A allowed) | ➖ | Stores no passwords |
| Secure RNG for keys/nonces [crypto_random] | MUST (N/A allowed) | ✅ | Relies on `cryptography` CSPRNG; rolls no RNG. Demo keys derive from public seeds and are clearly marked DEMO-only, not production key generation |
| Delivery counters MITM [delivery_mitm] | MUST | ✅ | GitHub / PyPI over HTTPS |
| No unsigned hash over HTTP [delivery_unsigned] | MUST | ✅ | — |
| No leaked credentials [no_leaked_credentials] | MUST | ✅ | No real credentials; demo seeds are public, non-secret, and labeled |

## Analysis
| Criterion | Level | Status | Evidence / note |
|---|---|---|---|
| Static analysis applied [static_analysis] | MUST (N/A just.) | ✅ | **bandit** (security SAST) + **ruff** run in CI on every push/PR |
| Looks for common vulns [static_analysis_common_vulnerabilities] | SUGGESTED | ✅ | bandit targets common Python security issues |
| Fix static-analysis findings [static_analysis_fixed] | MUST | ✅ | Findings triaged; two B105 false positives suppressed with justification |
| Run static analysis often [static_analysis_often] | SUGGESTED | ✅ | Every push/PR in CI |
| Dynamic analysis [dynamic_analysis] | SUGGESTED (N/A allowed) | ⚠ | Hypothesis property tests generate inputs against the engine; no separate fuzz/dynamic tool yet |
| Dynamic check for unsafe memory [dynamic_analysis_unsafe] | SUGGESTED | ➖ | Memory-safe language |
| Assertions during dynamic analysis [dynamic_analysis_enable_assertions] | SUGGESTED | ➖ | — |

## Meta (earned on/after submission)
| Criterion | Level | Status | Note |
|---|---|---|---|
| Achieve passing badge [achieve_passing] | MUST | ⏳ | Granted when the form is submitted and complete |
| Link the badge within 48h [documentation_achievements] | MUST | ⏳ | Add the badge to README once earned |
| DCO or CLA [dco] | SHOULD | ✅ | CONTRIBUTING requires `git commit -s` + DCO |

## Already past passing (silver-level items satisfied)
- **Per-file license + copyright** [license_per_file, copyright_per_file]: SPDX headers on every source file.
- **Documented governance** [governance]: GOVERNANCE.md.
- **DCO** [dco]: required in CONTRIBUTING.

## Small gaps to note (none block passing)
- Add a standalone **CODE_OF_CONDUCT.md** (Contributor Covenant) — currently referenced in GOVERNANCE; a standalone file is the silver-level expectation [code_of_conduct].
- Optionally widen ruff's rule set for `warnings_strict`.
- Optionally add a dedicated dynamic-analysis/fuzz pass beyond Hypothesis.

## Bottom line
Every passing MUST is met or justifiably N/A, every SHOULD is met, and the one
historically blocking item for this kind of project, `static_analysis`, is now
satisfied by bandit + ruff in CI. The form should complete to a passing badge.
