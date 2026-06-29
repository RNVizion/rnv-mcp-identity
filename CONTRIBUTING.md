# Contributing

Thanks for considering a contribution. This project values correctness and honesty
over speed: the whole point of the codebase is a system that resolves or refuses
rather than guessing, and contributions are held to that same bar.

## Development setup

The core library has no runtime dependencies. For development, install the extras:

```
pip install -e ".[dev,verify,fastmcp]"
```

Run the full suite:

```
python -m pytest -q
```

Lint and security static analysis run in CI and can be run locally:

```
pip install -e ".[lint]"
ruff check .
bandit -c pyproject.toml -r src
```

The suite runs on Linux and Windows across Python 3.10 through 3.12 in CI, plus a
separate FastMCP demo job.

## What a good contribution looks like

- **New behavior ships with tests.** Every decision path, especially refusal paths,
  needs coverage. The suite includes named eval gates for correct resolution,
  correct refusal, and the absence of false refusals; a change that touches decision
  logic should keep those green and add cases where relevant.
- **Refusals stay honest.** If the engine can't establish something, the outcome is
  `deny` or `unknown` with a machine-readable reason, never a silent allow. Don't
  add a path that guesses.
- **Keep the core dependency-free.** Runtime dependencies belong behind optional
  extras (`verify`, `fastmcp`), not in the core decision engine.

## Proposing a spec change

SPEC.md is versioned in the repository. If your change alters normative behavior or
the wire format:

1. Update SPEC.md in the same pull request as the implementation.
2. For wire-format changes, bump the version noted in the spec and update the
   reference example in `examples/`.
3. Explain the rationale in the pull request description.

Spec-affecting changes require maintainer approval (see GOVERNANCE.md).

## Pull request process

1. Fork and branch from `main`.
2. Make the change with tests; run the suite locally.
3. Sign your commits (Developer Certificate of Origin): `git commit -s`. This
   certifies you have the right to submit the work under the project's license.
4. Open a pull request. CI must pass. A committer reviews; lazy consensus governs
   merging (see GOVERNANCE.md).

## Reporting bugs and security issues

Functional bugs go in the public issue tracker. Security vulnerabilities do **not**;
see SECURITY.md for private reporting.
