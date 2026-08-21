# Case workflow

Create one fresh directory per attempt, outside the supplied challenge tree when
possible. Hash inputs before analysis and never overwrite them.

```text
case/
├── manifest.json
├── inputs/
├── notes/
├── solvers/
├── transcripts/
└── proof/
```

`manifest.json` records input digests, observed versus derived or inferred facts,
constraints, ranking output, selected card, and tool versions. Store copied inputs
or immutable source references under `inputs/`; keep hypotheses in `notes/`, copied
and adapted solvers in `solvers/`, command output in `transcripts/`, and validation
commands plus results in `proof/`.

Use these states in the case record:

- `fingerprinted`: facts and input hashes are recorded.
- `ranked`: local AttackCards have been validated and ranked.
- `probed`: cheap discriminating probes completed.
- `attempted`: one bounded solver attempt ran.
- `verified`: an independent proof confirms the result.
- `rejected`: a probe or proof disproved the hypothesis.
- `blocked`: evidence, tooling, or budget prevents a justified attempt.
- `unsupported`: no precise local or authorized researched route exists.

Record why every transition occurred. A rejected or blocked card is useful case
evidence, not a silent failure.
