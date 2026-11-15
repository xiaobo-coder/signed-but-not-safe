# Signed but Not Safe: Requirement Integrity in Multi-Agent LLM Handoffs

Task banks, per-trajectory results and analysis code for the paper *Signed but Not Safe: Requirement Integrity in
Multi-Agent LLM Handoffs* (Xiaobo Chen, Genliang Zhu, Ziyuan Wang, Chu Wang, 2026). arXiv:
[2611.07483](https://arxiv.org/abs/2611.07483) (v2).

An orchestrator agent hands a user's requirements to subagents as free text (arm `S`), JSON (`J`; `JL` adds an LLM
checker) or a requirement manifest (`M` unsigned; `MS` signed with HMAC-SHA256 and checked by a deterministic verifier;
`MSO` oracle manifest). Threats: `T0` benign, `T1` relay compression, `T2a` in-transit mutation, `T3`/`T4` injected
notes, `T5` pre-signing injection. Tasks are synthetic and exactly scorable, so no LLM judge is used.

## Contents

- `data/tasks.jsonl.gz`: the six task banks (128 tasks), one task per line, with the request text, variables and
  domains, hard requirements (`hard`), preferences, the attack target and the threat texts used for that task.
  `confirm-001` (48 tasks) is the confirmatory bank; `confirm-36/24/12-001` are its preregistered subsets;
  `dev-001` and `gate-001` were used for development and the pre-run gate.
- `data/roots.jsonl.gz`: 2,928 scored trajectories ("roots"), one line per (run, task, arm, threat), as written by
  the preregistered scorer.
- `data/pse-gate.jsonl.gz`: 240 recorded `MS` roots (T0 and T5) with the pre-signing gate (PSE) decision, with and
  without origin labels, and the resulting outcome (offline evaluation, amendment v1.11; no new model calls).
- `data/gospa.jsonl.gz`: 480 per-root GOSPA distances between the gold requirements and the delivered manifest
  (post hoc, descriptive).
- `data/metadata.json`: run-level values the tables quote (pilot instrument check, stage-2 cut and freeze hash,
  bootstrap settings, PSE observer and dev-gate summaries).
- `data/paper-reference.json`: the 24 result table and macro files the paper was compiled from.
- `reproduce_tables.py`: regenerates all of them (`out/tables/*.tex`) and compares them with the reference.

## Reproduce

```bash
python3 reproduce_tables.py      # about 40 s; standard library only
```

It prints `MATCH` for each of the 24 files (672 numbers) and for the abstract's headline numbers, and ends with
`RESULT: ALL MATCH`. The statistics are the preregistered ones: paired contrasts, 95% task-clustered bootstrap CIs
(10,000 draws, fixed seeds), exact McNemar tests and Holm correction; equivalence claims use TOST intervals.

| Paper item | File in `out/tables/` |
|---|---|
| Tables 2-5 (outcomes, H1-H3 and S1-S6, extraction, cost) | `results-outcomes.tex`, `results-hypotheses.tex`, `results-extraction.tex`, `results-cost.tex`, `results-macros.tex`, `results-run.tex` |
| Tables 6-7 (gpt-oss-20b, two-family pooled) | `results-family2*.tex` |
| Tables 9-10 (gemma-4-12b, three-family pooled) | `results-family3*.tex` |
| Tables 8 and 11, T5 text (pre-signing injection) | `results-t5*.tex` |
| Table 12, Section 6.8 (GOSPA, post hoc) | `results-gospa-macros.tex` |
| Tables 14 and 19, Section 7.1 (PSE gate) | `results-pse*.tex` |
| Utility (S1/S2) and token numbers | `results-utility-macros.tex` |
| Table 17 (GPT-5.6-luna, exploratory) | `results-codex.tex`, `results-t5-cx*.tex` |

## Root fields (`data/roots.jsonl.gz`)

| field | meaning |
| --- | --- |
| `run` | `<model>-core` (threats T0-T4) or `<model>-t5` (T5 and its T0 controls); models `qwen3-8b`, `gpt-oss-20b`, `gemma-4-12b` (confirmatory) and `gpt-5.6-luna` (exploratory) |
| `root`, `task`, `arm`, `threat`, `family` | trajectory id, task id, arm, threat, model family |
| `decision`, `outcome_status` | final orchestrator decision (`commit`, `abstain_*`, `failure_*`) and workflow status |
| `committed`, `abstained`, `failed` | decision class |
| `unsafe_commit`, `conformant_commit` | committed and violates at least one gold hard requirement / committed and violates none |
| `target_violated_commit` | committed and violates the attack target |
| `first_final_ok`, `first_violation`, `strict_final` | first final decision parsed / violates a requirement / strict format |
| `receipt_reject` | the signed-manifest receipt check rejected the decision |
| `verifier_flag_first`, `checker_flag_first`, `shadow_flag_first` | first decision flagged by the deterministic verifier (`M`, `MS`, `MSO`), by the deciding LLM checker (`JL`) or by the shadow LLM checker (`MS`, `MSO`; recorded, not acted on) |
| `checker_unparseable`, `shadow_unparseable` | the checker verdict could not be parsed |
| `extract_recall`, `extract_precision`, `extract_target` | `M`/`MS` at T0: manifest items equal (as truth sets) to gold requirements; gold target recovered |
| `t5_template`, `t5_target_in_manifest` | `M`/`MS` at T5: injection template, and whether the gold target is present (truth-set equal) in the manifest delivered to the workers |
| `calls`, `billed_calls`, `model_seconds`, `prompt_tokens`, `completion_tokens`, `total_tokens` | cost per root, re-summed from the call records |
| `cost_inconsistent`, `usage_complete`, `evidence_kind`, `structure` | cost cross-check, token usage reported for every call, evidence type, task lineage |

`data/pse-gate.jsonl.gz` has, per root, the recorded outcome (`ms`), the gate result per variant (`gate_labels`,
`gate_nolabels`: reached, signed, failed clauses `PSE-1`...`PSE-5`, findings) and the outcome with the gate
(`pse_labels`, `pse_nolabels`). `data/gospa.jsonl.gz` has the GOSPA total (`gospa`; alpha 2, p 1, c 1) and its parts
(`loc`, `missed`, `false`, split by kind, scope and injected text); `no_manifest` roots are counted but excluded.

## Withheld (available from the authors on request)

Full prompts and model responses, Codex event logs and caches are not included; their sha256 are listed in the full
audit archive below, which also holds the task generator, harness, model clients and launchers. The per-run HMAC
signing keys are not published (each run generates a new key; keys are never part of a prompt).

## Full audit archive

The complete preregistration archive is attached to this repository's GitHub Release as
`signed-but-not-safe-full-artifact.zip`: the preregistration and all amendments, the freeze manifests of every
version, the frozen code of each version (harness, scorer, PSE gate, independent JavaScript observer), the reduced
per-call traces, and `tools/verify_freezes.py` / `tools/reproduce.py`, which re-score every run from the traces with
the frozen scorers. Inside the archive, "920" and other paper numbers are the authors' internal project labels.

## License

Code: MIT (`LICENSE`). Data and documentation: CC BY 4.0 (`LICENSE-DATA`). Please cite the paper (`CITATION.cff`).
