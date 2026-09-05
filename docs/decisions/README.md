# Design contracts

Design records are strict JSON files named `docs/decisions/<design-id>.json`,
where `design-id` is a lowercase UUID. Add a record through a `design-only` pull
request before writing implementation code. An implementation PR can reference
only a matching record already present in its base revision.

Scaffolded records are shape-valid drafts, not approved or merge-ready designs.
Replace every `EDIT ME`, `TODO`, `TBD`, and MergeGrounds template sentinel before
review; contract validation rejects unresolved placeholders in scalar text and
string arrays.

The accepted closed-world schema has these top-level fields:

```text
schema_version, design_id, title, problem, goals, non_goals, decisions,
invariants, trust_boundaries, failure_modes, rollback, observability, evaluation
```

`evaluation.acceptance_criteria` contains the canonical full definitions used by
the future implementation declaration. Each criterion has:

```json
{
  "id": "AC-POSITIVE",
  "class": "positive",
  "observable": "The externally visible result and its measurable boundary",
  "oracle": {
    "kind": "test",
    "ref": "TEST-POSITIVE",
    "evidence_class": "trusted_execution"
  },
  "failure_behavior": "A failed or missing observation denies the decision"
}
```

The strict R3/R4 baseline requires positive, negative, adversarial, and recovery
criteria. Failure modes reference a non-positive oracle. Invariants and rollback
verification reference criterion IDs. `evaluation.outcome_metrics` must define
at least one end-to-end signal with a trusted source, baseline and observation
windows, direction, numeric target, sample/missingness limits, and a
promotion-blocking failure action. Coding speed or model confidence is not an
outcome metric. Change declarations reference these canonical metric IDs without
redefining them.

Decision rationale is review context, not evidence. Model reasoning, model
confidence, author assertions, and self-review cannot satisfy any oracle or
independent challenge requirement.
