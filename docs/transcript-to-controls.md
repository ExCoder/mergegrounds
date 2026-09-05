# Transcript-to-control traceability

Status: engineering interpretation of the supplied transcript

The transcript is an input to threat modelling, not an authority record. Its named studies, dates, percentages, and anecdotes must be checked against primary sources before they are quoted as factual evidence or used to set a threshold. MergeGrounds does not depend on those numbers: it converts each plausible failure mode into a falsifiable control with explicit failure semantics.

| Transcript theme | Engineering mistake to prevent | Enforced or required response | Primary control location |
|---|---|---|---|
| Visible reasoning is not the model's trustworthy internal process | accepting a coherent chain-of-thought, confidence, or longer deliberation as correctness evidence | keep reasoning out of evidence; test the observable result against an independently defined oracle; retain only concise claims needed for review | `MG-META-003`; [`ai-assisted-development.md`](ai-assisted-development.md); [`evidence.md`](../skills/mergegrounds/references/evidence.md) |
| Faster generation is not necessarily faster delivery | reporting token/code-generation time or lines produced as productivity while review, debugging, incidents, and comprehension get worse | measure reviewed-design-to-production lead time, first-pass yield, review/rework/debug time, 7/30-day corrective churn, escapes, change-failure rate, recovery, complexity, duplication, knowledge spread, and total cost by comparable cohort | `MG-QLT-008`; [`governance-and-metrics.md`](governance-and-metrics.md) |
| Memory/RAG does not eliminate fabricated or unsupported answers | evaluating only generation while retrieval returns similar-but-wrong, stale, poisoned, or unauthorized content | test retrieval separately; bind corpus/index/retriever/reranker identities; gate relevance, no-support abstention, citations to exact spans, freshness, tenant ACLs, hybrid/reranked retrieval, and misleading-neighbor cases | `MG-AI-003`; [`ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) |
| “Check again” is correlated self-review | letting the authoring session confirm the user's diagnosis or approve its own patch | use a clean-context challenger initially unseeded with the author's conclusion; seek disconfirming cases; require independent human approval and explain-back; treat additional models only as defense in depth | `MG-REV-002`; [`ai-assisted-development.md`](ai-assisted-development.md) |
| Public benchmarks can be contaminated, non-executable, or gamed | selecting/promoting a model from a leaderboard, hiding skipped cases, or trusting an aggregate over a failed critical slice | use product-specific executable cases, exact case accounting, protected/private or time-split holdouts, overlap analysis, baseline-equivalent execution, critical-slice gates, and production canary/shadow evaluation | `MG-AI-002`; [`ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) |
| Fine-tuning can improve the target while degrading unrelated behavior | checking only the optimized metric or comparing against a mutable marketing model name | bind base/tokenizer/data/recipe/runtime/candidate identities; compare candidate with exact base and production baselines on target, retained capability, safety, privacy, authorization, injection, cost, and incident regressions; rehearse rollback | `MG-AI-005`; [`ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) |
| Context capacity is not dependable working memory | assuming that every provided document/fact was found, connected, or preserved after truncation | test beginning/middle/end position, low lexical overlap, aliases, multi-fact/multi-hop load, distractors, conflict, exact boundary, overflow, and explicit omission; bind ordered context and token/truncation manifests | `MG-AI-004`; [`ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) |
| Prompt politeness is not a security or privacy control | relying on tone, presumed model memory, or a provider promise instead of governing data and retained conversation state | classify/minimize context; never send secrets by default; treat chat memory, logs, summaries, training use, retention, deletion, location, subprocessors, and human access as provider/system controls; require a protected provider approval and runtime reconciliation | `MG-AI-006`; [`ai-product-assurance.md`](../skills/mergegrounds/references/ai-product-assurance.md) |

The transcript's agent/benchmark anecdote also motivates a separate execution-boundary rule: an evaluator or coding agent may optimize for task completion by exploiting package registries, network access, local Actions, ambient tokens, caches, or other side channels. Model intent is irrelevant. `MG-AI-007`, the untrusted-runner threat model, Python isolated mode, rejection of candidate-local Actions, deny-by-default egress, capability brokering, and immutable evidence subjects constrain what the process can do and make violations observable.

## Decision rule

A transcript claim becomes an engineering requirement only after this translation:

1. state the failure mode without relying on the anecdote or percentage;
2. identify the protected asset, trust boundary, and accountable owner;
3. define an observable positive, negative, adversarial, and recovery oracle;
4. bind evidence to the exact source/model/data/configuration subject and an authorized producer;
5. fail on missing, partial, stale, skipped, contaminated, or identity-mismatched evidence;
6. measure production outcomes and revisit the control when its assumptions or platform behavior change.

This prevents a persuasive video, paper abstract, vendor benchmark, or model explanation from becoming policy merely because it sounds plausible—the same epistemic standard the code gate applies to generated code.
