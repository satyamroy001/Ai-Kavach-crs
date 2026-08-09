# Architecture

## Pipeline overview

```
Ingestion (source or binary)
        │
        ▼
Discovery (fuzzing + static analysis + harness synthesis)
        │
        ▼
Triage (crash dedup + CWE clustering)
        │
        ▼
Reachability scoring (attack graph + network-domain crossing)
        │
        ▼
Patch generation (multiple candidates, LLM-driven)
        │
        ▼
Cyber Courtroom verification (attacker / defender / judge agents
   + adversarial patch-breaker + regression + differential testing)
        │
        ▼
Confidence engine (fuses tool signals into one score)
        │
        ▼
Confidence-gated human review
        │
        ▼
Signed patch + explainability report + provenance chain
        │
        ▼
Memory feedback (vulnerability fingerprint store, RAG)
```

## Stage details

### 1. Ingestion
Accepts either source code or a compiled binary. If only a binary is available (the
common case for legacy/closed defence systems), Ghidra performs headless decompilation
and angr lifts the result to an intermediate representation the rest of the pipeline can
reason over.

### 2. Discovery
- **Harness synthesis agent**: LLM writes fuzz entry-point wrappers automatically, since
  hand-writing harnesses (as required by tools like OSS-Fuzz) doesn't scale to novel
  targets.
- **AFL++**: coverage-guided fuzzing for the bulk of input-space exploration.
- **Static analysis (CodeQL/Semgrep)**: pattern- and taint-based detection to catch bug
  classes fuzzing alone might miss or take too long to find.

### 3. Triage
Deduplicates crashes that are really the same underlying bug, and localizes the root
cause line rather than just the crash site.

### 4. Reachability scoring
Builds a call/data-flow graph from entry points (e.g. a network-facing API) down to the
buggy function. Each edge is annotated with which network security boundary it crosses
(e.g. unclassified-facing service → DMZ → classified/air-gapped segment). A bug reachable
from an external-facing surface is scored higher priority than the same bug reachable only
from an isolated internal tool, even though the code-level severity is identical.

### 5. Patch generation
Given the localized bug, generates 3–5 candidate patches using different strategies
(bounds check, input validation, restructure). Each candidate is scored on diff size and
whether it risks reintroducing the same CWE class elsewhere in the file.

### 6. Cyber Courtroom verification
Structures verification as argued roles rather than a single check:
- **Attacker agent**: actively tries to defeat the patch — replays the original crash,
  mutates it, searches adjacent code paths for the same class of bug.
- **Defender agent**: explains why the patch should hold.
- **Judge**: weighs both, informed by the regression harness (original PoV re-run,
  differential testing of old vs. patched behavior on benign inputs, timed fuzz soak).
A patch is only "proven" if it survives this process, not merely if one test passes.

### 7. Confidence engine
Fuses signals from every tool that touched the bug (static analysis confidence, sanitizer
certainty, fuzzer reproducibility, courtroom verdict) into one calibrated score, rather
than trusting any single tool's verdict in isolation.

### 8. Human review gate
Patches above a confidence threshold can proceed automatically; patches below it are
routed to a human analyst dashboard before anything touches real infrastructure. This is
a deliberate design choice for a defence context — see `decisions.md`.

### 9. Provenance + reporting
Every deployed patch produces a signed, hash-chained record (what changed, why, what
evidence supported it) plus a human-readable explainability report, so the change is
auditable after the fact.

### 10. Memory feedback
Every vulnerability's fingerprint (bug pattern, CWE class, reachability, confidence,
patch outcome) is stored and used to guide future fuzzing seeds and patch suggestions on
the same or similar codebases.
