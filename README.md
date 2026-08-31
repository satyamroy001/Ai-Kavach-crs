# AI Kavach — Autonomous Cyber Reasoning System
# PRAGYAN-BHARAT 🇮🇳 (Made in India)
An LLM-driven system that autonomously **finds**, **patches**, and **proves the fix** for
software vulnerabilities in defence-relevant infrastructure — including binary-only,
air-gapped, legacy targets where source code and internet access aren't guaranteed.

Built for the AI Kavach hackathon.

## Problem

Defence and mission-critical infrastructure frequently operates under severe analysis constraints: legacy C/C++ code, closed firmware, limited build environments, incomplete source visibility, restricted execution environments, and zero external network connectivity. Conventional vulnerability-analysis workflows struggle in such conditions because they often depend on complete build pipelines, extensive dependencies, cloud-based intelligence, or isolated detection signals.

PRAGYAN-BHARAT addresses this gap through an evidence-driven autonomous security reasoning architecture that combines structural program intelligence, static analysis, dynamic fuzzing, sanitizer-based validation, security-relationship graphs, and local LLM reasoning. Rather than treating a suspicious pattern as a vulnerability, the system investigates the underlying execution path, data flow, ownership, lifetime, concurrency and attacker-reachable conditions.

The architecture extends beyond conventional find–patch–verify automation by introducing multi-hypothesis reasoning, CWE-grounded verification, dual-LLM cross-examination, adversarial negative-feedback loops, and repair-safety validation. A generated patch is therefore evaluated not merely for compilation, but for root-cause removal, behavioral preservation, ownership/lifetime correctness, synchronization safety, secondary vulnerability prevention, and reproducibility.

The objective is a self-contained cyber-reasoning pipeline capable of producing security decisions that are evidence-grounded, explainable, auditable and verifiable—even when the analysis environment is isolated from the internet.

## Architecture

Full pipeline diagram and stage-by-stage explanation: [`docs/architecture.md`](docs/architecture.md)

High level: **Ingestion → Discovery → Triage → Reachability scoring → Patch generation
→ Adversarial verification ("Cyber Courtroom") → Confidence-gated human review →
Signed patch + report → Memory feedback**

## What makes this different

1. **Binary-first analysis** — Ghidra/angr-based lifting for targets with no source
   available, not just source-code scanning.
2. **Cross-domain attack reachability graph** — scores each bug by whether an attacker
   can actually reach it, and *which network security boundary* they'd have to cross to
   do so (unclassified-facing vs. air-gapped/classified segment) — not just a flat
   file:line severity number.
3. **Cyber Courtroom verification** — instead of a single pass/fail check, the patch is
   argued over by role-based agents (attacker, defender, judge) before being declared
   trustworthy, on top of an adversarial agent that actively tries to re-break it.
4. **Confidence engine** — fuses signals from multiple tools (static analysis, sanitizers,
   fuzzer reproduction) into one calibrated confidence score instead of trusting any single
   tool's verdict.
5. **Confidence-gated human review** — low-confidence patches route to a human analyst
   instead of auto-deploying, matching real defence deployment requirements.
6. **Air-gapped local LLM + growing memory** — runs entirely offline (Ollama + local model),
   with a vulnerability "fingerprint" memory (bug pattern, CWE, reachability, confidence)
   that improves triage and patching over repeated runs.
7. **Multi-candidate patch ranking** — generates several possible fixes per bug, ranks by
   minimal code change + regression pass rate, picks the smallest safe fix.
8. **Signed patch provenance** — every deployed patch produces a signed, chained record of
   what changed, why, what evidence supported it, and what approved it — so months later
   there's an auditable answer to "what did the autonomous system change, and why."
9. **Auto-generated explainability reports** — every fixed vulnerability produces a
   human-readable report for analyst review and audit trail.

See [`docs/decisions.md`](docs/decisions.md) for why these choices were made over the
alternatives we considered.

## Status

Active work in progress. See the roadmap below for what's implemented vs. planned — this
section is kept honest and updated as the project progresses, not written all at once.

## Roadmap

- [x] Architecture design
- [x] Environment + toolchain setup
- [x] Demo vulnerable target
- [x] Manual fuzzing baseline (AFL++)
- [x] LLM-based crash triage
- [ ] Attack reachability graph (prototype)
- [ ] LLM-based patch generation (multi-candidate)
- [ ] Adversarial verification agent ("Cyber Courtroom")
- [ ] Confidence engine (multi-tool fusion)
- [ ] Regression test harness
- [ ] Explainability report generator
- [ ] Signed patch provenance chain
- [ ] End-to-end automated pipeline
- [ ] Demo dashboard

## Tech stack

- Fuzzing: AFL++
- Static analysis: CodeQL, Semgrep
- Dynamic analysis: AddressSanitizer (ASan)
- Binary analysis: Ghidra.
- LLM: Ollama (local, offline) — Qwen2.5-Coder
- Orchestration: Python
- Target language (initial): C

## Known limitations (current stage)

- Currently scoped to single-input crash cases; multi-input/stateful triage not yet
  implemented.
- Reachability graph is currently manually annotated for the demo target, not yet
  auto-derived from call-graph analysis.
- Tested only on a small demo target so far, not a full real-world codebase.

## Setup

See [`docs/setup.md`](docs/setup.md) (added as the toolchain is finalized).

## Project log

Session-by-session build notes: [`docs/devlog.md`](docs/devlog.md)

## License

MIT — see [`LICENSE`](LICENSE)
