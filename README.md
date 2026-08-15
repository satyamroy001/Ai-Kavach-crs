# AI Kavach — Autonomous Cyber Reasoning System
# PRAGYAN-BHARAT 🇮🇳 (Made in India)
An LLM-driven system that autonomously **finds**, **patches**, and **proves the fix** for
software vulnerabilities in defence-relevant infrastructure — including binary-only,
air-gapped, legacy targets where source code and internet access aren't guaranteed.

Built for the AI Kavach hackathon.

## Problem

Real defence infrastructure often runs closed firmware and legacy C/C++ code with no
build access, no source, and no internet connectivity. Existing autonomous vulnerability
research — such as DARPA's AI Cyber Challenge (AIxCC), won by Team Atlanta's ATLANTIS
system in August 2025 — targets open-source software with cloud LLM access and known
source code. That's a different, easier constraint set than defence infrastructure
actually presents.

This project adapts the same core idea — an LLM paired with fuzzers, static/dynamic
analysis, and a regression harness — to that harder, more realistic environment, and adds
reasoning layers a raw find-patch-verify loop doesn't have: knowing *whether an attacker
can actually reach a bug*, and *whether a patch can be trusted*, not just whether it compiles.

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
