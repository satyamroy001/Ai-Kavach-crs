# Design Decisions

This file records why key choices were made, so the reasoning is visible — not just the
final architecture.

## Why AFL++ over other fuzzers
AFL++ is actively maintained, has the largest community and documentation base of any
coverage-guided fuzzer, and supports the sanitizer/instrumentation modes we need for
crash triage. Alternatives considered: libFuzzer (good for library-level targets, less
suited to whole-binary fuzzing), honggfuzz (solid but smaller community — harder to debug
issues quickly during a time-boxed hackathon build).

## Why binary-first support matters here specifically
Most published autonomous vulnerability-finding systems (including AIxCC entrants) assume
source code access, because their target set is open-source software. Defence
infrastructure frequently does not offer that — legacy firmware, closed third-party
binaries, systems where the original build environment no longer exists. Designing around
"what if we only have the binary" from the start, rather than bolting it on later, is a
deliberate scope decision to fit the actual problem statement (Armed Forces
infrastructure), not just the easier open-source case.

## Why a human-in-the-loop gate instead of full autonomy
Fully autonomous, unsupervised patching of live defence infrastructure is a governance
risk, not just a technical one — even a high-accuracy system will be wrong sometimes, and
the cost of an unreviewed bad patch on real infrastructure is much higher than the cost of
a short human review delay. A confidence-gated review step is a deliberate trust and
safety decision, not a limitation of the system's capability.

## Why reachability scoring instead of flat severity
A bug's danger depends on whether an attacker can actually get to it, not just how bad
the bug is in isolation. Two identical buffer overflows — one reachable from an
internet-facing login API, one only reachable from an internal admin tool — represent very
different real-world risk. Prioritizing by reachability (and specifically by which network
security boundary is crossed) reflects how real security teams triage, rather than
treating every finding as equally urgent.

## Why multiple candidate patches instead of one
A single generated patch might compile and pass the immediate test but be a larger, riskier
change than necessary, or might fix the symptom without fixing the underlying cause.
Generating several candidates and ranking them by diff size and regression outcome mirrors
how a careful human reviewer would compare fix options rather than accepting the first
thing that works.

## Why local/offline LLM instead of a cloud API
Classified or sensitive defence code cannot be sent to an external cloud service. An
offline-capable model is a hard requirement for real deployment, not an optimization — so
it was built in as a starting constraint rather than adapted later.
