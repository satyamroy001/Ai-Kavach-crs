# PRAGYAN-BHARAT 🇮🇳

### Autonomous Cyber Reasoning & Vulnerability Triage System

> **AI Kavach — Autonomous Cyber Reasoning System**

> [!NOTE]
> **Repository Status:** Due to an ongoing evaluation and selection phase, core production code has been temporarily restricted. 
> * **Live Demos:** You can review working demonstrations and output artifacts inside the `targets/` folder.
> * **Fully Available Module:** **Stage Zero** (our Password and Sensitive Information Analyzer) is fully open and available to view in this repository- (password.py file).


PRAGYAN-BHARAT is an offline-first, evidence-driven cyber reasoning system designed to investigate software vulnerabilities in security-critical and defence-relevant environments.

Instead of relying on a single scanner or a single LLM decision, PRAGYAN-BHARAT combines **program structure, code property graphs, static analysis, dynamic execution evidence, sanitizers, fuzzing, and local LLM reasoning** to determine whether a suspected vulnerability is actually reachable, exploitable, and worth fixing.

The system is designed around a simple principle:

> **A suspicious line is not automatically a vulnerability. A vulnerability decision should be supported by evidence.**

---
Basic structure for Fuzzing and CodeQL- Heart of Pragyan-
PRAGYAN_BHARAT_WORKSPACE/
└── example_Candidate_Analysis/
    ├── AFL++/
    │   ├── seeds/
    │   ├── findings/
    │   ├── crashes/
    │   └── AFL_compact.txt
    ├── CodeQL/
    │   ├── database/
    │   ├── results/
    │   └── CodeQL_compact.txt
    ├── ASAN/
    │   ├── logs/
    │   └── ASAN_compact.txt
    ├── UBSAN/
    │   ├── logs/
    │   └── UBSAN_compact.txt
    ├── LLM/
    │   ├── execution_plan.txt
    │   ├── initial_analysis.txt
    │   └── candidate_generation.txt
    ├── Candidates/
    │   ├── example_Candidate1.cpp
    │   ├── example_Candidate2.cpp
    │   └── example_Candidate3.cpp
    └── FINAL_EVIDENCE.txt

## 1. Problem

Security-critical software is often difficult to analyze using conventional vulnerability scanners.

Real environments may contain:

* Legacy C/C++ software
* Large and complicated control/data flows
* Incomplete source visibility
* Limited build environments
* Offline or air-gapped systems
* Restricted execution environments
* Multiple interacting functions and components
* False positives from individual static-analysis tools
* Vulnerabilities that require a specific execution path to trigger

A conventional scanner may report:

```text
file.c:42 → suspicious memory operation
```

But that does not answer the questions that matter to a security analyst:

* Is the code actually reachable?
* Where does the input originate?
* Is the input attacker-controlled?
* What functions does the data pass through?
* Is there a security boundary involved?
* Can the condition actually be triggered?
* Can a sanitizer reproduce the failure?
* Can fuzzing reproduce the crash?
* What CWE best describes the root cause?
* Does a proposed fix actually remove the vulnerability?
* Did the fix introduce another bug?
* Can the result be independently verified?

PRAGYAN-BHARAT is designed to reason across these questions.

---

# 2. Core Architecture

```text
                         PRAGYAN-BHARAT
                               │
                               ▼
                    ┌─────────────────────┐
                    │   SOURCE INGESTION  │
                    │   Single-file input │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ LANGUAGE DETECTION  │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼──────────────────┐
             │                 │                  │
             ▼                 ▼                  ▼
      ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
      │ Tree-sitter │   │    Joern    │   │   CodeQL    │
      │ AST / Parse │   │     CPG     │   │  Semantic   │
      │ Structure   │   │ Data / Call │   │  Analysis   │
      └──────┬──────┘   │    Flow     │   └──────┬──────┘
             │          └──────┬──────┘          │
             │                 │                  │
             └─────────────────┼──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ SECURITY EVIDENCE   │
                    │     COLLECTION      │
                    └──────────┬──────────┘
                               │
                 ┌─────────────┼──────────────┐
                 │             │              │
                 ▼             ▼              ▼
          ┌───────────┐ ┌───────────┐ ┌────────────┐
          │  AFL++    │ │ ASan /    │ │ Semgrep /  │
          │  Fuzzing  │ │ UBSan     │ │ Static     │
          │           │ │ Runtime   │ │ Patterns   │
          └─────┬─────┘ └─────┬─────┘ └──────┬─────┘
                │             │              │
                └─────────────┼──────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ EVIDENCE MERGER     │
                    │ Human-readable      │
                    │ security report     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ LOCAL LLM REASONING │
                    │      Ollama         │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
         ┌────────────┐ ┌────────────┐ ┌────────────┐
         │ Security  │ │ Candidate  │ │ CWE / Root │
         │ Reasoning │ │ Analysis   │ │ Cause      │
         └─────┬──────┘ └─────┬──────┘ └─────┬──────┘
               │              │              │
               └──────────────┼──────────────┘
                              ▼
                    ┌─────────────────────┐
                    │ GRAPH VISUALIZATION │
                    │ Graphviz / GraphML  │
                    └─────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │ ANALYST-READY       │
                    │ SECURITY RESULT     │
                    └─────────────────────┘
```

---

# 3. Analysis Philosophy

PRAGYAN-BHARAT follows an **evidence-first reasoning model**.

A finding is not considered trustworthy merely because one tool reports it.

Instead, evidence is accumulated from multiple analysis layers:

```text
Program Structure
       +
Call/Data Flow
       +
Static Security Findings
       +
Runtime Behaviour
       +
Fuzzing Evidence
       +
Sanitizer Evidence
       +
LLM Security Reasoning
       ↓
Security Decision
```

This allows the system to distinguish between:

```text
SUSPICIOUS CODE
      ↓
POSSIBLE VULNERABILITY
      ↓
REACHABILITY ANALYSIS
      ↓
EXPLOITABILITY ANALYSIS
      ↓
EVIDENCE CORRELATION
      ↓
SECURITY CLASSIFICATION
```

---

# 4. Major Components

## 4.1 Tree-sitter

Tree-sitter provides language-aware source parsing and structural information.

It is used to extract information such as:

* Functions
* Variables
* Calls
* Conditions
* Expressions
* Control structures
* Source locations
* Syntax relationships

The resulting structural information can also be used for graph generation and visualization.

Tree-sitter provides the initial structural representation before deeper security reasoning.

---

## 4.2 Joern

Joern is the primary **Code Property Graph (CPG)** analysis component.

It provides a deeper representation of relationships between program elements, including:

* Abstract syntax
* Control flow
* Data flow
* Call relationships
* Function relationships
* Taint-style propagation
* Source-to-sink relationships

Conceptually:

```text
INPUT
  │
  ▼
SOURCE
  │
  ▼
FUNCTION A
  │
  ▼
FUNCTION B
  │
  ▼
VALIDATION
  │
  ▼
SINK
```

Instead of examining a vulnerable statement in isolation, PRAGYAN-BHARAT can reason about the surrounding program relationships.

### Why Joern?

A security finding becomes significantly more useful when the system understands:

```text
WHO controls the data?
        ↓
WHERE does it originate?
        ↓
HOW does it propagate?
        ↓
WHICH functions process it?
        ↓
WHERE does it reach?
        ↓
CAN the attacker influence the sink?
```

Joern provides the CPG foundation for this reasoning.

---

# 5. CodeQL

CodeQL provides semantic security analysis and query-based vulnerability detection where the target language and environment are supported.

It complements Joern rather than replacing it.

The architecture therefore uses:

```text
Joern  → structural relationships / CPG / data-flow reasoning

CodeQL → semantic security queries / vulnerability patterns

Tree-sitter → source parsing / structural representation
```

Multiple independent representations reduce dependence on one analysis engine.

---

# 6. Static Security Analysis

PRAGYAN-BHARAT can incorporate local static-analysis evidence from tools such as:

* CodeQL
* Semgrep
* Other available language-specific analysis tools

Static findings are treated as **evidence**, not unquestionable truth.

For example:

```text
Static Tool:
Potential buffer overflow

        ↓

PRAGYAN-BHARAT:
Investigate source → data flow → call flow → conditions → runtime evidence
```

This reduces the risk of blindly forwarding scanner output to an LLM.

---

# 7. AFL++ Dynamic Analysis

For suitable native targets, PRAGYAN-BHARAT integrates AFL++ for dynamic fuzzing.

The objective is to discover execution paths that can trigger abnormal behaviour.

The workflow is approximately:

```text
Source
  ↓
Instrumented Build
  ↓
Seed Generation
  ↓
AFL++
  ↓
Execution
  ↓
Crash / Interesting Input
  ↓
Reproduction
  ↓
ASan / UBSan
  ↓
Evidence
```

AFL++ is primarily relevant to native fuzzing workflows such as C/C++ targets.

It is therefore treated as a conditional analysis stage rather than pretending that fuzzing applies identically to every supported language.

---

# 8. ASan and UBSan

Runtime sanitizers provide concrete execution evidence.

### AddressSanitizer

ASan helps detect memory-safety problems including:

* Buffer overflows
* Use-after-free
* Stack/heap memory violations
* Other invalid memory accesses

### UndefinedBehaviorSanitizer

UBSan helps identify classes of undefined behaviour during execution.

Together with fuzzing:

```text
AFL++ discovers input
        ↓
Program executes
        ↓
ASan / UBSan observes failure
        ↓
Crash evidence
        ↓
PRAGYAN-BHARAT correlates crash with source
```

This provides stronger evidence than a static warning alone.

---

# 9. Evidence Correlation

The central component of PRAGYAN-BHARAT is the **evidence merger**.

Instead of sending isolated tool outputs to the LLM:

```text
CodeQL output
AFL++ output
ASan output
UBSan output
Joern analysis
Tree-sitter structure
Static findings
Source code
```

are consolidated into a human-readable security evidence report.

Conceptually:

```text
                 ┌─────────────┐
                 │   Source    │
                 └──────┬──────┘
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
      Joern          CodeQL          Tree-sitter
        │               │                │
        └───────────────┼────────────────┘
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
      AFL++            ASan             UBSan
        │               │                │
        └───────────────┼────────────────┘
                        ▼
              ┌──────────────────┐
              │ Evidence Merger  │
              └────────┬─────────┘
                       ▼
             SECURITY EVIDENCE FILE
                       │
                       ▼
                 LOCAL LLM
```

The LLM therefore reasons over evidence rather than generating a vulnerability verdict from source code alone.

---

# 10. Local LLM Reasoning

PRAGYAN-BHARAT uses **Ollama** to run the reasoning model locally.

The intended deployment model is:

```text
Internet
   ✕
   │
   │
┌──▼─────────────────────────┐
│       Local System         │
│                            │
│ Source                     │
│ Analysis Tools             │
│ Security Evidence          │
│ Ollama                     │
│ Local Coding/Security LLM  │
└────────────────────────────┘
```

This architecture is suitable for environments where source code and security evidence cannot be sent to external cloud APIs.

The LLM is not treated as the sole vulnerability detector.

Instead:

> **Tools produce evidence. The LLM reasons over the evidence.**

---

# 11. Security Relationship Reasoning

PRAGYAN-BHARAT focuses on relationships rather than isolated lines.

Important relationships include:

```text
SOURCE → DATA FLOW → TRANSFORMATION → SINK

CALLER → FUNCTION → CALLEE

INPUT → VALIDATION → SECURITY CHECK → SINK

ALLOCATE → USE → MODIFY → FREE

LOCK → SHARED STATE → UNLOCK
```

This allows the reasoning layer to investigate classes of security relationships involving:

* Data flow
* Control flow
* Input validation
* Memory ownership
* Lifetime
* Resource handling
* Synchronization
* Trust boundaries
* Source-to-sink relationships

---

# 12. Graph Representation

Security relationships can be represented as graphs.

Example:

```text
                 ┌──────────────┐
                 │ External     │
                 │ Input        │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Parser       │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Validation   │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Processing   │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ Sensitive    │
                 │ Sink         │
                 └──────────────┘
```

Graphviz/GraphML artifacts can be generated to make these relationships inspectable by analysts.

---

# 13. PRAGYAN-BHARAT Reasoning Pipeline

The complete reasoning workflow is:

### Stage 1 — Ingestion

Accept a target source file and identify the applicable analysis workflow.

### Stage 2 — Structural Analysis

Parse the program using Tree-sitter and derive structural relationships.

### Stage 3 — Code Property Graph

Use Joern where applicable to construct deeper program relationships.

### Stage 4 — Static Analysis

Run applicable static-analysis engines and collect security findings.

### Stage 5 — Dynamic Analysis

For supported native targets, execute AFL++ fuzzing and sanitizer-assisted analysis.

### Stage 6 — Evidence Correlation

Combine tool outputs into a single security evidence representation.

### Stage 7 — LLM Security Reasoning

The local LLM evaluates:

* Root cause
* Reachability
* Data flow
* Control flow
* Security conditions
* Potential CWE classification
* Evidence consistency
* False-positive likelihood

### Stage 8 — Result Generation

Produce:

* Human-readable security report
* Security relationships
* Graph artifacts
* Evidence summary
* Vulnerability classification
* Analyst-oriented reasoning

---

# 14. Multi-Tool Reasoning

PRAGYAN-BHARAT is deliberately designed so that no individual tool becomes the final authority.

For example:

```text
                 CodeQL
                   │
                   ▼
              Static finding
                   │
                   │
Joern ───────► Data-flow ───────► Security reasoning
                   │                    ▲
Tree-sitter ─► Structure              │
                                        │
AFL++ ───────► Crash ───────► ASan ────┘
                                        │
UBSan ───────► Runtime evidence ────────┘
```

A finding supported by several independent evidence sources receives stronger confidence than an isolated warning.

---

# 15. Vulnerability Triage

The system is intended to distinguish between:

### False Positive

```text
Suspicious pattern
      ↓
Not attacker reachable
      ↓
No exploitable condition
      ↓
Likely false positive
```

### Potential Vulnerability

```text
Suspicious pattern
      ↓
Reachable
      ↓
Security-sensitive data flow
      ↓
Exploit conditions appear possible
      ↓
Potential vulnerability
```

### Confirmed Runtime Vulnerability

```text
Suspicious pattern
      ↓
Reachable
      ↓
Triggering input
      ↓
Observed failure
      ↓
ASan / UBSan evidence
      ↓
Reproducible vulnerability
```

The distinction between these states is important for reducing analyst noise.

---

# 16. Patch Generation and Verification

The long-term PRAGYAN-BHARAT architecture extends beyond vulnerability discovery.

Once a vulnerability is sufficiently established, the system can generate candidate repairs.

The intended workflow is:

```text
Confirmed Vulnerability
          ↓
Root Cause Analysis
          ↓
Generate Candidate Fixes
          ↓
Compile / Validate
          ↓
Regression Testing
          ↓
Re-run Security Analysis
          ↓
Adversarial Verification
          ↓
Accept / Reject Patch
```

A patch should not be considered successful merely because it compiles.

The verification process should establish that:

* The original vulnerability is removed.
* The vulnerable path is no longer exploitable.
* Existing behaviour is preserved where required.
* The repair does not introduce a new vulnerability.
* Relevant tests still pass.
* Runtime evidence no longer reproduces the original failure.

---

# 17. Cyber Courtroom

A planned verification layer is the **Cyber Courtroom**.

Instead of allowing the same reasoning process that generated a patch to declare the patch correct, independent reasoning roles can challenge the proposed repair.

Conceptually:

```text
                 PATCH
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
    ATTACKER    DEFENDER     JUDGE
        │          │          │
        ▼          ▼          ▼
   Find ways    Explain     Evaluate
   to break     why fix     evidence
   the patch    works
        │          │          │
        └──────────┼──────────┘
                   ▼
             FINAL DECISION
```

The attacker role attempts to identify bypasses and residual weaknesses.

The defender role explains why the repair addresses the root cause.

The judge evaluates the evidence and arguments.

This is intended to reduce confirmation bias in automated patch verification.

---

# 18. Confidence-Gated Automation

Not every security decision should be automatically accepted.

PRAGYAN-BHARAT is designed around confidence-aware decision making:

```text
                Evidence
                   ↓
          ┌────────────────┐
          │ Confidence     │
          │ Evaluation     │
          └───────┬────────┘
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
 HIGH CONFIDENCE        LOW CONFIDENCE
       │                     │
       ▼                     ▼
 Automated path         Human analyst
       │                  review
       ▼                     │
 Verified result ◄───────────┘
```

This is particularly important for defence and mission-critical environments where an incorrect automated decision can be more dangerous than an unresolved finding.

---

# 19. Explainability

Every important decision should be traceable back to evidence.

A future report can contain:

```text
Finding
  ↓
Source location
  ↓
Program relationship
  ↓
Data-flow path
  ↓
Static evidence
  ↓
Dynamic evidence
  ↓
Sanitizer evidence
  ↓
LLM reasoning
  ↓
CWE classification
  ↓
Final confidence
  ↓
Recommended action
```

The goal is to answer:

> **Why did PRAGYAN-BHARAT believe this was a vulnerability?**

and:

> **What evidence supports that conclusion?**

---

# 20. Offline-First Design

PRAGYAN-BHARAT is designed for environments where external connectivity may be unavailable.

The core reasoning path can operate locally:

```text
┌─────────────────────────────────────────────┐
│              OFFLINE ENVIRONMENT             │
│                                             │
│  Source                                     │
│    ↓                                        │
│  Tree-sitter                               │
│    ↓                                        │
│  Joern / CodeQL / Static Analysis           │
│    ↓                                        │
│  AFL++ / ASan / UBSan                       │
│    ↓                                        │
│  Evidence Merger                            │
│    ↓                                        │
│  Ollama + Local LLM                         │
│    ↓                                        │
│  Security Report                            │
│                                             │
└─────────────────────────────────────────────┘
```

No cloud LLM is required for the local reasoning stage.

---

# 21. Current Implementation

PRAGYAN-BHARAT is actively being developed.

The current implementation focuses on the foundational evidence-driven analysis pipeline:

* Single-source-file ingestion
* Language-aware processing
* Tree-sitter structural analysis
* Joern integration
* CodeQL integration where applicable
* AFL++ fuzzing for applicable native targets
* ASan/UBSan runtime evidence
* Human-readable evidence aggregation
* Local Ollama-based security reasoning
* Security relationship analysis
* Graph/Graphviz-oriented artifacts

The architecture is intentionally being built incrementally rather than claiming capabilities that are not yet implemented.

---

# 22. Roadmap

### Foundation

* [x] Project architecture
* [x] Environment/toolchain setup
* [x] Demo vulnerable target
* [x] AFL++ fuzzing baseline
* [x] ASan/UBSan integration
* [x] LLM-based crash triage
* [x] Human-readable security evidence generation
* [x] Local Ollama reasoning
* [x] Tree-sitter-based structural analysis
* [x] Joern-based CPG analysis

### Analysis

* [ ] Automated reachability graph
* [ ] Automated source-to-sink reasoning
* [ ] Improved cross-tool evidence correlation
* [ ] Multi-hypothesis vulnerability reasoning
* [ ] Improved CWE classification
* [ ] Confidence scoring and calibration

### Automated Repair

* [ ] Multi-candidate patch generation
* [ ] Patch ranking
* [ ] Compilation validation
* [ ] Regression testing
* [ ] Re-run security analysis after repair

### Adversarial Verification

* [ ] Cyber Courtroom
* [ ] Attacker reasoning agent
* [ ] Defender reasoning agent
* [ ] Judge/verdict agent
* [ ] Automated patch-break attempts

### Operationalization

* [ ] Explainability report generator
* [ ] Patch provenance
* [ ] Signed analysis records
* [ ] Persistent vulnerability memory
* [ ] End-to-end autonomous pipeline
* [ ] Analyst dashboard

---

# 23. Technology Stack

| Layer                        | Technology                  |
| ---------------------------- | --------------------------- |
| Language parsing             | Tree-sitter                 |
| Code Property Graph          | Joern                       |
| Static semantic analysis     | CodeQL                      |
| Pattern analysis             | Semgrep                     |
| Dynamic fuzzing              | AFL++                       |
| Runtime analysis             | AddressSanitizer            |
| Undefined behaviour analysis | UBSan                       |
| Graph generation             | Graphviz / GraphML          |
| Local LLM runtime            | Ollama                      |
| LLM reasoning                | Local coding/security model |
| Orchestration                | Python                      |
| Initial target               | C / C++                     |

The architecture is designed so that analysis stages can be enabled according to the target language and available tooling.

---

# 24. Repository Structure

```text
PRAGYAN-BHARAT/
│
├── README.md
│
├── docs/
│   ├── architecture.md
│   ├── setup.md
│   ├── decisions.md
│   └── devlog.md
│
├── src/
│   └── ...
│
├── targets/
│   └── demo/
│
├── knowledge/
│   └── PRAGYAN_BHARAT_CWE_SECURITY_REASONING_DATASET.txt
│
├── scripts/
│   └── ...
│
└── LICENSE
```

Generated analysis artifacts are maintained separately from the core source tree.

---

# 25. Design Principles

PRAGYAN-BHARAT follows several core principles.

### Evidence over assumptions

A tool finding is evidence, not automatically a verdict.

### Multiple independent signals

Static, structural and runtime evidence should reinforce each other.

### Explainability

Security decisions should be traceable to evidence.

### Offline operation

Sensitive source code should not need to leave the analysis environment.

### Human safety gates

Low-confidence decisions should not silently become automated deployment decisions.

### Minimal repair

When repairing vulnerabilities, prefer the smallest change that removes the root cause without unnecessary behavioural changes.

### Reproducibility

A security finding should ideally be reproducible and auditable.

---

# 26. Why PRAGYAN-BHARAT?

Traditional vulnerability scanners answer:

> **"Does this code resemble a known bad pattern?"**

PRAGYAN-BHARAT aims to answer a more useful question:

> **"What is happening in this program, how does the suspicious behaviour propagate, can an attacker reach it, what evidence proves the vulnerability, and can a proposed repair be independently verified?"**

That difference defines the project's core philosophy.

---

# 27. Vision

PRAGYAN-BHARAT aims to evolve from a vulnerability triage engine into an autonomous cyber reasoning platform capable of:

```text
             UNDERSTAND
                 ↓
              DISCOVER
                 ↓
               TRIAGE
                 ↓
             CORRELATE
                 ↓
              REASON
                 ↓
               PATCH
                 ↓
             ATTACK FIX
                 ↓
              VERIFY
                 ↓
              EXPLAIN
                 ↓
              REMEMBER
```

The ultimate objective is not simply to generate more vulnerability alerts.

It is to produce **evidence-grounded, explainable and verifiable security decisions** suitable for highly constrained and security-sensitive environments.

---

# 28. AI Kavach

PRAGYAN-BHARAT is being developed for the **AI Kavach** track of the hackathon.

The project focuses on bringing together:

**Program Analysis + Security Evidence + Dynamic Validation + Local AI Reasoning**

into a unified autonomous cyber-reasoning workflow.

---

## 🇮🇳 PRAGYAN-BHARAT

**Evidence-driven. Offline-first. Security-focused.**

> **Don't just find suspicious code. Understand it. Prove it. Fix it. Verify it.**
