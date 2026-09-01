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

                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
     ⚔️ ATTACKER      🛡️ DEFENDER      ⚖️ JUDGE
   (Break the patch) (Explain fix)  (Evaluate evidence)
         │                │                │
         └────────────────┼────────────────┘
                          ▼
                 ✅ FINAL VERIFIED RESULT

# PRAGYAN BHARAT WORKSPACE - Candidate Analysis Framework

**Repository Architecture**

* **`AFL++/`**  
  Fuzzing campaign artifacts.
  * `seeds/`: Initial test case corpus.
  * `findings/`: Execution queue and status logs.
  * `crashes/`: Isolated inputs causing program faults.
  * `AFL_compact.txt`: Condensed fuzzing execution metrics.

* **`CodeQL/`**  
  Static semantic analysis outputs.
  * `database/`: Queryable database snapshot.
  * `results/`: Detailed vulnerability reports.
  * `CodeQL_compact.txt`: Executive summary of static defects.

* **`ASAN/`**  
  AddressSanitizer memory error logs.
  * `logs/`: Runtime stack traces for memory violations.
  * `ASAN_compact.txt`: Condensed memory error breakdown.

* **`UBSAN/`**  
  UndefinedBehaviorSanitizer diagnostics.
  * `logs/`: Runtime logs for compiler-detected undefined behavior.
  * `UBSAN_compact.txt`: Summary of undefined behavior instances.

* **`LLM/`**  
  AI-driven analysis and workflow management.
  * `execution_plan.txt`: Automated triage roadmap.
  * `initial_analysis.txt`: Preliminary codebase review.
  * `candidate_generation.txt`: Generated code alterations or variants.

* **`Candidates/`**  
  Source code implementations under testing (`example_Candidate1.cpp`, `example_Candidate2.cpp`, `example_Candidate3.cpp`).

* **`FINAL_EVIDENCE.txt`**  
  Aggregated proof-of-concept records and final evaluation verdicts.

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

# 2. Core Architecture- FULL DIAGRAM (BLUE-PRINT)

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
# ⚡ Performance Philosophy

PRAGYAN-BHARAT follows:

"Analyze less data, but analyze the right data."

            
