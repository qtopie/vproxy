# AGENTS.md - System Operating Guidelines

Welcome Agent! You are a core collaborator in this repository. You MUST strictly adhere to these operational rules.

## 1. Context Loading & Memory Rule
- **Always Check `.agents/TASK.md` First:** Before taking any action, read `.agents/TASK.md` to restore context.
- **Maintain `.agents/TASK.md`:** Update `.agents/TASK.md` checklist items as you progress. If interrupted, write the current status under `Current Context`.

## 2. Spec-First Gate (Strict Enforcement)
- **SSOT (Single Source of Truth):** All behavioral contracts belong in `specs/`. Never implement feature logic without an approved Spec.
- **No Spec, No Code:** 
  1. Draft/Update files in `specs/` or `docs/rfcs/`.
  2. Wait for explicit user approval (`APPROVE`).
  3. Generate or update test harness fixtures (`harness/`) and test stubs (`testings/`).
  4. Only then implement business logic code.

## 3. Harness Engineering & Testing Gate
- **Harness-Driven Development:** Maintain fixtures, mocks, and runners in `harness/`.
- **Structured Diagnostic Feedback:** When tests fail, read the `Harness Failure Report` automatically written to `.agents/TASK.md` to perform targeted fixes instead of guessing logs.
- **No Shallow Tests:** Never write trivial Getter/Setter tests; tests must cover real boundary conditions and error scenarios.
- **Mock External Dependencies:** Always mock databases, network I/O, external RPCs, and hardware APIs in unit tests and harness mocks (`harness/mocks/`).

## 4. Grounding & Code Rules
- **Read Before Write:** Read target files and their dependencies before editing.
- **Zero Assumptions:** Ask the user if architecture or variable definitions are missing.
- **Minimal Diff:** Modify only what is required. Do not refactor unrelated code.

## 5. Execution & Safety Red Lines
- **Prohibited Commands:** Never run `git push --force`, `rm -rf /`, or alter external systems.
- **Mandatory Self-Validation:** Run `./scripts/check.sh` (or `./scripts/check-harness.sh`) before marking a task complete.
- **Error Limit:** If test/compile fixes fail > 3 times, stop and ask the user for guidance.

## 6. TUN Init → Test → Clean Workflow
- **Scope:** Applies whenever a contributor or automated agent enables TUN/Wintun transparent mode (for example via `vproxy init` or when `VP_USE_TUN=1`).
- **Requirements:** Must run with Administrator privileges and verify `wintun.dll` is present in the working directory or `C:\Windows\System32` prior to enabling TUN.
- **Automated Verification:** Immediately after `vproxy init` completes, execute the standard connectivity verification suite (DNS resolution, TCP connect to port 443, and a short HTTPS GET). These checks must use a configurable timeout (default: 15s).
- **Mandatory Cleanup:** Regardless of the verification outcome (success, failure, or timeout), run `vproxy clean` (or call `tproxy.Cleanup()`) immediately to restore original routing and remove injected routes/interfaces. Failing to perform cleanup is prohibited.
- **Failure Handling & Reporting:** If verification fails or times out, record diagnostics under `.agents/TASK.md` in `Current Context` including timestamp, short vproxy log excerpt, and the verification results; then escalate to the repository owner or on-call maintainer.
- **Enforcement:** All agents, automated tasks, and collaborators must follow this workflow when using TUN. Any deviations must be documented in `.agents/TASK.md` with justification and approval.
