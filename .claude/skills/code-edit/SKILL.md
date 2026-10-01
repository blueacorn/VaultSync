---
name: code-edit
description: Required rules when editing any code
---

rules:

  - id: no-invention
    description: >
      Claude MUST NOT invent, hallucinate, or propose APIs, modules, files, or patterns
      that do not exist in the codebase unless explicitly instructed to propose new design.
    requires:
      - "Verify existence of any referenced API, module, or file before using it"
      - "Ask clarifying questions when details are uncertain"
      - "Propose new design ONLY when user explicitly requests it"
    prohibits:
      - "Inventing APIs or modules"
      - "Assuming undocumented behavior"
      - "Using deprecated or removed APIs"
      - "Hallucinating missing implementation details"

  - id: clarify-ambiguity
    description: >
      When context is insufficient or requirements are unclear, Claude MUST ask clarifying
      questions before generating code or making architectural decisions.
    requires:
      - "Identify missing context before proceeding"
      - "Ask specific, actionable questions"
      - "Wait for user clarification before code generation"
    prohibits:
      - "Making assumptions about requirements"
      - "Proceeding with speculative designs"

  - id: incremental-changes
    description: >
      Prefer deterministic, reproducible, incremental changes over large speculative rewrites.
    requires:
      - "Make focused, targeted changes"
      - "Validate each change against existing constraints"
      - "Preserve existing functionality unless explicitly changing it"
    prohibits:
      - "Large refactors without user approval or plan"
      - "Speculative cleanup or over-engineering"
      - "Adding abstractions beyond what the task requires"

  - id: minimal-context-mode
    description: >
      Respect minimal-context discipline: only use files explicitly provided or referenced.
      Do not explore beyond necessary scope.
    requires:
      - "Use files explicitly mentioned by the user"
      - "Follow cross-references (imports, requires, etc.) only when needed"
      - "Ask before exploring adjacent modules"
    prohibits:
      - "Exploring the full codebase speculatively"
      - "Reading files not relevant to the current task"

  - id: security-constraints
    description: >
      Never break security, sandboxing, or data-handling constraints.
    requires:
      - "Validate against security constraints before code generation"
      - "Review code for OWASP top 10 vulnerabilities"
      - "Fix security issues immediately if discovered"
    prohibits:
      - "Introducing command injection, XSS, SQL injection, or similar vulnerabilities"
      - "Bypassing security constraints or sandboxing"
      - "Storing credentials in code or logs"

  - id: code-compilation
    description: >
      Always produce compilable code
    requires:
      - "Verify code compiles or runs without errors"
      - "Include all necessary imports and dependencies"
      - "Test code locally before reporting completion"

  - id: test-coverage
    description: >
      Always add or update test cases for generated code.
    requires:
      - "Create test cases for new functionality"
      - "Update existing tests if behavior changes"
      - "Run tests before marking task complete"

  - id: output-style
    description: >
      Format output for clarity and actionability.
    requires:
      - "Use clear sectioning when appropriate"
      - "Default to concise, implementation-ready output"
      - "Use markdown links for file references: [filename](path)"
    prohibits:
      - "Providing long prose"

  - id: ambiguity-resolution
    description: >
      When encountering unexpected state (unfamiliar files, branches, or configuration),
      investigate before destructive action. Do not use destructive shortcuts.
    requires:
      - "Identify root causes before taking corrective action"
      - "Investigate merge conflicts rather than discarding changes"
      - "Ask user before deleting or overwriting work"
    prohibits:
      - "Destructive operations (rm -rf, reset --hard, force-push)"
