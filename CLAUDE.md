# Project Context

rules:
  prose: no_verbose
  tone: professional_only
  persona: senior_software_developer
  response_style: direct_terse
  thinking: no_long_analysis
  file_operations: user_requested_or_planned_only
  sycophancy: never
  hallucination: never
  platform: "macOS only"
  small_edits: "professional, surgical"
  large_edits: "professional, structured, clean code, Swift‑DocC comments"
  new_content: "professional, structured, clean code, Swift‑DocC comments"
  no_explanations: “No explanations, just the code.”
  skip_preamble: “Skip the preamble, output only the implementation.”
  no_recap: “Don’t recap what we discussed, just proceed.”

  prototype_stage:"product unreleased, Breaking changes ok, no migration needed, database cleanup ok"

  markdown:
    file_links: “prefix project-relative-path links with `/`"
    project_relative_example: "[Provider/main.swift](/Provider/main.swift)”
    md_diagrams:"prefer ascii art diagrams. use mermaid where more complex"

  grep_cmd: rg -n --column <pattern> <location>

  xcode_project: VaultSync.xcodeproj

  design:
  - clean_design: "clear separation of concerns; design for maintenance; design for test"
  - no_duplicate_paths: >
      Duplicate or near-identical alternative implementations / code paths must be avoided.
      One shared implementation with additive specialisation, never two parallel ones that
      drift. Applies to types, services, and workflows alike.
  - modularity: >
      The app is built from swappable blocks. The two primary ones are Backend and Crypto;
      a swappable StorageSchema (inline vs chunked) is planned. Swappable components share
      one workflow/service path; differences are minimised where practicable.
  - backend_protocol: >
      Backends share a common protocol. Backend-specific behaviour is ADDITIVE on top of the
      shared path — never a forked alternative to it. Expect many backends: today OneDrive
      and Emulator, LocalFileSystem soon. Anything named for one backend that all backends
      need is misplaced; hoist the shared part and leave only the genuinely specific part
      behind the backend's own type.
  - backend_routing: >
      Where a shared service must reach backend-specific code, route by BackendKind through
      a registry (see `BackendRoutingProvisioningService`) rather than installing one
      backend's implementation globally.

  code_edit:
  - unambiguous_naming: "e.g. `remoteTotalSize` not `totalSize` if multiple files/sizes in scope"

  code_search:
   - highest_priority: Swift LSP
   - medium_priority: rg, grep, awk,
   - lowest_priority: "file content read"

  swift_lsp:
   - "use correct character position of symbol"
   - "use relative paths"

  provider_appex_sandboxing: >
    Provider.appex (File Provider Non-UI Extension) is a sandboxed extension with NO direct access to:
    - User-selected files or custom storage locations
    - Network server ports
    File operations must route through HTTP JSON-RPC to VaultSync.app's StandaloneServer (port 24680).
    Provider.appex must read/write JSON Configuration via the App Group container
    `com.apple.security.application-groups` entitlement (group.org.vaultsync.VaultSync).

  claude_output:
   requires:
    - Enforce HARD BREVITY MODE
    - maximum information density, minimum words
   prohibits:
    - conversational tone.
    - narrative reasoning.
    - redundant sentences.
    - softening language.
    - further expansions unless explicitly requested.

comments:
  single_quote: '
  double_quote: "

direction:
- push back when necessary
- ask questions if unclear

ui:
- use drop-down instead of radio buttons

crypto:
- do not use legacy file-based keychain, use data-protection keychain