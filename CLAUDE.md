# CLAUDE.md

This file is instructions for Claude Code when working in this repository.

-------------------------------------------------------------------------------

## Identity and scope

You are working on **Nimble**, a Windows 10/11 x64 tray BitTorrent client with a strict focus on:

    - Small binary footprint (single EXE)
    - High performance / low overhead
    - Correct protocol implementations
    - Robustness and safe parsing
    - Windows-native integrations (Win32 + WinHTTP/SChannel)

Do not introduce cross-platform frameworks or compatibility layers.

-------------------------------------------------------------------------------

## Non-negotiable rules

### 1) Wiring required (everything must be wired)
If you implement something, it must be reachable and demonstrably used:

    - A menu action / UI interaction OR a test hook must call it
    - The engine must route the command to the relevant subsystem
    - The subsystem must produce an observable effect:
        - event
        - state change shown in status window
        - file output
        - network behavior validated via test

No unused modules. No “library-only” changes without a caller.

### 2) No dead code
When replacing or refactoring:

    - delete the old code
    - delete old functions/types
    - delete old config paths
    - update all call sites

No commented-out code. No “legacy” folders. No duplicate implementations.

### 3) Absolutely not backward compatible
Nimble is not released. There is no need for backward compatibility.
If a design needs to change:

    - change it cleanly
    - update all uses
    - migrate or break config/resume formats without hesitation

Never keep deprecated APIs “just in case”.

### 4) Footprint is a core feature
Prefer Windows APIs over third-party dependencies.
For trackers:

    - Use WinHTTP for HTTP and HTTPS
    - Rely on SChannel (do not ship a TLS stack by default)

Avoid heavy crates:
    - reqwest, hyper, big async stacks with many features, large logging frameworks
If a dependency is unavoidable, minimize features and justify it explicitly.

### 5) Windows-only means Windows-first
Use Win32 and WinSock directly where it reduces size/complexity.
No additional abstraction layers that add bloat.

-------------------------------------------------------------------------------

## Implementation guidelines

### Protocol correctness
Follow BEPs. Implement caps and timeouts everywhere.
Key ones:
    - BEP-3 (peer)
    - BEP-10 (extended)
    - BEP-9 (magnet)
    - BEP-5 (DHT v4/v6)
    - BEP-15 (UDP tracker)
    - BEP-14 (LSD)
    - BEP-29 (µTP)
    - UPnP IGD / NAT-PMP (port mapping)

### Safety / hardening requirements
All decoders and network parsers must enforce:
    - maximum input size
    - maximum nesting depth for bencode
    - maximum message length for peer protocol
    - strict integer overflow checks
    - sanity checks for piece/block ranges
    - strict timeout/backoff on network retries

Torrent file path sanitization:
    - reject absolute paths
    - reject `..`
    - normalize separators
    - keep safe file creation within download root

### Performance requirements
Hot paths should:
    - avoid allocations
    - reuse buffers (pools where appropriate)
    - avoid expensive string formatting
    - keep lock contention low (prefer message passing / single-owner state)

### Code style
    - Keep functions small and purpose-driven
    - Prefer explicit state machines for protocols
    - Keep module boundaries strict (UI never implements protocol logic)

-------------------------------------------------------------------------------

## How to work in this repo (Claude Code process)

When implementing any feature, do this sequence:

    1) Identify the entry point and wiring path:
        - UI action or test -> Engine Command -> Subsystem API -> Observable Result

    2) Add minimal interfaces first:
        - add only the API surface needed for the feature slice
        - do not add unrelated scaffolding

    3) Implement the smallest correct version:
        - correct, safe, tested
        - then iterate to optimize

    4) Add tests:
        - unit tests for parsers/state machines
        - integration/smoke tests for engine wiring

    5) Footprint review:
        - verify dependencies and features
        - avoid default features
        - avoid new crates if Windows provides the capability

-------------------------------------------------------------------------------

## Required acceptance checklist for each completed change

    - Builds on Windows (debug + release)
    - Fully wired end-to-end (no orphan code)
    - No dead code left behind
    - No compatibility layers added
    - Caps/timeouts implemented
    - Tests added/updated and passing
    - Dependency changes are minimized and justified

-------------------------------------------------------------------------------

## Nimble-specific implementation notes

Trackers:
    - Use WinHTTP for HTTP/HTTPS announces (SChannel TLS)
    - UDP tracker uses raw UDP sockets

Magnets:
    - Use BEP-10 + ut_metadata to fetch metadata
    - DHT should be a primary peer discovery path when trackers absent

NAT:
    - UPnP: SSDP discovery + SOAP mapping
    - NAT-PMP: UDP to gateway, mapping refresh

Storage:
    - Write pieces safely, verify SHA-1, then mark complete
    - Resume format is versioned; migration is allowed, compatibility is not required

UI:
    - Win32 tray icon + minimal status window + minimal settings
    - UI emits commands; engine emits events/stats

-------------------------------------------------------------------------------

## Hard bans (do not do these)

    - Leaving old code after refactor
    - Commenting out large code blocks instead of deleting
    - Adding heavyweight GUI frameworks
    - Bundling TLS stacks in the default Windows build
    - Adding unused “future” abstractions without wiring
    - Keeping deprecated APIs for compatibility
    - Leaving code comments about fixes/issue etc
