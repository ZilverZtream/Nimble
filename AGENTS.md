# AGENTS.md

Nimble is a Windows-only tray BitTorrent client. This file defines how AI agents (Codex, ChatGPT, etc.) must work in this repository.

-------------------------------------------------------------------------------

## Project goals

    - Windows 10/11 x64 only
    - Single EXE, tray-first UX (no heavy GUI frameworks)
    - Minimal footprint and minimal dependencies
    - High performance, low allocations, robustness
    - Full feature set:
        - .torrent + magnet (ut_metadata)
        - HTTP/HTTPS trackers (WinHTTP/SChannel), UDP trackers
        - Peer wire protocol + extensions (BEP-10)
        - DHT (v4 + v6), PEX, LSD
        - UPnP IGD + NAT-PMP
        - IPv4 + IPv6 end-to-end
        - µTP (BEP-29)
        - Disk cache w/ write-behind, resume, per-file priorities

-------------------------------------------------------------------------------

## Non-negotiable engineering rules

### 1) Wiring required (no “floating” code)
Every new feature must be end-to-end wired:

    UI (or CLI test hook) -> core command -> subsystem -> observable result

No adding modules, types, or functions that are not called anywhere.
If something is introduced, it must be reachable from a clear entry point:
    - tray menu / status window action
    - engine command
    - subsystem tick/loop
    - integration test that runs it

### 2) No dead code
Never “replace” code and leave the old version behind.
No commented-out blocks.
No duplicate parallel implementations.
If you refactor or supersede something:

    - delete the old code
    - update references
    - ensure build + tests pass

### 3) Absolutely no backward compatibility requirements
Nimble is not released. Do not keep compatibility layers.
If a design is improved:

    - change the API
    - update all call sites
    - migrate config/resume formats with a single-step migration (or break them)

No deprecation periods.

### 4) Small footprint is a first-class constraint
Avoid heavy crates and default features. Prefer Windows APIs.
Specifically:
    - Trackers: WinHTTP (HTTP + HTTPS via SChannel)
    - Avoid shipping TLS stacks (no OpenSSL/rustls in default build)
    - Avoid heavyweight HTTP clients (reqwest/hyper) unless proven smaller and necessary
    - Avoid big logging frameworks

If a new dependency is proposed, you must justify:
    - why Windows APIs are insufficient
    - size impact / features enabled
    - alternative considered and rejected

### 5) Windows-only means Windows-first design
No cross-platform abstraction layers that add bloat.
Use Windows APIs directly when it reduces complexity and size.

### 6) Safety hardening is mandatory
All parsers and network handlers must enforce caps:
    - bencode nesting depth
    - ut_metadata max size
    - tracker response size
    - peer message length (hard cap)
    - timeouts and backoff
Sanitize file paths in torrents:
    - no absolute paths
    - no `..`
    - normalize separators
    - reject invalid UTF-8 where needed or preserve raw bytes safely

-------------------------------------------------------------------------------

## Codebase workflow expectations (for agents)

### 1) Make small, complete, reviewable changes
Prefer “vertical slices”:
    - one feature from command -> subsystem -> observable output
over “horizontal scaffolding”.

### 2) Keep allocations out of hot paths
    - reuse buffers
    - pool block buffers
    - avoid String formatting in tight loops
    - parse into borrowed slices where possible

### 3) Tests are part of delivery
Every meaningful change must include at least one of:
    - unit test (parser, picker, limiter)
    - integration test (protocol chunk, storage/resume)
    - smoke test (engine starts, receives command, emits event)

### 4) Diagnostics without bloat
Logging must be:
    - cheap
    - optionally compiled out
    - not dependent on huge crates

-------------------------------------------------------------------------------

## Required “done” checklist for any feature PR

    - Compiles in debug and release
    - Wired end-to-end (no orphan code)
    - No dead code remains
    - No backward-compat layer introduced
    - Input caps / safety checks included
    - At least one test added or updated
    - Any new dependency justified and minimized (features off)

-------------------------------------------------------------------------------

## Agent prompt template (use this when starting a task)

    Task:
        <what to build>

    Constraints:
        - Windows-only
        - smallest footprint
        - wiring required
        - no dead code
        - no backward compatibility

    Deliverable:
        - code changes across the relevant crates
        - tests
        - short notes on how to run / verify

-------------------------------------------------------------------------------

## Notes on repo structure

    crates/nimble-app
        - Win32 tray UI, status window, settings dialog
        - sends commands to engine, renders events/stats

    crates/nimble-core
        - engine loop, session manager, scheduling, limits, torrent lifecycle

    crates/nimble-net
        - peers (TCP + extensions), WinHTTP trackers, UDP trackers, µTP

    crates/nimble-dht
        - DHT v4/v6 (BEP-5)

    crates/nimble-nat
        - UPnP IGD + NAT-PMP

    crates/nimble-lsd
        - LSD (BEP-14)

    crates/nimble-storage
        - layout, disk IO, cache, resume

    crates/nimble-bencode
        - bencode + .torrent parsing

    crates/nimble-util
        - bitfield, ids, time, tiny log, hashing glue

-------------------------------------------------------------------------------

## Hard bans

    - Leaving old code after refactor
    - Adding large GUI frameworks
    - Adding a bundled TLS stack in the default Windows build
    - “TODO-only” features without wiring
    - Keeping deprecated APIs for compatibility
    - Leaving patch/fix comments in the source code
