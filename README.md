# Nimble

**Nimble** is a Windows 10/11 x64 tray-first BitTorrent client focused on:

    - Ultra-small footprint (single EXE, minimal dependencies)
    - High throughput and low overhead
    - Full feature set (trackers, magnets, DHT, PEX, LSD, UPnP, NAT-PMP, IPv6, µTP)
    - Clean separation: Win32 tray UI ⟷ core engine

This repository contains all modules the project will use, with placeholder implementations where appropriate.

--------------------------------------------------------------------

## Features (planned and included in this repository layout)

Input & metadata
    - .torrent parsing (bencode) and infohash v1
    - Magnet links (BEP-9) via metadata exchange (ut_metadata)
    - Selective file download priorities (Skip / Normal / High)

Trackers
    - HTTP trackers (WinHTTP)
    - HTTPS trackers (WinHTTP + SChannel)
    - UDP trackers (BEP-15)

Peer connections
    - TCP peer wire protocol (BEP-3)
    - Extension protocol (BEP-10)
    - PEX via ut_pex
    - Endgame mode
    - Better peer scoring (latency + throughput + reliability)

Decentralized discovery
    - DHT (BEP-5), IPv4 + IPv6 where available
    - Local Service Discovery (BEP-14)

NAT traversal
    - UPnP IGD (SSDP + SOAP, port mapping + renew)
    - NAT-PMP (port mapping + renew)

Networking
    - IPv4 + IPv6 support (trackers + peers + DHT where applicable)
    - µTP (BEP-29) as an additional peer transport

Storage
    - Safe piece writing + SHA-1 verification
    - Resume state (crash-safe, versioned)
    - Disk cache with write-behind
    - Optional preallocation

UI / UX (Windows tray)
    - Tray icon by the clock, state-aware (idle/active/paused/error)
    - Right-click menu:
        - Add Torrent File...
        - Add Magnet Link...
        - Open Downloads Folder
        - Status Window...
        - Pause All / Resume All
        - Settings...
        - Quit
    - Minimal status window (list view)
    - Minimal settings dialog (limits, port, toggles)

--------------------------------------------------------------------

## Repository layout

    Nimble/
      Cargo.toml
      README.md
      LICENSE
      .gitignore
      .editorconfig
      .github/workflows/ci.yml
      crates/
        nimble-app/        # Win32 tray app (the EXE)
        nimble-core/       # Session manager, torrent lifecycle, scheduling
        nimble-net/        # TCP/UDP sockets, peer protocol, WinHTTP trackers
        nimble-dht/        # DHT v4/v6 (BEP-5)
        nimble-nat/        # UPnP IGD + NAT-PMP
        nimble-lsd/        # Local Service Discovery (BEP-14)
        nimble-storage/    # File layout, cache, resume, disk IO
        nimble-bencode/    # Bencode + .torrent parsing
        nimble-util/       # Bitfield, ids, time, tiny logging, etc.

--------------------------------------------------------------------

## Build (Windows 10/11 x64)

Requirements
    - Rust (MSVC toolchain)
    - Visual Studio Build Tools (C++ build tools installed)

Build
    - Debug:
        cargo build
    - Release (size-optimized):
        cargo build --release

Run
    - Debug:
        cargo run -p nimble-app
    - Release:
        .\target\release\nimble-app.exe

Notes
    - The tray UI is implemented with raw Win32 APIs for minimal footprint.
    - Tracker HTTP/HTTPS uses WinHTTP (SChannel TLS) to avoid shipping a TLS library.
    - Many modules are placeholders initially; each exposes stable interfaces intended for incremental implementation.

--------------------------------------------------------------------

## Configuration & data locations

Portable mode
    - If a file named `nimble.toml` exists next to the EXE, Nimble uses it and stores resume data beside it.

Default mode
    - Config:
        %AppData%\Nimble\nimble.toml
    - Resume data:
        %AppData%\Nimble\resume\<infohash>.dat
    - Logs (optional):
        %AppData%\Nimble\logs\nimble.log

--------------------------------------------------------------------

## Development principles

Footprint rules
    - Prefer Windows OS APIs (WinHTTP/SChannel) over bundled stacks.
    - Avoid heavyweight crates; disable default features everywhere.
    - Keep parsing and allocations minimal; reuse buffers and pools.

Safety rules
    - Strict caps:
        - bencode nesting depth
        - max metadata size (ut_metadata)
        - max peer message length
        - max tracker response length
    - Sanitize torrent file paths (no absolute paths, no traversal).

--------------------------------------------------------------------

## Work checklist (high level)

Foundations
    - Win32 tray app + event bus (done as a starter)
    - Config + portable mode
    - Logging (tiny)

Core torrent engine
    - bencode + .torrent parsing + infohash
    - storage layout + hashing + resume
    - peer TCP protocol + scheduler + limits
    - trackers (HTTP/HTTPS + UDP)

Magnets & discovery
    - BEP-10 + ut_metadata
    - DHT (v4/v6)
    - PEX (ut_pex)
    - LSD (BEP-14)

NAT & transports
    - UPnP IGD
    - NAT-PMP
    - IPv6 end-to-end
    - µTP

UX improvements
    - Status window + per-torrent actions
    - Per-file priority view
    - Settings dialog improvements

--------------------------------------------------------------------

## License

MIT License (see LICENSE).
