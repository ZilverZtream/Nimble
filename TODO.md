# Nimble – Master TODO

This file is the **single source of truth** for all work in Nimble.

-------------------------------------------------------------------------------

## Rules (MANDATORY)

- Every checkbox represents real, executable work.
- A checkbox MUST be checked when the work is complete.
- “Complete” means:
    - code exists
    - code is wired end-to-end
    - build succeeds
    - superseded code is deleted
- If a TODO item is already done (by anyone) but unchecked:
    - CHECK IT OFF
- Do NOT leave completed items unchecked.
- If a TODO becomes obsolete:
    - replace it with a checked note explaining why
- There are NO backward-compatibility requirements.
    - APIs, config, resume formats may break freely.

Leaving completed TODOs unchecked is considered a bug.

-------------------------------------------------------------------------------

# A. Repository & Build Foundations

## A1. Build configuration
- [ ] A1.1 Enforce release profile (LTO, strip, panic=abort)
- [ ] A1.2 Verify MSVC toolchain usage
- [ ] A1.3 Verify single-EXE output (no bundled DLLs)
- [ ] A1.4 CI builds debug and release on Windows
- [ ] A1.5 Optional binary size guardrail script

## A2. Dependency discipline
- [ ] A2.1 Audit workspace dependencies
- [ ] A2.2 Disable default features everywhere possible
- [ ] A2.3 Document justification for each dependency
- [ ] A2.4 Remove unused transitive deps

## A3. Logging & diagnostics
- [ ] A3.1 Implement tiny logger backend
- [ ] A3.2 Optional OutputDebugStringW logging
- [ ] A3.3 Ring-buffer recent log storage
- [ ] A3.4 Compile-time log level stripping

-------------------------------------------------------------------------------

# B. Win32 Tray Application

## B1. Tray lifecycle
- [x] B1.1 Hidden window creation
- [x] B1.2 Shell_NotifyIcon registration
- [x] B1.3 Tray icon removal on shutdown
- [x] B1.4 Clean shutdown on WM_DESTROY

## B2. Tray menu
- [x] B2.1 Add Torrent File menu item
- [x] B2.2 Add Magnet Link menu item
- [x] B2.3 Open Downloads Folder menu item
- [x] B2.4 Status Window menu item
- [x] B2.5 Pause All menu item
- [x] B2.6 Resume All menu item
- [ ] B2.7 Settings menu item
- [x] B2.8 Quit menu item

## B3. Tray icon state
- [ ] B3.1 Idle icon
- [ ] B3.2 Active icon
- [ ] B3.3 Paused icon
- [ ] B3.4 Error icon
- [ ] B3.5 Tooltip with live stats

-------------------------------------------------------------------------------

# C. Engine Core & Wiring

## C1. Engine lifecycle
- [x] C1.1 Engine thread startup
- [x] C1.2 Engine shutdown handling
- [x] C1.3 Command channel processing
- [x] C1.4 Event emission channel

## C2. Command wiring
- [x] C2.1 AddTorrentFile command wired
- [x] C2.2 AddMagnet command wired
- [x] C2.3 PauseAll command wired
- [x] C2.4 ResumeAll command wired
- [x] C2.5 Shutdown command wired

## C3. Session manager
- [x] C3.1 Torrent registry
- [ ] C3.2 Max active torrents enforcement
- [x] C3.3 Torrent lifecycle states
- [ ] C3.4 Graceful stop/start transitions

-------------------------------------------------------------------------------

# D. Bencode & Torrent Parsing

## D1. Bencode decoder
- [x] D1.1 Integer parsing
- [x] D1.2 Byte string parsing
- [x] D1.3 List parsing
- [x] D1.4 Dictionary parsing
- [x] D1.5 Zero-copy decoding where possible
- [x] D1.6 Nesting depth cap
- [x] D1.7 Input size cap
- [x] D1.8 Fuzz tests

## D2. Torrent parsing
- [x] D2.1 Parse announce URL
- [x] D2.2 Parse announce-list tiers
- [x] D2.3 Parse piece length
- [x] D2.4 Parse pieces SHA-1 list
- [x] D2.5 Parse single-file torrents
- [x] D2.6 Parse multi-file torrents

## D3. Path safety
- [x] D3.1 Reject absolute paths
- [x] D3.2 Reject `..` traversal
- [x] D3.3 Normalize separators
- [x] D3.4 Safe UTF-8 handling

## D4. Infohash
- [x] D4.1 Canonical bencode of info dict
- [x] D4.2 SHA-1 infohash computation
- [x] D4.3 Verification tests with known torrents

-------------------------------------------------------------------------------

# E. Storage & Resume

## E1. File layout
- [x] E1.1 Global offset mapping
- [x] E1.2 Multi-file boundary handling
- [x] E1.3 File creation policy

## E2. Piece storage
- [x] E2.1 Block receipt tracking
- [x] E2.2 Piece completion detection
- [x] E2.3 SHA-1 verification
- [x] E2.4 Piece invalidation on mismatch

## E3. Disk cache
- [ ] E3.1 Cache data structures
- [ ] E3.2 Write-behind queue
- [ ] E3.3 Periodic flush
- [ ] E3.4 Flush on shutdown
- [ ] E3.5 Configurable cache size

## E4. Resume system
- [ ] E4.1 Resume file format v1
- [ ] E4.2 Bitfield persistence
- [ ] E4.3 Partial piece persistence
- [ ] E4.4 Safe write/replace strategy
- [ ] E4.5 Resume load on startup
- [ ] E4.6 Resume format migration allowed (no backward compatibility)

-------------------------------------------------------------------------------

# F. Peer Protocol (TCP)

## F1. Connection handling
- [x] F1.1 Outbound peer connections
- [x] F1.2 Inbound peer listener
- [x] F1.3 Connection caps (global/per-torrent)
- [x] F1.4 Backoff on failures

## F2. Handshake
- [x] F2.1 Peer ID generation
- [x] F2.2 Reserved bits handling
- [x] F2.3 Protocol validation

## F3. Core messages
- [x] F3.1 keep-alive
- [x] F3.2 choke / unchoke
- [x] F3.3 interested / not interested
- [x] F3.4 have
- [x] F3.5 bitfield
- [x] F3.6 request
- [x] F3.7 piece
- [x] F3.8 cancel

## F4. Safety caps
- [x] F4.1 Max message length
- [x] F4.2 Block size validation
- [x] F4.3 Piece index validation

-------------------------------------------------------------------------------

# G. Scheduler, Limits & Scoring

## G1. Bandwidth limiting
- [ ] G1.1 Global download limiter
- [ ] G1.2 Global upload limiter
- [ ] G1.3 Per-torrent limits
- [ ] G1.4 Token bucket implementation

## G2. Choking algorithm
- [ ] G2.1 Regular rechoke interval
- [ ] G2.2 Optimistic unchoke
- [ ] G2.3 Seed vs leecher behavior

## G3. Piece picker
- [x] G3.1 Rarest-first algorithm
- [x] G3.2 Availability tracking
- [ ] G3.3 Sequential mode
- [ ] G3.4 File priority integration

## G4. Endgame mode
- [ ] G4.1 Endgame detection
- [ ] G4.2 Duplicate requests
- [ ] G4.3 Cancel redundant blocks

## G5. Peer scoring
- [ ] G5.1 Throughput scoring
- [ ] G5.2 Latency scoring
- [ ] G5.3 Reliability scoring
- [ ] G5.4 Penalize bad peers
- [ ] G5.5 Integrate scoring into scheduler

-------------------------------------------------------------------------------

# H. Trackers

## H1. HTTP trackers (WinHTTP)
- [x] H1.1 Announce URL builder
- [x] H1.2 started event
- [x] H1.3 stopped event
- [x] H1.4 completed event
- [x] H1.5 Compact peer parsing
- [x] H1.6 Failure reason handling

## H2. HTTPS trackers (WinHTTP + SChannel)
- [x] H2.1 TLS via SChannel
- [x] H2.2 HTTPS announce success path
- [x] H2.3 Error handling

## H3. UDP trackers (BEP-15)
- [x] H3.1 Connect request
- [x] H3.2 Announce request
- [x] H3.3 Transaction ID validation
- [x] H3.4 Retry & timeout logic

## H4. Tracker management
- [ ] H4.1 Tier rotation
- [ ] H4.2 Backoff strategy
- [ ] H4.3 Multi-tracker aggregation

-------------------------------------------------------------------------------

# I. Extension Protocol & Magnets

## I1. BEP-10 base
- [x] I1.1 Extended handshake
- [x] I1.2 Extension ID negotiation

## I2. ut_metadata
- [x] I2.1 Metadata request
- [x] I2.2 Piece assembly
- [x] I2.3 Size cap enforcement
- [ ] I2.4 Infohash verification
- [ ] I2.5 Transition to full torrent

## I3. PEX (ut_pex)
- [ ] I3.1 Parse added peers
- [ ] I3.2 Parse dropped peers
- [ ] I3.3 Rate limit PEX updates
- [ ] I3.4 Feed peer candidate queue

-------------------------------------------------------------------------------

# J. DHT (BEP-5)

## J1. Core DHT
- [ ] J1.1 Node ID generation
- [ ] J1.2 Routing table (k-buckets)
- [ ] J1.3 RPC encoding/decoding
- [ ] J1.4 ping
- [ ] J1.5 find_node
- [ ] J1.6 get_peers
- [ ] J1.7 announce_peer

## J2. Tokens & safety
- [ ] J2.1 Token generation
- [ ] J2.2 Token validation
- [ ] J2.3 Rate limiting

## J3. Bootstrap
- [ ] J3.1 Default router list
- [ ] J3.2 Initial crawl
- [ ] J3.3 Node refresh logic

## J4. DHT for magnets
- [ ] J4.1 get_peers for infohash
- [ ] J4.2 Peer extraction
- [ ] J4.3 Fallback when no trackers

## J5. DHT IPv6
- [ ] J5.1 IPv6 socket
- [ ] J5.2 IPv6 routing table
- [ ] J5.3 Dual-stack operation

-------------------------------------------------------------------------------

# K. Local Service Discovery (BEP-14)

- [ ] K1. Multicast announce sender
- [ ] K2. Multicast listener
- [ ] K3. Parse LSD messages
- [ ] K4. Add discovered peers
- [ ] K5. Rate limiting

-------------------------------------------------------------------------------

# L. NAT Traversal

## L1. UPnP IGD
- [ ] L1.1 SSDP discovery
- [ ] L1.2 Device description fetch
- [ ] L1.3 Control URL detection
- [ ] L1.4 AddPortMapping
- [ ] L1.5 Renew mapping
- [ ] L1.6 Delete mapping on shutdown

## L2. NAT-PMP
- [ ] L2.1 Gateway discovery
- [ ] L2.2 Add mapping
- [ ] L2.3 Renew mapping
- [ ] L2.4 Error handling

-------------------------------------------------------------------------------

# M. IPv6 End-to-End

- [ ] M1. IPv6 peer connections
- [ ] M2. IPv6 inbound listener
- [ ] M3. IPv6 tracker support
- [ ] M4. IPv6 DHT integration
- [ ] M5. UI visibility of IPv6 status

-------------------------------------------------------------------------------

# N. µTP (BEP-29)

- [ ] N1. µTP socket implementation
- [ ] N2. Congestion control
- [ ] N3. Retransmission logic
- [ ] N4. Connection lifecycle
- [ ] N5. Scheduler integration
- [ ] N6. Peer scoring integration

-------------------------------------------------------------------------------

# O. UI – Status & Settings

## O1. Status window
- [x] O1.1 Window creation
- [ ] O1.2 Torrent list view
- [ ] O1.3 Live stats updates
- [ ] O1.4 Per-torrent context menu

## O2. Per-torrent actions
- [ ] O2.1 Pause/resume torrent
- [ ] O2.2 Remove torrent (keep data)
- [ ] O2.3 Remove torrent + delete data
- [ ] O2.4 Force recheck
- [ ] O2.5 Open containing folder

## O3. File priorities UI
- [ ] O3.1 File list view
- [ ] O3.2 Priority toggles
- [ ] O3.3 Wiring to piece picker

## O4. Settings dialog
- [ ] O4.1 Download directory
- [ ] O4.2 Listen port
- [ ] O4.3 Feature toggles
- [ ] O4.4 Limits configuration
- [ ] O4.5 Disk/cache settings

-------------------------------------------------------------------------------

# P. Reliability & Testing

## P1. Unit tests
- [x] P1.1 Bencode decoder tests
- [x] P1.2 Torrent parser tests
- [x] P1.3 Piece picker tests
- [ ] P1.4 Bandwidth limiter tests

## P2. Integration tests
- [x] P2.1 Engine startup/shutdown
- [x] P2.2 Add torrent workflow
- [ ] P2.3 Magnet workflow
- [ ] P2.4 Resume after crash

## P3. Torture tests
- [ ] P3.1 Kill during download
- [ ] P3.2 Network drop/reconnect
- [ ] P3.3 Tracker failure rotation

-------------------------------------------------------------------------------

# Q. Cleanup & Hardening

- [ ] Q1. Remove unused code paths
- [ ] Q2. Audit for dead code
- [ ] Q3. Allocation hot-path audit
- [ ] Q4. Final dependency audit
- [ ] Q5. Final binary size review
