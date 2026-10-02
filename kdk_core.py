#!/usr/bin/env python3
"""KryptDisk 1.44 mesh node core.

The core maintains persistent Ed25519/X25519 node identity, signed peer
discovery, fixed-size padded frames, Brownian/collision-earned relay, uniform
PoW-gated injection, encrypted native messages and receipts, and the canonical
1,474,560-byte Airgap object format.

Large objects and patch capsules use encrypted chunk transport with randomized
initial diffusion, receiver-led PULL discovery and bounded WANT repair. Dingo
height witnesses provide the shared logical clock used by traffic pacing,
discovery, file embargoes and progressive Cuckoo key release.

Authenticated patch capsules are reconstructed, hash-verified, staged and
atomically promoted. A supervising launcher confirms the promoted build,
performs a controlled restart and restores the previous core if startup fails.
"""

TEST_MARKER = "KDK"
AUTO_PATCH_TEST = 5

import math
import argparse
import socket
import time
import random
import threading
import os
import hashlib
import heapq
import json
import csv
import base64
import difflib
import msgpack
import sys
import subprocess
import re
import textwrap
import shutil
import platform
import ipaddress
import unicodedata

# Capture the original process launch context at import time. launch_node.py may
# later chdir into nodes/<name>; reconstructing sys.argv[0] after that change
# produced a false "restart entry script is missing" failure on Pi/Termux.
KDK_PROCESS_START_CWD = os.path.abspath(os.getcwd())

def _kdk_resolve_initial_entry() -> str:
    raw = str(sys.argv[0] if sys.argv and sys.argv[0] else "").strip()
    if not raw:
        return os.path.abspath(__file__)
    if os.path.isabs(raw):
        return os.path.normpath(raw)

    candidates = [
        os.path.abspath(os.path.join(KDK_PROCESS_START_CWD, raw)),
        os.path.abspath(raw),
    ]

    # Defensive fallback: search upward from both the original cwd and this
    # module for a launcher with the same basename.
    basename = os.path.basename(raw)
    for origin in (KDK_PROCESS_START_CWD, os.path.dirname(os.path.abspath(__file__))):
        here = os.path.abspath(origin)
        for _ in range(6):
            candidates.append(os.path.join(here, basename))
            parent = os.path.dirname(here)
            if parent == here:
                break
            here = parent

    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return os.path.abspath(os.path.join(KDK_PROCESS_START_CWD, raw))

KDK_PROCESS_INITIAL_ENTRY = _kdk_resolve_initial_entry()
QUIET_CONTROL = "--quiet-control" in sys.argv
import select
try:
    import termios
except ModuleNotFoundError:
    # Windows has no termios. The terminal helper functions below degrade
    # gracefully when termios is unavailable.
    termios = None
try:
    import msvcrt
except ModuleNotFoundError:
    msvcrt = None
from collections import deque
from typing import Dict, Tuple, List, Optional, Any

NACL_IMPORT_ERROR = None
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.public import PrivateKey, PublicKey, Box
    from nacl.secret import SecretBox
except Exception as exc:
    # Utility patch-capsule commands do not need PyNaCl. Running a live node still does.
    # Preserve the original exception so packaged builds report the real cause rather
    # than failing later with an unhelpful "NoneType is not callable" message.
    NACL_IMPORT_ERROR = exc
    SigningKey = VerifyKey = PrivateKey = PublicKey = Box = SecretBox = None



# ----------------------------- Configuration --------------------------------

HEARTBEAT_INTERVAL = 10.0
ACTIVE_TIMEOUT = 60.0
DISCOVER_INTERVAL = 30.0
DISCOVER_JITTER_MAX = 0.25

# LAN/WAN latency normalisation.
# Local/loopback/private-interface sends receive a small stochastic delay so
# dense LAN clusters cannot ricochet PAYLOADs at effectively zero latency and
# become trivially distinguishable from WAN propagation.
KDK_LAN_DELAY_MS = 13.5
KDK_LAN_DELAY_JITTER_MS = 0.75

# Detect long event-loop suspension (for example Windows sleep).
# On resume, force heartbeat/HELLO and discovery immediately rather than waiting
# for the normal adaptive timers to expire.
KDK_RESUME_GAP_SECS = 60.0

MAX_FRAME_SIZE = 900
KDK_MESSAGE_MAX_CHARS = 450

PAYLOAD_TTL_DEFAULT = 12
PAYLOAD_TTL_POST_QUORUM = 1
PAYLOAD_DEDUPE_TTL = 300.0

# Bounded runtime bookkeeping. Bootstrap sees a high volume of
# relayed payloads, so per-payload state must age out rather than grow for the
# lifetime of the process. Ten minutes matches the envelope replay horizon.
KDK_QUORUM_TRACKER_TTL = 10 * 60
KDK_DECRYPT_ATTEMPTED_TTL = 10 * 60
KDK_DIRECT_INBOX_MAX = 512
# Completed sender/seeder chunk maps remain useful for Pull/WANT for a day,
# then may be reconstructed from retained update capsules if needed.
KDK_CHUNK_TX_STORE_TTL = 24 * 60 * 60

# Collision-driven emission protocol
COLLISION_TRIGGER_N = 5          # emit one payload every N collisions (tune with --n)
EMIT_BUDGET_PER_TICK = 1         # max payloads emitted per run-loop tick

FAN_CHOICES = [1, 1, 2, 2, 3]
FAN_JITTER_MIN = 0.02
FAN_JITTER_MAX = 0.15

POW_MAX_ITER = 500_000  # legacy/compat PoW

ENVELOPE_REPLAY_TTL = 600.0
ENVELOPE_TS_SKEW = 300.0

# RPC
RPC_DEDUPE_TTL = 120.0            # vault dedupe reply TTL

# ---------------------------------------------------------------------------
# Vault RPC retry scheduling (client-side):
#   - Initial send happens normally.
#   - If no reply observed, allow up to 3 *further* attempts (max 4 total sends).
#   - Retry times are randomized over a nominal 60-second window with minimum spacing.
#   - Retries must be unobservable: every resend rebuilds the envelope (fresh sid/nonce/ciphertext),
#     yielding a new payload hash (ph) and a new PoW stamp.
#   - No "FAIL" timeout semantics; just "give up" after schedule exhausted.
# ---------------------------------------------------------------------------
RETRY_FURTHER_ATTEMPTS = 3
RETRY_WINDOW_SECS = 60
RETRY_MIN_DELAY_SECS = 5
RETRY_MIN_GAP_SECS = 10
RETRY_INFLIGHT_GRACE_SECS = 2.0

# Vault soft rate limiting
VAULT_RATE_WINDOW = 3.0           # seconds
VAULT_RATE_MAX = 10               # max RPC per src per window
VAULT_RATE_RETRY_AFTER = 1.5      # suggested backoff

# Persistent vault RID dedupe cache (crash-safe)
VAULT_RID_LOG_PATH = os.path.join("vault_store", "rid_cache.msgpackl")
VAULT_RID_LOG_COMPACT_EVERY = 500

# Orphan log softening
ORPHAN_LOG_TTL = 30.0             # only log first orphan per (src,rid,cmd) within this window

# Message / receipt feature toggles
ENABLE_MESSAGE_HOTKEY = True
ENABLE_RECEIPTS = True

# Airgap layer
ENABLE_AIRGAP_HOTKEY = True
AIRGAP_SIZE = 1_474_560              # 1.44 MB floppy-capacity canonical object
AIRGAP_MAGIC = b"KDKAG144"           # 8 bytes
AIRGAP_HEADER_SIZE = 512
AIRGAP_MAX_PLAINTEXT = AIRGAP_SIZE - AIRGAP_HEADER_SIZE - 128
AIRGAP_DIR = "airgap"
AIRGAP_PENDING_DIR = os.path.join(AIRGAP_DIR, "pending")
AIRGAP_OUT_DIR = os.path.join(AIRGAP_DIR, "out")
AIRGAP_UNLOCKED_DIR = os.path.join(AIRGAP_DIR, "unlocked")
AIRGAP_STATE_DIR = os.path.join(AIRGAP_DIR, "state")
AIRGAP_MIN_BLOCKS = 1
AIRGAP_DEFAULT_BLOCKS = 6

# Cuckoo Clock v1: progressive Airgap key release.
# For live use, set the minimum delay to 3600 seconds. For field testing,
# the default remains 20 minutes so a three-chunk release can be
# observed without waiting an hour.
CUCKOO_ENABLED_DEFAULT = True
CUCKOO_MIN_DELAY_SECS_TEST = 20 * 60
CUCKOO_MIN_DELAY_SECS_LIVE = 60 * 60
CUCKOO_MIN_CHUNKS = 3
CUCKOO_MAX_CHUNKS = 12
CUCKOO_DEFAULT_CHUNKS = 3
CUCKOO_DEFAULT_MIN_WITNESSES = 1
KDK_CUCKOO_KEY_RELEASE_REPEATS = 3

# Dingo height is obtained only from a locally validating dingocoind node or
# from a fresh signed mesh witness. Public explorer HTTP lookups were removed
# after endurance testing exposed rate limiting and socket accumulation.
KDK_HEIGHT_WAIT_NOTICE_SECS = 60.0
KDK_HEIGHT_ERROR_LOG_SECS = 60.0

# Dingo block-height heartbeat. Fresh locally validated or signed witnessed
# heights drive the shared scheduler, discovery timing, file/WANT embargoes and
# progressive Cuckoo key release. Patch bytes still travel through the ordinary
# encrypted chunk and collision-earned relay paths.
DINGO_HEIGHT_BEACON_ENABLED = True
# Local Dingo clients are polled promptly for a new public height.
# Height announcements are signed hop-by-hop but deliberately NOT encrypted.
# An idle node seeds one random verified peer immediately; during churn the
# beacon occupies an ordinary collision-earned queue turn. Relays use the same
# one-peer stochastic rule and never award collision turns themselves.
DINGO_HEIGHT_BEACON_INTERVAL_SECS = 2.0
DINGO_HEIGHT_BEACON_TOLERANCE_BLOCKS = 2
DINGO_HEIGHT_BEACON_MAX_RECIPIENTS = 1  # compatibility field; public beacon fanout is one
DINGO_HEIGHT_BEACON_STALE_SECS = 30 * 60
KDK_DINGO_PUBLIC_BEACON_TTL = 16
KDK_DINGO_IDLE_SEED_SECS = 5.0

# Sender-wide ordinary-file cooling period.
KDK_FILE_EMBARGO_BLOCKS = 2
KDK_FILE_EMBARGO_FALLBACK_SECS = 120.0

# Traffic streamlining defaults: keep mesh alive but reduce control-plane chatter.
# Sparse discovery remains seconds-based because 30 s is sub-block. Stable
# discovery prefers Dingo height: one stochastic probe every two fresh heights.
# The 120 s timer is retained only as degraded-mode fallback when no fresh
# Dingo height is available.
DISCOVER_STABLE_INTERVAL = 120.0
KDK_DISCOVER_STABLE_BLOCKS = 2
HEARTBEAT_RECENT_TRAFFIC_SUPPRESS_SECS = 30.0
HUD_STATE_HYSTERESIS_SECS = 3.0

# Chunking layer
KDK_OBJECT_MAX_SIZE = AIRGAP_SIZE
KDK_LOGICAL_CHUNK_SIZE = 128 * 1024
KDK_WIRE_CHUNK_SIZE = 192  # absolute ceiling; live transfers auto-size below this
KDK_DYNAMIC_CHUNK_MIN = 48
KDK_DYNAMIC_CHUNK_SAFETY_PAD = 72

# Dingo-height traffic discipline. Height controls eligibility, while the
# existing Brownian/collision scheduler still controls the exact transmit turn.
KDK_HEIGHT_PACING_ENABLED = True
KDK_HEIGHT_POLL_SECS = 2.0
KDK_HEIGHT_STALE_SECS = 180.0
KDK_HEIGHT_FALLBACK_SECS = 60.0
KDK_HEIGHT_PACED_PER_HEIGHT = 1

# Initial chunk baseline: the sender emits one manifest followed by one shuffled
# pass of all chunks. Receiver-led PULL and bounded encrypted WANT requests repair
# missing residue later without introducing per-chunk ACK/NACK traffic.
KDK_CHUNK_FULL_WAVES = 1
KDK_CHUNK_SPRINKLE_FRACTION = 0.0
KDK_CHUNK_MANIFEST_REPEATS = 1

# Slow-diffusion meshes may take a long time to complete a full object.
# Keep partial chunk state for long periods so delayed chunks still assemble.
KDK_CHUNK_PARTIAL_TTL = 24 * 60 * 60   # 24 hours

KDK_CHUNK_DIR = "chunked"
KDK_CHUNK_COMPLETE_DIR = os.path.join(KDK_CHUNK_DIR, "complete")

# Update over chunks
# Updates deliberately ride the ordinary encrypted/chunked object path.
# Peers may transport bytes, but version/hash checks are local policy.
KDK_UPDATE_KIND = "KDK_UPDATE_PATCH"
KDK_UPDATE_DIR = "updates"
KDK_UPDATE_INCOMING_DIR = os.path.join(KDK_UPDATE_DIR, "incoming")
KDK_UPDATE_STAGED_DIR = os.path.join(KDK_UPDATE_DIR, "staged")
KDK_UPDATE_APPLIED_DIR = os.path.join(KDK_UPDATE_DIR, "applied")
KDK_UPDATE_SEED_DIR = os.path.join(KDK_UPDATE_DIR, "seed")
KDK_UPDATE_REJECTED_DIR = os.path.join(KDK_UPDATE_DIR, "rejected")
KDK_UPDATE_BACKUP_DIR = os.path.join(KDK_UPDATE_DIR, "backups")
KDK_UPDATE_MAX_SCRIPT_SIZE = 2_000_000
KDK_PATCH_CAPSULE_MAX_SIZE = 50_000
KDK_HASH_DIGEST_PATH = os.path.join(KDK_UPDATE_DIR, "hash_digest.json")
KDK_VERSION_NOTICE_INTERVAL_SECS = 10 * 60

# Learned peer digest. These are bootstrap candidates only; peers still have
# to prove themselves by signing HELLO/HEARTBEAT/PAYLOAD traffic.
KDK_PEER_DIGEST_DIR = "peers"
KDK_PEER_DIGEST_PATH = os.path.join(KDK_PEER_DIGEST_DIR, "peer_digest.json")
KDK_PEER_DIGEST_MAX_AGE = 7 * 24 * 60 * 60
# Peer observations are hot-path events. Persist the non-authoritative bootstrap
# cache periodically rather than fsync'ing it from every verified packet.
KDK_PEER_DIGEST_FLUSH_INTERVAL_SECS = 60.0
KDK_MANUAL_PEERS_PATH = os.path.join(KDK_PEER_DIGEST_DIR, "manual_peers.json")
KDK_PEER_POLICY_PATH = os.path.join(KDK_PEER_DIGEST_DIR, "peer_policy.json")
KDK_PROFILE_PATH = "profile.json"
KDK_STANDARD_PEER_PORTS = tuple(range(6001, 6011))

# Legacy fallback hook retained for compatibility.
# Public builds do not ship private/test LAN peers; bootstrap peers come from configuration.
KDK_DEFAULT_LAN_PROFILE = {}

# Bounded missing-chunk repair using encrypted WANT requests.
KDK_WANT_ENABLED = True
KDK_WANT_MAX_ROUNDS = 12             # bounded repair pulses; allow larger objects to finish residue cleanup
KDK_WANT_CONVERGENCE_ROUNDS = 4          # extra tail rounds only when the previous final round made progress
KDK_WANT_DELAY_SECS = 22.0
KDK_WANT_FINAL_DELAY_SECS = 8.0        # when only a few chunks remain, ask sooner
KDK_WANT_FINAL_MISSING = 16
KDK_WANT_MIN_INTERVAL_SECS = 26.0       # wait between WANT rounds so prior repairs can arrive
KDK_WANT_STALE_RETRY_SECS = 45.0       # do not burn extra WANT rounds unless progress was seen, or this elapsed
# WANT privacy discipline: once a repair request would otherwise be eligible,
# embargo it for a random 1-2 *fresh Dingo block heights*. The block advance
# only removes the embargo; actual emission still waits for the ordinary
# collision-earned queue/height scheduler like every other payload.
KDK_WANT_DINGO_DELAY_MIN_BLOCKS = 1
KDK_WANT_DINGO_DELAY_MAX_BLOCKS = 2
KDK_WANT_MAX_MISSING = 256
KDK_WANT_FINAL_DOUBLE_MISSING = 16   # if WANT list is this small, sender emits the requested repair set twice
KDK_WANT_FINAL_REPEATS = 2
KDK_WANT_FINAL_RESCUE_MISSING = 4    # if WANT list is tiny, sender emits the requested repair set three times
KDK_WANT_FINAL_RESCUE_REPEATS = 3

# After a requested repair chunk is transmitted, keep it in an
# in-flight cache for a short grace period. Repeated WANTs during this window
# do not re-add the same chunk to the repair set. If the receiver still reports
# it missing after the timeout, it becomes eligible for retransmission again.
KDK_REPAIR_INFLIGHT_TIMEOUT_SECS = 18.0
KDK_REPAIR_INFLIGHT_MAX = 2048

# Repair-wave timing/backoff. When a sender already has a sizeable
# repair side-set for an object, fresh WANT packets for that same object are
# briefly deferred so the current wave has time to cross the mesh and be
# reflected in the receiver's next missing set.
KDK_REPAIR_WANT_DEFER_THRESHOLD = 36
KDK_REPAIR_WANT_DEFER_LOW_WATER = 8
KDK_REPAIR_WANT_DEFER_SECS = 20.0

# A WANT is itself carried inside an encrypted fixed-size KDK frame.  A large
# missing-index list can therefore exceed MAX_FRAME_SIZE and deadlock the queue
# if retried unchanged.  Split missing indexes into small independent WANT
# envelopes; the sender already handles each WANT as a partial repair request.
KDK_WANT_BATCH_SIZE = 24

# Receiver-side adaptive WANT cadence. The receiver does not
# know sequence order, only the manifest total and the set of unique chunks
# already seen.  It therefore estimates the current transfer rhythm from
# recent unique chunk arrival gaps and only asks for repairs after the stream
# has gone quiet relative to that cadence.
KDK_WANT_CADENCE_WINDOW = 8
KDK_WANT_CADENCE_DEFAULT_SECS = 5.0
KDK_WANT_CADENCE_FACTOR = 4.0
KDK_WANT_CADENCE_FINAL_FACTOR = 2.5
KDK_WANT_CADENCE_MIN_SECS = 15.0
KDK_WANT_CADENCE_MAX_SECS = 75.0

# Collision-triggered turns can dry up exactly when the ordinary
# queue reaches zero and only the coalesced repair side-set remains.  A small
# idle repair pump lets pending repairs earn a sparse local turn even without
# fresh collisions, preventing q=0 repair=N deadlock.
KDK_REPAIR_IDLE_PUMP_SECS = 1.25

# Do not let an early WANT convert a fresh object into pure
# repair mode.  WANT/repair is for the residue/tail, not the first sweep.
# For larger objects, keep normal data chunks flowing until only this
# fraction remains in the ordinary queue, then allow targeted repair/prune.
KDK_REPAIR_ALLOW_WHEN_REMAINING_FRACTION = 0.20
KDK_REPAIR_ALLOW_WHEN_REMAINING_CHUNKS = 8
KDK_REPAIR_EARLY_GATE_MIN_CHUNKS = 8

# Receiver-led pull swarm for update capsules. Update objects use a
# canonical wire chunk size so chunk indexes mean the same thing at every seeder.
KDK_PULL_ENABLED = True
KDK_UPDATE_CANONICAL_WIRE_CHUNK_SIZE = 96
KDK_PULL_RANDOM_BATCH = 18
KDK_PULL_MAX_PEERS = 8
KDK_PULL_MIN_PEERS = 2
KDK_PULL_INTERVAL_SECS = 18.0
KDK_PULL_DISCOVERY_RETRY_SECS = 18.0
KDK_PULL_DISCOVERY_MAX_ATTEMPTS = 6
KDK_PULL_SERVE_COOLDOWN_SECS = 4.0
KDK_PULL_BUSY_QUEUE = 96
# Update pull remains stochastic/coarse until 80% complete,
# then the existing exact missing-index WANT path takes over. Chunk indexing
# remains the established 1..N wire convention.
KDK_PULL_COARSE_FRACTION = 0.80
KDK_PULL_COARSE_BACKLOG_MAX = 10


# Peer-hint discovery layer
# Peer hints are NOT separate wire packets and are NOT attached to raw dummy payloads.
# They are optional blocks inside ordinary decryptable KD-ENVELOPE v3 payloads
# (message, receipt, airgap ticket/receipt, chunk, RPC, etc.).
ENABLE_PEER_HINTS = True
PEER_HINT_PROB = 0.30
PEER_HINT_MAX = 3
PEER_HINT_TTL_SECS = 1800
PEER_HINT_CONNECT_PROB = 0.20
PEER_HINT_CONNECT_JITTER_MIN = 20.0
PEER_HINT_CONNECT_JITTER_MAX = 180.0
PEER_HINT_PROBE_INTERVAL = 10.0
PEER_HINT_MAX_CANDIDATES = 128

# Directory/rendezvous hints are signed DISCOVER_REPLY hints
# from a verified node. They are not authority: receivers still HELLO/probe
# candidates and verify each peer cryptographically before trusting traffic.
ENABLE_DIRECTORY_HINTS = True
DIRECTORY_HINT_MAX = 16

# Queue emission pacing. A queued real envelope (message, chunk, receipt, RPC)
# is released only on a collision-earned turn. After any queued envelope is
# emitted, the node waits a random number of future turns before releasing
# another queued envelope; those intervening turns emit dummy traffic.
# Keep the default gap tight but use probabilistic weighted
# selection so real work progresses while dummy traffic remains interleaved.
QUEUE_EMIT_GAP_MIN_TURNS = 1
QUEUE_EMIT_GAP_MAX_TURNS = 3
QUEUE_DUMMY_BLEND_NORMAL = 0.35
QUEUE_DUMMY_BLEND_BUSY = 0.25
QUEUE_DUMMY_BLEND_REPAIR = 0.04

# An accepted update manifest must be followed by a useful data
# sweep. Update chunks still use ordinary encrypted PAYLOAD frames and earned
# Brownian turns, but they bypass the one-substantive-packet-per-height gate and
# receive a strong internal queue bias so a small patch cannot stall for hours.
KDK_UPDATE_TRANSFER_BURST_PROB = 0.98

# Keep manifests robust and logs small by default.
KDK_LOG_MAX_BYTES = 5 * 1024 * 1024
KDK_LOG_BACKUPS = 3
KDK_MANIFEST_REPEAT_COUNT = 4
KDK_MANIFEST_EARLY_AT_CHUNKS = 10
KDK_MANIFEST_PRIORITY_PROB_BUSY = 0.35
KDK_MANIFEST_PRIORITY_PROB_NORMAL = 0.18
# Repair chunks should finish missing residues promptly without
# turning the whole mesh into a deterministic file-transfer mode.
KDK_REPAIR_INSERT_WINDOW = 10
KDK_REPAIR_LATE_ROUND = 5
# Repair requests are coalesced in a side-set, not appended
# repeatedly to the main outbound queue. This keeps q bounded while allowing
# late WANT rounds to finish efficiently.
KDK_REPAIR_SET_BURST_PROB = 1.0
KDK_REPAIR_SET_MAX = 512

# End-to-end reliability for probabilistic transport.
# Retries rebuild encrypted envelopes, so stable logical IDs remain private on wire.
KDK_RELIABILITY_DIR = "reliability"
KDK_RELIABILITY_STATE_PATH = os.path.join(KDK_RELIABILITY_DIR, "state.json")
KDK_RETRY_DELAYS_SECS = (20, 45, 90, 180, 300, 600)
KDK_RELIABLE_MAX_AGE_SECS = 6 * 60 * 60
KDK_DELIVERED_CACHE_TTL_SECS = 7 * 24 * 60 * 60
KDK_DELIVERED_CACHE_MAX = 4096

# Diagnostic payload tracing. Disabled by default and runtime-toggleable from
# Console -> Trace. Trace output is metadata-only JSONL: no plaintext, keys,
# signatures or ciphertext are written. The log is deliberately bounded.
KDK_TRACE_ENABLED_DEFAULT = False
KDK_TRACE_LOG_MAX_BYTES = 2 * 1024 * 1024
KDK_TRACE_LOG_BACKUPS = 2
KDK_TRACE_TRACK_TTL_SECS = 60 * 60
KDK_TRACE_TRACK_MAX = 1024
KDK_TRACE_BLOCK_TYPES = {"message", "receipt", "receipt_ack"}


# ----------------------------- Utilities ------------------------------------

def qprint(*args, **kwargs):
    line = " ".join(str(a) for a in args)

    if not QUIET_CONTROL:
        print(*args, **kwargs)
        return

    # In quiet-control mode, suppress dummy TURN churn so prompts remain usable.
    if "[TURN]" in line and "class=DUMMY" in line:
        return

    KEEP = (
        "[RUN]",
        "[AIRGAP]",
        "[CHUNK]",
        "[QUEUE]",
        "KDK-CHUNK",
        "AIRGAP-TICKET",
        "AIRGAP-RECEIPT",
        "[RECEIPT]",
        "[TURN]",
        "[VERSION",
        "[UPDATE",
    )

    if any(k in line for k in KEEP):
        print(*args, **kwargs)

def compute_script_hash() -> str:
    try:
        with open(__file__, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except Exception:
        return "unknown"

SCRIPT_VERSION = "10.20.96-KryptDisk-1.44-Beta-1"
# Release identity is deliberately separate from monotonic revision ordering.
# Nodes may follow an alternative lineage by local choice, but automatic update
# offers never cross an explicitly different origin/lineage boundary.
SCRIPT_ORIGIN = "KryptDisk-official"
SCRIPT_LINEAGE = "stable"
# Monotonic build order used for update decisions within a release lineage.
SCRIPT_REVISION = 102096
SCRIPT_HASH = compute_script_hash()

def revision_from_version(v: str) -> int:
    """Compatibility revision for older nodes that advertise no build number.

    Only the leading dotted numeric run is considered.  Product numbers in the
    descriptive suffix (for example KryptDisk-1.44) must never affect ordering.
    """
    m = re.match(r"^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v or ""))
    if not m:
        return 0
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return major * 10000 + minor * 100 + patch

def version_cmp(a: str, b: str, a_revision=None, b_revision=None) -> int:
    """Compare monotonic revisions, falling back to leading semantic numbers."""
    try:
        ra = int(a_revision) if a_revision is not None else revision_from_version(a)
    except Exception:
        ra = revision_from_version(a)
    try:
        rb = int(b_revision) if b_revision is not None else revision_from_version(b)
    except Exception:
        rb = revision_from_version(b)
    return -1 if ra < rb else (1 if ra > rb else 0)

def extract_script_revision_from_bytes(data: bytes) -> int:
    try:
        text = data[:65536].decode("utf-8", "ignore")
        m = re.search(r'^SCRIPT_REVISION\s*=\s*(\d+)', text, re.M)
        if m:
            return int(m.group(1))
        return revision_from_version(extract_script_version_from_bytes(data))
    except Exception:
        return 0

def extract_script_version_from_bytes(data: bytes) -> str:
    try:
        text = data[:65536].decode("utf-8", "ignore")
        m = re.search(r'^SCRIPT_VERSION\s*=\s*["\']([^"\']+)["\']', text, re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "0.0"

def extract_script_release_identity_from_bytes(data: bytes) -> Tuple[str, str]:
    """Return (origin, lineage) embedded in a core, with legacy-compatible defaults."""
    try:
        text = data[:65536].decode("utf-8", "ignore")
        mo = re.search(r'^SCRIPT_ORIGIN\s*=\s*["\']([^"\']+)["\']', text, re.M)
        ml = re.search(r'^SCRIPT_LINEAGE\s*=\s*["\']([^"\']+)["\']', text, re.M)
        origin = mo.group(1) if mo else SCRIPT_ORIGIN
        lineage = ml.group(1) if ml else SCRIPT_LINEAGE
        return str(origin), str(lineage)
    except Exception:
        return SCRIPT_ORIGIN, SCRIPT_LINEAGE

def kdk_release_identity_matches(origin: str = "", lineage: str = "") -> bool:
    """Legacy peers with no identity remain compatible; explicit forks do not auto-cross."""
    origin = str(origin or "").strip()
    lineage = str(lineage or "").strip()
    if origin and origin != SCRIPT_ORIGIN:
        return False
    if lineage and lineage != SCRIPT_LINEAGE:
        return False
    return True

def unique_destination(directory: str, filename: str) -> str:
    """Return a collision-safe path without overwriting an existing file."""
    ensure_dir(directory)
    safe = "".join(c for c in os.path.basename(filename) if c.isalnum() or c in ("-", "_", ".", " ")).strip() or "object.bin"
    stem, ext = os.path.splitext(safe)
    candidate = os.path.join(directory, safe)
    n = 2
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{stem} ({n}){ext}")
        n += 1
    return candidate

def atomic_write_verified(path: str, data: bytes, expected_hash: str = "") -> None:
    ensure_dir(os.path.dirname(path) or ".")
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    if expected_hash and hashlib.sha256(open(tmp, "rb").read()).hexdigest() != expected_hash:
        try: os.remove(tmp)
        except Exception: pass
        raise ValueError("written file hash mismatch")
    os.replace(tmp, path)

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def kdk_canonicalize_message_text(text: str) -> str:
    """Return the conservative canonical form for native KDK text messages.

    Transport standardisation only: NFC Unicode, LF line endings, no trailing
    spaces/tabs on a line, and no blank lines at the outer edges. Internal
    spacing, tabs, blank lines, punctuation, emoji and other content survive.
    File payloads never pass through this function.
    """
    text = unicodedata.normalize("NFC", str(text or ""))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t]+$", "", line) for line in text.split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def kdk_validate_display_name(value: str) -> str:
    """Return a safe human label; cryptographic identity is independent of it."""
    name = unicodedata.normalize("NFC", str(value or "")).strip()
    if not name:
        raise ValueError("display name cannot be blank")
    if len(name) > 32:
        raise ValueError("display name is too long; maximum is 32 characters")
    if any(unicodedata.category(ch).startswith("C") for ch in name):
        raise ValueError("display name contains a control character")
    return name


def kdk_load_display_name(path: str, fallback: str) -> str:
    """Load an optional persistent display name, preserving legacy fallback."""
    profile_path = os.path.abspath(str(path or KDK_PROFILE_PATH))
    try:
        with open(profile_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except FileNotFoundError:
        return kdk_validate_display_name(fallback)
    except Exception as exc:
        raise ValueError(f"display-name profile is unreadable: {profile_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"display-name profile must be a JSON object: {profile_path}")
    return kdk_validate_display_name(data.get("display_name"))


def kdk_save_display_name(path: str, name: str) -> str:
    """Atomically persist only the mutable human label for this profile."""
    clean = kdk_validate_display_name(name)
    profile_path = os.path.abspath(str(path or KDK_PROFILE_PATH))
    ensure_dir(os.path.dirname(profile_path) or ".")
    tmp = profile_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"format": 1, "display_name": clean}, f, ensure_ascii=False,
                  sort_keys=True, separators=(",", ":"))
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass
    os.replace(tmp, profile_path)
    return clean

def kdk_json_dumps_canonical(obj: dict) -> bytes:
    """Canonical JSON bytes for update capsules: sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def kdk_parse_canonical_capsule(blob: bytes) -> dict:
    """Parse a capsule and require canonical JSON byte-for-byte."""
    if not isinstance(blob, (bytes, bytearray)):
        raise ValueError("capsule must be bytes")
    raw = bytes(blob)
    bundle = json.loads(raw.decode("utf-8", "strict"))
    if not isinstance(bundle, dict):
        raise ValueError("capsule root is not a JSON object")
    canonical = kdk_json_dumps_canonical(bundle)
    if canonical != raw:
        raise ValueError("patch capsule is not canonical JSON")
    return bundle

def kdk_make_text_span_capsule(base_raw: bytes, target_raw: bytes, note: str = "") -> bytes:
    """Build an exact external patch capsule from base bytes to target bytes.

    The patch is deliberately separate from the script.  It carries:
      base_hash   = sha256(exact current/base bytes)
      target_hash = sha256(exact new/target bytes)
      ops         = byte-span replacements that transform base -> target

    A receiver applies it only when its current file hash exactly equals
    base_hash, and accepts only when the patched result equals target_hash.
    """
    if not isinstance(base_raw, (bytes, bytearray)) or not isinstance(target_raw, (bytes, bytearray)):
        raise ValueError("base and target must be bytes")
    base_raw = bytes(base_raw)
    target_raw = bytes(target_raw)

    base_text = base_raw.decode("utf-8", "strict")
    target_text = target_raw.decode("utf-8", "strict")
    base_lines = base_text.splitlines(keepends=True)
    target_lines = target_text.splitlines(keepends=True)

    # byte offset at start of each base line
    offsets = [0]
    total = 0
    for line in base_lines:
        total += len(line.encode("utf-8"))
        offsets.append(total)

    ops = []
    sm = difflib.SequenceMatcher(a=base_lines, b=target_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        start = offsets[i1]
        end = offsets[i2]
        old = base_raw[start:end]
        new = "".join(target_lines[j1:j2]).encode("utf-8")
        ops.append({
            "end": int(end),
            "new_b64": base64.b64encode(new).decode("ascii"),
            "new_len": int(len(new)),
            "old_hash": sha256(old),
            "old_len": int(len(old)),
            "op": "replace_bytes",
            "start": int(start),
        })

    base_origin, base_lineage = extract_script_release_identity_from_bytes(base_raw)
    target_origin, target_lineage = extract_script_release_identity_from_bytes(target_raw)
    bundle = {
        "base_hash": sha256(base_raw),
        "base_version": extract_script_version_from_bytes(base_raw),
        "base_revision": extract_script_revision_from_bytes(base_raw),
        "base_origin": base_origin,
        "base_lineage": base_lineage,
        "kind": KDK_UPDATE_KIND,
        "note": str(note or "KDK external patch capsule: exact base -> exact target"),
        "ops": ops,
        "patch_format": "text_spans_v1",
        "target_hash": sha256(target_raw),
        "target_version": extract_script_version_from_bytes(target_raw),
        "target_revision": extract_script_revision_from_bytes(target_raw),
        "target_origin": target_origin,
        "target_lineage": target_lineage,
        "transport": "mesh-chunks",
        "ver": 2,
    }
    return kdk_json_dumps_canonical(bundle)

def kdk_apply_patch_capsule_to_bytes(current_raw: bytes, capsule_raw: bytes) -> Tuple[bytes, dict]:
    """Apply a KDK patch capsule to current bytes with exact hash validation."""
    current_raw = bytes(current_raw)
    bundle = kdk_parse_canonical_capsule(capsule_raw)

    if bundle.get("kind") != KDK_UPDATE_KIND:
        raise ValueError("not a KDK update capsule")

    base_hash = str(bundle.get("base_hash", ""))
    target_hash = str(bundle.get("target_hash", ""))
    patch_format = str(bundle.get("patch_format", ""))

    if len(base_hash) != 64 or len(target_hash) != 64:
        raise ValueError("base_hash and target_hash must be full 64-char sha256 hashes")

    current_hash = sha256(current_raw)
    if current_hash != base_hash:
        raise ValueError(f"base hash mismatch current={current_hash[:16]} base={base_hash[:16]}")

    if patch_format == "text_spans_v1":
        ops = bundle.get("ops", [])
        if not isinstance(ops, list):
            raise ValueError("ops must be a list")
        out = bytearray()
        cursor = 0
        last_start = -1
        for op in sorted(ops, key=lambda x: int(x.get("start", 0))):
            if not isinstance(op, dict) or op.get("op") != "replace_bytes":
                raise ValueError("unsupported text_spans_v1 op")
            start = int(op.get("start", -1))
            end = int(op.get("end", -1))
            if start < cursor or end < start or start < 0 or end > len(current_raw):
                raise ValueError("invalid or overlapping patch span")
            if start < last_start:
                raise ValueError("patch spans out of order")
            old = current_raw[start:end]
            if sha256(old) != str(op.get("old_hash", "")):
                raise ValueError(f"old span hash mismatch at {start}:{end}")
            new = base64.b64decode(str(op.get("new_b64", "")).encode("ascii"), validate=True)
            if len(old) != int(op.get("old_len", len(old))):
                raise ValueError("old_len mismatch")
            if len(new) != int(op.get("new_len", len(new))):
                raise ValueError("new_len mismatch")
            out.extend(current_raw[cursor:start])
            out.extend(new)
            cursor = end
            last_start = start
        out.extend(current_raw[cursor:])
        patched_raw = bytes(out)

    elif patch_format == "regex_subs_v1":
        # Legacy dev format retained for old capsules, but still exact-hash gated.
        text = current_raw.decode("utf-8", "strict")
        ops = bundle.get("ops", [])
        if not isinstance(ops, list) or not ops:
            raise ValueError("bad regex ops")
        for op in ops:
            if not isinstance(op, dict) or op.get("op") != "regex_sub":
                raise ValueError("unsupported regex_subs_v1 op")
            pat = str(op.get("pattern", ""))
            repl = str(op.get("replacement", ""))
            count = int(op.get("count", 1) or 1)
            text, n = re.subn(pat, repl, text, count=count, flags=re.M)
            if n != count:
                raise ValueError(f"patch op {op.get('name','?')} matched {n}, expected {count}")
        patched_raw = text.encode("utf-8")

    else:
        raise ValueError(f"unsupported patch_format {patch_format!r}")

    patched_hash = sha256(patched_raw)
    if patched_hash != target_hash:
        raise ValueError(f"patched hash mismatch {patched_hash[:16]} != {target_hash[:16]}")

    embedded_version = extract_script_version_from_bytes(patched_raw)
    target_version = str(bundle.get("target_version", ""))
    if target_version and embedded_version != target_version:
        raise ValueError(f"patched version mismatch {embedded_version!r} != {target_version!r}")

    return patched_raw, bundle

def kdk_make_patch_capsule_file(base_path: str, target_path: str, out_path: str) -> bytes:
    base_raw = open(base_path, "rb").read()
    target_raw = open(target_path, "rb").read()
    capsule = kdk_make_text_span_capsule(base_raw, target_raw)
    with open(out_path, "wb") as f:
        f.write(capsule)
    return capsule

def kdk_apply_patch_capsule_file(script_path: str, capsule_path: str, apply: bool = False) -> Tuple[bytes, dict]:
    current_raw = open(script_path, "rb").read()
    capsule_raw = open(capsule_path, "rb").read()
    patched_raw, bundle = kdk_apply_patch_capsule_to_bytes(current_raw, capsule_raw)
    if apply:
        backup = f"{script_path}.bak_{sha256(current_raw)[:12]}"
        tmp = f"{script_path}.kdkpatchtmp"
        with open(backup, "wb") as f:
            f.write(current_raw)
        with open(tmp, "wb") as f:
            f.write(patched_raw)
        os.replace(tmp, script_path)
    return patched_raw, bundle

def kdk_load_hash_digest(path: str = KDK_HASH_DIGEST_PATH) -> dict:
    """Load the tiny local accepted-hash digest ledger."""
    try:
        if not os.path.exists(path):
            return {"current": "", "accepted": []}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"current": "", "accepted": []}
        accepted = data.get("accepted", [])
        if not isinstance(accepted, list):
            accepted = []
        clean = []
        seen = set()
        for rec in accepted:
            if not isinstance(rec, dict):
                continue
            h = str(rec.get("hash", ""))
            if len(h) != 64 or h in seen:
                continue
            seen.add(h)
            clean.append({
                "hash": h,
                "version": str(rec.get("version", "")),
                "ts": int(rec.get("ts", 0) or 0),
            })
        return {"current": str(data.get("current", "")), "accepted": clean[-64:]}
    except Exception:
        return {"current": "", "accepted": []}

def kdk_hash_digest_seen(path: str, h: str) -> bool:
    if len(str(h)) != 64:
        return False
    data = kdk_load_hash_digest(path)
    return any(str(r.get("hash", "")) == str(h) for r in data.get("accepted", []))

def kdk_record_hash_digest(path: str, h: str, version: str, ts: Optional[int] = None):
    """Record an accepted script hash. Keeps only a small rolling ledger."""
    if len(str(h)) != 64:
        return
    ensure_dir(os.path.dirname(path) or ".")
    data = kdk_load_hash_digest(path)
    accepted = data.get("accepted", [])
    if not any(str(r.get("hash", "")) == str(h) for r in accepted):
        accepted.append({
            "hash": str(h),
            "version": str(version or ""),
            "ts": int(ts if ts is not None else time.time()),
        })
    data = {"current": str(h), "accepted": accepted[-64:]}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True, separators=(",", ":"))
    os.replace(tmp, path)

KDK_UPDATE_RESTART_MARKER = os.path.join(KDK_UPDATE_DIR, "restart_pending.json")
KDK_UPDATE_STARTUP_TIMEOUT_SECS = 15.0
KDK_UPDATE_RESTART_EXIT_CODE = 42
KDK_MANUAL_RESTART_EXIT_CODE = 43


def kdk_runtime_launch_spec() -> dict:
    """Return the exact launch command needed to recreate this node process.

    The launch path and cwd are captured before launch_node.py can chdir into a
    node runtime directory. This keeps Raspberry Pi, Linux and Termux restarts
    pointed at the real launcher instead of nodes/<name>/launch_node.py.
    """
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        executable = os.path.abspath(sys.executable)
        command = [executable] + list(sys.argv[1:])
        kind = "frozen-executable"
        entry = executable
        cwd = KDK_PROCESS_START_CWD
    else:
        entry = os.path.abspath(KDK_PROCESS_INITIAL_ENTRY)
        command = [os.path.abspath(sys.executable), entry] + list(sys.argv[1:])
        kind = "python-script"
        cwd = KDK_PROCESS_START_CWD

    return {
        "kind": kind,
        "command": command,
        "cwd": os.path.abspath(cwd),
        "python": os.path.abspath(sys.executable),
        "entry": entry,
        "platform": platform.system() if "platform" in globals() else os.name,
        "frozen": frozen,
        "captured_before_chdir": True,
    }


def kdk_write_restart_marker(record: dict) -> None:
    ensure_dir(KDK_UPDATE_DIR)
    tmp = KDK_UPDATE_RESTART_MARKER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(record, f, sort_keys=True, separators=(",", ":"))
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
    os.replace(tmp, KDK_UPDATE_RESTART_MARKER)


def kdk_load_restart_marker() -> dict:
    try:
        with open(KDK_UPDATE_RESTART_MARKER, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def kdk_clear_restart_marker() -> None:
    try:
        os.remove(KDK_UPDATE_RESTART_MARKER)
    except FileNotFoundError:
        pass


def kdk_write_supervisor_ready(node) -> bool:
    """Publish a launcher-verifiable ready record after full node startup.

    The launcher supplies an absolute ready-file path and a random ownership
    token in the environment.  The child records its PID/PPID, node identity,
    bound port and build hash only after construction and socket bind succeed.
    """
    ready_path = str(os.environ.get("KDK_READY_PATH", "") or "").strip()
    token = str(os.environ.get("KDK_LAUNCH_TOKEN", "") or "").strip()
    expected_launcher = str(os.environ.get("KDK_LAUNCHER_PID", "") or "").strip()
    if not ready_path or not token:
        return False
    try:
        pid = int(os.getpid())
        ppid = int(os.getppid())
        expected_launcher_pid = int(expected_launcher) if expected_launcher else 0
        # Android/Termux process accounting can report the child PID as its own
        # parent when launched through the app runtime.  There the random token,
        # private ready path and exact Popen child PID remain the ownership proof.
        is_termux = bool(os.environ.get("TERMUX_VERSION") or "/com.termux/" in str(sys.executable))
        ppid_verified = bool(expected_launcher_pid and ppid == expected_launcher_pid)
        if expected_launcher_pid and not ppid_verified:
            qprint(
                f"[RUN] supervisor PPID not verified expected={expected_launcher_pid} actual={ppid}; "
                "continuing with token/Popen ownership proof"
            )
        record = {
            "format": 2,
            "token": token,
            "pid": pid,
            "ppid": ppid,
            "launcher_pid": expected_launcher_pid,
            "ppid_verified": ppid_verified,
            "termux_ppid_compat": bool(is_termux and expected_launcher_pid and not ppid_verified),
            "ppid_compat": bool(expected_launcher_pid and not ppid_verified),
            "name": str(getattr(node, "name", "")),
            "port": int(getattr(node, "port", 0)),
            "version": SCRIPT_VERSION,
            "revision": int(SCRIPT_REVISION),
            "origin": SCRIPT_ORIGIN,
            "lineage": SCRIPT_LINEAGE,
            "hash": hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest(),
            "ready_ts": int(time.time()),
        }
        ensure_dir(os.path.dirname(os.path.abspath(ready_path)) or ".")
        tmp = os.path.abspath(ready_path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(record, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, os.path.abspath(ready_path))
        qprint(f"[RUN] supervisor confirmed launcher={ppid} child={os.getpid()}")
        return True
    except Exception as exc:
        qprint(f"[RUN] supervisor ready record failed: {exc}")
        return False


def kdk_clear_supervisor_ready() -> None:
    ready_path = str(os.environ.get("KDK_READY_PATH", "") or "").strip()
    if not ready_path:
        return
    try:
        os.remove(os.path.abspath(ready_path))
    except FileNotFoundError:
        pass
    except Exception:
        pass


def kdk_confirm_promoted_startup() -> bool:
    """Clear the pending marker only after the new node has constructed fully.

    main() calls this after key loading, socket bind and runtime configuration.
    The waiting parent therefore treats a cleared marker as proof that the
    promoted build reached a usable startup point.
    """
    marker = kdk_load_restart_marker()
    if not marker:
        return False
    expected = str(marker.get("target_hash", ""))
    try:
        actual = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()
    except Exception:
        return False
    if len(expected) == 64 and actual != expected:
        return False
    kdk_clear_restart_marker()
    qprint(f"[UPDATE] startup confirmed version={SCRIPT_VERSION} hash={actual[:16]}")
    return True


def kdk_restore_update_backup(marker: dict) -> bool:
    target = os.path.abspath(str(marker.get("target_path", "") or __file__))
    backup = os.path.abspath(str(marker.get("backup_path", "") or ""))
    expected = str(marker.get("previous_hash", ""))
    if not backup or not os.path.isfile(backup):
        return False
    raw = open(backup, "rb").read()
    if len(expected) == 64 and hashlib.sha256(raw).hexdigest() != expected:
        return False
    atomic_write_verified(target, raw, expected)
    return True


def kdk_supervise_promoted_restart(record: dict) -> int:
    """Launch the promoted build, confirm startup, or restore the backup.

    This adapter deliberately uses subprocess on every platform. The node has
    already completed graceful shutdown, so Windows, Linux, Raspberry Pi and
    Termux all follow the same protocol and no child inherits a live UDP socket.
    """
    launch = dict(record.get("launch", {}) or {})
    command = [str(x) for x in list(launch.get("command", []) or [])]
    cwd = os.path.abspath(str(launch.get("cwd", "") or KDK_PROCESS_START_CWD))
    if not command or not os.path.isfile(command[0]):
        raise RuntimeError(f"restart executable/interpreter is missing: {command[0] if command else '<empty>'}")
    if len(command) > 1 and launch.get("kind") == "python-script" and not os.path.isfile(command[1]):
        raise RuntimeError(f"restart entry script is missing: {command[1]}")
    if not os.path.isdir(cwd):
        if len(command) > 1 and launch.get("kind") == "python-script":
            cwd = os.path.dirname(os.path.abspath(command[1]))
        else:
            cwd = os.path.dirname(os.path.abspath(command[0]))
    if not os.path.isdir(cwd):
        raise RuntimeError(f"restart working directory is missing: {cwd}")

    kdk_write_restart_marker(record)
    qprint(f"[UPDATE] relaunch command={command!r} cwd={cwd!r}")
    env = os.environ.copy()
    env["KDK_UPDATE_RESTART"] = str(record.get("target_hash", ""))
    child = subprocess.Popen(command, cwd=cwd, env=env)
    deadline = time.time() + float(KDK_UPDATE_STARTUP_TIMEOUT_SECS)
    while time.time() < deadline:
        if not os.path.exists(KDK_UPDATE_RESTART_MARKER):
            qprint(f"[UPDATE] promoted node confirmed pid={child.pid}")
            return 0
        rc = child.poll()
        if rc is not None:
            break
        time.sleep(0.20)

    try:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=3.0)
    except Exception:
        try:
            child.kill()
        except Exception:
            pass

    marker = kdk_load_restart_marker() or record
    restored = kdk_restore_update_backup(marker)
    kdk_clear_restart_marker()
    if not restored:
        qprint("[UPDATE] promoted startup failed and automatic rollback was not possible")
        return KDK_UPDATE_RESTART_EXIT_CODE

    qprint(f"[UPDATE] promoted startup failed; restored {str(marker.get('previous_version','previous build'))}")
    rollback_launch = dict(marker.get("launch", {}) or {})
    rollback_command = [str(x) for x in list(rollback_launch.get("command", []) or [])]
    if rollback_command:
        subprocess.Popen(rollback_command, cwd=str(rollback_launch.get("cwd", "") or cwd), env=os.environ.copy())
        return 0
    return KDK_UPDATE_RESTART_EXIT_CODE


def now_ts() -> float:
    return time.time()

def short8(x: str) -> str:
    return str(x)[:8]

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def gen_rid() -> str:
    return os.urandom(8).hex()

def pow_epoch(epoch_secs: int = 60) -> int:
    # coarse time window so a stamp has a limited lifetime
    try:
        es = int(epoch_secs)
        if es <= 0:
            es = 60
    except Exception:
        es = 60
    return int(time.time() // es)

def _leading_zero_bits_from_digest(d: bytes) -> int:
    n = 0
    for b in d:
        if b == 0:
            n += 8
            continue
        for i in range(7, -1, -1):
            if (b >> i) & 1 == 0:
                n += 1
            else:
                return n
        return n
    return n

def pow_hash(origin_id: str, ph: str, epoch: int, nonce: int) -> bytes:
    s = f"{origin_id}|{ph}|{int(epoch)}|{int(nonce)}".encode("utf-8", "ignore")
    return hashlib.sha256(s).digest()

def pow_valid(origin_id: str, ph: str, epoch: int, nonce: int, bits: int) -> bool:
    try:
        b = int(bits)
        if b <= 0:
            return True
    except Exception:
        b = 0
    d = pow_hash(origin_id, ph, epoch, nonce, bits=0) if False else pow_hash(origin_id, ph, epoch, nonce)
    return _leading_zero_bits_from_digest(d) >= b

def mine_pow_stamp(origin_id: str, ph: str, bits_required: int, epoch_secs: int, max_tries: int) -> dict:
    bits = int(bits_required)
    epoch = pow_epoch(int(epoch_secs))
    max_tries = int(max_tries)

    start = random.getrandbits(32)
    for i in range(max_tries):
        nonce = (start + i) & 0xFFFFFFFF
        if pow_valid(origin_id, ph, epoch, nonce, bits):
            return {"epoch": epoch, "nonce": nonce, "bits": bits}
    return {"epoch": epoch, "nonce": None, "bits": bits, "fail": True}

def _rate_limit_cooldown_collisions(retry_after: float) -> int:
    try:
        ra = float(retry_after)
    except Exception:
        ra = float(VAULT_RATE_RETRY_AFTER)
    return max(1, int(round(ra * 2.0)))


# ----------------------------- Terminal helpers -----------------------------

def centre_console_window() -> bool:
    """Centre an existing Windows console in the monitor work area.

    Linux/macOS terminal windows belong to their terminal emulator or window
    manager, so those platforms deliberately remain unchanged. Any Windows API
    failure is non-fatal and node startup continues normally.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return False

        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return False
        width = max(1, int(rect.right - rect.left))
        height = max(1, int(rect.bottom - rect.top))

        # Use the monitor containing the console and its usable work area,
        # avoiding taskbars rather than assuming the primary screen bounds.
        monitor_default_to_nearest = 2
        monitor = user32.MonitorFromWindow(hwnd, monitor_default_to_nearest)
        info = wintypes.MONITORINFO()
        info.cbSize = ctypes.sizeof(info)
        if not monitor or not user32.GetMonitorInfoW(monitor, ctypes.byref(info)):
            return False

        work = info.rcWork
        x = int(work.left + max(0, (work.right - work.left - width) // 2))
        y = int(work.top + max(0, (work.bottom - work.top - height) // 2))

        swp_no_size = 0x0001
        swp_no_zorder = 0x0004
        swp_no_activate = 0x0010
        return bool(user32.SetWindowPos(
            hwnd, None, x, y, 0, 0,
            swp_no_size | swp_no_zorder | swp_no_activate,
        ))
    except Exception:
        return False


def windows_keep_awake(enable: bool) -> bool:
    """Opt in/out of Windows system-sleep suppression for this process lifetime."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        es_continuous = 0x80000000
        es_system_required = 0x00000001
        flags = es_continuous | es_system_required if bool(enable) else es_continuous
        return bool(ctypes.windll.kernel32.SetThreadExecutionState(flags))
    except Exception:
        return False


def term_enter_raw_noecho() -> Optional[list]:
    """stdin -> noncanonical + no-echo (hotkey mode)"""
    if termios is None:
        return None
    try:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] &= ~termios.ICANON
        new[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, new)
        return old
    except Exception:
        return None

def term_enter_canonical_echo() -> Optional[list]:
    """stdin -> canonical + echo (line input mode), return previous attrs"""
    if termios is None:
        return None
    try:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        new = termios.tcgetattr(fd)
        new[3] |= termios.ICANON
        new[3] |= termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, new)
        return old
    except Exception:
        return None

def term_restore(old: Optional[list]):
    if termios is None:
        return
    try:
        if old is None:
            return
        fd = sys.stdin.fileno()
        termios.tcsetattr(fd, termios.TCSANOW, old)
    except Exception:
        pass

def flush_stdin():
    if termios is None:
        return
    try:
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:
        pass


# ----------------------------- KDNode ---------------------------------------

class KDNode:
    def __init__(self, port: int, peers: list, relay: bool, name: str = "", vault_mode: bool = False,
                 test_drop_list_once: bool = False, collision_trigger_n: int = COLLISION_TRIGGER_N):
        self.port = port
        self.peers = peers
        self.relay = relay
        self.name = name or f"Node{port}"
        self.vault_mode = vault_mode
        self.test_drop_list_once = bool(test_drop_list_once)

        self.verbose = False

        # Lightweight status model. These counters are intentionally separate
        # from logging so they can later feed a proper TUI without changing
        # protocol code.
        self.status_line_enabled = False
        # Lightweight structured-console mode.  This is intentionally not a
        # full curses/TUI layer: it is only a fixed, human-readable dashboard
        # for live mesh testing.
        self.status_box_enabled = False
        self.status_colour_enabled = True
        self.status_interval = 1.0
        self.status_spinner_i = 0
        self.status_last_event = "idle"

        # Runtime-only diagnostic payload trace. This never changes protocol
        # behaviour and is deliberately OFF on every fresh start.
        self.trace_payloads_enabled = bool(KDK_TRACE_ENABLED_DEFAULT)
        self.trace_event_count = 0
        self.trace_tracked_payloads: Dict[str, float] = {}
        # Explicit relay-witness filters. These are runtime-only diagnostics and
        # never alter the wire message. Hash watches match a payload-hash prefix;
        # origin watches adopt any PAYLOAD whose outer origin node-id matches.
        self.trace_watch_hash_prefixes = set()
        self.trace_watch_origin_prefixes = set()
        self.trace_log_path = os.path.join("logs", "trace.log")
        self._trace_lock = threading.Lock()

        self._status_prev_sample = None
        self._status_box_lines = 0
        self.metric_turns = 0
        self.metric_rx_payloads = 0
        self.metric_tx_payloads = 0
        self.metric_mesh_forwards = 0
        self.metric_last_rx_ts = 0.0
        self.metric_last_tx_ts = 0.0
        self._status_stop = threading.Event()
        # UI-only wake event: typewriter animation can request an immediate HUD
        # repaint without shortening the normal idle status refresh interval.
        self._status_redraw = threading.Event()
        self._shutdown_requested = False
        self._shutdown_mode = "graceful"
        self._shutdown_reason = ""
        self._pending_update_restart = None
        self._status_last_len = 0
        self._status_alt_screen_active = False
        self._hud_display_state = "LINK"
        self._hud_display_colour = "yellow"
        self._hud_display_state_ts = 0.0

        # Beta activity/message pane. This is deliberately a small overlay
        # beneath the existing HUD, not a full TUI rewrite.
        self.activity_pane_enabled = True
        self.activity_lines = deque(maxlen=300)
        # Cosmetic incoming-message typewriter. Jobs are rendered by a tiny
        # background worker so transport, receipts and the node event loop never
        # wait for UI animation. A single queue prevents simultaneous messages
        # from visually typing over one another.
        self.activity_typewriter_queue = deque()
        self.activity_typewriter_lock = threading.Lock()
        self.activity_typewriter_active = False
        self.activity_action_index = 0
        self.activity_actions = ["Text", "File", "Airgap", "Patch", "Console", "Restart", "Exit"]
        self.console_actions = ["Peers", "Discover", "Nodes", "Queue", "Version", "Name", "Dingo", "RTT Probe", "Trace", "Trace Watch"]
        self.activity_mode = "main"  # main | console
        self.activity_focus_index = 1  # main: 0=To, 1..N=action toolbar; console uses console_action_index
        self.activity_dropdown_open = False
        self.activity_recipient_search = ""
        self.activity_recipient_selected_id = ""
        self.activity_recipient_view_start = 0
        self.activity_recipient_page_size = 8
        self.activity_console_dropdown_open = False
        self.activity_console_action_index = 0
        self.activity_scroll_offset = 0
        self.activity_history_body_height = 6
        self.activity_tab_direction = 1
        self.activity_input_text = ""
        self.activity_input_multiline = False
        # Optional contextual help shown immediately above a
        # single-line editor prompt. This is UI-only and never enters history.
        self.activity_input_hint = ""
        self.activity_input_mode = ""
        self.activity_airgap_menu_open = False
        self.activity_airgap_menu_index = 0  # 0=Export, 1=Import, 2=Timelock Status, 3=Clean-up
        self.activity_patch_menu_open = False
        self.activity_patch_menu_index = 0
        self.activity_patch_candidate_path = ""
        self.activity_patch_history_open = False
        self.activity_peer_menu_open = False
        self.activity_peer_menu_level = "list"
        self.activity_peer_menu_index = 0
        self.activity_peer_menu_node_id = ""
        self.activity_peer_menu_search = ""
        self.activity_peer_menu_selected_key = ""
        self.activity_peer_menu_view_start = 0
        self.activity_peer_menu_page_size = 8
        self.activity_timelock_status_open = False
        self.activity_recipient_index = 0
        self.peer_name_by_node_id: Dict[str, str] = {}

        self.inbound_blocks = deque()
        self.outbound_queue = deque()
        self.decrypt_attempted = {}

        ensure_dir("inbox")
        ensure_dir("retrieved")
        ensure_dir(KDK_CHUNK_DIR)
        ensure_dir(KDK_CHUNK_COMPLETE_DIR)
        ensure_dir(KDK_UPDATE_DIR)
        ensure_dir(KDK_UPDATE_INCOMING_DIR)
        ensure_dir(KDK_UPDATE_STAGED_DIR)
        ensure_dir(KDK_UPDATE_APPLIED_DIR)
        ensure_dir(KDK_UPDATE_SEED_DIR)
        ensure_dir(KDK_UPDATE_REJECTED_DIR)
        ensure_dir(KDK_UPDATE_BACKUP_DIR)
        ensure_dir("vault_store")
        ensure_dir("keys")
        ensure_dir("logs")
        ensure_dir(KDK_PEER_DIGEST_DIR)
        ensure_dir(AIRGAP_DIR)
        ensure_dir(AIRGAP_PENDING_DIR)
        ensure_dir(AIRGAP_OUT_DIR)
        ensure_dir(AIRGAP_UNLOCKED_DIR)
        ensure_dir(AIRGAP_STATE_DIR)
        ensure_dir(KDK_RELIABILITY_DIR)

        self.signing_key, self.verify_key, self.box_sk, self.box_pk = self._load_or_create_keys()
        self.node_id = sha256(self.verify_key.encode())[:16]
        self.peer_policy_path = KDK_PEER_POLICY_PATH
        self.peer_policy: Dict[str, str] = {}
        self.load_peer_policy()

        self.caps = {
            "relay": bool(self.relay),
            "vault": bool(self.vault_mode),
            "rpc": True,
            "env": 3,
            "script_version": SCRIPT_VERSION,
            "script_revision": SCRIPT_REVISION,
            "script_origin": SCRIPT_ORIGIN,
            "script_lineage": SCRIPT_LINEAGE,
            "script_hash": SCRIPT_HASH,
            "name": self.name,
            "update_transport": "mesh-chunks",
            "update_kind": KDK_UPDATE_KIND,
        }

        _started_now = now_ts()
        self.active_nodes: Dict[str, float] = {self.node_id: _started_now}
        # Persistent-within-run last-heard history for Console -> Nodes. Unlike
        # active_nodes, this is not dropped at ACTIVE_TIMEOUT, so a peer can be
        # shown as Stale/Offline instead of disappearing from the health view.
        self.peer_last_seen: Dict[str, float] = {self.node_id: _started_now}
        self.peer_id_by_addr: Dict[Tuple[str, int], str] = {}
        self.peer_pubkey_by_addr: Dict[Tuple[str, int], bytes] = {}
        # Roaming support: a peer is identified by node_id; addr is only the
        # currently observed endpoint. This lets a roaming peer move from LAN
        # (192.168.x.x:6006) to public/BT/EE NAT (86.x.x.x:random_port).
        self.peer_addr_by_node_id: Dict[str, Tuple[str, int]] = {}
        self.peer_addrs_by_node_id: Dict[str, set] = {}
        # Keep best LAN and public observations separately.  The latest
        # endpoint may flap LAN<->VPN during mixed tests, but directory
        # replies to roaming/public peers should prefer a public endpoint
        # when one has ever been observed for that node.
        self.peer_lan_addr_by_node_id: Dict[str, Tuple[str, int]] = {}
        self.peer_public_addr_by_node_id: Dict[str, Tuple[str, int]] = {}
        self.metric_peer_roams = 0

        self.pubkey_by_node_id: Dict[str, bytes] = {self.node_id: self.verify_key.encode()}
        self.peer_keys: Dict[str, PublicKey] = {}
        self.peer_caps: Dict[str, dict] = {}

        # Throttle version/update diagnostics and automatic offers.
        self.version_check_seen = set()
        self.version_mismatch_seen = set()
        # Operator-facing version mismatch notices are rate-limited so the
        # status box does not get torn up by repeated debug chatter.
        self.version_notice_seen = {}
        self.update_offer_seen = set()

        # peer-hint discovery state. Hints are learned only after a
        # successful envelope decrypt, then probed later with jittered HELLO.
        self.peer_hint_enabled = ENABLE_PEER_HINTS
        self.peer_hint_candidates: Dict[str, dict] = {}
        self.peer_hint_pending_probes: Dict[Tuple[str, int], float] = {}
        self.last_peer_hint_probe_ts = 0.0
        self.last_quorum_digest = ""
        self.directory_hint_enabled = ENABLE_DIRECTORY_HINTS
        self.directory_public_host = ""
        # Optional per-peer public directory map. Keys may be full node IDs or
        # unique prefixes, values are (host, port). This lets a directory node
        # advertise a peer's real public/VPN endpoint to roaming peers instead
        # of blindly rewriting every LAN peer to one public host.
        self.directory_public_map: Dict[str, Tuple[str, int]] = {}

        # Symbolic pulse monitor: local, deliberately non-omniscient view of
        # recently emitted/observed payloads.  This feeds the status box only;
        # it does not affect protocol behaviour or wire format.
        self.pulse_tracks: Dict[str, dict] = {}
        self.pulse_order = deque(maxlen=12)
        self.pulse_max_age = 90.0
        # Left-to-right propagation trace. Each local event appends a glyph
        # into the next position from X=0 toward X=Q/history. Idle time appends
        # quiet dots, so the page fills naturally left-to-right rather than
        # behaving like a right-to-left oscilloscope.
        self.pulse_stream_width = 42
        self.pulse_stream = deque(maxlen=int(self.pulse_stream_width))
        self.pulse_stream_last_tick = 0.0
        # Dummy churn can arrive extremely fast, so thin it before it reaches
        # the visual trace. Meaningful/airgap/receipt glyphs are never thinned.
        self.pulse_dummy_thin_i = 0
        self.pulse_dummy_thin_every = 5
        self.receipt_sent_count = 0
        self.receipt_recv_count = 0

        # Crash-safe logical-delivery state. Queue entries themselves remain
        # ephemeral; these records regenerate fresh encrypted envelopes after
        # loss, restart, or a missing receipt.
        self.pending_messages: Dict[str, dict] = {}
        self.pending_receipts: Dict[str, dict] = {}
        self.delivered_message_ids: Dict[str, float] = {}
        self.received_receipt_ids: Dict[str, float] = {}

        self.seen_payloads: Dict[str, float] = {}
        self.quorum_tracker: Dict[str, dict] = {}

        # Time-lock research metrics. These counters are deliberately separate
        # from token_count: token_count resets every N collisions to drive the
        # Brownian scheduler, whereas these accumulate all locally observed
        # collisions/quorum events until a real Dingo-height sample is written.
        # The CSV is metadata-only and contains no payloads, keys or ciphertext.
        self.timelock_metrics_interval_blocks = 10
        self.timelock_metrics_path = os.path.join("logs", f"timelock_metrics_{self.port}.csv")
        self.timelock_metrics_base_height = 0
        self.timelock_metrics_base_ts = 0.0
        self.timelock_metrics_collisions = 0
        self.timelock_metrics_quorums = 0
        # Wall-clock gaps caused by suspend/resume are excluded from active_secs.
        # continuous=0 also marks obviously discontinuous height observations so
        # those rows can be excluded from collision-rate analysis without loss.
        self.timelock_metrics_inactive_secs = 0.0
        self.timelock_metrics_continuous = True

        # Short rolling collision window used only by the live HUD. The
        # research CSV remains based on complete Dingo-height intervals.
        self.timelock_live_collision_window_secs = 30.0
        self.timelock_live_collision_times = deque()

        # Counter-token protocol
        self.token_count = 0
        # Emit exactly every N collisions. For six-node tests, start with --n 5,
        # then try --n 4 for busier churn or --n 6/7 for quieter churn.
        try:
            self.token_trigger = max(1, int(collision_trigger_n))
        except Exception:
            self.token_trigger = max(1, int(COLLISION_TRIGGER_N))

        # Queue pacing state. 0 means the next earned turn may release one
        # queued envelope. Positive values mean that many earned turns must be
        # spent as dummy traffic before the next queued envelope is released.
        self.queue_emit_gap_min_turns = int(QUEUE_EMIT_GAP_MIN_TURNS)
        self.queue_emit_gap_max_turns = int(QUEUE_EMIT_GAP_MAX_TURNS)
        self.queue_emit_turns_wait = 0

        self.seen_sids: Dict[Tuple[str, str], float] = {}

        self.pending_rpcs: Dict[str, dict] = {}
        self.vault_rid_cache: Dict[Tuple[str, str, str], dict] = {}

        self.vault_rid_log_count = 0
        self.vault_rid_log_load()

        self.vault_rate: Dict[str, deque] = {}
        self.vault_exec_counts: Dict[Tuple[str, str, str], int] = {}
        self.orphan_seen: Dict[Tuple[str, str, str], float] = {}

        self.last_heartbeat_ts = 0.0
        self.last_discover_ts = 0.0
        self.last_discover_height = 0

        self.pow_bits_required = 16
        self.pow_epoch_secs = 60
        self.pow_mine_tries = 2_000_000

        self.direct_inbox_count = 0
        self.direct_inbox: List[dict] = []

        self.chunk_rx: Dict[str, dict] = {}
        self.chunk_tx_store: Dict[str, dict] = {}
        # Pending repair chunks are held in a coalescing side-set
        # keyed by (dst, object, index), rather than multiplied into the main
        # outbound queue by repeated WANTs.
        self.repair_pending: Dict[Tuple[str, str, int], dict] = {}
        self.repair_inflight: Dict[Tuple[str, str, int], dict] = {}
        # Last accepted WANT intake per (receiver, object). This is
        # sender-side timing only; it prevents repeated WANT packets from
        # topping the repair set back up before the current wave has landed.
        self.repair_want_last_accept: Dict[Tuple[str, str], float] = {}
        self.repair_last_idle_pump_ts = 0.0
        # Objects that have entered targeted repair mode. Once a
        # receiver sends WANT, stop walking the original random chunk queue for
        # that object and answer only the receiver's exact missing indexes.
        self.chunk_repair_mode_objects: set = set()  # (dst_id, object_id) pairs; legacy name retained
        # Completed chunked objects are remembered briefly so late repair/data
        # duplicates do not recreate a fresh partial receive state after a
        # successful reassembly.  Value is completion timestamp.
        self.chunk_completed: Dict[str, float] = {}
        # Receiver-led pull swarm state. Requests are ordinary encrypted control
        # blocks; replies are ordinary manifest/data blocks. Nothing here changes
        # relay uniformity or bypasses the earned-turn scheduler.
        self.pull_last_serve: Dict[Tuple[str, str], float] = {}
        self.pull_discovery_seen: Dict[str, float] = {}
        self.pull_discovery_state = {"active": False, "attempts": 0, "last_ts": 0.0, "base_version": "", "base_revision": 0, "base_hash": ""}

        # Update trust policy. "manual" is the public/default mode: a received
        # capsule remains inert until the operator inspects and stages it. "stage"
        # may stage valid forward capsules automatically, while "force-latest" is
        # retained as an explicit development/trusted-mesh convenience policy.
        self.update_policy = "manual"
        self.update_auto_apply = False
        self.update_auto_restart = True
        self.update_offer_file = ""
        self.update_base_file = ""
        self.update_allow_rollback = False
        # Mutable human label only. The work directory, key files and node ID
        # remain the permanent profile/identity anchor when this value changes.
        self.profile_path = os.path.abspath(KDK_PROFILE_PATH)

        # Airgap test state. These are intentionally local; mesh only carries tickets/receipts.
        self.airgap_tickets_by_hash: Dict[str, dict] = {}
        self.airgap_blobs_by_hash: Dict[str, str] = {}
        self.airgap_unlocked: set = set()
        self.airgap_unlocked_paths_by_hash: Dict[str, str] = {}
        self.airgap_download_paths_by_hash: Dict[str, str] = {}
        self.airgap_exports_by_hash: Dict[str, dict] = {}

        # Cuckoo Clock v1 state.  The payload blob is still AIRGAP_1440,
        # but the file key is no longer delivered in one ticket.  It is wrapped
        # as a tiny KDK object and its chunks are admitted into q only when the
        # Dingo/test height witness condition for each chunk is satisfied.
        self.cuckoo_enabled = bool(CUCKOO_ENABLED_DEFAULT)
        self.cuckoo_min_delay_secs = int(CUCKOO_MIN_DELAY_SECS_TEST)
        self.cuckoo_min_chunks = int(CUCKOO_MIN_CHUNKS)
        self.cuckoo_max_chunks = int(CUCKOO_MAX_CHUNKS)
        self.cuckoo_default_chunks = int(CUCKOO_DEFAULT_CHUNKS)
        self.cuckoo_min_witnesses = int(CUCKOO_DEFAULT_MIN_WITNESSES)
        self.cuckoo_pending = []
        self.cuckoo_released = set()
        self.airgap_pending_keys_by_hash: Dict[str, bytes] = {}

        self.airgap_block_secs = 60
        # Airgap height source. "test" uses the local simulated block clock;
        # "dingo-cli" requires a local validating Dingocoin node; "dingo-auto"
        # prefers the local client and otherwise accepts a fresh signed mesh
        # witness. The CLI applies the selected public default after construction.
        self.airgap_height_source = "test"
        self.airgap_dingo_cli = "dingocoin-cli"
        self.airgap_dingo_cli_args = []
        self.airgap_dingo_allow_fallback = False
        self.airgap_last_height_source = "test"
        self.airgap_last_height_error = ""
        # Persist a monotonic Dingo floor across node restarts.
        # A delayed/replayed but still syntactically fresh beacon must never move
        # the effective chain clock backwards after this node has seen a higher height.
        self.dingo_height_floor = 0
        safe_airgap_name = ''.join(c for c in self.name if c.isalnum() or c in ('-', '_')) or 'node'
        self.airgap_state_path = os.path.join(AIRGAP_STATE_DIR, f"{safe_airgap_name}_{self.port}.json")
        self.airgap_load_state()

        # Dingo block-height heartbeat state. Nodes without a local Dingo
        # client simply do not witness; they can still receive/cache beacons.
        self.dingo_height_beacon_enabled = bool(DINGO_HEIGHT_BEACON_ENABLED)
        self.dingo_height_beacon_interval_secs = float(DINGO_HEIGHT_BEACON_INTERVAL_SECS)
        self.dingo_height_beacon_tolerance_blocks = int(DINGO_HEIGHT_BEACON_TOLERANCE_BLOCKS)
        self.dingo_height_beacon_max_recipients = int(DINGO_HEIGHT_BEACON_MAX_RECIPIENTS)
        self.dingo_last_beacon_check_ts = 0.0
        self.dingo_last_beacon_height = 0
        self.dingo_pending_beacon_height = 0
        self.dingo_pending_beacon_updated_ts = 0.0
        self.dingo_public_seen_heights: Dict[int, float] = {}
        self.dingo_network_height = int(getattr(self, "dingo_height_floor", 0) or 0)
        self.dingo_network_height_ts = 0.0
        self.dingo_network_height_witness = "persisted-floor" if self.dingo_network_height > 0 else ""
        self.dingo_height_by_witness: Dict[str, dict] = {}
        # Shared logical-clock scheduler state.  We pace substantive user
        # traffic by Dingo height, but keep ACK/receipt/WANT/control traffic immediate.
        self.dingo_scheduler_height = 0
        self.dingo_scheduler_height_ts = 0.0
        self.dingo_scheduler_last_poll_ts = 0.0
        self.dingo_scheduler_sent_at_height = 0
        self.dingo_scheduler_fallback_epoch = 0
        self.dingo_height_wait_last_notice_ts = 0.0
        self.dingo_height_wait_suppressed = 0
        self.file_embargo_start_height = 0
        self.file_embargo_start_ts = 0.0
        self.file_transfer_inflight = False
        self.deferred_file_transfers = deque()
        self._dedup_error_state: Dict[str, dict] = {}

        self.activity_system("Node started")


        self.stdin_lock = threading.Lock()
        self._raw_term_state: Optional[list] = None

        self._test_drop_once = False
        self.log_path = os.path.join("logs", f"node_{self.port}.log")
        self.log_max_bytes = int(KDK_LOG_MAX_BYTES)
        self.log_backups = int(KDK_LOG_BACKUPS)
        self.compact_logs = True
        self.reliability_load_state()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.settimeout(0.5)

        # Non-blocking LAN latency normalisation. send_message() serialises/signs
        # immediately, but local datagrams are released later by one scheduler
        # thread. This avoids both blocking the receive loop and spawning one
        # Timer/thread per packet under heavy Brownian churn.
        self.lan_delay_enabled = True
        self.lan_delay_ms = float(KDK_LAN_DELAY_MS)
        self.lan_delay_jitter_ms = float(KDK_LAN_DELAY_JITTER_MS)
        self._lan_delay_local_ips = self._discover_local_ipv4s()
        self._delayed_send_heap = []
        self._delayed_send_seq = 0
        self._delayed_send_cv = threading.Condition()
        self._delayed_send_stop = threading.Event()
        self._delayed_send_thread = None
        self.metric_lan_delayed_sends = 0

        self.manual_peers_path = KDK_MANUAL_PEERS_PATH
        self.manual_peer_addrs = set()
        self.load_manual_peers()

    def _schedule_next_queue_emit_gap(self) -> int:
        """Pick how many future earned turns to spend as dummy traffic before
        another queued envelope may be released.

        If min=max=1, queued envelopes can go out on consecutive earned turns.
        If the random draw is 7, six intervening earned turns are dummy traffic
        and the seventh future turn may release the next queued envelope.
        """
        lo = max(1, int(getattr(self, "queue_emit_gap_min_turns", QUEUE_EMIT_GAP_MIN_TURNS)))
        hi = max(lo, int(getattr(self, "queue_emit_gap_max_turns", QUEUE_EMIT_GAP_MAX_TURNS)))
        return max(0, random.randint(lo, hi) - 1)

    def _chunk_block_telemetry(self, blocks) -> Optional[str]:
        """Return compact chunk telemetry description for a one-block envelope."""
        try:
            if not isinstance(blocks, list) or not blocks:
                return None
            b = blocks[0]
            if not isinstance(b, dict):
                return None
            btype = b.get("type")
            data = b.get("data", {}) if isinstance(b.get("data", {}), dict) else {}
            oid = str(data.get("object_id", ""))
            if not oid:
                return None
            if btype == "kdk_chunk_manifest":
                return (
                    f"kind=manifest object={oid[:8]} "
                    f"chunks={int(data.get('chunk_count', 0))} bytes={int(data.get('total_size', 0))}"
                )
            if btype == "kdk_chunk_data":
                idx = int(data.get("index", -1)) + 1
                total = int(data.get("chunk_count", 0))
                return f"kind=data object={oid[:8]} idx={idx}/{total}"
            if btype == "kdk_chunk_want":
                rnd = int(data.get("round", 0))
                miss = data.get("missing", [])
                try:
                    mcount = len(miss)
                except Exception:
                    mcount = 0
                return f"kind=want object={oid[:8]} round={rnd} missing={mcount}"
        except Exception:
            return None
        return None

    def _queue_label_weight(self, label: str) -> int:
        """Scheduler weight for queued traffic classes.

        This is not a strict priority queue. It is a weighted draw so payload,
        repair, receipts and dummy traffic remain statistically blended rather
        than producing an obvious file-transfer mode.
        """
        l = str(label or "").upper()
        if "MANIFEST-PRIME" in l:
            return 900
        if "MANIFEST" in l:
            return 180
        if "REPAIR" in l:
            return 420
        if "WANT" in l:
            return 260
        if "RECEIPT" in l:
            return 80
        if l in ("MESSAGE", "RPC-REPLY", "RPC-RATE-RESEND"):
            return 70
        if "AIRGAP" in l:
            return 65
        if "KDK-FILE" in l or "KDK-CHUNK" in l:
            return 60
        if "UPDATE" in l or "PATCH" in l:
            return 45
        if "DINGO-BEACON" in l:
            return 25
        return 40

    def _repair_pending_count(self) -> int:
        try:
            return len(getattr(self, "repair_pending", {}) or {})
        except Exception:
            return 0

    def _repair_inflight_count(self) -> int:
        try:
            return len(getattr(self, "repair_inflight", {}) or {})
        except Exception:
            return 0

    def _repair_pending_count_for(self, dst_id: str = "", object_id: str = "") -> int:
        try:
            total = 0
            for k in (getattr(self, "repair_pending", {}) or {}).keys():
                try:
                    k_dst, k_oid, _k_idx = k
                except Exception:
                    continue
                if dst_id and k_dst != dst_id:
                    continue
                if object_id and k_oid != object_id:
                    continue
                total += 1
            return total
        except Exception:
            return 0

    def _repair_inflight_count_for(self, dst_id: str = "", object_id: str = "") -> int:
        try:
            total = 0
            for k in (getattr(self, "repair_inflight", {}) or {}).keys():
                try:
                    k_dst, k_oid, _k_idx = k
                except Exception:
                    continue
                if dst_id and k_dst != dst_id:
                    continue
                if object_id and k_oid != object_id:
                    continue
                total += 1
            return total
        except Exception:
            return 0

    def _outbound_has_repair(self) -> bool:
        try:
            if self._repair_pending_count() > 0:
                return True
            return any("REPAIR" in str(item[2]).upper() or "WANT" in str(item[2]).upper() for item in self.outbound_queue)
        except Exception:
            return False

    def _pop_repair_pending_item(self):
        """Return one coalesced repair item, or None.

        dev16.20: strict priority repair queue.  WANT packets update a
        side-set keyed by (dst, object, index); emission pops exactly one
        requested chunk from that set before ordinary queued data is serviced.
        This prevents the normal queue from ballooning and avoids walking the
        old random chunk schedule once the receiver has supplied exact gaps.
        """
        rp = getattr(self, "repair_pending", None)
        if not rp:
            return None
        try:
            # Prefer later WANT rounds and older pending entries.  This is not
            # random: once we are in repair mode, every repair turn should be
            # useful and targeted.
            def score(kv):
                _key, rec = kv
                try:
                    rnd = int(rec.get("round", 0) or 0)
                except Exception:
                    rnd = 0
                try:
                    ts = float(rec.get("ts", 0.0) or 0.0)
                except Exception:
                    ts = 0.0
                return (-rnd, ts)

            chosen_key, chosen_rec = sorted(rp.items(), key=score)[0]
            rp.pop(chosen_key, None)
            # Move this repair to an in-flight cache rather than
            # forgetting it immediately. If another WANT arrives before the
            # resend timeout, the chunk is not added again. This prevents a
            # repeated WANT wave from refilling repair_pending while packets
            # are still crossing the mesh.
            try:
                ri = getattr(self, "repair_inflight", None)
                if ri is None:
                    self.repair_inflight = {}
                    ri = self.repair_inflight
                ri[chosen_key] = {
                    "dst": chosen_rec.get("dst"),
                    "object_id": chosen_key[1] if isinstance(chosen_key, tuple) and len(chosen_key) > 1 else "",
                    "index": chosen_key[2] if isinstance(chosen_key, tuple) and len(chosen_key) > 2 else -1,
                    "round": int(chosen_rec.get("round", 0) or 0),
                    "sent_ts": now_ts(),
                }
                maxn = int(globals().get("KDK_REPAIR_INFLIGHT_MAX", 2048))
                if len(ri) > maxn:
                    for vk, _vr in sorted(ri.items(), key=lambda kv: float(kv[1].get("sent_ts", 0.0) or 0.0))[:max(1, len(ri)-maxn)]:
                        ri.pop(vk, None)
            except Exception:
                pass
            return (chosen_rec.get("dst"), [chosen_rec.get("block")], "KDK-CHUNK-REPAIR")
        except Exception as e:
            self.log_event(f"[REPAIR_SET] pop failed err={type(e).__name__}: {e}")
            return None

    def _dummy_blend_probability(self) -> float:
        """Chance to spend an otherwise eligible turn on dummy traffic.

        dev16.25 repair-drain fix:
        A coalesced repair side-set is real work even when the ordinary
        outbound queue is empty.  dev16.24 accidentally returned 1.0 whenever
        q==0, which meant repair_pending>0 could sit forever because every
        earned turn was treated as dummy traffic.  Check repair_pending first so
        q=0 repair=N drains normally.
        """
        q = len(getattr(self, "outbound_queue", []) or [])
        repair_n = self._repair_pending_count()
        if repair_n > 0:
            # In pure repair mode the receiver is already waiting for exact
            # missing chunks. Keep a little dummy traffic when mixed with ordinary
            # traffic, but do not starve repairs when q is empty.
            base = float(globals().get("QUEUE_DUMMY_BLEND_REPAIR", 0.04))
            return min(base, 0.02) if q <= 0 else base
        if q <= 0:
            return 1.0
        if self._outbound_has_repair():
            return float(globals().get("QUEUE_DUMMY_BLEND_REPAIR", 0.04))
        if q >= 25:
            return float(globals().get("QUEUE_DUMMY_BLEND_BUSY", 0.25))
        return float(globals().get("QUEUE_DUMMY_BLEND_NORMAL", 0.35))

    def _queue_item_is_manifest(self, item) -> bool:
        try:
            blocks = item[1]
            if isinstance(blocks, list) and blocks:
                b = blocks[0]
                return isinstance(b, dict) and b.get("type") == "kdk_chunk_manifest"
        except Exception:
            pass
        return False

    def _choose_outbound_queue_index(self) -> int:
        """Weighted random choice across queued envelopes.

        dev16.14: WANT-aware repair bias. When requested repair chunks are
        pending, most real transmission opportunities select from those repair
        envelopes first. This keeps the outward traffic class as ordinary
        encrypted PAYLOAD, but internally avoids spending too many turns on
        already-delivered random chunks while a receiver is missing a residue.
        """
        q = list(self.outbound_queue)
        if not q:
            return -1

        # Cuckoo key chunks are tiny but unlock-gating critical. Once a
        # height-gated key chunk is released, give its first copy deterministic
        # priority, then give repeats a strong bias.
        try:
            prime_cuckoo_idxs = [i for i, item in enumerate(q) if "CUCKOO-KEY-PRIME" in str(item[2]).upper()]
            if prime_cuckoo_idxs:
                return prime_cuckoo_idxs[0]
            cuckoo_idxs = [i for i, item in enumerate(q) if "CUCKOO-KEY" in str(item[2]).upper()]
            if cuckoo_idxs and random.random() < 0.75:
                return cuckoo_idxs[0]
        except Exception:
            pass

        # Manifests are tiny but essential. If a newly queued file
        # has a prime manifest waiting, emit it before random data so the
        # receiver learns object size/chunk count early. Later manifest copies
        # get a modest bias while preserving stochastic order.
        try:
            prime_idxs = [i for i, item in enumerate(q) if "MANIFEST-PRIME" in str(item[2]).upper()]
            if prime_idxs:
                return prime_idxs[0]
            manifest_idxs = [i for i, item in enumerate(q) if self._queue_item_is_manifest(item)]
            if manifest_idxs:
                p = float(globals().get("KDK_MANIFEST_PRIORITY_PROB_BUSY", 0.35)) if len(q) > 40 else float(globals().get("KDK_MANIFEST_PRIORITY_PROB_NORMAL", 0.18))
                if random.random() < p:
                    return manifest_idxs[0]
        except Exception:
            pass

        # Once an update manifest has been emitted, strongly favour
        # its ordinary data sweep. This prevents periodic beacon/control traffic
        # from leaving the receiver at have=0 and repeatedly requesting the full
        # object. Selection remains stochastic and still occurs only on earned
        # Brownian turns; the outward wire class remains encrypted PAYLOAD.
        try:
            update_data_idxs = []
            for i, item in enumerate(q):
                label_u = str(item[2]).upper() if len(item) >= 3 else ""
                kind, _oid, _idx = self._queue_chunk_info(item)
                if kind == "data" and ("KDK-UPDATE" in label_u or "PATCH" in label_u):
                    update_data_idxs.append(i)
            if update_data_idxs and random.random() < float(globals().get("KDK_UPDATE_TRANSFER_BURST_PROB", 0.98)):
                return random.choice(update_data_idxs)
        except Exception:
            pass

        try:
            for _key in list(getattr(self, "chunk_repair_mode_objects", set()) or []):
                if isinstance(_key, tuple) and len(_key) == 2:
                    _dst, _oid = _key
                    self._prune_normal_chunk_queue_for_repair(_oid, _dst)
            q = list(self.outbound_queue)
            if not q:
                return -1
        except Exception:
            pass

        # Repair bursts are still probabilistic, not absolute priority.  This
        # preserves the dummy/payload blend while making WANT lists effective.
        repair_idxs = []
        for i, item in enumerate(q):
            try:
                label = str(item[2]).upper()
            except Exception:
                label = ""
            if "REPAIR" in label or "WANT" in label:
                repair_idxs.append(i)
        if repair_idxs and random.random() < float(globals().get("QUEUE_REPAIR_BURST_PROB", 0.96)):
            # Within repair traffic, still use weights so WANT/repair labels can
            # be tuned without becoming FIFO or visibly deterministic.
            weights = []
            for i in repair_idxs:
                try:
                    weights.append(max(1, int(self._queue_label_weight(q[i][2]))))
                except Exception:
                    weights.append(1)
            total = sum(weights)
            r = random.uniform(0, total)
            acc = 0.0
            for i, w in zip(repair_idxs, weights):
                acc += w
                if r <= acc:
                    return i
            return repair_idxs[-1]

        repair_mode_pairs = getattr(self, "chunk_repair_mode_objects", set()) or set()
        weights = []
        for item in q:
            try:
                label = item[2]
            except Exception:
                label = ""
            w = max(1, int(self._queue_label_weight(label)))
            # Defensive guard: if an object has entered targeted repair mode,
            # do not spend turns on its leftover normal data chunks.
            try:
                kind, oid, _idx = self._queue_chunk_info(item)
                dst = str(item[0]) if isinstance(item, (tuple, list)) and len(item) >= 1 else ""
                if kind == "data" and (dst, oid) in repair_mode_pairs and "REPAIR" not in str(label).upper():
                    w = 1
            except Exception:
                pass
            weights.append(w)
        total = sum(weights)
        r = random.uniform(0, total)
        acc = 0.0
        for i, w in enumerate(weights):
            acc += w
            if r <= acc:
                return i
        return len(q) - 1

    def _queue_chunk_info(self, item):
        """Return (kind, object_id, index) for a queued chunk envelope."""
        try:
            blocks = item[1]
            if not isinstance(blocks, list) or not blocks:
                return ("", "", None)
            b = blocks[0]
            if not isinstance(b, dict):
                return ("", "", None)
            btype = str(b.get("type", ""))
            data = b.get("data", {}) if isinstance(b.get("data", {}), dict) else {}
            oid = str(data.get("object_id", ""))
            if not oid:
                return ("", "", None)
            if btype == "kdk_chunk_data":
                return ("data", oid, int(data.get("index", -1)))
            if btype == "kdk_chunk_manifest":
                return ("manifest", oid, None)
            if btype == "kdk_chunk_want":
                return ("want", oid, None)
        except Exception:
            pass
        return ("", "", None)

    def _normal_chunk_queue_count_for_object(self, object_id: str, dst_id: str = "") -> int:
        """Count ordinary queued data chunks for one receiver/object pair.

        Repair mode is receiver-scoped: a WANT from one receiver must not suppress
        another receiver's data for the same canonical object.  If dst_id is omitted,
        this returns the aggregate count for compatibility with diagnostics.
        """
        if not object_id:
            return 0
        try:
            total = 0
            for item in list(getattr(self, "outbound_queue", []) or []):
                kind, oid, _idx = self._queue_chunk_info(item)
                try:
                    label = str(item[2]).upper()
                    item_dst = str(item[0])
                except Exception:
                    label = ""
                    item_dst = ""
                if kind == "data" and oid == object_id and (not dst_id or item_dst == str(dst_id)) and "REPAIR" not in label:
                    total += 1
            return total
        except Exception:
            return 0

    def _prune_normal_chunk_queue_for_repair(self, object_id: str, dst_id: str) -> int:
        """Remove only this receiver's ordinary data tail for an object.

        Earlier builds keyed repair mode by object_id alone.  With several
        receivers pulling the same patch, a WANT from one receiver could prune
        another receiver's freshly queued coarse data.  Scope pruning to the
        exact (dst_id, object_id) pair instead.
        """
        if not object_id or not dst_id:
            return 0
        try:
            oldq = list(getattr(self, "outbound_queue", []) or [])
            if not oldq:
                return 0
            newq = []
            removed = 0
            for item in oldq:
                kind, oid, _idx = self._queue_chunk_info(item)
                try:
                    label = str(item[2]).upper()
                    item_dst = str(item[0])
                except Exception:
                    label = ""
                    item_dst = ""
                if kind == "data" and oid == object_id and item_dst == str(dst_id) and "REPAIR" not in label:
                    removed += 1
                    continue
                newq.append(item)
            if removed:
                self.outbound_queue = deque(newq)
            return removed
        except Exception as e:
            self.log_event(
                f"[REPAIR_MODE] prune failed dst={short8(dst_id)} object={str(object_id)[:8]} "
                f"err={type(e).__name__}: {e}"
            )
            return 0

    def _clear_repair_state_for_object(self, object_id: str, dst_id: str = "") -> int:
        """Clear repair state for one receiver/object pair after completion."""
        removed = 0
        try:
            if object_id and dst_id:
                getattr(self, "chunk_repair_mode_objects", set()).discard((str(dst_id), str(object_id)))
            elif object_id:
                # Compatibility/administrative clear: remove all receiver pairs for this object.
                modes = getattr(self, "chunk_repair_mode_objects", set()) or set()
                for key in list(modes):
                    if isinstance(key, tuple) and len(key) == 2 and str(key[1]) == str(object_id):
                        modes.discard(key)
            rp = getattr(self, "repair_pending", {}) or {}
            for key in list(rp.keys()):
                try:
                    k_dst, k_oid, _k_idx = key
                except Exception:
                    continue
                if k_oid == object_id and (not dst_id or k_dst == dst_id):
                    rp.pop(key, None)
                    removed += 1
            ri = getattr(self, "repair_inflight", {}) or {}
            for key in list(ri.keys()):
                try:
                    k_dst, k_oid, _k_idx = key
                except Exception:
                    continue
                if k_oid == object_id and (not dst_id or k_dst == dst_id):
                    ri.pop(key, None)
                    removed += 1
            if object_id and dst_id:
                removed += self._prune_normal_chunk_queue_for_repair(object_id, dst_id)
        except Exception as e:
            self.log_event(
                f"[REPAIR_MODE] clear failed dst={short8(dst_id) if dst_id else '-'} "
                f"object={str(object_id)[:8]} err={type(e).__name__}: {e}"
            )
        return removed

    def _enqueue_repair_chunk(self, dst_id: str, block: dict, round_no: int = 0):
        """Coalesce a requested repair chunk into the repair side-set.

        Repair still rides as ordinary encrypted PAYLOAD, but repeated WANTs no
        longer multiply the same object/index into the main queue.  New WANTs
        refresh the pending record and raise its round number.
        """
        try:
            data = block.get("data", {}) if isinstance(block, dict) else {}
            oid = str(data.get("object_id", ""))
            idx = int(data.get("index", -1))
            if not oid or idx < 0:
                raise ValueError("bad repair block")
            rp = getattr(self, "repair_pending", None)
            if rp is None:
                self.repair_pending = {}
                rp = self.repair_pending
            # Hard cap; drop the oldest/lowest-round pending item if needed.
            maxn = int(globals().get("KDK_REPAIR_SET_MAX", 512))
            if len(rp) >= maxn:
                try:
                    victim = sorted(rp.items(), key=lambda kv: (int(kv[1].get("round", 0)), float(kv[1].get("ts", 0))))[0][0]
                    rp.pop(victim, None)
                except Exception:
                    pass
            key = (str(dst_id), oid, idx)
            # If this exact repair was recently transmitted, leave it
            # in flight. A later WANT after the timeout may requeue it.
            try:
                ri = getattr(self, "repair_inflight", None)
                if ri is None:
                    self.repair_inflight = {}
                    ri = self.repair_inflight
                inf = ri.get(key)
                if inf:
                    age = now_ts() - float(inf.get("sent_ts", 0.0) or 0.0)
                    timeout = float(globals().get("KDK_REPAIR_INFLIGHT_TIMEOUT_SECS", 18.0))
                    sent_round = int(inf.get("round", 0) or 0)
                    incoming_round = int(round_no or 0)

                    # A later WANT is authoritative evidence that the
                    # receiver still lacks this chunk. Clear stale sender-side
                    # in-flight state immediately. A duplicate WANT from the same
                    # round remains coalesced until the normal timeout expires.
                    if incoming_round > sent_round:
                        ri.pop(key, None)
                    elif age < timeout:
                        return False
                    else:
                        # Still requested after timeout: allow retransmission.
                        ri.pop(key, None)
            except Exception:
                pass
            old = rp.get(key)
            rp[key] = {
                "dst": dst_id,
                "block": block,
                "round": max(int(round_no or 0), int((old or {}).get("round", 0) or 0)),
                "ts": now_ts(),
            }
            return True
        except Exception as e:
            self.log_event(f"[REPAIR_SET] enqueue failed dst={short8(dst_id)} err={type(e).__name__}: {e}")
            self.outbound_queue.append((dst_id, [block], "KDK-CHUNK-REPAIR"))
            return True

    def inject_height_wait_cover(self):
        """Preserve dummy traffic while rate-limiting explicit HEIGHT-WAIT notices."""
        now = now_ts()
        interval = max(5.0, float(globals().get("KDK_HEIGHT_WAIT_NOTICE_SECS", 60.0)))
        last = float(getattr(self, "dingo_height_wait_last_notice_ts", 0.0) or 0.0)
        if now - last >= interval:
            suppressed = int(getattr(self, "dingo_height_wait_suppressed", 0) or 0)
            self.dingo_height_wait_last_notice_ts = now
            self.dingo_height_wait_suppressed = 0
            if suppressed:
                self.log_event(f"[HEIGHT-WAIT] dummy turns suppressed={suppressed}")
            self.inject_dummy("HEIGHT-WAIT")
        else:
            self.dingo_height_wait_suppressed = int(getattr(self, "dingo_height_wait_suppressed", 0) or 0) + 1
            self.inject_dummy("DUMMY")

    def on_token_trigger(self):
        self.metric_turns += 1
        """
        Forced emission event.
        """
        wait = int(getattr(self, "queue_emit_turns_wait", 0))
        repair_n = self._repair_pending_count()
        pure_repair = (repair_n > 0 and not self.outbound_queue)
        if (self.outbound_queue or repair_n > 0) and (pure_repair or wait <= 0) and (pure_repair or random.random() >= self._dummy_blend_probability()):
            idx = -1
            try:
                repair_item = None
                if self._repair_pending_count() > 0:
                    repair_item = self._pop_repair_pending_item()

                if repair_item is not None:
                    dst_id, blocks, label = repair_item
                    idx = -2
                    remove_from_queue = False
                else:
                    idx = self._choose_outbound_queue_index()
                    if idx < 0:
                        idx = 0
                    if idx >= len(self.outbound_queue):
                        raise IndexError(f"chosen queue index {idx} >= qlen {len(self.outbound_queue)}")
                    queued_item = self.outbound_queue[idx]
                    dst_id, blocks, label = queued_item  # peek, don't remove yet
                    remove_from_queue = True

                # Height synchronises eligibility, not exact transmission time.
                # If the current Dingo epoch has already spent its substantive
                # slot, preserve the queued item and use this Brownian turn as dummy traffic.
                if not self._height_send_allowed(label):
                    self.inject_height_wait_cover()
                    self.queue_emit_turns_wait = 0
                    return

                chunk_meta = self._chunk_block_telemetry(blocks)
                if str(label or "") == "DINGO-BEACON-PUBLIC":
                    ph = self.inject_public_dingo_beacon(dst_id, blocks)
                else:
                    ph = self.inject_envelope(dst_id, blocks, label=label)
                if ph:
                    self._height_note_sent(label)
                if remove_from_queue:
                    # The queue may be touched by another thread between peek
                    # and successful injection.  Remove the exact item if it is
                    # still present; otherwise leave the deque alone rather than
                    # rotating/popping the wrong entry or raising IndexError.
                    try:
                        if 0 <= idx < len(self.outbound_queue) and self.outbound_queue[idx] == queued_item:
                            del self.outbound_queue[idx]
                        else:
                            self.outbound_queue.remove(queued_item)
                    except ValueError:
                        self.log_event(
                            f"[QUEUE] injected item already removed label={label} idx={idx} q_now={len(self.outbound_queue)}"
                        )

                q_after = len(self.outbound_queue)
                repair_after = self._repair_pending_count()
                # In pure repair mode there may be no ambient collision stream
                # to count down a random queue wait.  Keep repairs moving; dummy traffic
                # is still provided by normal mesh dummy traffic and relay churn.
                next_wait = 0 if (repair_after > 0 and q_after == 0) else (self._schedule_next_queue_emit_gap() if (q_after > 0 or repair_after > 0) else 0)
                self.queue_emit_turns_wait = next_wait

                if chunk_meta:
                    self.log_event(
                        f"[CHUNK_TX] {chunk_meta} dst={short8(dst_id)} ph={str(ph or '')[:8]} q_after={q_after} repair_pending={repair_after}"
                    )

                self.log_event(
                    f"[TURN] trigger class=MESSAGE label={label} dst={short8(dst_id)} "
                    f"idx={idx} q_after={q_after} repair_pending={repair_after} next_q_wait={next_wait}"
                )

            except Exception as e:
                # A failed repair injection must not disappear merely because
                # it was popped into the in-flight set before serialization.
                try:
                    if 'repair_item' in locals() and repair_item is not None:
                        rdst, rblocks, _rlabel = repair_item
                        rb = rblocks[0] if isinstance(rblocks, list) and rblocks else None
                        if isinstance(rb, dict):
                            data = rb.get("data", {}) or {}
                            key = (str(rdst), str(data.get("object_id", "")), int(data.get("index", -1)))
                            getattr(self, "repair_inflight", {}).pop(key, None)
                            self._enqueue_repair_chunk(str(rdst), rb, round_no=0)
                except Exception:
                    pass
                self.log_event(
                    f"[INJECT_FAIL] err={type(e).__name__}: {e} q_still={len(self.outbound_queue)} repair_pending={self._repair_pending_count()}"
                )
                self.queue_emit_turns_wait = 1

        else:
            if self.outbound_queue and wait > 0:
                self.queue_emit_turns_wait = max(0, wait - 1)
                self.log_event(
                    f"[TURN] trigger class=DUMMY queue_wait={wait}->{self.queue_emit_turns_wait} "
                    f"q={len(self.outbound_queue)}"
                )
            elif self.outbound_queue:
                self.log_event(
                    f"[TURN] trigger class=DUMMY_BLEND q={len(self.outbound_queue)} "
                    f"p={self._dummy_blend_probability():.2f}"
                )
            else:
                self.log_event("[TURN] trigger class=DUMMY")

            self.inject_dummy("DUMMY")

        # reset (no hoarding)
        self.token_count = 0
    # ------------------------- Key persistence -------------------------------

    def _key_paths(self):
        safe = "".join(c for c in self.name if c.isalnum() or c in ("-", "_")).strip() or f"node_{self.port}"
        return (
            os.path.join("keys", f"{safe}.ed25519.seed"),
            os.path.join("keys", f"{safe}.x25519.sk"),
        )

    def _load_or_create_keys(self):
        if SigningKey is None or PrivateKey is None:
            raise RuntimeError(
                "PyNaCl could not be loaded. The Windows executable is missing its "
                f"bundled crypto library. Original import error: {NACL_IMPORT_ERROR!r}"
            )

        ed_path, box_path = self._key_paths()

        if os.path.exists(ed_path):
            seed = open(ed_path, "rb").read()
            if len(seed) != 32:
                raise ValueError(f"Bad Ed25519 seed length in {ed_path}")
            sk = SigningKey(seed)
        else:
            sk = SigningKey.generate()
            open(ed_path, "wb").write(sk.encode())

        vk = sk.verify_key

        if os.path.exists(box_path):
            bsk = open(box_path, "rb").read()
            if len(bsk) != 32:
                raise ValueError(f"Bad X25519 private key length in {box_path}")
            box_sk = PrivateKey(bsk)
        else:
            box_sk = PrivateKey.generate()
            open(box_path, "wb").write(box_sk.encode())

        return sk, vk, box_sk, box_sk.public_key

    # ------------------------- Messaging -------------------------------------

    def log(self, s: str):
        if self.verbose:
            qprint(s)

    def _log_rotate_if_needed(self):
        """Bound per-node logs so long churn tests do not create GB files."""
        try:
            max_bytes = int(getattr(self, "log_max_bytes", KDK_LOG_MAX_BYTES) or 0)
            if max_bytes <= 0 or not os.path.exists(self.log_path):
                return
            if os.path.getsize(self.log_path) < max_bytes:
                return
            backups = max(0, int(getattr(self, "log_backups", KDK_LOG_BACKUPS) or 0))
            if backups <= 0:
                try:
                    open(self.log_path, "w", encoding="utf-8").close()
                except Exception:
                    pass
                return
            oldest = f"{self.log_path}.{backups}"
            if os.path.exists(oldest):
                try:
                    os.remove(oldest)
                except Exception:
                    pass
            for i in range(backups - 1, 0, -1):
                src = f"{self.log_path}.{i}"
                dst = f"{self.log_path}.{i+1}"
                if os.path.exists(src):
                    try:
                        os.replace(src, dst)
                    except Exception:
                        pass
            try:
                os.replace(self.log_path, f"{self.log_path}.1")
            except Exception:
                pass
        except Exception:
            pass

    def _compact_log_keep(self, s: str) -> bool:
        """Default to protocol-level logging; --verbose keeps wire-level trace."""
        if bool(getattr(self, "verbose", False)) or not bool(getattr(self, "compact_logs", True)):
            return True
        text = str(s)

        # AIRGAP is operator-important, but its polling/waiting lines are not.
        # Keep lifecycle/results in compact logs and leave recurring wait-state
        # diagnostics to --verbose. This preserves the 5 MiB rotation budget.
        if "[AIRGAP]" in text:
            noisy_airgap = (
                "height unavailable",
                "locks remain waiting",
                "matched hash=",
                "blob missing",
                "decrypt paused",
            )
            if any(k in text for k in noisy_airgap):
                return False
            return True

        # Always keep important protocol / operator events.
        keep_markers = (
            "[RUN]", "[ERROR", "[WARN", "[PATCH", "[UPDATE",
            "[VERSION", "[PEER_DIGEST", "[DINGO", "[HEIGHT",
            "[RECEIPT]", "[WANT]", "[QUEUE] chunk receipt",
            "[CHUNK] complete", "[CHUNK] complete failed",
            "[CHUNK] manifest", "[CHUNK] manifest rejected",
            "[CHUNK_Q] kind=manifest", "[CHUNK_TX] kind=manifest",
            "[CHUNK_TX] kind=want", "[CHUNK_TX] kind=receipt",
            "KDK-CHUNK-RECEIPT", "KDK-WANT",
        )
        if any(k in text for k in keep_markers):
            return True

        # Keep chunk data progress only at coarse milestones.
        if "[CHUNK_TX] kind=data" in text or "[CHUNK] data" in text:
            m = re.search(r"idx=(\d+)/(\d+)", text)
            if m:
                try:
                    idx = int(m.group(1)); total = int(m.group(2))
                    return idx in (1, total) or idx % 10 == 0
                except Exception:
                    return False
            return False

        # Suppress high-volume wire trace by default.
        noisy = (
            "[UDP_IN]", "[UDP_MSG]", "[RX_PAYLOAD]", "[SEEN]",
            "[DECRYPT_TRY]", "[DECRYPT_FAIL]", "[MESH]", "[BCAST]",
            "[COLLISION]", "[INJECT] DUMMY", "[TURN] trigger class=DUMMY",
            "[DIRECTORY] candidate",
        )
        if any(k in text for k in noisy):
            return False
        return True

    def _trace_rotate_if_needed(self):
        try:
            path = str(getattr(self, "trace_log_path", os.path.join("logs", "trace.log")))
            if not os.path.exists(path) or os.path.getsize(path) < int(KDK_TRACE_LOG_MAX_BYTES):
                return
            backups = max(1, int(KDK_TRACE_LOG_BACKUPS))
            for i in range(backups - 1, 0, -1):
                older = f"{path}.{i}"
                newer = f"{path}.{i + 1}"
                if os.path.exists(older):
                    try:
                        os.replace(older, newer)
                    except Exception:
                        pass
            try:
                os.replace(path, f"{path}.1")
            except Exception:
                pass
        except Exception:
            pass

    def trace_payload(self, event: str, ph: str = "", **fields):
        """Write one bounded metadata-only diagnostic trace event.

        Deliberately contains no message text, keys, signatures or ciphertext.
        Unknown/non-serialisable values are stringified rather than affecting
        the live mesh. When tracing is OFF this returns immediately.
        """
        if not bool(getattr(self, "trace_payloads_enabled", False)):
            return
        try:
            rec = {
                "ts": round(now_ts(), 6),
                "clock": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
                "node": str(getattr(self, "name", "")),
                "node_id": short8(str(getattr(self, "node_id", ""))),
                "event": str(event),
            }
            if ph:
                rec["ph"] = str(ph)
            for key, value in fields.items():
                if value is None:
                    continue
                if isinstance(value, (str, int, float, bool)):
                    rec[str(key)] = value
                elif isinstance(value, (tuple, list)) and len(value) <= 4:
                    rec[str(key)] = [str(x) for x in value]
                else:
                    rec[str(key)] = str(value)
            ensure_dir("logs")
            line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            with self._trace_lock:
                self._trace_rotate_if_needed()
                with open(self.trace_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self.trace_event_count = int(getattr(self, "trace_event_count", 0)) + 1
        except Exception:
            # Diagnostics must never disturb live transport.
            pass

    def _trace_is_tracked(self, ph: str) -> bool:
        """Return whether a payload hash belongs to a selected diagnostic object.

        Exact tracked hashes are populated automatically for locally originated
        or locally decrypted interesting objects. Explicit hash-prefix watches
        allow an intermediate relay to witness one known payload without enabling
        the old full-mesh firehose trace.
        """
        if not ph:
            return False
        try:
            phs = str(ph).lower()
            for prefix in tuple(getattr(self, "trace_watch_hash_prefixes", set()) or ()):
                if phs.startswith(str(prefix).lower()):
                    return True
            now = now_ts()
            table = getattr(self, "trace_tracked_payloads", {})
            ts = float(table.get(str(ph), 0.0) or 0.0)
            if ts and now - ts <= float(KDK_TRACE_TRACK_TTL_SECS):
                return True
            if str(ph) in table:
                table.pop(str(ph), None)
        except Exception:
            pass
        return False

    def _trace_watch_matches(self, ph: str = "", origin: str = "") -> bool:
        """Return True when an explicit relay-watch filter matches this PAYLOAD."""
        try:
            phs = str(ph or "").lower()
            org = str(origin or "").lower()
            for prefix in tuple(getattr(self, "trace_watch_hash_prefixes", set()) or ()):
                if phs and phs.startswith(str(prefix).lower()):
                    return True
            for prefix in tuple(getattr(self, "trace_watch_origin_prefixes", set()) or ()):
                if org and org.startswith(str(prefix).lower()):
                    return True
        except Exception:
            pass
        return False

    def _trace_track(self, ph: str) -> None:
        """Remember one selected payload hash in memory; never changes wire state."""
        if not ph:
            return
        try:
            table = getattr(self, "trace_tracked_payloads", {})
            now = now_ts()
            table[str(ph)] = now
            if len(table) > int(KDK_TRACE_TRACK_MAX):
                stale = sorted(table.items(), key=lambda kv: float(kv[1]))[:-int(KDK_TRACE_TRACK_MAX)]
                for key, _ts in stale:
                    table.pop(key, None)
            self.trace_tracked_payloads = table
        except Exception:
            pass

    def _trace_identity_interesting(self, ident: dict) -> bool:
        try:
            return str((ident or {}).get("block_type", "")) in KDK_TRACE_BLOCK_TYPES
        except Exception:
            return False

    def _trace_block_identity(self, blocks: list) -> dict:
        """Extract safe logical identifiers from locally known plaintext blocks."""
        out = {}
        try:
            for block in list(blocks or []):
                if not isinstance(block, dict):
                    continue
                btype = str(block.get("type", "") or "")
                data = block.get("data", {}) or {}
                if not isinstance(data, dict):
                    continue
                if btype == "message":
                    out["mid"] = str(data.get("message_id", "") or "")[:32]
                elif btype == "receipt":
                    out["rid"] = str(data.get("receipt_id", "") or "")[:32]
                    out["subject_id"] = str(data.get("subject_id", "") or data.get("message_id", "") or data.get("object_id", ""))[:32]
                elif btype == "receipt_ack":
                    out["rid"] = str(data.get("receipt_id", "") or "")[:32]
                if btype:
                    out.setdefault("block_type", btype)
        except Exception:
            pass
        return {k: v for k, v in out.items() if v}

    def log_event(self, s: str):
        line = f"{time.strftime('%H:%M:%S')} {s}"
        try:
            self.status_last_event = str(s).replace("\n", " ")[:96]
        except Exception:
            pass
        if not bool(getattr(self, "status_box_enabled", False)):
            qprint(line)
        try:
            if not self._compact_log_keep(str(s)):
                return
            self._log_rotate_if_needed()
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def check_peer_version(self, peer_id, caps, addr):
        peer_ver = caps.get("script_version", "?") if isinstance(caps, dict) else "?"
        peer_rev = caps.get("script_revision") if isinstance(caps, dict) else None
        peer_hash = caps.get("script_hash", "?") if isinstance(caps, dict) else "?"
        peer_origin = caps.get("script_origin", "") if isinstance(caps, dict) else ""
        peer_lineage = caps.get("script_lineage", "") if isinstance(caps, dict) else ""

        # Log first observed version/hash tuple per peer. This proves whether
        # caps are actually arriving over HELLO / DISCOVER / HEARTBEAT without
        # flooding logs every few seconds.
        seen_key = (str(peer_id), str(peer_ver), str(peer_hash))
        seen = getattr(self, "version_check_seen", set())
        if seen_key not in seen:
            try:
                seen.add(seen_key)
                self.version_check_seen = seen
            except Exception:
                pass
            self.log_event(
                f"[VERSION_CHECK] peer={short8(peer_id)} "
                f"peer_ver={peer_ver} peer_hash={peer_hash} "
                f"local_ver={SCRIPT_VERSION} local_hash={SCRIPT_HASH} addr={addr}"
            )

        if not kdk_release_identity_matches(peer_origin, peer_lineage):
            lineage_key = (str(peer_id), str(peer_origin), str(peer_lineage))
            if lineage_key not in getattr(self, "version_mismatch_seen", set()):
                self.version_mismatch_seen.add(lineage_key)
                self.log_event(
                    f"[VERSION] different lineage peer={short8(peer_id)} "
                    f"remote={peer_origin or '?'}:{peer_lineage or '?'} "
                    f"local={SCRIPT_ORIGIN}:{SCRIPT_LINEAGE}; automatic update comparison suppressed"
                )
            return

        if not peer_hash or peer_hash == "?" or peer_hash == SCRIPT_HASH:
            return

        mismatch_key = (
            str(peer_id), str(peer_ver), str(peer_hash),
            str(SCRIPT_VERSION), str(SCRIPT_HASH),
        )
        mismatch_seen = getattr(self, "version_mismatch_seen", set())
        first_mismatch = mismatch_key not in mismatch_seen
        if first_mismatch:
            try:
                mismatch_seen.add(mismatch_key)
                self.version_mismatch_seen = mismatch_seen
            except Exception:
                pass
            msg = (
                f"[VERSION] MISMATCH peer={short8(peer_id)} "
                f"ver={peer_ver} hash={peer_hash} "
                f"mine={SCRIPT_VERSION} hash={SCRIPT_HASH} @ {addr}"
            )
            # Keep the raw diagnostic in logs, but do not print it below the
            # status box. The operator-facing notice is added to the activity
            # pane below, with a ten-minute throttle.
            self.log_event(msg)

        cmpv_for_notice = version_cmp(str(peer_ver), SCRIPT_VERSION, peer_rev, SCRIPT_REVISION)
        try:
            notice_key = (str(peer_id), str(peer_ver), str(peer_hash), str(SCRIPT_VERSION), str(SCRIPT_HASH))
            now_notice = now_ts()
            notice_seen = getattr(self, "version_notice_seen", {})
            last_notice = float(notice_seen.get(notice_key, 0.0) or 0.0) if isinstance(notice_seen, dict) else 0.0
            if first_mismatch or (now_notice - last_notice) >= float(KDK_VERSION_NOTICE_INTERVAL_SECS):
                peer_name = self.activity_peer_name(peer_id)
                local_short = str(SCRIPT_VERSION).split("-dev")[-1] if "-dev" in str(SCRIPT_VERSION) else str(SCRIPT_VERSION)
                remote_short = str(peer_ver).split("-dev")[-1] if "-dev" in str(peer_ver) else str(peer_ver)
                if cmpv_for_notice > 0:
                    notice = f"Update available from {peer_name} ({remote_short}); local {local_short}"
                elif cmpv_for_notice < 0:
                    notice = f"Peer {peer_name} is behind ({remote_short}); local {local_short}"
                else:
                    notice = f"Version hash mismatch with {peer_name} ({remote_short})"
                self.activity_system(notice)
                if not isinstance(notice_seen, dict):
                    notice_seen = {}
                notice_seen[notice_key] = now_notice
                self.version_notice_seen = notice_seen
        except Exception:
            pass

        if peer_ver == SCRIPT_VERSION:
            if first_mismatch:
                self.log_event(
                    f"[UPDATE_COLLISION] same_version_hash_mismatch "
                    f"peer={short8(peer_id)} ver={peer_ver} "
                    f"peer_hash={peer_hash} local_hash={SCRIPT_HASH}"
                )
            return

        cmpv = version_cmp(str(peer_ver), SCRIPT_VERSION, peer_rev, SCRIPT_REVISION)
        if cmpv > 0:
            if first_mismatch:
                self.log_event(
                    f"[UPDATE] newer_peer_seen peer={short8(peer_id)} "
                    f"remote={peer_ver} local={SCRIPT_VERSION} "
                    f"policy={getattr(self, 'update_policy', 'off')}"
                )
            return

        if cmpv < 0:
            if first_mismatch:
                self.log_event(
                    f"[UPDATE] older_peer_seen peer={short8(peer_id)} "
                    f"remote={peer_ver} local={SCRIPT_VERSION}"
                )
            # Dev auto-offer: when this node is newer, push its current script
            # to the older peer as a normal KDK chunked object. The receiver
            # still accepts only strictly newer versions under its own policy.
            self.maybe_auto_offer_update(peer_id, peer_ver, peer_hash, peer_origin, peer_lineage)

    def _discover_local_ipv4s(self) -> set:
        """Best-effort set of IPv4 addresses assigned to this host."""
        out = {"127.0.0.1"}
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                out.add(str(info[4][0]))
        except Exception:
            pass
        try:
            host, aliases, ips = socket.gethostbyname_ex(socket.getfqdn())
            for ip in ips:
                out.add(str(ip))
        except Exception:
            pass
        # UDP connect selects the egress interface without transmitting data.
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect(("1.1.1.1", 53))
                out.add(str(probe.getsockname()[0]))
            finally:
                probe.close()
        except Exception:
            pass
        return {ip for ip in out if ip and ip != "0.0.0.0"}

    def _lan_delay_target(self, addr: Tuple[str, int]) -> bool:
        """Return True for loopback/private/link-local or this host's own IP."""
        if not bool(getattr(self, "lan_delay_enabled", True)):
            return False
        try:
            host = str(addr[0]).strip()
            ip = ipaddress.ip_address(host)
            if ip.version != 4:
                return False
            if ip.is_loopback or ip.is_private or ip.is_link_local:
                return True
            return host in getattr(self, "_lan_delay_local_ips", set())
        except Exception:
            return str(addr[0]).strip().lower() == "localhost"

    def _sample_lan_delay_secs(self) -> float:
        mean_ms = max(0.0, float(getattr(self, "lan_delay_ms", KDK_LAN_DELAY_MS)))
        jitter_ms = max(0.0, float(getattr(self, "lan_delay_jitter_ms", KDK_LAN_DELAY_JITTER_MS)))
        if mean_ms <= 0.0:
            return 0.0
        if jitter_ms <= 0.0:
            return mean_ms / 1000.0
        # Gaussian jitter, clipped to +/-4 sigma to prevent pathological sleeps.
        ms = random.gauss(mean_ms, jitter_ms)
        lo = max(0.0, mean_ms - 4.0 * jitter_ms)
        hi = mean_ms + 4.0 * jitter_ms
        return min(hi, max(lo, ms)) / 1000.0

    def _send_wire_now(self, wire: bytes, addr: Tuple[str, int]):
        try:
            self.sock.sendto(wire, addr)
        except OSError as e:
            qprint(f"[WARN] sendto {addr} failed: {e}")

    def _queue_delayed_wire(self, wire: bytes, addr: Tuple[str, int]):
        delay = self._sample_lan_delay_secs()
        if delay <= 0.0:
            self._send_wire_now(wire, addr)
            return
        due = time.monotonic() + delay
        cv = self._delayed_send_cv
        with cv:
            self._delayed_send_seq += 1
            heapq.heappush(
                self._delayed_send_heap,
                (due, int(self._delayed_send_seq), bytes(wire), (str(addr[0]), int(addr[1]))),
            )
            self.metric_lan_delayed_sends = int(getattr(self, "metric_lan_delayed_sends", 0)) + 1
            cv.notify()

    def _delayed_send_loop(self):
        """Release LAN-normalised datagrams at their stochastic due times."""
        cv = self._delayed_send_cv
        stop = self._delayed_send_stop
        while not stop.is_set():
            item = None
            with cv:
                while not stop.is_set():
                    if not self._delayed_send_heap:
                        cv.wait(timeout=0.5)
                        continue
                    due = float(self._delayed_send_heap[0][0])
                    wait = due - time.monotonic()
                    if wait > 0.0:
                        cv.wait(timeout=min(wait, 0.5))
                        continue
                    item = heapq.heappop(self._delayed_send_heap)
                    break
            if item is not None:
                _due, _seq, wire, addr = item
                self._send_wire_now(wire, addr)

    def _start_delayed_send_thread(self):
        if not bool(getattr(self, "lan_delay_enabled", True)):
            return
        t = getattr(self, "_delayed_send_thread", None)
        if t is not None and t.is_alive():
            return
        self._delayed_send_stop.clear()
        t = threading.Thread(
            target=self._delayed_send_loop,
            name=f"kdk-lan-delay-{self.port}",
            daemon=True,
        )
        self._delayed_send_thread = t
        t.start()
        self.log_event(
            f"[LAN_DELAY] enabled mean_ms={float(self.lan_delay_ms):.3f} "
            f"jitter_ms={float(self.lan_delay_jitter_ms):.3f} "
            f"local_ips={','.join(sorted(getattr(self, '_lan_delay_local_ips', set())))}"
        )

    def send_message(self, msg: dict, addr: Tuple[str, int]):
        known_nid = self._peer_node_id_for_addr(addr)
        if known_nid and self.peer_is_blocked(known_nid):
            return
        # Every UDP hop must be signed by the node that is actually sending
        # this packet.  Relayed PAYLOAD messages keep the same inner payload
        # hash (ph), but the outer node_id/vk/sig must belong to the relay.
        # Otherwise strict roaming verification drops relayed packets as
        # node_id/signing-key mismatches before they can count as collisions.
        msg["node_id"] = self.node_id
        msg["vk"] = self.verify_key.encode()
        msg["ts"] = now_ts()
        msg.pop("sig", None)

        to_sign = dict(msg)
        packed = msgpack.packb(to_sign, use_bin_type=True)
        msg["sig"] = self.signing_key.sign(packed).signature

        wire = msgpack.packb(msg, use_bin_type=True)
        if self._lan_delay_target(addr):
            self._queue_delayed_wire(wire, addr)
        else:
            self._send_wire_now(wire, addr)

    def _verified_payload_peers(self, exclude_addr: Optional[Tuple[str, int]] = None) -> list:
        """Return at most one current verified endpoint per cryptographic node.

        self.peers is intentionally a broad discovery/bootstrap candidate pool and may
        contain historical roaming endpoints, unverified peer hints and manual port
        probes.  PAYLOAD traffic must not treat those endpoint records as independent
        mesh participants.  Relay/origin fanout therefore uses the latest endpoint
        learned from signature-verified traffic, deduplicated by stable node_id.
        """
        out = []
        seen = set()
        try:
            exclude = tuple(exclude_addr) if exclude_addr else None
        except Exception:
            exclude = None
        for nid, addr in list(getattr(self, "peer_addr_by_node_id", {}).items()):
            if not nid or nid == self.node_id:
                continue
            if not self.peer_relay_allowed(nid):
                continue
            if not isinstance(addr, tuple) or len(addr) != 2:
                continue
            try:
                peer = (str(addr[0]), int(addr[1]))
            except Exception:
                continue
            if peer[1] <= 0 or peer[1] > 65535:
                continue
            # peer_addr_by_node_id is populated only after signature verification.
            if nid not in getattr(self, "pubkey_by_node_id", {}):
                continue
            if exclude is not None and peer == exclude:
                continue
            if peer in seen:
                continue
            seen.add(peer)
            out.append(peer)
        return out

    def broadcast(self, msg: dict):
        # Control-plane discovery continues to use the broad candidate pool.
        # PAYLOAD origin traffic normally uses one current signature-verified
        # endpoint per node. A node can, however, restart with valid peer keys/
        # activity restored through discovery while peer_addr_by_node_id is still
        # empty. In that state older builds silently consumed queued PAYLOADs
        # without sending a UDP datagram. Use the candidate pool only as a
        # transport fallback; cryptographic verification remains unchanged.
        is_payload = msg.get("type") == "PAYLOAD"
        if is_payload:
            targets = self._verified_payload_peers()
            if not targets:
                seen = set()
                fallback = []
                for raw in list(getattr(self, "peers", []) or []):
                    try:
                        peer = (str(raw[0]), int(raw[1]))
                    except Exception:
                        continue
                    if peer[1] <= 0 or peer[1] > 65535 or peer in seen:
                        continue
                    seen.add(peer)
                    fallback.append(peer)
                targets = fallback
                self.log_event(
                    f"[BCAST] fallback candidate pool ph={str(msg.get('ph',''))[:8]} targets={len(targets)}"
                )
            if not targets:
                self.log_event(
                    f"[BCAST] no payload endpoints ph={str(msg.get('ph',''))[:8]}"
                )
        else:
            targets = list(self.peers)

        for host, port in targets:
            if is_payload:
                self.log_event(
                    f"[BCAST] type={msg.get('type')} ph={str(msg.get('ph',''))[:8]} -> {(host, port)}"
                )
                trace_ph = str(msg.get("ph", "") or "")
                if self._trace_is_tracked(trace_ph):
                    self.trace_payload(
                        "BCAST", trace_ph, to=f"{host}:{port}",
                        ttl=int(msg.get("ttl", PAYLOAD_TTL_DEFAULT)),
                        hops=int(msg.get("hops", 0)), wave=int(msg.get("wave", 0)),
                        mode=str(msg.get("tx_mode", "origin"))
                    )
            self.send_message(msg, (host, port))

    # ------------------------- PoW (legacy compat) ---------------------------

    def do_pow(self, frame: bytes):
        # Legacy/compat PoW (not used by the newer stamp-based validator).
        bits = int(getattr(self, "pow_bits_required", 16))
        target_nibbles = max(bits // 4, 0)
        target = "0" * target_nibbles
        for _ in range(POW_MAX_ITER):
            nonce = os.urandom(8)
            h = hashlib.sha256(nonce + frame).hexdigest()
            if h.startswith(target):
                return nonce, h[:8]
        nonce = os.urandom(8)
        h = hashlib.sha256(nonce + frame).hexdigest()
        return nonce, h[:8]

    # ------------------------- Heartbeat + Discover --------------------------

    def send_hello(self, addr: Tuple[str, int]):
        """Send HELLO and remember its nonce long enough to measure HELLO_ACK RTT."""
        nonce = os.urandom(16)
        nonce_hex = nonce.hex()
        now_mono = time.monotonic()

        probes = getattr(self, "_hello_probe_sent", None)
        if not isinstance(probes, dict):
            probes = {}
            self._hello_probe_sent = probes

        # Bound diagnostic state. HELLO probes are non-authoritative and may never
        # receive an ACK when a candidate endpoint is stale or unreachable.
        for key, rec in list(probes.items()):
            try:
                sent_mono = float((rec or {}).get("sent_mono", 0.0))
            except Exception:
                sent_mono = 0.0
            if not sent_mono or (now_mono - sent_mono) > 60.0:
                probes.pop(key, None)
        if len(probes) >= 1024:
            try:
                oldest = min(
                    probes.items(),
                    key=lambda item: float((item[1] or {}).get("sent_mono", 0.0))
                )[0]
                probes.pop(oldest, None)
            except Exception:
                probes.clear()

        probes[nonce_hex] = {
            "sent_mono": now_mono,
            "addr": (str(addr[0]), int(addr[1])),
        }

        self.send_message({
            "type": "HELLO",
            "vk": self.verify_key.encode(),
            "ek": self.box_pk.encode(),
            "caps": self.caps,
            "nonce": nonce,
        }, addr)

    def send_hello_ack(self, addr: Tuple[str, int], hello_nonce=None):
        """Echo the HELLO nonce so the initiator can correlate one RTT sample."""
        nonce = hello_nonce if isinstance(hello_nonce, (bytes, bytearray)) else os.urandom(16)
        self.send_message({
            "type": "HELLO_ACK",
            "vk": self.verify_key.encode(),
            "ek": self.box_pk.encode(),
            "caps": self.caps,
            "nonce": bytes(nonce),
        }, addr)

    def manual_rtt_probe(self) -> int:
        """Send tracked HELLO probes to known verified non-LAN peers on demand.

        This is diagnostic only. It bypasses normal discovery/heartbeat suppression
        so an operator can collect repeatable application-level WAN RTT samples
        without changing PAYLOAD propagation behaviour.
        """
        sent = 0
        seen = set()

        for nid, addr in list(getattr(self, "peer_addr_by_node_id", {}).items()):
            if nid == self.node_id:
                continue
            if not isinstance(addr, tuple) or len(addr) != 2:
                continue
            try:
                host = str(addr[0])
                port = int(addr[1])
            except Exception:
                continue

            # Prefer genuinely remote/WAN endpoints. Loopback and private/LAN
            # routes are precisely what this diagnostic is intended to compare
            # against later, so do not include them in the baseline sample.
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_loopback or ip.is_private or ip.is_link_local:
                    continue
            except Exception:
                if host.strip().lower() in ("localhost",):
                    continue

            endpoint = (host, port)
            if endpoint in seen:
                continue

            # Only probe endpoints whose peer identity/key has already been
            # verified by ordinary mesh traffic.
            if nid not in getattr(self, "pubkey_by_node_id", {}):
                continue

            seen.add(endpoint)
            self.send_hello(endpoint)
            sent += 1
            self.log_event(
                f"[HELLO_RTT_PROBE] peer={short8(str(nid))} addr={host}:{port}"
            )

        self.activity_system(f"RTT Probe: sent {sent} WAN HELLO probe{'s' if sent != 1 else ''}")
        return sent

    def maybe_send_heartbeats(self, now: float):
        if now - self.last_heartbeat_ts < HEARTBEAT_INTERVAL:
            return
        self.last_heartbeat_ts = now

        suppress_recent = float(HEARTBEAT_RECENT_TRAFFIC_SUPPRESS_SECS)
        sent = 0
        skipped = 0
        for host, port in list(self.peers):
            addr = (host, port)
            peer_id = self.peer_id_by_addr.get(addr)
            if addr not in self.peer_pubkey_by_addr:
                # Unknown endpoint: HELLO is still useful, but keep it on the slower heartbeat cadence.
                self.send_hello(addr)
                sent += 1
                continue

            # Any recently verified packet from this peer already proves liveness.
            # Avoid adding heartbeat noise during active mesh churn.
            try:
                last_seen = float(self.active_nodes.get(peer_id, 0.0) or 0.0) if peer_id else 0.0
            except Exception:
                last_seen = 0.0
            if last_seen and (now - last_seen) < suppress_recent:
                skipped += 1
                continue

            # Include caps so version/hash/update state stays fresh after initial HELLO.
            self.send_message({"type": "HEARTBEAT", "vk": self.verify_key.encode(), "caps": self.caps}, addr)
            sent += 1

        if skipped and not sent:
            self.log_event(f"[HEARTBEAT] suppressed recent peers={skipped}")

    def maybe_handle_resume_gap(self) -> float:
        """Detect a long execution pause and force immediate mesh refresh.

        Compare both monotonic and wall elapsed time.  Some platforms include
        suspend time in their monotonic clock and some do not; the wall-clock
        fallback keeps this useful across Windows/Linux/Termux.  A large clock
        correction can at worst cause a harmless extra discovery refresh.
        """
        mono_now = time.monotonic()
        wall_now = time.time()

        prev_mono = getattr(self, "_resume_last_mono", None)
        prev_wall = getattr(self, "_resume_last_wall", None)
        self._resume_last_mono = mono_now
        self._resume_last_wall = wall_now

        if prev_mono is None or prev_wall is None:
            return 0.0

        mono_gap = max(0.0, mono_now - float(prev_mono))
        wall_gap = max(0.0, wall_now - float(prev_wall))
        gap = max(mono_gap, wall_gap)

        threshold = float(globals().get("KDK_RESUME_GAP_SECS", 60.0))
        if gap < threshold:
            return 0.0

        self.log_event(f"[RESUME] execution gap {gap:.0f}s detected")
        self.log_event("[RESUME] refreshing peer discovery")

        # Keep research collision-rate samples honest across suspend/resume.
        # The row is retained, but the gap is excluded from active_secs and the
        # interval is explicitly marked discontinuous.
        self.timelock_metrics_inactive_secs = (
            float(getattr(self, "timelock_metrics_inactive_secs", 0.0) or 0.0) + gap
        )
        self.timelock_metrics_continuous = False

        # The normal loop calls heartbeat and discovery immediately after this.
        # Reset their clocks so known peers are probed now, while retaining the
        # learned peer digest and all cryptographic identity state.
        self.last_heartbeat_ts = 0.0
        self.last_discover_ts = 0.0
        self.last_discover_height = 0
        return gap

    def _fresh_dingo_height_for_control(self, now: float) -> int:
        """Return a fresh real Dingo height for control-plane pacing, else 0."""
        try:
            h = int(getattr(self, "dingo_scheduler_height", 0) or 0)
            hts = float(getattr(self, "dingo_scheduler_height_ts", 0.0) or 0.0)
            stale = float(globals().get("KDK_HEIGHT_STALE_SECS", 180.0))
            if h > 0 and hts > 0 and (float(now) - hts) <= stale:
                return h
        except Exception:
            pass
        return 0

    def _discover_message(self) -> dict:
        return {
            "type": "DISCOVER",
            "vk": self.verify_key.encode(),
            "ek": self.box_pk.encode(),
            "caps": self.caps,
            "nonce": os.urandom(8),
        }

    def _send_stable_discover_probe(self) -> bool:
        """Send one DISCOVER to one random candidate instead of broadcasting."""
        candidates = []
        seen = set()
        for raw in list(getattr(self, "peers", []) or []):
            try:
                peer = (str(raw[0]), int(raw[1]))
            except Exception:
                continue
            if peer[1] <= 0 or peer[1] > 65535 or peer in seen:
                continue
            seen.add(peer)
            candidates.append(peer)
        if not candidates:
            return False
        peer = random.choice(candidates)
        self.send_message(self._discover_message(), peer)
        self.log_event(f"[DISCOVER] stable stochastic probe -> {peer[0]}:{peer[1]}")
        return True

    def maybe_discover(self, now: float):
        """Adaptive discovery with Dingo-height pacing once the mesh is healthy.

        Sparse/cold topology still uses the 30-second bootstrap broadcast because
        that interval is shorter than a normal block and an isolated node must be
        able to find the mesh. Once at least two peers are verified and recently
        active, routine discovery becomes one random probe every two fresh Dingo
        heights. If no fresh height exists, the old 120-second stable timer is a
        backup only.
        """
        try:
            recent = sum(1 for nid, ts in self.active_nodes.items()
                         if nid != self.node_id and (now - float(ts or 0.0)) < max(ACTIVE_TIMEOUT, 60.0))
            verified = len([nid for nid in self.peer_keys.keys() if nid != self.node_id])
        except Exception:
            recent = 0
            verified = 0

        stable = (verified >= 2 and recent >= 2)
        if not stable:
            interval = float(DISCOVER_INTERVAL)
            if now - self.last_discover_ts < interval:
                return
            self.last_discover_ts = now + random.uniform(0.0, DISCOVER_JITTER_MAX)
            self.broadcast(self._discover_message())
            self.log_event(f"[DISCOVER] sparse broadcast recent={recent} verified={verified}")
            return

        h = self._fresh_dingo_height_for_control(now)
        if h > 0:
            blocks = max(1, int(globals().get("KDK_DISCOVER_STABLE_BLOCKS", 2)))
            last_h = int(getattr(self, "last_discover_height", 0) or 0)
            if last_h > 0 and (h - last_h) < blocks:
                return
            if self._send_stable_discover_probe():
                self.last_discover_height = h
                self.last_discover_ts = now
                self.log_event(f"[DISCOVER] height-paced height={h} every={blocks} blocks")
            return

        # No fresh chain clock: degraded-mode fallback to the old stable timer.
        interval = float(DISCOVER_STABLE_INTERVAL)
        if now - self.last_discover_ts < interval:
            return
        if self._send_stable_discover_probe():
            self.last_discover_ts = now + random.uniform(0.0, DISCOVER_JITTER_MAX)
            self.log_event(f"[DISCOVER] fallback-seconds interval={interval:.0f}s")

    # ------------------------- Receive path ----------------------------------

    def _peer_digest_addr_string(self, addr: Tuple[str, int]) -> str:
        try:
            return f"{addr[0]}:{int(addr[1])}"
        except Exception:
            return ""

    def load_peer_policy(self, path: str = "") -> int:
        """Load local operator policy keyed by stable cryptographic node ID."""
        path = str(path or getattr(self, "peer_policy_path", KDK_PEER_POLICY_PATH))
        self.peer_policy = {}
        try:
            if not os.path.exists(path):
                return 0
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("peers", {}) if isinstance(data, dict) else {}
            if not isinstance(records, dict):
                return 0
            for nid, state in records.items():
                nid = str(nid or "").strip().lower()
                state = str(state or "allow").strip().lower()
                if len(nid) < 8 or state not in ("muted", "suspended", "blocked"):
                    continue
                self.peer_policy[nid] = state
            return len(self.peer_policy)
        except Exception:
            return 0

    def save_peer_policy(self, path: str = "") -> None:
        """Persist only non-default peer policies atomically."""
        path = str(path or getattr(self, "peer_policy_path", KDK_PEER_POLICY_PATH))
        try:
            ensure_dir(os.path.dirname(path) or ".")
            clean = {str(nid): str(state) for nid, state in dict(getattr(self, "peer_policy", {}) or {}).items() if str(state) in ("muted", "suspended", "blocked")}
            tmp = path + f".{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "peers": clean}, f, indent=2, sort_keys=True)
                f.flush()
                try: os.fsync(f.fileno())
                except Exception: pass
            os.replace(tmp, path)
        except Exception as e:
            self.log_event(f"[PEER_POLICY] save failed path={path} err={type(e).__name__}: {e}")

    def peer_policy_state(self, node_id: str) -> str:
        nid = str(node_id or "").strip().lower()
        return str((getattr(self, "peer_policy", {}) or {}).get(nid, "allow") or "allow").lower()

    def set_peer_policy(self, node_id: str, state: str) -> bool:
        nid = str(node_id or "").strip().lower()
        state = str(state or "allow").strip().lower()
        if not nid or nid == str(getattr(self, "node_id", "")).lower() or state not in ("allow", "muted", "suspended", "blocked"):
            return False
        if state == "allow": self.peer_policy.pop(nid, None)
        else: self.peer_policy[nid] = state
        self.save_peer_policy()
        self.log_event(f"[PEER_POLICY] peer={short8(nid)} state={state}")
        return True

    def peer_is_blocked(self, node_id: str) -> bool:
        return self.peer_policy_state(node_id) == "blocked"

    def peer_is_suspended(self, node_id: str) -> bool:
        return self.peer_policy_state(node_id) in ("suspended", "blocked")

    def peer_direct_muted(self, node_id: str) -> bool:
        return self.peer_policy_state(node_id) in ("muted", "suspended", "blocked")

    def peer_relay_allowed(self, node_id: str) -> bool:
        return self.peer_policy_state(node_id) not in ("suspended", "blocked")

    def _peer_node_id_for_addr(self, addr) -> str:
        try: return str((getattr(self, "peer_id_by_addr", {}) or {}).get(tuple(addr), "") or "")
        except Exception: return ""

    def remove_manual_peer_identity(self, node_id: str) -> int:
        nid = str(node_id or "")
        addrs = set((getattr(self, "peer_addrs_by_node_id", {}) or {}).get(nid, set()) or set())
        current = (getattr(self, "peer_addr_by_node_id", {}) or {}).get(nid)
        if current: addrs.add(current)
        removed = 0
        for addr in list(addrs):
            if addr in getattr(self, "manual_peer_addrs", set()):
                self.manual_peer_addrs.discard(addr); removed += 1
        if removed: self.save_manual_peers()
        return removed

    def load_manual_peers(self, path: str = "") -> int:
        """Restore operator-added bootstrap endpoints.

        Manual peers are candidates, not trusted identities. Every endpoint still
        has to complete the normal signed HELLO exchange before it is accepted.
        """
        path = str(path or getattr(self, "manual_peers_path", KDK_MANUAL_PEERS_PATH))
        added = 0
        try:
            if not os.path.exists(path):
                return 0
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("peers", []) if isinstance(data, dict) else []
            for rec in records if isinstance(records, list) else []:
                if isinstance(rec, str):
                    addr = self._parse_hint_addr(rec)
                elif isinstance(rec, dict):
                    addr = self._parse_hint_addr(f"{rec.get('host', '')}:{rec.get('port', '')}")
                else:
                    addr = None
                if not addr:
                    continue
                self.manual_peer_addrs.add(addr)
                if addr in self.peers:
                    continue
                self.peers.append(addr)
                added += 1
            if added:
                self.log_event(f"[MANUAL_PEERS] loaded candidates={added} path={path}")
        except Exception as e:
            self.log_event(f"[MANUAL_PEERS] load failed path={path} err={type(e).__name__}: {e}")
        return added

    def save_manual_peers(self, path: str = "") -> None:
        """Persist the current operator-added endpoints atomically."""
        path = str(path or getattr(self, "manual_peers_path", KDK_MANUAL_PEERS_PATH))
        try:
            ensure_dir(os.path.dirname(path) or ".")
            records = []
            seen = set()
            for addr in list(getattr(self, "manual_peer_addrs", set()) or set()):
                try:
                    host, port = str(addr[0]), int(addr[1])
                except Exception:
                    continue
                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)
                records.append({"host": host, "port": port})
            records.sort(key=lambda r: (r["host"], r["port"]))
            tmp = path + f".{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "peers": records}, f, indent=2, sort_keys=True)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp, path)
        except Exception as e:
            self.log_event(f"[MANUAL_PEERS] save failed path={path} err={type(e).__name__}: {e}")

    def add_manual_peer_ip(self, host: str) -> list:
        """Add and probe all standard KryptDisk ports for one IP address."""
        ip = str(ipaddress.ip_address(str(host).strip()))
        if not hasattr(self, "manual_peer_addrs"):
            self.manual_peer_addrs = set()
        added = []
        for port in KDK_STANDARD_PEER_PORTS:
            addr = (ip, int(port))
            # Do not probe our own loopback socket. Other ports on the same host
            # remain valid because several KryptDisk nodes may share one machine.
            if ip in ("127.0.0.1", "::1") and int(port) == int(self.port):
                continue
            self.manual_peer_addrs.add(addr)
            if addr not in self.peers:
                self.peers.append(addr)
                added.append(addr)
            self.send_hello(addr)
        self.save_manual_peers()
        self.last_discover_ts = 0.0
        self.last_discover_height = 0
        return added

    def load_peer_digest(self, path: str = "") -> int:
        path = str(path or getattr(self, "peer_digest_path", KDK_PEER_DIGEST_PATH) or KDK_PEER_DIGEST_PATH)
        """Seed self.peers from the learned peer digest.

        The digest is a memory of previously verified endpoints, not a trust
        store. Every restored endpoint is still just a HELLO/DISCOVER candidate
        and must prove the same signing key before it is accepted.
        """
        added = 0
        try:
            if not os.path.exists(path):
                return 0
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            peers = data.get("peers", []) if isinstance(data, dict) else []
            if not isinstance(peers, list):
                return 0
            now = now_ts()
            for rec in peers:
                if not isinstance(rec, dict):
                    continue
                nid = str(rec.get("node_id", "") or "")
                if nid and nid == self.node_id:
                    continue
                last_seen = float(rec.get("last_seen", 0) or 0)
                if last_seen and now - last_seen > KDK_PEER_DIGEST_MAX_AGE:
                    continue
                addr = self._parse_hint_addr(rec.get("last_addr") or rec.get("addr") or "")
                if not addr or addr in self.peers:
                    continue
                self.peers.append(addr)
                added += 1
            if added:
                self.log_event(f"[PEER_DIGEST] loaded candidates={added} path={path}")
        except Exception as e:
            self.log_event(f"[PEER_DIGEST] load failed path={path} err={type(e).__name__}: {e}")
        return added

    def save_peer_digest(self, path: str = "", force: bool = False):
        if bool(getattr(self, "peer_digest_disabled", False)):
            return
        path = str(path or getattr(self, "peer_digest_path", KDK_PEER_DIGEST_PATH) or KDK_PEER_DIGEST_PATH)
        """Write the learned-peer bootstrap cache.

        This function performs real disk I/O (including fsync). Normal verified
        packet handling therefore only marks the digest dirty; periodic
        maintenance calls this writer at a bounded cadence. ``force`` is kept for
        graceful-shutdown compatibility.
        """
        now = now_ts()
        try:
            ensure_dir(os.path.dirname(path) or ".")
            records = []
            for nid, ts in list(self.active_nodes.items()):
                if nid == self.node_id:
                    continue
                try:
                    if now - float(ts) > KDK_PEER_DIGEST_MAX_AGE:
                        continue
                except Exception:
                    pass
                addr = self.peer_addr_by_node_id.get(nid)
                if not addr:
                    continue
                vk = self.pubkey_by_node_id.get(nid, b"") or b""
                caps = self.peer_caps.get(nid, {}) or {}
                name = ""
                if isinstance(caps, dict):
                    name = str(caps.get("name", "") or "")
                if not name:
                    name = str(self.peer_name_by_node_id.get(nid, "") or "")
                records.append({
                    "name": name,
                    "node_id": str(nid),
                    "last_addr": self._peer_digest_addr_string(addr),
                    "vk_hash": sha256(bytes(vk))[:16] if isinstance(vk, (bytes, bytearray)) else "",
                    "last_seen": int(float(ts or now)),
                })
            records.sort(key=lambda r: (str(r.get("name", "")), str(r.get("node_id", ""))))
            data = {
                "version": 1,
                "self": {"name": self.name, "node_id": self.node_id, "port": self.port},
                "updated": int(now),
                "peers": records[-128:],
            }
            # Use a node-specific temp file rather than a shared
            # peer_digest.json.tmp.  On native Linux a single temp+replace is
            # usually fine, but VirtualBox Shared Folders (vboxsf) can leave a
            # shared temp file "Text file busy" when two local nodes save the
            # digest at about the same time.  A unique temp path avoids concurrent nodes
            # fighting over the same .tmp file.
            base = os.path.basename(path)
            directory = os.path.dirname(path) or "."
            safe_name = ''.join(c for c in str(getattr(self, "name", "node")) if c.isalnum() or c in ('-', '_')) or 'node'
            tmp = os.path.join(directory, f".{base}.{safe_name}.{int(getattr(self, 'port', 0))}.{os.getpid()}.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except Exception:
                    pass
            try:
                os.replace(tmp, path)
                self._peer_digest_last_save_ts = now
                self._peer_digest_dirty = False
            except OSError as e:
                # vboxsf can reject atomic replace semantics.  The digest is a
                # small bootstrap cache, not authoritative state, so fall back
                # to a direct overwrite rather than letting the node spam HUD
                # errors forever.  If this write is interrupted, load_peer_digest
                # already treats malformed JSON as non-fatal.
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2, sort_keys=True)
                    self._peer_digest_last_save_ts = now
                    self._peer_digest_dirty = False
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass
                    self.log_event(f"[PEER_DIGEST] direct-save fallback after replace failed err={type(e).__name__}: {e}")
                except Exception:
                    raise
        except Exception as e:
            self.log_event(f"[PEER_DIGEST] save failed err={type(e).__name__}: {e}")

    def maybe_flush_peer_digest(self, now: float):
        """Persist a dirty peer digest at most once per configured interval."""
        if bool(getattr(self, "peer_digest_disabled", False)):
            return
        if not bool(getattr(self, "_peer_digest_dirty", False)):
            return

        last = float(getattr(self, "_peer_digest_last_save_ts", 0.0) or 0.0)
        if last and (float(now) - last) < float(KDK_PEER_DIGEST_FLUSH_INTERVAL_SECS):
            return

        # Set the timestamp inside save_peer_digest only after a successful write.
        self.save_peer_digest()

    def _remember_observed_peer(self, sender_node_id: str, addr: Tuple[str, int], vk_bytes: bytes, ek_bytes: Optional[bytes] = None, caps: Optional[dict] = None, mtype: str = ""):
        """Learn/update a peer by stable cryptographic identity, not by IP:port.

        Standard roaming remains latest-verified-endpoint wins.  The one narrow
        exception is a peer already observed on loopback: a later public/LAN
        observation of that same cryptographic identity must not displace the
        working loopback route.  This prevents co-located nodes from flapping
        between 127.0.0.1 and the host's public/NAT address while leaving ordinary
        remote/LAN/VPN roaming behaviour unchanged.

        It is deliberately called only after signature verification succeeds.
        """
        if not isinstance(sender_node_id, str) or not sender_node_id or sender_node_id == "unknown":
            return
        if sender_node_id == self.node_id:
            return

        prev_addr = self.peer_addr_by_node_id.get(sender_node_id)
        first_seen = prev_addr is None

        def _is_loopback_endpoint(candidate) -> bool:
            try:
                return bool(ipaddress.ip_address(str(candidate[0])).is_loopback)
            except Exception:
                return str(candidate[0] if candidate else "").strip().lower() == "localhost"

        # A verified loopback observation is conclusive evidence that this peer is
        # co-located.  Prefer it over alternate observations of the same identity.
        # Conversely, the first verified loopback packet may promote an existing
        # public/LAN route to loopback.
        preferred_addr = addr
        if prev_addr and _is_loopback_endpoint(prev_addr) and not _is_loopback_endpoint(addr):
            preferred_addr = prev_addr

        roamed = bool(prev_addr and prev_addr != preferred_addr)

        heard_now = now_ts()
        self.active_nodes[sender_node_id] = heard_now
        self.peer_last_seen[sender_node_id] = heard_now
        self.peer_id_by_addr[addr] = sender_node_id
        self.peer_pubkey_by_addr[addr] = vk_bytes
        self.pubkey_by_node_id[sender_node_id] = vk_bytes
        self.peer_addr_by_node_id[sender_node_id] = preferred_addr
        self.peer_addrs_by_node_id.setdefault(sender_node_id, set()).add(addr)
        try:
            if self._host_is_lanish(str(addr[0])):
                self.peer_lan_addr_by_node_id[sender_node_id] = addr
            else:
                self.peer_public_addr_by_node_id[sender_node_id] = addr
        except Exception:
            pass

        # Add every verified observed endpoint to the fallback candidate pool.
        # PAYLOAD routing uses peer_addr_by_node_id, so co-located peers retain
        # loopback as their preferred transport while public/NAT endpoints remain
        # available for discovery and recovery.
        if addr not in self.peers:
            self.peers.append(addr)

        if ek_bytes:
            try:
                self.peer_keys[sender_node_id] = PublicKey(ek_bytes)
            except Exception:
                pass

        if isinstance(caps, dict):
            self.peer_caps[sender_node_id] = caps
            peer_name = str(caps.get("name", "") or "").strip()
            if peer_name:
                self.peer_name_by_node_id[sender_node_id] = peer_name
            self.check_peer_version(sender_node_id, caps, addr)

        # Peer observations are the hottest receive path. The digest is only a
        # future-bootstrap cache, so defer persistence to periodic maintenance.
        self._peer_digest_dirty = True

        if first_seen:
            self.log_event(f"[ROAM] learned peer={short8(sender_node_id)} addr={preferred_addr} via={mtype}")
        elif roamed:
            self.metric_peer_roams = int(getattr(self, "metric_peer_roams", 0)) + 1
            self.log_event(f"[ROAM] peer={short8(sender_node_id)} moved {prev_addr} -> {preferred_addr} via={mtype}")

    def handle_packet(self, data: bytes, addr: Tuple[str, int]):
        self.log_event(f"[UDP_IN] bytes={len(data)} addr={addr}")

        try:
            msg = msgpack.unpackb(data, raw=False)
            self.log_event(
                f"[UDP_MSG] type={msg.get('type','?')} bytes={len(data)}"
            )
        except Exception as e:
            qprint(f"[DROP] msgpack failed addr={addr} bytes={len(data)} err={e}")
            self.log_event(f"[DROP] msgpack failed addr={addr} bytes={len(data)} err={e}")
            return

        mtype = msg.get("type")
        sender_node_id = msg.get("node_id", "unknown")
        sig = msg.get("sig", b"")

        vk_bytes = msg.get("vk") or msg.get("sender_vk") or self.peer_pubkey_by_addr.get(addr)
        if not vk_bytes:
            self.log_event(f"[DROP] no vk addr={addr} type={mtype}")
            return

        try:
            vk = VerifyKey(vk_bytes)
            # Do not trust a supplied node_id blindly; it must match the signing key.
            derived_node_id = sha256(vk.encode())[:16]
            if sender_node_id != derived_node_id:
                self.log_event(
                    f"[DROP] node_id mismatch claimed={short8(sender_node_id)} "
                    f"derived={short8(derived_node_id)} addr={addr} type={mtype}"
                )
                return

            to_verify = dict(msg)
            to_verify.pop("sig", None)
            packed = msgpack.packb(to_verify, use_bin_type=True)
            vk.verify(packed, sig)
        except Exception as e:
            self.log_event(
                f"[WARN] Signature verify failed from {addr}: {e}"
            )
            return

        if self.peer_is_blocked(sender_node_id):
            self.log_event(f"[PEER_POLICY] blocked packet peer={short8(sender_node_id)} type={mtype}")
            return

        ek_bytes = msg.get("ek")
        caps = msg.get("caps")
        self._remember_observed_peer(sender_node_id, addr, vk_bytes, ek_bytes, caps, str(mtype))

        if mtype == "HELLO":
            self.log(f"[HS] HELLO from {short8(sender_node_id)} @ {addr}")
            self.send_hello_ack(addr, msg.get("nonce"))
        elif mtype == "HELLO_ACK":
            self.log(f"[HS] HELLO_ACK from {short8(sender_node_id)} @ {addr}")
            try:
                nonce = msg.get("nonce", b"")
                nonce_hex = nonce.hex() if isinstance(nonce, (bytes, bytearray)) else str(nonce)
                probes = getattr(self, "_hello_probe_sent", {})
                rec = probes.pop(nonce_hex, None) if isinstance(probes, dict) else None
                if isinstance(rec, dict):
                    sent_mono = float(rec.get("sent_mono", 0.0) or 0.0)
                    if sent_mono > 0.0:
                        rtt_ms = max(0.0, (time.monotonic() - sent_mono) * 1000.0)
                        sent_addr = rec.get("addr")
                        self.log_event(
                            f"[HELLO_RTT] peer={short8(sender_node_id)} "
                            f"addr={addr[0]}:{addr[1]} rtt_ms={rtt_ms:.3f} "
                            f"probe={sent_addr}"
                        )
            except Exception as e:
                self.log_event(f"[HELLO_RTT] sample failed peer={short8(sender_node_id)} err={type(e).__name__}: {e}")
        elif mtype == "HEARTBEAT":
            return
        elif mtype == "DISCOVER":
            self.handle_discover(addr, sender_node_id)
        elif mtype == "DISCOVER_REPLY":
            self.handle_discover_reply(addr, sender_node_id, msg)
        elif mtype == "DINGO_HEIGHT":
            self.handle_public_dingo_height(msg, addr, sender_node_id)
        elif mtype == "PAYLOAD":
            self.log_event(f"[RX_PAYLOAD] ph={str(msg.get('ph',''))[:8]} from={short8(sender_node_id)} addr={addr}")
            self.handle_payload(msg, addr, sender_node_id)

    def _host_is_lanish(self, host: str) -> bool:
        """True for RFC1918/link-local/localhost style addresses.

        Used only for choosing which directory address to advertise. It does
        not grant trust and does not bypass HELLO/signature verification.
        """
        try:
            import ipaddress
            ip = ipaddress.ip_address(str(host))
            return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
        except Exception:
            h = str(host or "")
            return h.startswith("192.168.") or h.startswith("10.") or h.startswith("172.16.") or h.startswith("localhost")

    def _directory_public_map_addr(self, peer_id: str) -> Optional[Tuple[str, int]]:
        """Return a configured public addr for peer_id, accepting unique prefixes."""
        mapping = getattr(self, "directory_public_map", {}) or {}
        if not isinstance(peer_id, str) or not peer_id or not isinstance(mapping, dict):
            return None
        if peer_id in mapping:
            return mapping.get(peer_id)
        matches = [addr for key, addr in mapping.items() if isinstance(key, str) and peer_id.startswith(key)]
        if len(matches) == 1:
            return matches[0]
        return None

    def _directory_public_observed_addr(self, peer_id: str) -> Optional[Tuple[str, int]]:
        """Prefer a public observed endpoint for public/roaming requesters.

        A peer can be seen through both a LAN endpoint and a VPN/public/NAT
        endpoint.  The normal roaming table stores the latest endpoint, which
        may flap back to LAN on the home mesh.  For a roaming requester, scan
        all observed addresses and prefer a non-LAN address if one exists.
        """
        if not isinstance(peer_id, str) or not peer_id:
            return None
        # Strongest signal first: explicit public observation tracked at
        # receive time. This survives later LAN observations overwriting
        # peer_addr_by_node_id.
        explicit_public = getattr(self, "peer_public_addr_by_node_id", {}).get(peer_id)
        if explicit_public:
            try:
                h, p = explicit_public
                if not self._host_is_lanish(str(h)):
                    return (str(h), int(p))
            except Exception:
                pass

        addrs = []
        cur = self.peer_addr_by_node_id.get(peer_id)
        if cur:
            addrs.append(cur)
        for a in list((self.peer_addrs_by_node_id.get(peer_id) or set())):
            if a not in addrs:
                addrs.append(a)

        public = []
        for a in addrs:
            try:
                h, p = a
                p = int(p)
                if p <= 0 or p > 65535:
                    continue
                if not self._host_is_lanish(str(h)):
                    public.append((str(h), p))
            except Exception:
                continue
        if not public:
            return None

        # Prefer the current endpoint if it is already public; otherwise use
        # the most recently inserted public candidate from the observed set.
        cur = self.peer_addr_by_node_id.get(peer_id)
        try:
            if cur and not self._host_is_lanish(str(cur[0])):
                return (str(cur[0]), int(cur[1]))
        except Exception:
            pass
        return public[-1]

    def _addr_for_directory_requester(self, peer_addr: Tuple[str, int], requester_addr: Tuple[str, int], peer_id: str = "") -> Optional[Tuple[str, int]]:
        """Return the peer address that should be advertised to this requester.

        LAN requesters get the learned LAN address. Roaming/public requesters
        first get a per-peer public map entry when configured. Otherwise, a
        --directory-public-host alias may rewrite only the host and preserve the
        peer's port. If neither is available, private/LAN peers are withheld
        from public requesters.
        """
        if not isinstance(peer_addr, tuple) or len(peer_addr) != 2:
            return None
        host, port = peer_addr
        try:
            port = int(port)
        except Exception:
            return None
        if port <= 0 or port > 65535:
            return None

        requester_host = str(requester_addr[0]) if requester_addr else ""
        peer_host = str(host or "")
        requester_is_lan = self._host_is_lanish(requester_host)
        peer_is_lan = self._host_is_lanish(peer_host)

        if requester_is_lan:
            lan = getattr(self, "peer_lan_addr_by_node_id", {}).get(peer_id)
            if lan:
                try:
                    return (str(lan[0]), int(lan[1]))
                except Exception:
                    pass
            return (peer_host, port)

        mapped = self._directory_public_map_addr(peer_id)
        if mapped:
            return mapped

        observed_public = self._directory_public_observed_addr(peer_id)
        if observed_public:
            return observed_public

        public_host = str(getattr(self, "directory_public_host", "") or "").strip()
        if peer_is_lan and public_host:
            return (public_host, port)
        if not peer_is_lan:
            return (peer_host, port)
        return None

    def build_peer_directory_hints(self, requester_id: str, requester_addr: Tuple[str, int]) -> list:
        """Build signed DISCOVER_REPLY directory hints for verified peers.

        This deliberately advertises only peers for which we have seen a signed
        packet and have Ed25519/X25519 material. The receiver still performs
        HELLO/probing before any hinted peer is cryptographically accepted.
        """
        if not getattr(self, "directory_hint_enabled", ENABLE_DIRECTORY_HINTS):
            return []
        now = now_ts()
        hints = []
        for nid, ts in list(self.active_nodes.items()):
            if nid in (self.node_id, requester_id):
                continue
            try:
                if now - float(ts) > ACTIVE_TIMEOUT:
                    continue
            except Exception:
                continue
            vk = self.pubkey_by_node_id.get(nid)
            ek_obj = self.peer_keys.get(nid)
            caps = self.peer_caps.get(nid, {}) or {}
            peer_addr = self.peer_addr_by_node_id.get(nid) or self._peer_hint_addr_for_node(nid)
            if not vk or not ek_obj or not peer_addr:
                continue
            adv_addr = self._addr_for_directory_requester(peer_addr, requester_addr, nid)
            if not adv_addr:
                continue
            try:
                hints.append({
                    "node_id": nid,
                    "vk": bytes(vk),
                    "ek": bytes(ek_obj),
                    "caps": dict(caps) if isinstance(caps, dict) else {},
                    "addr": f"{adv_addr[0]}:{int(adv_addr[1])}",
                    "observed_addr": f"{peer_addr[0]}:{int(peer_addr[1])}",
                    "ts": int(ts),
                    "via": self.node_id,
                })
            except Exception:
                continue
            if len(hints) >= DIRECTORY_HINT_MAX:
                break
        return hints

    def handle_discover(self, addr: Tuple[str, int], sender_node_id: str):
        advertised_vault = None

        for nid, caps in self.peer_caps.items():
            if nid == self.node_id:
                continue
            if not (isinstance(caps, dict) and caps.get("vault")):
                continue

            vk = self.pubkey_by_node_id.get(nid)
            ek_obj = self.peer_keys.get(nid)
            if not vk or not ek_obj:
                continue

            try:
                advertised_vault = {
                    "node_id": nid,
                    "vk": vk,
                    "ek": bytes(ek_obj),
                    "caps": caps,
                }
                break
            except Exception:
                continue

        msg = {
            "type": "DISCOVER_REPLY",
            "vk": self.verify_key.encode(),
            "ek": self.box_pk.encode(),
            "caps": self.caps,
            "seen": sender_node_id,
        }

        directory_hints = self.build_peer_directory_hints(sender_node_id, addr)
        if directory_hints:
            msg["peer_directory"] = directory_hints
            self.log_event(f"[DIRECTORY] reply to={short8(sender_node_id)} hints={len(directory_hints)} addr={addr}")
        else:
            self.log_event(f"[DIRECTORY] reply to={short8(sender_node_id)} hints=0 addr={addr}")

        if advertised_vault is not None:
            msg["advertised_vault"] = advertised_vault

        self.send_message(msg, addr)

    def handle_discover_reply(self, addr: Tuple[str, int], sender_node_id: str, msg: dict):
        caps = msg.get("caps", {})

        if isinstance(caps, dict) and caps.get("vault"):
            prev = self.peer_caps.get(sender_node_id, {})
            if not (isinstance(prev, dict) and prev.get("vault")):
                qprint(f"[DISCOVER] Learned vault {short8(sender_node_id)} @ {addr}")

        # General peer directory/rendezvous hints. These are signed by the
        # DISCOVER_REPLY sender, but still only treated as candidates: each
        # hinted address is probed with HELLO and must verify itself.
        peer_dir = msg.get("peer_directory", [])
        if isinstance(peer_dir, list) and getattr(self, "directory_hint_enabled", ENABLE_DIRECTORY_HINTS):
            learned = 0
            for h in peer_dir[:DIRECTORY_HINT_MAX]:
                if not isinstance(h, dict):
                    continue
                nid = h.get("node_id")
                vk = h.get("vk")
                ek = h.get("ek")
                hcaps = h.get("caps", {})
                haddr = self._parse_hint_addr(h.get("addr"))
                if not isinstance(nid, str) or not nid or nid == self.node_id:
                    continue
                if not isinstance(vk, (bytes, bytearray)) or not isinstance(ek, (bytes, bytearray)):
                    continue
                if not haddr:
                    continue
                try:
                    # Sanity check: advertised node_id must match advertised vk.
                    derived = sha256(bytes(vk))[:16]
                    if derived != nid:
                        self.log_event(f"[DIRECTORY] drop id/vk mismatch id={short8(nid)} derived={short8(derived)} via={short8(sender_node_id)}")
                        continue
                    self.pubkey_by_node_id.setdefault(nid, bytes(vk))
                    self.peer_keys.setdefault(nid, PublicKey(bytes(ek)))
                    if isinstance(hcaps, dict):
                        self.peer_caps.setdefault(nid, dict(hcaps))
                    key = f"{nid}|{haddr[0]}:{haddr[1]}"
                    self.peer_hint_candidates[key] = {
                        "node_id": nid,
                        "addr": haddr,
                        "via": sender_node_id,
                        "seen_ts": now_ts(),
                        "hint_ts": h.get("ts", 0),
                        "directory": True,
                        "failures": 0,
                    }
                    if haddr not in self.peers:
                        self.peers.append(haddr)
                    # Probe immediately so the hinted peer can prove itself.
                    self.send_hello(haddr)
                    learned += 1
                    self.log_event(f"[DIRECTORY] candidate id={short8(nid)} addr={haddr[0]}:{haddr[1]} via={short8(sender_node_id)}")
                except Exception as e:
                    self.log_event(f"[DIRECTORY] candidate rejected id={short8(str(nid))} err={e}")
            if learned:
                qprint(f"[DISCOVER] Learned {learned} directory peer hint(s) via {short8(sender_node_id)}")

        adv = msg.get("advertised_vault")
        if not isinstance(adv, dict):
            return

        nid = adv.get("node_id")
        vk = adv.get("vk")
        ek = adv.get("ek")
        vcaps = adv.get("caps", {})

        if not isinstance(nid, str) or not nid:
            return
        if nid == self.node_id:
            return
        if not isinstance(vk, (bytes, bytearray)):
            return
        if not isinstance(ek, (bytes, bytearray)):
            return
        if not (isinstance(vcaps, dict) and vcaps.get("vault")):
            return

        learned_new = False

        if nid not in self.pubkey_by_node_id:
            self.pubkey_by_node_id[nid] = bytes(vk)
            learned_new = True

        if nid not in self.peer_keys:
            try:
                self.peer_keys[nid] = PublicKey(bytes(ek))
                learned_new = True
            except Exception:
                return

        prev_caps = self.peer_caps.get(nid, {})
        if not (isinstance(prev_caps, dict) and prev_caps.get("vault")):
            self.peer_caps[nid] = dict(vcaps)
            learned_new = True

        self.active_nodes[nid] = now_ts()

        if learned_new:
            qprint(f"[DISCOVER] Learned advertised vault {short8(nid)} via {short8(sender_node_id)}")

    # ------------------------- Quorum & relay --------------------------------

    def check_quorum_for_payload(self, payload_hash: str):
        qt = self.quorum_tracker.get(payload_hash)
        if not qt:
            return
        now = now_ts()
        active = {nid for nid, ts in self.active_nodes.items() if now - ts < ACTIVE_TIMEOUT}
        if not qt["quorum_reached"] and active and qt["seen_by"] >= active:
            qt["quorum_reached"] = True
            qt["ttl"] = PAYLOAD_TTL_POST_QUORUM
            self.last_quorum_digest = payload_hash
            self.timelock_metrics_quorums = int(getattr(self, "timelock_metrics_quorums", 0) or 0) + 1
            qprint(f"[QUORUM] Payload {payload_hash[:8]} reached quorum across active nodes")

    def compute_wave_fanout(self, n: int) -> int:
        """Return the stochastic relay fanout for this node.

        A launcher/runtime override may supply an explicit weighted choice list
        (for example --fan-choices 1,1,1,1,2).  If no override is supplied,
        retain the historical mesh-size-dependent profile unchanged.
        """
        if n <= 0:
            return 0
        override = getattr(self, "fan_choices", None)
        if isinstance(override, (list, tuple)) and override:
            choices = [int(x) for x in override if int(x) > 0]
        elif n < 16:
            choices = [1, 1, 2, 2, 3]
        else:
            choices = [2, 2, 3, 3, 4]
        if not choices:
            choices = [1]
        return min(n, random.choice(choices))


    def mesh_should_forward(self, seen_before: bool, src_id: str, ttl: int, quorum_reached: bool = False) -> bool:
        """Relay every PAYLOAD sighting until local quorum knowledge is complete.

        A duplicate/collision is evidence that another node has seen the payload, not
        a reason to stop diffusion.  Successful local decryption is deliberately not
        an input to this decision.  Once quorum is known locally, ordinary diffusion
        stops (the existing post-quorum TTL handling remains separate).
        """
        if not self.relay:
            return False
        if quorum_reached:
            return False
        if ttl <= 0:
            return False
        # Do not suppress a collision merely because this node originated the
        # payload. If it returns before quorum, the origin participates in the
        # same decrypt/collision/relay lifecycle as every other node.
        return True
    
    
    def mesh_forward_wave(self, payload_hash: str, msg: dict, from_addr: Tuple[str, int], ttl: int):
        # Relay only to identity-deduplicated, signature-verified current endpoints.
        # self.peers remains the discovery/bootstrap candidate pool and is deliberately
        # not used for PAYLOAD fanout.
        candidates = self._verified_payload_peers(exclude_addr=from_addr)
        if not candidates:
            return

        fan = self.compute_wave_fanout(len(candidates))
        if fan <= 0:
            return

        random.shuffle(candidates)
        chosen = candidates[:fan]

        new_ttl = max(ttl - 1, 0)
        if new_ttl <= 0:
            return

        msg2 = dict(msg)
        msg2["ttl"] = new_ttl
        msg2["hops"] = int(msg.get("hops", 0)) + 1
        msg2["wave"] = int(msg.get("wave", 0))
        msg2["last_tx_ts"] = now_ts()
        msg2["tx_mode"] = "relay"

        for peer in chosen:
            self.log_event(
                f"[MESH] {payload_hash[:8]} -> {peer} "
                f"(ttl={new_ttl}, fan={fan}, wave={msg2['wave']}, hops={msg2['hops']}, mode={msg2['tx_mode']})"
            )
            self.metric_mesh_forwards += 1
            self.metric_last_tx_ts = now_ts()
            if self._trace_is_tracked(payload_hash):
                self.trace_payload(
                    "FORWARD", payload_hash, to=f"{peer[0]}:{peer[1]}",
                    ttl=new_ttl, hops=msg2["hops"], wave=msg2["wave"], mode="relay"
                )
            self.send_message(msg2, peer)

    # ------------------------- Frames & Envelope v3 ---------------------------



    # ------------------------- Airgap test layer ------------------------------

    def airgap_save_state(self):
        """Persist local airgap state so the node can restart mid-wait."""
        try:
            ensure_dir(AIRGAP_STATE_DIR)
            tickets = {}
            for ph, rec in self.airgap_tickets_by_hash.items():
                r = dict(rec)
                fk = r.get("file_key")
                if isinstance(fk, (bytes, bytearray)):
                    r["file_key_b64"] = base64.b64encode(bytes(fk)).decode("ascii")
                r.pop("file_key", None)
                tickets[ph] = r
            pending_keys = {}
            for ph, kb in getattr(self, "airgap_pending_keys_by_hash", {}).items():
                if isinstance(kb, (bytes, bytearray)):
                    pending_keys[ph] = base64.b64encode(bytes(kb)).decode("ascii")
            data = {
                "tickets": tickets,
                "blobs": dict(self.airgap_blobs_by_hash),
                "unlocked": sorted(list(self.airgap_unlocked)),
                "unlocked_paths": dict(getattr(self, "airgap_unlocked_paths_by_hash", {}) or {}),
                "download_paths": dict(getattr(self, "airgap_download_paths_by_hash", {}) or {}),
                "exports": dict(getattr(self, "airgap_exports_by_hash", {}) or {}),
                "pending_keys": pending_keys,
                "cuckoo_pending": self._cuckoo_pending_for_json(),
                "cuckoo_released": sorted(list(getattr(self, "cuckoo_released", set()) or set())),
                "dingo_height_floor": int(max(
                    int(getattr(self, "dingo_height_floor", 0) or 0),
                    int(getattr(self, "dingo_network_height", 0) or 0),
                )),
            }
            tmp = self.airgap_state_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp, self.airgap_state_path)
        except Exception as e:
            self.log_event(f"[AIRGAP] state save failed err={e}")

    def _cuckoo_pending_for_json(self):
        """Return Cuckoo pending records with chunk bytes encoded for JSON state."""
        out = []
        for rec in list(getattr(self, "cuckoo_pending", []) or []):
            try:
                r = dict(rec)
                b = r.get("block")
                if isinstance(b, dict):
                    bb = dict(b)
                    data = dict(bb.get("data", {}) or {})
                    raw = data.get("data")
                    if isinstance(raw, (bytes, bytearray)):
                        data["data_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
                        data.pop("data", None)
                    bb["data"] = data
                    r["block"] = bb
                out.append(r)
            except Exception:
                continue
        return out

    def _cuckoo_pending_from_json(self, rows):
        """Decode Cuckoo pending records loaded from JSON state."""
        out = []
        for rec in list(rows or []):
            if not isinstance(rec, dict):
                continue
            try:
                r = dict(rec)
                b = r.get("block")
                if isinstance(b, dict):
                    bb = dict(b)
                    data = dict(bb.get("data", {}) or {})
                    if "data_b64" in data and "data" not in data:
                        try:
                            data["data"] = base64.b64decode(str(data.get("data_b64") or ""))
                        except Exception:
                            data["data"] = b""
                        data.pop("data_b64", None)
                    bb["data"] = data
                    r["block"] = bb
                out.append(r)
            except Exception:
                continue
        return out

    def airgap_load_state(self):
        """Load local airgap state. Invalid/missing blob files are ignored."""
        try:
            if not os.path.exists(self.airgap_state_path):
                return
            with open(self.airgap_state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            tickets = data.get("tickets", {}) if isinstance(data, dict) else {}
            blobs = data.get("blobs", {}) if isinstance(data, dict) else {}
            unlocked = data.get("unlocked", []) if isinstance(data, dict) else []
            pending_keys = data.get("pending_keys", {}) if isinstance(data, dict) else {}
            unlocked_paths = data.get("unlocked_paths", {}) if isinstance(data, dict) else {}
            download_paths = data.get("download_paths", {}) if isinstance(data, dict) else {}
            exports = data.get("exports", {}) if isinstance(data, dict) else {}
            cuckoo_pending = data.get("cuckoo_pending", []) if isinstance(data, dict) else []
            cuckoo_released = data.get("cuckoo_released", []) if isinstance(data, dict) else []
            try:
                self.dingo_height_floor = max(0, int(data.get("dingo_height_floor", 0) or 0)) if isinstance(data, dict) else 0
            except Exception:
                self.dingo_height_floor = 0

            self.airgap_tickets_by_hash = {}
            if isinstance(tickets, dict):
                for ph, rec in tickets.items():
                    if not (isinstance(ph, str) and len(ph) == 64 and isinstance(rec, dict)):
                        continue
                    r = dict(rec)
                    b64 = r.pop("file_key_b64", None)
                    if isinstance(b64, str):
                        try:
                            r["file_key"] = base64.b64decode(b64.encode("ascii"))
                        except Exception:
                            pass
                    self.airgap_tickets_by_hash[ph] = r

            self.airgap_blobs_by_hash = {}
            if isinstance(blobs, dict):
                for ph, path in blobs.items():
                    if isinstance(ph, str) and isinstance(path, str) and os.path.exists(path):
                        self.airgap_blobs_by_hash[ph] = path

            self.airgap_unlocked = set(x for x in unlocked if isinstance(x, str))
            self.airgap_unlocked_paths_by_hash = {}
            if isinstance(unlocked_paths, dict):
                for ph, path in unlocked_paths.items():
                    if isinstance(ph, str) and isinstance(path, str) and os.path.exists(path):
                        self.airgap_unlocked_paths_by_hash[ph] = path

            self.airgap_download_paths_by_hash = {}
            if isinstance(download_paths, dict):
                for ph, path in download_paths.items():
                    if isinstance(ph, str) and isinstance(path, str) and path:
                        self.airgap_download_paths_by_hash[ph] = path

            self.airgap_exports_by_hash = {}
            if isinstance(exports, dict):
                for ph, rec in exports.items():
                    if isinstance(ph, str) and len(ph) == 64 and isinstance(rec, dict):
                        self.airgap_exports_by_hash[ph] = dict(rec)

            self.airgap_pending_keys_by_hash = {}
            if isinstance(pending_keys, dict):
                for ph, b64 in pending_keys.items():
                    if isinstance(ph, str) and len(ph) == 64 and isinstance(b64, str):
                        try:
                            kb = base64.b64decode(b64.encode("ascii"))
                            if len(kb) == SecretBox.KEY_SIZE:
                                self.airgap_pending_keys_by_hash[ph] = kb
                        except Exception:
                            pass

            if isinstance(cuckoo_pending, list):
                self.cuckoo_pending = self._cuckoo_pending_from_json(cuckoo_pending)
            if isinstance(cuckoo_released, list):
                self.cuckoo_released = set(str(x) for x in cuckoo_released)

            if self.airgap_tickets_by_hash or self.airgap_blobs_by_hash or self.cuckoo_pending:
                qprint(
                    f"[AIRGAP] loaded state tickets={len(self.airgap_tickets_by_hash)} "
                    f"blobs={len(self.airgap_blobs_by_hash)} unlocked={len(self.airgap_unlocked)} "
                    f"from={self.airgap_state_path}"
                )
        except Exception as e:
            qprint(f"[AIRGAP] state load skipped err={e}")

    def airgap_test_height(self) -> int:
        """Local simulated block-height source used by the original lab flow."""
        try:
            return int(time.time() // max(1, int(self.airgap_block_secs)))
        except Exception:
            return int(time.time() // 60)

    def get_dingo_height_cli(self, cli_path: str = "", extra_args: Optional[list] = None) -> int:
        """Return local Dingocoin block height using dingocoin-cli getblockcount."""
        cli = str(cli_path or getattr(self, "airgap_dingo_cli", "dingocoin-cli") or "dingocoin-cli")
        args = list(extra_args if extra_args is not None else getattr(self, "airgap_dingo_cli_args", []) or [])
        cmd = [cli] + [str(a) for a in args] + ["getblockcount"]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10)
            return int(out.decode("utf-8", "replace").strip())
        except Exception as e:
            raise RuntimeError(f"dingocoin-cli getblockcount failed cmd={' '.join(cmd)!r}: {e}")

    def airgap_dingo_height(self) -> int:
        """Compatibility wrapper for the airgap height path."""
        return self.get_dingo_height_cli()

    def _log_event_dedup(self, key: str, message: str, interval: float = KDK_HEIGHT_ERROR_LOG_SECS):
        """Log one repeated operational error per interval, with a suppression count."""
        now = now_ts()
        state = self._dedup_error_state.setdefault(str(key), {"last": 0.0, "count": 0, "message": ""})
        if str(state.get("message", "")) != str(message):
            state.update({"last": 0.0, "count": 0, "message": str(message)})
        if now - float(state.get("last", 0.0) or 0.0) >= max(1.0, float(interval)):
            suppressed = int(state.get("count", 0) or 0)
            suffix = f" repeated={suppressed}" if suppressed else ""
            self.log_event(f"{message}{suffix}")
            state["last"] = now
            state["count"] = 0
        else:
            state["count"] = int(state.get("count", 0) or 0) + 1

    def dingo_height_diagnostics(self) -> dict:
        """Report the local validating client and freshest accepted mesh witness."""
        diag = {
            "client_height": None, "client_error": "",
            "network_height": None, "network_witness": "", "network_age": None,
        }
        try:
            diag["client_height"] = int(self.get_dingo_height_cli())
        except Exception as e:
            diag["client_error"] = str(e)
        nh = self.get_dingo_network_height()
        if nh > 0:
            diag["network_height"] = int(nh)
            diag["network_witness"] = str(getattr(self, "dingo_network_height_witness", "") or "")
            nts = float(getattr(self, "dingo_network_height_ts", 0.0) or 0.0)
            if nts > 0:
                diag["network_age"] = max(0.0, now_ts() - nts)
        return diag

    def get_dingo_network_height(self) -> int:
        """Highest trusted height observed from local witness or signed beacons."""
        try:
            return int(getattr(self, "dingo_network_height", 0) or 0)
        except Exception:
            return 0

    def dingo_build_height_beacon(self, client_height: int) -> dict:
        """Legacy envelope block retained for compatibility with older peers."""
        h = int(client_height)
        return {
            "type": "dingo_height_beacon",
            "enc": "plain",
            "data": {
                "ver": 2,
                "chain": "DINGO",
                "height": h,
                "client_height": h,
                "observed_ts": int(now_ts()),
                "source": "dingo-cli",
                "witness": self.node_id,
            },
        }

    def dingo_build_public_height_message(self, height: int, ttl: Optional[int] = None, hops: int = 0) -> dict:
        """Build the cleartext, hop-signed public Dingo height packet."""
        h = int(height)
        return {
            "type": "DINGO_HEIGHT",
            "ver": 3,
            "chain": "DINGO",
            "height": h,
            "client_height": h,
            "observed_ts": int(now_ts()),
            "source": "dingo-public",
            "witness": self.node_id,
            "ttl": max(1, int(ttl if ttl is not None else KDK_DINGO_PUBLIC_BEACON_TTL)),
            "hops": max(0, int(hops)),
        }

    def dingo_public_target(self, exclude_addr: Optional[Tuple[str, int]] = None):
        """Choose one random current verified peer for public-height diffusion."""
        candidates = []
        exclude = tuple(exclude_addr) if exclude_addr else None
        for nid, addr in list(getattr(self, "peer_addr_by_node_id", {}).items()):
            if not nid or nid == self.node_id or nid not in getattr(self, "pubkey_by_node_id", {}):
                continue
            try:
                peer = (str(addr[0]), int(addr[1]))
            except Exception:
                continue
            if peer[1] <= 0 or peer[1] > 65535:
                continue
            if exclude is not None and peer == exclude:
                continue
            candidates.append((str(nid), peer))
        if not candidates:
            return None
        return random.choice(candidates)

    def dingo_mesh_idle(self, now: float) -> bool:
        """Idle means no queued real work/repair and no recent PAYLOAD activity."""
        if self.outbound_queue or self._repair_pending_count() > 0:
            return False
        last = max(
            float(getattr(self, "metric_last_rx_ts", 0.0) or 0.0),
            float(getattr(self, "metric_last_tx_ts", 0.0) or 0.0),
        )
        quiet = max(0.5, float(globals().get("KDK_DINGO_IDLE_SEED_SECS", 5.0)))
        return last <= 0.0 or (float(now) - last) >= quiet

    def inject_public_dingo_beacon(self, dst_id: str, blocks: list) -> str:
        """Send a queued cleartext height packet on an ordinary earned turn."""
        addr = getattr(self, "peer_addr_by_node_id", {}).get(str(dst_id))
        if not isinstance(addr, tuple) or len(addr) != 2:
            raise RuntimeError(f"public Dingo beacon has no verified endpoint for {short8(dst_id)}")
        msg = blocks[0] if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) else {}
        if str(msg.get("type", "")) != "DINGO_HEIGHT":
            raise ValueError("bad public Dingo beacon queue item")
        h = int(msg.get("height", 0) or 0)
        self.send_message(dict(msg), (str(addr[0]), int(addr[1])))
        self.log_event(f"[DINGO_PUBLIC_TX] height={h} dst={short8(dst_id)} mode=earned-turn")
        return f"dingo-{h}"

    def _emit_or_queue_public_dingo_height(self, height: int, now: float,
                                           exclude_addr: Optional[Tuple[str, int]] = None,
                                           ttl: Optional[int] = None, hops: int = 0,
                                           reason: str = "local") -> bool:
        """Seed/relay one public beacon; idle is immediate, churn is earned-turn."""
        target = self.dingo_public_target(exclude_addr=exclude_addr)
        if target is None:
            return False
        dst_id, addr = target
        msg = self.dingo_build_public_height_message(height, ttl=ttl, hops=hops)

        if self.dingo_mesh_idle(now):
            self.send_message(dict(msg), addr)
            self.log_event(
                f"[DINGO_PUBLIC_TX] height={int(height)} dst={short8(dst_id)} "
                f"mode=idle-seed reason={reason} ttl={int(msg.get('ttl', 0))}"
            )
            return True

        # During churn the public height has no shortcut: it occupies an ordinary
        # collision-earned queue turn. Coalesce older unsent public heights first.
        try:
            self.outbound_queue = deque(
                item for item in self.outbound_queue
                if not (isinstance(item, tuple) and len(item) >= 3 and item[2] == "DINGO-BEACON-PUBLIC")
            )
        except Exception:
            pass
        self.outbound_queue.append((dst_id, [msg], "DINGO-BEACON-PUBLIC"))
        self.log_event(
            f"[DINGO_PUBLIC_QUEUE] height={int(height)} dst={short8(dst_id)} "
            f"reason={reason} ttl={int(msg.get('ttl', 0))} qlen={len(self.outbound_queue)}"
        )
        return True

    def dingo_remove_pending_beacons(self) -> int:
        """Compatibility helper: remove old encrypted and public pending beacons."""
        try:
            old_len = len(self.outbound_queue)
            self.outbound_queue = deque(
                item for item in self.outbound_queue
                if not (isinstance(item, tuple) and len(item) >= 3
                        and item[2] in ("DINGO-BEACON", "DINGO-BEACON-PUBLIC"))
            )
            return max(0, old_len - len(self.outbound_queue))
        except Exception:
            return 0

    def _height_paced_label(self, label: str) -> bool:
        """Return True for substantive traffic governed by the Dingo metronome."""
        u = str(label or "").upper()
        # Lightweight convergence/control traffic remains immediate.
        immediate = ("ACK", "RECEIPT", "WANT", "HELLO", "HEARTBEAT", "DISCOVER",
                     "DINGO-BEACON", "RPC-REPLY", "RATE", "REPAIR", "KDK-UPDATE")
        if any(x in u for x in immediate):
            return False
        return any(x in u for x in ("MESSAGE", "KDK-CHUNK", "KDK-MANIFEST",
                                    "UPDATE", "PATCH", "CUCKOO"))

    def timelock_live_collision_rate(self, now: float = None) -> float:
        """Return the local rolling collision rate used by the live HUD.

        This is an observer-local mesh activity rate, not a hardware hashrate
        and not an estimate of a global network total.
        """
        try:
            t = float(now_ts() if now is None else now)
            window = max(
                5.0,
                float(getattr(self, "timelock_live_collision_window_secs", 30.0) or 30.0),
            )
            q = getattr(self, "timelock_live_collision_times", None)
            if q is None:
                self.timelock_live_collision_times = deque()
                q = self.timelock_live_collision_times
            cutoff = t - window
            while q and float(q[0]) < cutoff:
                q.popleft()
            return float(len(q)) / window
        except Exception:
            return 0.0

    def _timelock_metrics_active_peer_count(self, now: float) -> int:
        """Return recently active verified peers, excluding this node."""
        try:
            return sum(
                1 for nid, ts in self.active_nodes.items()
                if nid != self.node_id and now - float(ts) < ACTIVE_TIMEOUT
            )
        except Exception:
            return 0

    def maybe_log_timelock_metrics(self, height: int, now: float, source: str = "", witness: str = "") -> None:
        """Write one compact research sample per configured Dingo-height interval.

        This deliberately samples only accepted real Dingo heights. It never
        substitutes the local fallback epoch, because the purpose of the log is
        to compare local mesh activity against an external temporal yardstick.
        Counts are this node's observations during the interval, not estimates
        of global mesh totals.

        elapsed_secs is wall-clock elapsed time. active_secs excludes detected
        suspend/resume gaps. collisions_per_sec therefore represents active
        churn time. continuous=0 marks a suspend/resume gap or an unusually
        large height jump; such rows remain useful diagnostically but should be
        excluded from clean collision-rate statistics.
        """
        try:
            h = int(height)
            if h <= 0:
                return

            interval = max(1, int(getattr(self, "timelock_metrics_interval_blocks", 10) or 10))
            base_h = int(getattr(self, "timelock_metrics_base_height", 0) or 0)
            base_ts = float(getattr(self, "timelock_metrics_base_ts", 0.0) or 0.0)

            if base_h <= 0 or base_ts <= 0.0 or h < base_h:
                self.timelock_metrics_base_height = h
                self.timelock_metrics_base_ts = float(now)
                self.timelock_metrics_collisions = 0
                self.timelock_metrics_quorums = 0
                self.timelock_metrics_inactive_secs = 0.0
                self.timelock_metrics_continuous = True
                return

            delta_h = h - base_h
            if delta_h < interval:
                return

            elapsed = max(0.0, float(now) - base_ts)
            inactive = max(
                0.0,
                min(elapsed, float(getattr(self, "timelock_metrics_inactive_secs", 0.0) or 0.0)),
            )
            active_secs = max(0.0, elapsed - inactive)
            collisions = int(getattr(self, "timelock_metrics_collisions", 0) or 0)
            collision_rate = (float(collisions) / active_secs) if active_secs > 0.0 else 0.0
            quorums = int(getattr(self, "timelock_metrics_quorums", 0) or 0)
            active_peers = self._timelock_metrics_active_peer_count(float(now))
            n_value = int(getattr(self, "token_trigger", COLLISION_TRIGGER_N) or COLLISION_TRIGGER_N)
            pow_bits = int(getattr(self, "pow_bits_required", 0) or 0)
            witness_short = short8(str(witness or "")) if witness else ""

            process_continuous = bool(getattr(self, "timelock_metrics_continuous", True))
            height_continuous = delta_h <= (interval * 2)
            continuous = 1 if (process_continuous and height_continuous) else 0

            ensure_dir("logs")
            path = str(getattr(self, "timelock_metrics_path", os.path.join("logs", f"timelock_metrics_{self.port}.csv")))
            metrics_header = [
                "timestamp_utc", "node", "node_id", "height", "delta_blocks",
                "elapsed_secs", "active_secs", "collisions", "collisions_per_sec",
                "continuous", "quorums", "active_peers", "n", "pow_bits",
                "height_source", "height_witness"
            ]

            # 10.20.95 extends the CSV schema. Preserve any earlier metrics file
            # rather than mixing new-width rows under the old header.
            needs_header = (not os.path.exists(path)) or os.path.getsize(path) == 0
            if not needs_header:
                try:
                    with open(path, "r", encoding="utf-8", newline="") as rf:
                        existing_header = next(csv.reader(rf), [])
                    if existing_header != metrics_header:
                        archive = path + ".pre-10.20.95"
                        if os.path.exists(archive):
                            archive = path + "." + time.strftime("%Y%m%d-%H%M%S") + ".pre-10.20.95"
                        os.replace(path, archive)
                        needs_header = True
                        self.log_event(f"[TIMELOCK_METRICS] archived previous CSV schema to {archive}")
                except Exception:
                    # If header inspection fails, leave the existing file alone;
                    # the outer instrumentation guard will protect the mesh.
                    raise

            with open(path, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                if needs_header:
                    writer.writerow(metrics_header)
                writer.writerow([
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(now))),
                    str(getattr(self, "name", "")),
                    short8(str(getattr(self, "node_id", ""))),
                    h, delta_h, round(elapsed, 3), round(active_secs, 3), collisions,
                    round(collision_rate, 3), continuous, quorums, active_peers,
                    n_value, pow_bits, str(source or ""), witness_short
                ])

            self.log_event(
                f"[TIMELOCK_METRICS] height={h} delta={delta_h} elapsed={elapsed:.1f}s "
                f"active={active_secs:.1f}s collisions={collisions} coll/s={collision_rate:.2f} "
                f"continuous={continuous} quorums={quorums} peers={active_peers} "
                f"N={n_value} pow_bits={pow_bits} source={source or 'unknown'}"
            )

            self.timelock_metrics_base_height = h
            self.timelock_metrics_base_ts = float(now)
            self.timelock_metrics_collisions = 0
            self.timelock_metrics_quorums = 0
            self.timelock_metrics_inactive_secs = 0.0
            self.timelock_metrics_continuous = True
        except Exception as exc:
            try:
                self.log_event(f"[TIMELOCK_METRICS] write failed err={type(exc).__name__}: {exc}")
            except Exception:
                pass

    def maybe_refresh_dingo_scheduler_height(self, now: float):
        """Refresh the scheduler from one canonical Dingo-height view.

        Prefer a locally verified dingocoin-cli height. Nodes without a local
        client consume the freshest accepted signed network beacon instead.
        Only when neither source is fresh does _height_window_key() fall back
        to the local coarse clock.
        """
        if not bool(globals().get("KDK_HEIGHT_PACING_ENABLED", True)):
            return
        interval = max(0.5, float(globals().get("KDK_HEIGHT_POLL_SECS", 2.0)))
        if now - float(getattr(self, "dingo_scheduler_last_poll_ts", 0.0) or 0.0) < interval:
            return
        self.dingo_scheduler_last_poll_ts = now

        h = 0
        source = ""
        source_ts = 0.0
        witness = ""

        # A local full node is the strongest source and may refresh the same
        # height while waiting for the next block.
        try:
            h = int(self.get_dingo_height_cli())
            if h > 0:
                source = "dingo-local"
                source_ts = now
                witness = self.node_id
                old_network = int(getattr(self, "dingo_network_height", 0) or 0)
                if h >= old_network:
                    self.dingo_network_height = h
                    self.dingo_network_height_ts = now
                    self.dingo_network_height_witness = self.node_id
        except Exception:
            h = 0

        # No local client: use the canonical network observation, but never
        # refresh its age merely because the scheduler polled it again.
        if h <= 0:
            network_h = self.get_dingo_network_height()
            network_ts = float(getattr(self, "dingo_network_height_ts", 0.0) or 0.0)
            stale = float(globals().get("KDK_HEIGHT_STALE_SECS", 180.0))
            if network_h > 0 and network_ts > 0 and now - network_ts <= stale:
                h = int(network_h)
                source = "dingo-witness"
                source_ts = network_ts
                witness = str(getattr(self, "dingo_network_height_witness", "") or "")

        if h <= 0:
            return

        old = int(getattr(self, "dingo_scheduler_height", 0) or 0)
        old_source = str(getattr(self, "dingo_scheduler_source", "") or "")
        if h > old or (h == old and source != old_source):
            self.dingo_scheduler_height = h
            self.dingo_scheduler_height_ts = source_ts
            self.dingo_scheduler_source = source
            self.dingo_scheduler_witness = witness
            self.dingo_scheduler_sent_at_height = 0
            detail = f" witness={short8(witness)}" if source == "dingo-witness" and witness else ""
            self.log_event(f"[HEIGHT] source={source} height={h}{detail}; substantive traffic eligible")
            self.activity_system(f"Dingo height {h}: transmission window open")
            self.maybe_log_timelock_metrics(h, now, source=source, witness=witness)
        elif h == old:
            self.dingo_scheduler_height_ts = source_ts
            self.dingo_scheduler_source = source
            self.dingo_scheduler_witness = witness

    def _height_window_key(self, now: float) -> tuple:
        """Return (source, epoch). Fall back locally only when Dingo is stale."""
        h = int(getattr(self, "dingo_scheduler_height", 0) or 0)
        hts = float(getattr(self, "dingo_scheduler_height_ts", 0.0) or 0.0)
        source = str(getattr(self, "dingo_scheduler_source", "dingo") or "dingo")
        stale = float(globals().get("KDK_HEIGHT_STALE_SECS", 180.0))
        if h > 0 and hts > 0 and now - hts <= stale:
            return (source, h)
        secs = max(10.0, float(globals().get("KDK_HEIGHT_FALLBACK_SECS", 60.0)))
        return ("fallback", int(now // secs))

    def _height_send_allowed(self, label: str, now: Optional[float] = None) -> bool:
        if not bool(globals().get("KDK_HEIGHT_PACING_ENABLED", True)) or not self._height_paced_label(label):
            return True
        now = now_ts() if now is None else float(now)
        source, epoch = self._height_window_key(now)
        key = (source, int(epoch))
        if getattr(self, "_dingo_scheduler_window_key", None) != key:
            self._dingo_scheduler_window_key = key
            self.dingo_scheduler_sent_at_height = 0
        limit = max(1, int(globals().get("KDK_HEIGHT_PACED_PER_HEIGHT", 1)))
        return int(getattr(self, "dingo_scheduler_sent_at_height", 0) or 0) < limit

    def _height_note_sent(self, label: str, now: Optional[float] = None):
        if not self._height_paced_label(label):
            return
        now = now_ts() if now is None else float(now)
        source, epoch = self._height_window_key(now)
        key = (source, int(epoch))
        if getattr(self, "_dingo_scheduler_window_key", None) != key:
            self._dingo_scheduler_window_key = key
            self.dingo_scheduler_sent_at_height = 0
        self.dingo_scheduler_sent_at_height = int(getattr(self, "dingo_scheduler_sent_at_height", 0) or 0) + 1
        self.log_event(f"[HEIGHT_TX] source={source} epoch={epoch} label={label} used={self.dingo_scheduler_sent_at_height}")

    def maybe_send_dingo_height_beacon(self, now: float):
        """Publish a new locally validated height with one stochastic clear packet.

        The outer UDP packet remains Ed25519 signed by the transmitting hop, but
        the public Dingo height is not wrapped in a KD envelope and is not
        encrypted. Idle nodes seed one random verified peer immediately. During
        churn the packet waits in the ordinary collision-earned queue.
        """
        if not bool(getattr(self, "dingo_height_beacon_enabled", True)):
            return
        try:
            interval = max(0.5, float(getattr(
                self, "dingo_height_beacon_interval_secs", DINGO_HEIGHT_BEACON_INTERVAL_SECS
            )))
        except Exception:
            interval = float(DINGO_HEIGHT_BEACON_INTERVAL_SECS)
        if now - float(getattr(self, "dingo_last_beacon_check_ts", 0.0) or 0.0) < interval:
            return
        self.dingo_last_beacon_check_ts = now

        try:
            h = int(self.get_dingo_height_cli())
        except Exception:
            return

        last = int(getattr(self, "dingo_last_beacon_height", 0) or 0)
        if h <= last:
            return

        # A mesh copy and a later local observation share one per-height state.
        already_public = int(h) in getattr(self, "dingo_public_seen_heights", {})

        # The local validating node learns the height even if there is nobody
        # available to receive the public seed yet.
        legacy = self.dingo_build_height_beacon(h)
        self.dingo_accept_height_beacon(self.node_id, dict(legacy.get("data", {})), local=True)
        self.dingo_last_beacon_height = h
        self.dingo_pending_beacon_height = h
        self.dingo_pending_beacon_updated_ts = now
        self.dingo_public_seen_heights[int(h)] = now
        if len(self.dingo_public_seen_heights) > 256:
            for old_h in sorted(self.dingo_public_seen_heights)[:-128]:
                self.dingo_public_seen_heights.pop(old_h, None)

        if already_public:
            self.log_event(f"[DINGO_PUBLIC_LOCAL_SUPPRESS] height={h} reason=already-seen")
            return

        sent = self._emit_or_queue_public_dingo_height(h, now, reason="local")
        if sent:
            mode = "idle seed" if self.dingo_mesh_idle(now) else "earned-turn queue"
            self.activity_system(f"Dingo height {h}: public beacon {mode}")
        else:
            self.log_event(f"[DINGO_PUBLIC] height={h} no verified relay target")

    def handle_public_dingo_height(self, msg: dict, addr: Tuple[str, int], sender_node_id: str):
        """Accept and stochastically relay one cleartext hop-signed height."""
        try:
            h = int(msg.get("height", 0) or 0)
            ttl = int(msg.get("ttl", KDK_DINGO_PUBLIC_BEACON_TTL) or KDK_DINGO_PUBLIC_BEACON_TTL)
            hops = int(msg.get("hops", 0) or 0)
        except Exception:
            return
        if h <= 0 or ttl <= 0:
            return

        now = now_ts()
        data = {
            "ver": int(msg.get("ver", 3) or 3),
            "chain": str(msg.get("chain", "DINGO") or "DINGO"),
            "height": h,
            "client_height": int(msg.get("client_height", h) or h),
            "observed_ts": int(msg.get("observed_ts", int(now)) or int(now)),
            "source": "dingo-public",
            # Each hop is independently signed, so that hop is the witness used
            # by the existing monotonic height acceptance policy.
            "witness": sender_node_id,
        }

        already = int(h) in getattr(self, "dingo_public_seen_heights", {})
        self.dingo_accept_height_beacon(sender_node_id, data, local=False)
        self.dingo_public_seen_heights[int(h)] = now
        if len(self.dingo_public_seen_heights) > 256:
            for old_h in sorted(self.dingo_public_seen_heights)[:-128]:
                self.dingo_public_seen_heights.pop(old_h, None)

        # One relay per node per height. Duplicates terminate naturally.
        if already or ttl <= 1:
            self.log_event(
                f"[DINGO_PUBLIC_RX] height={h} from={short8(sender_node_id)} "
                f"duplicate={already} ttl={ttl} relay=0"
            )
            return

        relayed = self._emit_or_queue_public_dingo_height(
            h, now, exclude_addr=addr, ttl=ttl - 1, hops=hops + 1, reason="relay"
        )
        self.log_event(
            f"[DINGO_PUBLIC_RX] height={h} from={short8(sender_node_id)} "
            f"duplicate=0 ttl={ttl} relay={1 if relayed else 0}"
        )

    def dingo_accept_height_beacon(self, src_id: str, data: dict, local: bool = False):
        """Validate and cache a Dingo height beacon carried inside a KDK envelope."""
        if not isinstance(data, dict):
            return
        chain = str(data.get("chain", "") or "").upper()
        if chain != "DINGO":
            return
        try:
            h = int(data.get("height", 0) or 0)
        except Exception:
            return
        if h <= 0:
            return
        witness = str(data.get("witness", "") or src_id or "")
        if not witness:
            return
        if witness != src_id and not local:
            self.log_event(f"[DINGO_BEACON] witness/src mismatch witness={short8(witness)} src={short8(src_id)}")
            return
        try:
            obs_ts = int(data.get("observed_ts", 0) or 0)
        except Exception:
            obs_ts = 0
        now = now_ts()
        if obs_ts and now - float(obs_ts) > float(DINGO_HEIGHT_BEACON_STALE_SECS):
            self.log_event(f"[DINGO_BEACON] stale height={h} witness={short8(witness)}")
            return

        prev_rec = self.dingo_height_by_witness.get(witness, {}) if isinstance(getattr(self, "dingo_height_by_witness", {}), dict) else {}
        try:
            prev_h = int(prev_rec.get("height", 0) or 0)
        except Exception:
            prev_h = 0
        if h < prev_h:
            self.log_event(f"[DINGO_BEACON] ignored decreasing height witness={short8(witness)} {h}<{prev_h}")
            return

        # Monotonicity is node-wide, not merely per witness. The
        # floor is persisted so a restart cannot make an old lower beacon look
        # acceptable just because dingo_height_by_witness was empty again.
        floor_h = int(getattr(self, "dingo_height_floor", 0) or 0)
        network_h = int(getattr(self, "dingo_network_height", 0) or 0)
        monotonic_floor = max(floor_h, network_h)
        if h < monotonic_floor:
            self.log_event(
                f"[DINGO_BEACON] ignored below monotonic floor witness={short8(witness)} "
                f"height={h} floor={monotonic_floor}"
            )
            return

        rec = dict(data)
        rec["height"] = h
        rec["recv_ts"] = int(now)
        rec["src"] = src_id
        self.dingo_height_by_witness[witness] = rec

        old_network = int(getattr(self, "dingo_network_height", 0) or 0)
        if h > old_network:
            self.dingo_network_height = h
            self.dingo_network_height_ts = now
            self.dingo_network_height_witness = witness
            self.dingo_height_floor = max(int(getattr(self, "dingo_height_floor", 0) or 0), h)
            # Beacon cadence is sparse, so persisting the new floor here is cheap
            # and prevents restart-time regression of the logical chain clock.
            try:
                self.airgap_save_state()
            except Exception:
                pass
            if local:
                self.log_event(f"[DINGO_BEACON] local height={h}")
            else:
                self.log_event(f"[DINGO_BEACON] accepted height={h} witness={short8(witness)} src={short8(src_id)}")
                self.activity_system(f"Dingo height beacon from {self.activity_peer_name(src_id)}: {h}")

    def get_airgap_height(self, args):
        source = getattr(args, "airgap_height_source", "test")

        if source == "test":
            return self.airgap_test_height()

        if source == "dingo-cli":
            return self.get_dingo_height_cli(getattr(args, "dingo_cli", "dingocoin-cli"), getattr(args, "dingo_cli_arg", []) or [])

        if source == "dingo-auto":
            try:
                return self.get_dingo_height_cli(getattr(args, "dingo_cli", "dingocoin-cli"), getattr(args, "dingo_cli_arg", []) or [])
            except Exception as cli_err:
                network_h = self.get_dingo_network_height()
                network_ts = float(getattr(self, "dingo_network_height_ts", 0.0) or 0.0)
                if network_h > 0 and network_ts > 0 and now_ts() - network_ts <= float(KDK_HEIGHT_STALE_SECS):
                    return int(network_h)
                raise RuntimeError(f"dingo-auto failed local={cli_err}; no fresh mesh witness")

        raise RuntimeError(f"unknown height source: {source}")

    def airgap_current_height(self) -> int:
        """Return the active airgap timelock height.

        source="test"  -> original local simulated block clock.
        source="dingo" -> local Dingocoin chain height via dingocoin-cli.
        """
        source = str(getattr(self, "airgap_height_source", "test") or "test").lower()
        try:
            if source == "test":
                self.airgap_last_height_source = "test"
                self.airgap_last_height_error = ""
                return self.airgap_test_height()

            if source in ("dingo", "dingocoin", "dingo-cli"):
                h = self.get_dingo_height_cli()
                self.airgap_last_height_source = "dingo-cli"
                self.airgap_last_height_error = ""
                return h

            if source == "dingo-auto":
                try:
                    h = self.get_dingo_height_cli()
                    self.airgap_last_height_source = "dingo-cli"
                    self.airgap_last_height_error = ""
                    return h
                except Exception as cli_err:
                    network_h = self.get_dingo_network_height()
                    network_ts = float(getattr(self, "dingo_network_height_ts", 0.0) or 0.0)
                    if network_h > 0 and network_ts > 0 and now_ts() - network_ts <= float(KDK_HEIGHT_STALE_SECS):
                        witness = str(getattr(self, "dingo_network_height_witness", "") or "")
                        self.airgap_last_height_source = f"dingo-witness:{short8(witness)}"
                        self.airgap_last_height_error = f"local unavailable: {cli_err}"
                        return int(network_h)
                    raise RuntimeError(f"local Dingo unavailable and no fresh mesh witness: {cli_err}")

            raise RuntimeError(f"unknown height source: {source}")

        except Exception as e:
            self.airgap_last_height_source = f"{source}-error"
            self.airgap_last_height_error = str(e)
            if bool(getattr(self, "airgap_dingo_allow_fallback", False)):
                self.log_event(f"[AIRGAP] dingo height unavailable; falling back to test height err={e}")
                self.airgap_last_height_source = "test-fallback"
                return self.airgap_test_height()
            raise

    def _airgap_pack_header(self, header: dict) -> bytes:
        hb = msgpack.packb(header, use_bin_type=True)
        if len(hb) > AIRGAP_HEADER_SIZE - 10:
            raise ValueError("airgap header too large")
        return AIRGAP_MAGIC + len(hb).to_bytes(2, "big") + hb + os.urandom(AIRGAP_HEADER_SIZE - 10 - len(hb))

    def _airgap_parse_header(self, blob: bytes) -> dict:
        """Parse and validate the fixed AIRGAP_1440 header.

        Keep this isolated so create/import/unlock all use the same local
        variable path.  The caller receives an airgap_header dict; no ambient
        or UI header variable is relied on.
        """
        if len(blob) != AIRGAP_SIZE:
            raise ValueError(f"bad airgap size {len(blob)} != {AIRGAP_SIZE}")
        if blob[:8] != AIRGAP_MAGIC:
            raise ValueError("bad airgap magic")
        hlen = int.from_bytes(blob[8:10], "big")
        if hlen <= 0 or hlen > AIRGAP_HEADER_SIZE - 10:
            raise ValueError("bad airgap header length")
        airgap_header = msgpack.unpackb(blob[10:10 + hlen], raw=False)
        if not isinstance(airgap_header, dict):
            raise ValueError("bad airgap header")
        if airgap_header.get("class") != "AIRGAP_1440":
            raise ValueError("bad airgap class")
        if int(airgap_header.get("size", 0)) != AIRGAP_SIZE:
            raise ValueError("bad declared airgap size")
        enc_len = int(airgap_header.get("enc_len", 0))
        if enc_len <= 0 or AIRGAP_HEADER_SIZE + enc_len > AIRGAP_SIZE:
            raise ValueError("bad encrypted payload length")
        orig_len = int(airgap_header.get("orig_len", 0))
        if orig_len < 0 or orig_len > AIRGAP_MAX_PLAINTEXT:
            raise ValueError("bad original length")
        return airgap_header

    def build_airgap_blob(self, plaintext: bytes, filename_hint: str = "") -> Tuple[bytes, bytes, dict]:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise ValueError("plaintext must be bytes")
        plaintext = bytes(plaintext)
        if len(plaintext) > AIRGAP_MAX_PLAINTEXT:
            raise ValueError(f"file too large for AIRGAP_1440 test container ({len(plaintext)} > {AIRGAP_MAX_PLAINTEXT})")

        file_key = os.urandom(SecretBox.KEY_SIZE)
        box = SecretBox(file_key)
        enc = box.encrypt(plaintext)  # nonce + ciphertext + tag
        airgap_header = {
            "class": "AIRGAP_1440",
            "ver": 1,
            "size": AIRGAP_SIZE,
            "orig_len": len(plaintext),
            "enc_len": len(enc),
            # Deterministic across seeders: identical script bytes must produce
            # identical update bundle bytes/chunks on every recipient.
            "created_ts": 0,
            "filename_hint": os.path.basename(filename_hint or "payload.bin")[:80],
            "cipher": "XSalsa20-Poly1305",
        }
        head = self._airgap_pack_header(airgap_header)
        if len(head) + len(enc) > AIRGAP_SIZE:
            raise ValueError("encrypted payload exceeds AIRGAP_1440 capacity")
        blob = head + enc + os.urandom(AIRGAP_SIZE - len(head) - len(enc))
        return blob, file_key, airgap_header

    def build_airgap_ticket_object_bytes(self, ticket_block: dict) -> bytes:
        """Serialize an AIRGAP ticket block as a chunked object payload.

        The ticket itself is too large for a single directed frame once the
        key/material/metadata are packed. So it rides as a normal KDK object.
        """
        return msgpack.packb({
            "kind": "KDK_AIRGAP_TICKET_OBJECT",
            "ver": 1,
            "block": ticket_block,
        }, use_bin_type=True)

    def maybe_handle_airgap_ticket_object(self, blob: bytes, object_id: str, src_id: str) -> bool:
        """Recognise and process a chunked AIRGAP ticket object."""
        try:
            obj = msgpack.unpackb(bytes(blob), raw=False)
            if not isinstance(obj, dict) or obj.get("kind") != "KDK_AIRGAP_TICKET_OBJECT":
                return False
            block = obj.get("block")
            if not isinstance(block, dict):
                raise ValueError("missing ticket block")
            if block.get("type") != "airgap_ticket":
                raise ValueError("not an airgap ticket block")
            data = block.get("data", {})
            if not isinstance(data, dict):
                raise ValueError("bad ticket data")
            self.airgap_handle_ticket(src_id, data)
            ph = str(data.get("payload_hash", ""))
            self.activity_system(f"Airgap ticket received from {self.activity_peer_name(src_id)} ({ph[:12]})")
            self.log_event(f"[AIRGAP_TICKET_OBJECT] received object={object_id[:8]} from={short8(src_id)} hash={ph[:12]}")
            return True
        except Exception as e:
            self.log_event(f"[AIRGAP_TICKET_OBJECT] rejected object={object_id[:8]} from={short8(src_id)} err={e}")
            return False


    # ------------------------- Cuckoo Clock v1 ------------------------------

    def cuckoo_chunk_count_for_delay(self, delay_blocks: int, requested: int = 0) -> int:
        """Return the staged key-chunk count for a lock.

        Cuckoo v1 deliberately caps this at 12.  These are not data-size
        chunks; they are scheduled releases of the tiny encrypted Airgap file
        key object.  WANT/repair still handles any missing pieces.
        """
        try:
            n = int(requested or 0)
        except Exception:
            n = 0
        if n <= 0:
            n = int(getattr(self, "cuckoo_default_chunks", CUCKOO_DEFAULT_CHUNKS))
        n = max(int(getattr(self, "cuckoo_min_chunks", CUCKOO_MIN_CHUNKS)), n)
        n = min(int(getattr(self, "cuckoo_max_chunks", CUCKOO_MAX_CHUNKS)), n)
        try:
            n = min(n, max(int(getattr(self, "cuckoo_min_chunks", CUCKOO_MIN_CHUNKS)), int(delay_blocks)))
        except Exception:
            pass
        return max(1, int(n))

    def cuckoo_min_delay_blocks(self) -> int:
        bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))
        secs = max(0, int(getattr(self, "cuckoo_min_delay_secs", CUCKOO_MIN_DELAY_SECS_TEST) or 0))
        return max(1, int(math.ceil(float(secs) / bs)))

    def cuckoo_release_schedule(self, current_height: int, delay_blocks: int, chunk_count: int) -> list:
        """Evenly distribute chunk releases from now to target height."""
        cur = int(current_height)
        delay = max(int(delay_blocks), int(chunk_count), 1)
        n = max(1, int(chunk_count))
        last = cur
        heights = []
        for i in range(n):
            h = cur + int(math.ceil(((i + 1) * delay) / float(n)))
            h = max(h, last + 1)
            heights.append(h)
            last = h
        return heights

    def cuckoo_consensus_height(self) -> int:
        """Return a conservative height usable by the Cuckoo release gate.

        For test height we use the local simulated clock.  For Dingo sources we
        use signed/verified local+mesh witness beacons and require at least
        cuckoo_min_witnesses recent observations before claiming consensus.
        """
        source = str(getattr(self, "airgap_height_source", "test") or "test").lower()
        if source == "test":
            return int(self.airgap_current_height())

        now = now_ts()
        heights = []
        try:
            local_h = int(self.airgap_current_height())
            heights.append(local_h)
        except Exception:
            pass

        try:
            for _w, rec in (getattr(self, "dingo_height_by_witness", {}) or {}).items():
                try:
                    ts = float(rec.get("recv_ts", rec.get("observed_ts", 0.0)) or 0.0)
                    if ts <= 0 or now - ts > float(DINGO_HEIGHT_BEACON_STALE_SECS):
                        continue
                    heights.append(int(rec.get("height", 0) or 0))
                except Exception:
                    continue
        except Exception:
            pass

        if not heights:
            return 0
        need = max(1, int(getattr(self, "cuckoo_min_witnesses", CUCKOO_DEFAULT_MIN_WITNESSES) or 1))
        heights = sorted([h for h in heights if h > 0], reverse=True)
        if len(heights) < need:
            return 0
        # Height that at least `need` witnesses have reached.
        return int(heights[need - 1])

    def cuckoo_build_key_object_blocks(self, payload_hash: str, payload_id: str, file_key: bytes,
                                       target_height: int, release_heights: list,
                                       filename_hint: str = "") -> list:
        """Build a tiny KDK object containing the Airgap file key.

        It uses normal KDK chunk manifests/data blocks, but with deliberately
        small chunks so the key object can be released progressively.
        """
        if len(file_key) != SecretBox.KEY_SIZE:
            raise ValueError("bad cuckoo file key")
        key_obj = {
            "kind": "KDK_AIRGAP_CUCKOO_KEY_OBJECT",
            "ver": 1,
            "payload_hash": str(payload_hash),
            "payload_id": str(payload_id),
            "file_key": bytes(file_key),
            "target_height": int(target_height),
            "release_heights": [int(x) for x in release_heights],
            "filename_hint": os.path.basename(filename_hint or "payload.bin")[:80],
        }
        plaintext = msgpack.packb(key_obj, use_bin_type=True)
        n = max(1, len(release_heights))
        chunk_size = max(1, int(math.ceil(len(plaintext) / float(n))))
        if chunk_size > KDK_WIRE_CHUNK_SIZE:
            # Should not happen for this tiny object, but fall back safely.
            chunk_size = KDK_WIRE_CHUNK_SIZE
            n = int(math.ceil(len(plaintext) / float(chunk_size)))
        chunks = [plaintext[i:i + chunk_size] for i in range(0, len(plaintext), chunk_size)]
        # If the object was smaller than expected, pad with empty chunks so the
        # schedule still has the requested number of ticks.
        while len(chunks) < len(release_heights):
            chunks.append(b"")
        object_hash = sha256(plaintext)
        object_id = sha256(b"KDKCUCKOO1" + str(payload_hash).encode() + plaintext)[:32]
        manifest = {
            "type": "kdk_chunk_manifest",
            "enc": "plain",
            "data": {
                "kind": "KDK_CHUNK_MANIFEST",
                "ver": 3,
                "object_id": object_id,
                "object_hash": object_hash,
                "total_size": len(plaintext),
                "wire_chunk_size": chunk_size,
                "chunk_count": len(chunks),
                "filename_hint": f"cuckoo_key_{str(payload_hash)[:12]}.kdkkey",
                "cuckoo": True,
                "release_heights": [int(x) for x in release_heights[:len(chunks)]],
            },
        }
        blocks = [manifest]
        for i, ch in enumerate(chunks):
            blocks.append({
                "type": "kdk_chunk_data",
                "enc": "plain",
                "data": {
                    "kind": "KDK_CHUNK_DATA",
                    "ver": 4,
                    "object_id": object_id,
                    # Cuckoo chunks are self-describing so loss of the separate
                    # manifest cannot strand a complete 3/3 key object. This
                    # mirrors ordinary KDK chunk bootstrap metadata while also
                    # preserving the time-gate information required by WANT.
                    "object_hash": object_hash,
                    "total_size": len(plaintext),
                    "wire_chunk_size": chunk_size,
                    "filename_hint": f"cuckoo_key_{str(payload_hash)[:12]}.kdkkey",
                    "cuckoo": True,
                    "release_heights": [int(x) for x in release_heights[:len(chunks)]],
                    "index": i,
                    "chunk_count": len(chunks),
                    "data": ch,
                },
            })
        return blocks

    def queue_cuckoo_key_blocks(self, dst_id: str, blocks: list, release_heights: list,
                                payload_hash: str = ""):
        """Queue the Cuckoo manifest now; hold data chunks until due."""
        if not blocks:
            return
        manifest = blocks[0]
        chunk_blocks = list(blocks[1:])
        mdata = manifest.get("data", {}) if isinstance(manifest, dict) else {}
        oid = str(mdata.get("object_id", ""))
        by_idx = {}
        rel_by_idx = {}
        for i, cb in enumerate(chunk_blocks):
            try:
                idx = int((cb.get("data", {}) or {}).get("index", i))
            except Exception:
                idx = i
            by_idx[idx] = cb
            try:
                rel_by_idx[idx] = int(release_heights[idx])
            except Exception:
                rel_by_idx[idx] = int(release_heights[-1]) if release_heights else 0
        if oid:
            self.chunk_tx_store[oid] = {
                "dst": dst_id,
                "manifest": manifest,
                "chunks": by_idx,
                "created_ts": now_ts(),
                "filename_hint": str(mdata.get("filename_hint", "")),
                "cuckoo": True,
                "release_heights": rel_by_idx,
            }
        # The receiver needs the manifest before WANT can help.  Send a few
        # manifest copies immediately, but hold the data chunks until their
        # Dingo/test release heights are witnessed.
        for _ in range(max(1, int(KDK_MANIFEST_REPEAT_COUNT))):
            self.outbound_queue.append((dst_id, [manifest], "KDK-CUCKOO-MANIFEST"))
        pending = getattr(self, "cuckoo_pending", None)
        if pending is None:
            self.cuckoo_pending = []
            pending = self.cuckoo_pending
        for idx, cb in sorted(by_idx.items()):
            token = f"{oid}:{idx}"
            if token in getattr(self, "cuckoo_released", set()):
                continue
            pending.append({
                "dst": dst_id,
                "object_id": oid,
                "index": int(idx),
                "release_height": int(rel_by_idx.get(idx, 0)),
                "block": cb,
                "payload_hash": str(payload_hash or ""),
                "queued_ts": now_ts(),
            })
        self.log_event(
            f"[CUCKOO] scheduled key object={oid[:8]} payload={str(payload_hash)[:12]} "
            f"chunks={len(by_idx)} releases={','.join(str(x) for x in release_heights)}"
        )
        self.airgap_save_state()

    def maybe_release_cuckoo_chunks(self):
        pending = list(getattr(self, "cuckoo_pending", []) or [])
        if not pending:
            return
        h = 0
        try:
            h = int(self.cuckoo_consensus_height())
        except Exception as e:
            self._log_event_dedup("cuckoo-height", f"[CUCKOO] height unavailable; release paused err={e}")
            return
        kept = []
        released = 0
        relset = getattr(self, "cuckoo_released", None)
        if relset is None:
            self.cuckoo_released = set()
            relset = self.cuckoo_released
        for rec in pending:
            try:
                oid = str(rec.get("object_id", ""))
                idx = int(rec.get("index", -1))
                rh = int(rec.get("release_height", 0))
                token = f"{oid}:{idx}"
                if token in relset:
                    continue
                if h >= rh > 0:
                    dst = str(rec.get("dst", ""))
                    block = rec.get("block")
                    if dst and isinstance(block, dict):
                        # Queue the released key chunk as ordinary chunk-data.
                        # Send a small number of copies because receivers may
                        # have exhausted their WANT rounds before the height
                        # gate opened; WANT/repair still handles residues.
                        repeats = max(1, int(globals().get("KDK_CUCKOO_KEY_RELEASE_REPEATS", 3)))
                        for rno in range(repeats):
                            label = "KDK-CUCKOO-KEY-PRIME" if rno == 0 else "KDK-CUCKOO-KEY"
                            self.outbound_queue.append((dst, [block], label))
                        # Make a due Cuckoo key chunk eligible for the next
                        # normal TURN emission immediately. It still rides q;
                        # we simply avoid leaving a released key chunk parked
                        # behind an old queue-wait counter.
                        try:
                            self.queue_emit_turns_wait = 0
                        except Exception:
                            pass
                        relset.add(token)
                        released += 1
                        self.log_event(
                            f"[CUCKOO] release object={oid[:8]} idx={idx+1} height={h} due={rh} "
                            f"dst={short8(dst)} repeats={repeats} qlen={len(self.outbound_queue)}"
                        )
                        try:
                            self.activity_system(f"[CUCKOO] key chunk {idx+1} released ({oid[:8]})")
                        except Exception:
                            pass
                    else:
                        kept.append(rec)
                else:
                    kept.append(rec)
            except Exception:
                kept.append(rec)
        if released:
            self.cuckoo_pending = kept
            self.airgap_save_state()

    def maybe_handle_airgap_key_object(self, blob: bytes, object_id: str, src_id: str) -> bool:
        """Recognise a completed Cuckoo key object and install its file key."""
        try:
            obj = msgpack.unpackb(bytes(blob), raw=False)
            if not isinstance(obj, dict) or obj.get("kind") != "KDK_AIRGAP_CUCKOO_KEY_OBJECT":
                return False
            ph = str(obj.get("payload_hash", ""))
            fk = obj.get("file_key")
            if len(ph) != 64 or not isinstance(fk, (bytes, bytearray)) or len(fk) != SecretBox.KEY_SIZE:
                raise ValueError("bad cuckoo key object")
            self.airgap_pending_keys_by_hash[ph] = bytes(fk)
            if ph in self.airgap_tickets_by_hash:
                self.airgap_tickets_by_hash[ph]["file_key"] = bytes(fk)
            self.log_event(f"[CUCKOO] key object complete from={short8(src_id)} object={object_id[:8]} payload={ph[:12]}")
            self.activity_system(f"Cuckoo key complete ({ph[:12]})")
            self.airgap_save_state()
            self.airgap_try_unlock(ph)
            return True
        except Exception as e:
            self.log_event(f"[CUCKOO] key object rejected object={object_id[:8]} from={short8(src_id)} err={e}")
            return False

    def build_airgap_ticket_block(self, dst_id: str, payload_hash: str, file_key: bytes,
                                  target_height: int, blocks: int, filename_hint: str = "") -> dict:
        payload_id = sha256((payload_hash + "|" + dst_id + "|" + str(target_height)).encode())[:16]
        # Test-layer note: file_key is inside the recipient's encrypted envelope, but the canonical client
        # refuses to unwrap/use it before target_height. True cryptographic future-entropy locking
        # requires an external timelock/VDF/witness construction and is not implemented here.
        data = {
            "kind": "AIRGAP_TICKET",
            "payload_id": payload_id,
            "payload_class": "AIRGAP_1440",
            "payload_hash": payload_hash,
            "declared_size": AIRGAP_SIZE,
            "target_height": int(target_height),
            "blocks": int(blocks),
            # Cuckoo Clock v1: file_key is deliberately withheld from the
            # immediate ticket. It is delivered later as a tiny encrypted KDK
            # chunk object whose chunks are admitted into q by block-height
            # consensus. Legacy receivers should reject this ticket until the
            # key object completes.
            "file_key": b"",
            "cuckoo": True,
            "cuckoo_chunks": 0,
            "cuckoo_key_object_id": "",
            "cuckoo_release_heights": [],
            "from": self.name,
            "filename_hint": os.path.basename(filename_hint or "payload.bin")[:80],
            "created_height": self.airgap_current_height(),
            "height_source": str(getattr(self, "airgap_height_source", "test") or "test"),
        }
        data["ticket_hash"] = sha256(msgpack.packb({k: v for k, v in data.items() if k != "ticket_hash"}, use_bin_type=True))
        return {"type": "airgap_ticket", "enc": "plain", "data": data}

    def build_airgap_receipt_block(self, payload_id: str, payload_hash: str, status: str, file_key: Optional[bytes] = None) -> dict:
        tag_src = (file_key or b"") + payload_hash.encode() + status.encode()
        return {
            "type": "airgap_receipt",
            "enc": "plain",
            "data": {
                "kind": "AIRGAP_RECEIPT",
                "payload_id": payload_id,
                "payload_hash": payload_hash,
                "status": status,
                "receipt_tag": hashlib.sha256(tag_src).hexdigest()[:32],
                "ts": int(now_ts()),
                "from": self.name,
            },
        }

    def pick_peer_interactive(self, prompt_label: str = "PEER") -> Optional[str]:
        now = now_ts()
        eligible = []
        for nid, ts in self.active_nodes.items():
            if nid == self.node_id or now - ts > ACTIVE_TIMEOUT:
                continue
            if nid in self.peer_keys:
                eligible.append(nid)

        # Quiet-control must still show this selector. Sort likely end-users
        # (relay=False) before relay-only nodes for a friendlier recipient list.
        eligible.sort(key=lambda nid: (bool((self.peer_caps.get(nid, {}) or {}).get("relay")), nid))

        if not eligible:
            print(f"[{prompt_label}] no eligible peer with X25519 key")
            return None

        print(f"[{prompt_label}] eligible recipients:")
        for i, nid in enumerate(eligible, 1):
            caps = self.peer_caps.get(nid, {}) or {}
            role = "relay" if caps.get("relay") else "control"
            print(f"  {i}. {short8(nid)} role={role} caps={caps}")

        sel = input(f"[{prompt_label}] recipient number or node-id prefix (blank=random control peer): ").strip()
        if not sel:
            controls = [nid for nid in eligible if not bool((self.peer_caps.get(nid, {}) or {}).get("relay"))]
            return random.choice(controls or eligible)

        # Accept numeric selection.
        try:
            idx = int(sel) - 1
            if 0 <= idx < len(eligible):
                return eligible[idx]
        except Exception:
            pass

        # Accept a pasted node-id prefix, e.g. 27a249f4.
        matches = [nid for nid in eligible if nid.startswith(sel)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            print(f"[{prompt_label}] ambiguous node-id prefix {sel!r}; matches={','.join(short8(m) for m in matches)}")
            return None

        print(f"[{prompt_label}] bad recipient selection")
        return None

    def airgap_create_interactive(self):
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                dst = self.pick_peer_interactive("AIRGAP")
                if not dst:
                    return
                mode = input("[AIRGAP] input mode: [t]ext or [f]ile? (default=t): ").strip().lower() or "t"
                filename_hint = "message.txt"
                if mode.startswith("f"):
                    path = input("[AIRGAP] file path <= AIRGAP_1440 capacity: ").strip().strip('"')
                    if not path or not os.path.exists(path):
                        qprint("[AIRGAP] file not found")
                        return
                    plaintext = open(path, "rb").read()
                    filename_hint = os.path.basename(path)
                else:
                    text = input("[AIRGAP] text message: ")
                    plaintext = text.encode("utf-8", "ignore")
                    filename_hint = "message.txt"

                source_label = str(getattr(self, "airgap_height_source", "test") or "test")
                btxt = input(f"[AIRGAP] {source_label} blocks min={AIRGAP_MIN_BLOCKS} default={AIRGAP_DEFAULT_BLOCKS}: ").strip()
                try:
                    blocks = int(btxt) if btxt else AIRGAP_DEFAULT_BLOCKS
                except Exception:
                    blocks = AIRGAP_DEFAULT_BLOCKS
                blocks = max(AIRGAP_MIN_BLOCKS, blocks)
                try:
                    current_height = self.airgap_current_height()
                except Exception as e:
                    qprint(f"[AIRGAP] cannot create ticket: height source unavailable err={e}")
                    return
                blocks = max(blocks, self.cuckoo_min_delay_blocks(), CUCKOO_MIN_CHUNKS)
                target_height = current_height + blocks
                cuckoo_chunks = self.cuckoo_chunk_count_for_delay(blocks)
                cuckoo_releases = self.cuckoo_release_schedule(current_height, blocks, cuckoo_chunks)

                blob, file_key, airgap_header = self.build_airgap_blob(plaintext, filename_hint=filename_hint)
                payload_hash = sha256(blob)
                out = os.path.join(AIRGAP_OUT_DIR, f"airgap_{payload_hash[:12]}.kdk")
                with open(out, "wb") as f:
                    f.write(blob)

                block = self.build_airgap_ticket_block(dst, payload_hash, file_key, target_height, blocks, filename_hint=filename_hint)
                payload_id = str((block.get("data", {}) or {}).get("payload_id", payload_hash[:16]))
                key_blocks = self.cuckoo_build_key_object_blocks(payload_hash, payload_id, file_key, target_height, cuckoo_releases, filename_hint=filename_hint)
                k_oid = str((key_blocks[0].get("data", {}) or {}).get("object_id", ""))
                block["data"]["cuckoo_chunks"] = len(key_blocks) - 1
                block["data"]["cuckoo_key_object_id"] = k_oid
                block["data"]["cuckoo_release_heights"] = list(cuckoo_releases)
                ticket_bytes = self.build_airgap_ticket_object_bytes(block)
                ticket_blocks = self.build_kdk_object_blocks(
                    ticket_bytes,
                    filename_hint=f"airgap_ticket_{payload_hash[:12]}.kdkagticket",
                    object_id=sha256(ticket_bytes)[:32],
                )
                self.queue_kdk_object_blocks(dst, ticket_blocks, label="KDK-AIRGAP-TICKET")
                self.queue_cuckoo_key_blocks(dst, key_blocks, cuckoo_releases, payload_hash=payload_hash)
                self.log_event(f"[AIRGAP_TICKET_CHUNKED] dst={short8(dst)} hash={payload_hash[:12]} qlen={len(self.outbound_queue)} cuckoo_chunks={len(key_blocks)-1}")
                self.log_event(
                    f"[AIRGAP] created blob={out} source={filename_hint} plaintext_bytes={len(plaintext)} size={len(blob)} hash={payload_hash[:12]} "
                    f"dst={short8(dst)} target_height={target_height} blocks={blocks} qlen={len(self.outbound_queue)}"
                )
                qprint(f"[AIRGAP] courier file: {out}")
                qprint("[AIRGAP] ticket queued; it will ride normal MESSAGE/TURN emission")
                self.activity_system(f"Airgap courier created ({os.path.basename(out)})")
                self.activity_system(f"Airgap ticket queued for {self.activity_peer_name(dst)}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    # Re-enter hotkey mode after line-input prompts.
                    # self._raw_term_state is the original terminal state for final shutdown.
                    term_enter_raw_noecho()

    def airgap_import_interactive(self):
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                path = input("[AIRGAP] path to received .kdk blob: ").strip().strip('"')
                if not path or not os.path.exists(path):
                    qprint("[AIRGAP] file not found")
                    return
                download_path = input("[AIRGAP] download folder [blank=retrieved]: ").strip().strip('"') or "retrieved"
                blob = open(path, "rb").read()
                airgap_header = self._airgap_parse_header(blob)
                payload_hash = sha256(blob)
                local = os.path.join(AIRGAP_PENDING_DIR, f"{payload_hash}.kdk")
                with open(local, "wb") as f:
                    f.write(blob)
                self.airgap_blobs_by_hash[payload_hash] = local
                self.airgap_download_paths_by_hash[payload_hash] = download_path
                self.airgap_save_state()
                self.log_event(f"[AIRGAP] imported blob hash={payload_hash[:12]} size={len(blob)} filename={airgap_header.get('filename_hint')} download={download_path} path={local}")
                self.activity_system(f"Airgap courier imported ({payload_hash[:12]})")
                self.airgap_try_unlock(payload_hash)
            except Exception as e:
                qprint(f"[AIRGAP] import rejected: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    # Re-enter hotkey mode after line-input prompts.
                    # self._raw_term_state is the original terminal state for final shutdown.
                    term_enter_raw_noecho()

    def airgap_show_pending(self):
        try:
            h = self.airgap_current_height()
        except Exception as e:
            qprint(f"[AIRGAP] height unavailable source={getattr(self, 'airgap_height_source', 'test')} err={e}")
            return
        qprint(f"[AIRGAP] current_height={h} source={getattr(self, 'airgap_last_height_source', getattr(self, 'airgap_height_source', 'test'))} block_secs={self.airgap_block_secs}")
        qprint(f"[AIRGAP] blobs={len(self.airgap_blobs_by_hash)} tickets={len(self.airgap_tickets_by_hash)} unlocked={len(self.airgap_unlocked)}")
        for ph, t in list(self.airgap_tickets_by_hash.items()):
            have_blob = ph in self.airgap_blobs_by_hash
            target = int(t.get("target_height", 0))
            state = "unlocked" if ph in self.airgap_unlocked else ("ready" if h >= target and have_blob else "waiting")
            qprint(f"  {ph[:12]} blob={have_blob} target={target} remaining={max(0, target-h)} state={state}")

    def activity_format_duration(self, seconds: float, prefer_years: bool = False) -> str:
        try:
            secs = max(0.0, float(seconds))
        except Exception:
            secs = 0.0
        minute, hour, day = 60.0, 3600.0, 86400.0
        month, year = 30.0 * day, 365.0 * day

        def fmt(value, singular):
            n = int(round(value)) if abs(value - round(value)) < 0.02 else round(value, 1)
            return f"{n} {singular}" + ("" if n == 1 else "s")

        if prefer_years or secs >= year:
            return fmt(secs / year, "year")
        if secs >= month:
            return fmt(secs / month, "month")
        if secs >= day:
            return fmt(secs / day, "day")
        if secs >= hour:
            return fmt(secs / hour, "hour")
        if secs >= minute:
            return fmt(secs / minute, "minute")
        return fmt(secs, "second")

    def activity_timelock_confirmation_text(self, raw: str, blocks: int,
                                            target_height: int) -> str:
        raw_l = re.sub(r"\s+", "", str(raw or "").strip().lower())
        bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))
        seconds = max(0, int(blocks)) * bs
        years_typed = bool(re.search(r"(?:y|yr|yrs|year|years)$", raw_l))
        human = self.activity_format_duration(seconds, prefer_years=years_typed)
        if years_typed or "year" in human:
            # Dark emphasis on the pale activity pane.
            human = "\033[2m" + human.upper() + "\033[22m"
        try:
            unlock_epoch = time.time() + seconds
            if seconds >= 365.0 * 86400.0:
                unlock = time.strftime("%d %b %Y", time.localtime(unlock_epoch))
            elif seconds >= 86400.0:
                unlock = time.strftime("%d %b %H:%M", time.localtime(unlock_epoch))
            else:
                unlock = time.strftime("%H:%M", time.localtime(unlock_epoch))
            return f"{human} · {int(blocks):,} blocks · unlock ~{unlock} · height {int(target_height)}"
        except Exception:
            return f"{human} · {int(blocks):,} blocks · height {int(target_height)}"

    def activity_airgap_key_progress(self, ph: str, ticket: dict) -> tuple:
        try:
            total = max(0, int((ticket or {}).get("cuckoo_chunks", 0) or 0))
        except Exception:
            total = 0
        if total <= 0:
            return 0, 0

        ready = (
            isinstance((ticket or {}).get("file_key"), (bytes, bytearray))
            and len((ticket or {}).get("file_key")) == SecretBox.KEY_SIZE
        )
        if not ready:
            kb = (getattr(self, "airgap_pending_keys_by_hash", {}) or {}).get(ph)
            ready = isinstance(kb, (bytes, bytearray)) and len(kb) == SecretBox.KEY_SIZE
        if ready:
            return total, total

        oid = str((ticket or {}).get("cuckoo_key_object_id", "") or "")
        rec = (getattr(self, "chunk_rx", {}) or {}).get(oid, {}) if oid else {}
        have = len((rec or {}).get("chunks", {}) or {})
        return min(total, max(0, int(have))), total

    def activity_airgap_status_rows(self) -> list:
        """Unlocked inventory plus active timelocks; no unrelated System traffic."""
        try:
            try:
                height = int(self.airgap_current_height())
            except Exception:
                height = 0
            bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))
            tickets = dict(getattr(self, "airgap_tickets_by_hash", {}) or {})
            blobs = dict(getattr(self, "airgap_blobs_by_hash", {}) or {})
            unlocked = set(getattr(self, "airgap_unlocked", set()) or set())
            exports = dict(getattr(self, "airgap_exports_by_hash", {}) or {})
            done, active = [], []

            for ph in sorted(set(tickets) | set(blobs) | unlocked):
                ticket = tickets.get(ph, {}) or {}
                filename = str(ticket.get("filename_hint")
                               or os.path.basename(str(blobs.get(ph, "") or ""))
                               or "timelocked file")
                if ph in unlocked:
                    done.append(f"  {filename}")
                    continue
                target = int(ticket.get("target_height", 0) or 0)
                have, total = self.activity_airgap_key_progress(ph, ticket)
                remaining = max(0, target - height) if target and height else None
                eta = (self.activity_format_duration(remaining * bs)
                       if remaining is not None and remaining > 0
                       else ("now" if remaining == 0 else "—"))
                have_blob = bool(blobs.get(ph) and os.path.exists(str(blobs.get(ph))))
                if not ticket: state = "COURIER ONLY"
                elif not have_blob: state = "WAITING FOR COURIER"
                elif total and have < total: state = "WAITING FOR KEY"
                elif remaining is None or remaining > 0: state = "TIMELOCKED"
                else: state = "READY"
                key = f"key {have}/{total}" if total else "key —"
                remain_text = (f"{remaining} blocks (~{eta})"
                               if remaining is not None else "remaining —")
                active.append(f"  {filename} · {key} · {remain_text} · {state}")

            for ph, rec in sorted(exports.items()):
                if ph in unlocked:
                    continue
                target = int((rec or {}).get("target_height", 0) or 0)
                remaining = max(0, target - height) if target and height else None
                if remaining is not None and target and height and remaining <= 0:
                    continue
                filename = str((rec or {}).get("filename_hint", "") or "timelocked file")
                total = max(0, int((rec or {}).get("key_chunks", 0) or 0))
                oid = str((rec or {}).get("key_object_id", "") or "")
                released = len([x for x in set(getattr(self, "cuckoo_released", set()) or set())
                                if oid and str(x).startswith(oid + ":")])
                released = min(total, released)
                eta = (self.activity_format_duration(remaining * bs)
                       if remaining is not None and remaining > 0
                       else ("now" if remaining == 0 else "—"))
                remain_text = (f"{remaining} blocks (~{eta})"
                               if remaining is not None else "remaining —")
                active.append(f"  {filename} · key released {released}/{total} · "
                              f"{remain_text} · OUTBOUND")

            return [" UNLOCKED"] + (done or ["  —"]) + ["", " TIMELOCKED"] + (active or ["  —"])
        except Exception as e:
            return [f" Timelock status unavailable: {e}"]

    def activity_airgap_status_show(self):
        """Compact receiver + sender timelock status snapshot."""
        try:
            try:
                height = int(self.airgap_current_height())
                height_text = str(height)
            except Exception:
                height = 0
                height_text = "unavailable"

            bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))
            tickets = dict(getattr(self, "airgap_tickets_by_hash", {}) or {})
            blobs = dict(getattr(self, "airgap_blobs_by_hash", {}) or {})
            unlocked = set(getattr(self, "airgap_unlocked", set()) or set())
            exports = dict(getattr(self, "airgap_exports_by_hash", {}) or {})
            keys = set(tickets) | set(blobs) | set(unlocked)

            self.activity_system(f"Timelock status · Dingo height {height_text}")
            shown = 0

            for ph in sorted(keys):
                ticket = tickets.get(ph, {}) or {}
                filename = str(
                    ticket.get("filename_hint")
                    or os.path.basename(str(blobs.get(ph, "") or ""))
                    or "timelocked file"
                )
                target = int(ticket.get("target_height", 0) or 0)
                have_blob = bool(blobs.get(ph) and os.path.exists(str(blobs.get(ph))))
                khave, ktotal = self.activity_airgap_key_progress(ph, ticket)
                remaining = max(0, target - height) if target and height else None
                eta = (self.activity_format_duration(remaining * bs) if remaining is not None and remaining > 0 else ("now" if remaining == 0 else "—"))

                if ph in unlocked:
                    state = "UNLOCKED"
                elif not ticket:
                    state = "COURIER ONLY"
                elif not have_blob:
                    state = "WAITING FOR COURIER"
                elif ktotal and khave < ktotal:
                    state = "WAITING FOR KEY"
                elif remaining is None or remaining > 0:
                    state = "TIMELOCKED"
                else:
                    state = "READY"

                key_text = f"key {khave}/{ktotal}" if ktotal else "key —"
                remain_text = (f"{remaining} blocks (~{eta})" if remaining is not None and remaining > 0 else ("0 blocks" if remaining == 0 else "remaining —"))
                self.activity_system(
                    f"{filename} · {ph[:12]} · {key_text} · {remain_text} · {state}"
                )
                shown += 1

            for ph, rec in sorted(exports.items()):
                if ph in keys:
                    continue
                filename = str((rec or {}).get("filename_hint", "") or "timelocked file")
                target = int((rec or {}).get("target_height", 0) or 0)
                total = max(0, int((rec or {}).get("key_chunks", 0) or 0))
                oid = str((rec or {}).get("key_object_id", "") or "")
                released = len([
                    token for token in set(getattr(self, "cuckoo_released", set()) or set())
                    if oid and str(token).startswith(oid + ":")
                ])
                released = min(total, released)
                remaining = max(0, target - height) if target and height else None
                eta = (self.activity_format_duration(remaining * bs) if remaining is not None and remaining > 0 else ("now" if remaining == 0 else "—"))
                self.activity_system(
                    f"{filename} · {ph[:12]} · key released {released}/{total} · "
                    f"{remaining} blocks (~{eta}) · OUTBOUND" if remaining is not None else "remaining — · OUTBOUND"
                )
                shown += 1

            if not shown:
                self.activity_system("No active timelocked files")
        except Exception as e:
            self.activity_system(f"Timelock status unavailable: {e}")

    def activity_parse_airgap_timelock(self, value: str) -> int:
        """Parse a human-friendly Airgap timelock.

        Accepted examples:
          blank                    -> AIRGAP_DEFAULT_BLOCKS
          6 / 10b / 10blocks       -> Dingo blocks
          20m / 20min / 20minutes  -> minutes
          2h / 2hr / 2hours        -> hours
          2d / 2days               -> days
          2mo / 2months            -> approximate 30-day months
          2y / 2years              -> approximate 365-day years

        Time units are converted to approximate block counts using the node's
        configured airgap_block_secs. Plain numbers retain the historic meaning
        of block counts.
        """
        s = str(value or "").strip().lower()
        if not s:
            return max(AIRGAP_MIN_BLOCKS, int(AIRGAP_DEFAULT_BLOCKS))

        # Permit a little natural spacing: "2 hr", "2 days", etc.
        s = re.sub(r"\s+", "", s)
        m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([a-z]*)", s)
        if not m:
            return max(AIRGAP_MIN_BLOCKS, int(AIRGAP_DEFAULT_BLOCKS))

        try:
            amount = float(m.group(1))
            unit = str(m.group(2) or "")
            bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))

            if unit in ("", "b", "block", "blocks"):
                n = int(round(amount))
            elif unit in ("m", "min", "mins", "minute", "minutes"):
                n = int(round((amount * 60.0) / bs))
            elif unit in ("h", "hr", "hrs", "hour", "hours"):
                n = int(round((amount * 3600.0) / bs))
            elif unit in ("d", "day", "days"):
                n = int(round((amount * 86400.0) / bs))
            elif unit in ("mo", "mon", "month", "months"):
                n = int(round((amount * 30.0 * 86400.0) / bs))
            elif unit in ("y", "yr", "yrs", "year", "years"):
                n = int(round((amount * 365.0 * 86400.0) / bs))
            else:
                return max(AIRGAP_MIN_BLOCKS, int(AIRGAP_DEFAULT_BLOCKS))
        except Exception:
            n = int(AIRGAP_DEFAULT_BLOCKS)

        return max(AIRGAP_MIN_BLOCKS, int(n))

    def airgap_safe_output_path(self, folder: str, filename: str) -> str:
        """Return a collision-safe path using the original filename where possible."""
        folder = str(folder or "").strip().strip('"') or "retrieved"
        # If the user supplied a file path with an extension, honour it. Otherwise
        # treat the value as a folder and use the original filename from metadata.
        filename = os.path.basename(str(filename or "payload.bin").strip() or "payload.bin")
        if not filename or filename in (".", ".."):
            filename = "payload.bin"
        ensure_dir(folder)
        base, ext = os.path.splitext(filename)
        candidate = os.path.join(folder, filename)
        if not os.path.exists(candidate):
            return candidate
        for i in range(1, 1000):
            cand = os.path.join(folder, f"{base}_{i}{ext}")
            if not os.path.exists(cand):
                return cand
        return os.path.join(folder, f"{base}_{int(now_ts())}{ext}")

    def activity_airgap_copy_unlocked_to(self, payload_hash: str, download_path: str) -> bool:
        """Copy the *current* unlocked payload to the requested folder/path.

        Never fall back to the newest unlocked file. That caused stale Airgap
        outputs to be re-announced for unrelated imports.  If the preferred
        destination already contains the exact unlocked bytes, treat it as the
        same delivery instead of manufacturing filename_1, filename_2, ... .
        A genuinely different file with the same name still uses the existing
        collision-safe suffix behaviour.
        """
        try:
            dst = str(download_path or "").strip().strip('"') or "retrieved"
            ph = str(payload_hash or "")
            if not ph or ph not in getattr(self, "airgap_unlocked", set()):
                return False
            src = (getattr(self, "airgap_unlocked_paths_by_hash", {}) or {}).get(ph, "")
            if not src or not os.path.exists(src):
                self.log_event(f"[AIRGAP] unlocked output missing hash={ph[:12]} path={src}")
                return False
            ticket = (getattr(self, "airgap_tickets_by_hash", {}) or {}).get(ph, {}) or {}
            filename = str(ticket.get("filename_hint", "") or os.path.basename(src) or "payload.bin")
            with open(src, "rb") as f:
                data = f.read()

            is_folder = os.path.isdir(dst) or not os.path.splitext(os.path.basename(dst))[1]
            if is_folder:
                ensure_dir(dst)
                preferred = os.path.join(dst, os.path.basename(filename))
            else:
                ensure_dir(os.path.dirname(dst) or ".")
                preferred = dst

            # Idempotent Airgap delivery: a repeat import/decrypt of the same
            # logical payload must not create suffixed duplicate user files.
            if os.path.isfile(preferred):
                try:
                    with open(preferred, "rb") as f:
                        existing = f.read()
                    if existing == data:
                        self.log_event(f"[AIRGAP] duplicate output suppressed hash={ph[:12]} path={preferred}")
                        return True
                except Exception:
                    pass

            dst = self.airgap_safe_output_path(dst, filename) if is_folder else preferred
            with open(dst, "wb") as f:
                f.write(data)
            self.activity_system(f"Airgap saved to {dst}")
            return True
        except Exception as e:
            self.activity_system(f"Airgap save failed: {e}")
            return False


    def airgap_discover_removable_media(self, max_results: int = 12) -> list:
        """Return mounted removable-media destinations for Airgap UI.

        Discovery never mounts media. On Linux we require a live removable-style
        block-device source (/dev/sd*, /dev/mmc* or /dev/fd*) instead of treating
        an arbitrary /mnt path as removable. VirtualBox shared folders (vboxsf)
        are explicitly excluded. On Windows, GetDriveTypeW identifies removable
        drives, with A:/B: labelled FDD.
        """
        found = []
        seen = set()
        max_results = max(1, int(max_results or 12))

        def add(root: str, kind: str, label: str):
            try:
                root = os.path.abspath(str(root or ""))
                if not root or not os.path.isdir(root):
                    return
                rp = os.path.realpath(root)
                if rp in seen:
                    return
                seen.add(rp)
                found.append({
                    "root": root,
                    "kind": kind,
                    "label": label or os.path.basename(root) or root,
                })
            except Exception:
                return

        try:
            if os.name == "nt":
                try:
                    import ctypes
                    get_drive_type = ctypes.windll.kernel32.GetDriveTypeW
                    DRIVE_REMOVABLE = 2
                    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                        root = f"{letter}:\\"
                        try:
                            dtype = int(get_drive_type(root))
                        except Exception:
                            continue
                        if dtype != DRIVE_REMOVABLE:
                            continue
                        kind = "FDD" if letter in ("A", "B") else "USB/removable"
                        add(root, kind, root.rstrip("\\"))
                        if len(found) >= max_results:
                            break
                except Exception:
                    pass
            else:
                mounted = []
                try:
                    with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) < 3:
                                continue
                            dev = parts[0].replace("\\040", " ")
                            mnt = parts[1].replace("\\040", " ")
                            fstype = parts[2].strip().lower()

                            if mnt in ("/", "/boot", "/boot/efi"):
                                continue

                            # Shared/network mounts are useful manual destinations,
                            # but must never masquerade as inserted removable media.
                            if fstype == "vboxsf":
                                continue

                            if dev.startswith("/dev/fd"):
                                if os.path.exists(dev):
                                    mounted.append((mnt, "FDD", os.path.basename(dev)))
                                continue

                            if dev.startswith(("/dev/sd", "/dev/mmc")):
                                # A disconnected USB can leave stale mount state.
                                # Only advertise it while the backing device exists.
                                if not os.path.exists(dev):
                                    continue
                                mounted.append((
                                    mnt,
                                    "USB/removable",
                                    os.path.basename(mnt) or os.path.basename(dev),
                                ))
                except Exception:
                    pass

                for mnt, kind, label in mounted:
                    add(mnt, kind, label)
                    if len(found) >= max_results:
                        break
        except Exception:
            pass

        return found[:max_results]

    def airgap_detect_fdd_labels(self) -> list:
        """Return locally configured floppy drives, if any."""
        labels = []
        try:
            if os.name == "nt":
                import ctypes
                buf = ctypes.create_unicode_buffer(1024)
                qdd = ctypes.windll.kernel32.QueryDosDeviceW
                for letter in ("A:", "B:"):
                    try:
                        if qdd(letter, buf, len(buf)):
                            labels.append(letter)
                    except Exception:
                        pass
            else:
                for dev in ("/dev/fd0", "/dev/fd1"):
                    if os.path.exists(dev):
                        labels.append(os.path.basename(dev))
        except Exception:
            pass
        return labels

    def airgap_filter_media_kind(self, media: list, wanted: str) -> list:
        wanted = str(wanted or "").lower()
        out = []
        for rec in list(media or []):
            kind = str((rec or {}).get("kind", "") or "").upper()
            if wanted == "fdd" and kind == "FDD":
                out.append(rec)
            elif wanted == "usb" and kind != "FDD":
                out.append(rec)
        return out

    def airgap_media_type_prompt(self, mode: str) -> str:
        """Select USB or floppy before scanning physical media."""
        fdds = self.airgap_detect_fdd_labels()
        self.activity_system("[1] USB")
        if fdds:
            self.activity_system(f"[2] Floppy {fdds[0]}")
            raw = self.activity_readline_in_pane(
                "Media [1/2]",
                hint="1 = scan USB   2 = scan floppy",
                mode=mode,
            ).strip()
            return "fdd" if raw == "2" else ("usb" if raw in ("", "1") else "")
        raw = self.activity_readline_in_pane(
            "Media [1]",
            hint="1 = scan USB",
            mode=mode,
        ).strip()
        return "usb" if raw in ("", "1") else ""

    def activity_airgap_offer_media_export(self, courier_path: str) -> bool:
        """Copy a freshly-created courier to selected physical media or folder."""
        try:
            media_type = self.airgap_media_type_prompt("EXPORT")
            if not media_type:
                self.activity_system("Airgap export cancelled")
                return False

            media = self.airgap_filter_media_kind(
                self.airgap_discover_removable_media(), media_type
            )

            if not media:
                if media_type == "usb":
                    self.activity_system("No USB media detected")
                    root = self.activity_readline_in_pane(
                        "Folder",
                        hint="enter/paste folder path",
                        mode="EXPORT",
                    ).strip().strip('"')
                    if not root:
                        self.activity_system("Airgap export cancelled")
                        return False
                    root = os.path.abspath(os.path.expanduser(root))
                    if not os.path.isdir(root):
                        self.activity_system("Airgap export cancelled (folder not found)")
                        return False
                    kind = "Folder"
                    label = os.path.basename(root.rstrip(os.sep)) or root
                else:
                    self.activity_system("No floppy media detected")
                    return False
            else:
                for i, rec in enumerate(media, 1):
                    kind_name = "Floppy" if media_type == "fdd" else "USB"
                    self.activity_system(f"[{i}] {kind_name} {rec.get('label', '')}")
                if len(media) == 1:
                    choice = 1
                else:
                    raw = self.activity_readline_in_pane(
                        f"Destination [1-{len(media)}]",
                        hint="choose the device to receive the Airgap courier",
                        mode="EXPORT",
                    ).strip()
                    try:
                        choice = int(raw)
                    except Exception:
                        choice = 0
                if not (1 <= choice <= len(media)):
                    self.activity_system("Airgap export cancelled (invalid destination)")
                    return False
                rec = media[choice - 1]
                root = str(rec.get("root", ""))
                kind = "Floppy" if media_type == "fdd" else "USB"
                label = str(rec.get("label", "") or "")

            dst = os.path.join(root, os.path.basename(courier_path))
            with open(courier_path, "rb") as rf:
                data = rf.read()
            if len(data) != AIRGAP_SIZE:
                raise ValueError("courier size changed before media export")

            with open(dst, "wb") as wf:
                wf.write(data)
                try:
                    wf.flush()
                    os.fsync(wf.fileno())
                except Exception:
                    pass
            if os.path.getsize(dst) != AIRGAP_SIZE:
                raise ValueError("media copy size mismatch")

            self.log_event(
                f"[AIRGAP] media export src={courier_path} dst={dst} kind={kind} bytes={AIRGAP_SIZE}"
            )
            self.activity_system(
                f"Airgap courier copied to {kind} {label}: {os.path.basename(dst)}"
            )
            return True
        except PermissionError:
            self.activity_system("Airgap export failed: destination is not writable by this user")
            self.log_event(f"[AIRGAP] media export failed src={courier_path} err=PermissionError")
            return False
        except Exception as e:
            self.activity_system(f"Airgap export failed: {e}")
            self.log_event(f"[AIRGAP] media export failed src={courier_path} err={e}")
            return False

    def airgap_discover_removable_couriers(self, max_results: int = 12) -> list:
        """Return exact-size .kdk Airgap couriers found on mounted removable media."""
        found = []
        seen_paths = set()
        max_results = max(1, int(max_results or 12))
        for rec in self.airgap_discover_removable_media(max_results=max_results):
            root = str(rec.get("root", ""))
            kind = str(rec.get("kind", "Removable"))
            label = str(rec.get("label", ""))
            root_depth = root.rstrip(os.sep).count(os.sep)
            inspected = 0
            try:
                for cur, dirs, files in os.walk(root):
                    depth = cur.rstrip(os.sep).count(os.sep) - root_depth
                    if depth >= 2:
                        dirs[:] = []
                    dirs[:] = [d for d in dirs if d not in ("lost+found", "$RECYCLE.BIN", "System Volume Information")]
                    for fn in files:
                        inspected += 1
                        if inspected > 500:
                            break
                        if not str(fn).lower().endswith(".kdk"):
                            continue
                        path = os.path.join(cur, fn)
                        try:
                            if os.path.getsize(path) != AIRGAP_SIZE:
                                continue
                        except Exception:
                            continue
                        rp = os.path.realpath(path)
                        if rp in seen_paths:
                            continue
                        seen_paths.add(rp)
                        found.append({"path": path, "kind": kind, "label": label or os.path.basename(root) or root})
                        if len(found) >= max_results:
                            return found
                    if inspected > 500:
                        break
            except Exception:
                continue
        return found[:max_results]

    def activity_airgap_interactive(self, mode: str):
        """Pane-native Airgap workflow with explicit Export / Import selection."""
        mode = str(mode or "").strip().lower()
        if mode not in ("export", "import"):
            return

        dst = self.activity_current_recipient_id()
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                if mode == "import":
                    media_type = self.airgap_media_type_prompt("IMPORT")
                    if not media_type:
                        self.activity_system("Airgap import cancelled")
                        return

                    couriers = self.airgap_filter_media_kind(
                        self.airgap_discover_removable_couriers(), media_type
                    )
                    value = ""

                    if couriers:
                        for i, rec in enumerate(couriers, 1):
                            kind_name = "Floppy" if media_type == "fdd" else "USB"
                            name = os.path.basename(str(rec.get("path", "") or ""))
                            self.activity_system(
                                f"[{i}] {kind_name} {rec.get('label', '')}: {name}"
                            )
                        if len(couriers) == 1:
                            value = str(couriers[0].get("path", ""))
                        else:
                            raw = self.activity_readline_in_pane(
                                f"Source [1-{len(couriers)}]",
                                hint="choose the courier to import",
                                mode="IMPORT",
                            ).strip()
                            try:
                                choice = int(raw)
                            except Exception:
                                choice = 0
                            if 1 <= choice <= len(couriers):
                                value = str(couriers[choice - 1].get("path", ""))
                    else:
                        self.activity_system(
                            "No USB Airgap courier detected"
                            if media_type == "usb"
                            else "No floppy Airgap courier detected"
                        )
                        value = self.activity_readline_in_pane(
                            "Courier path",
                            hint="enter/paste .kdk file path",
                            mode="IMPORT",
                        ).strip().strip('"')

                    if not value:
                        self.activity_system("Airgap import cancelled")
                        return
                    if not (os.path.isfile(value) and value.lower().endswith(".kdk")):
                        self.activity_system("Airgap import cancelled (courier not found)")
                        return

                    download_path = self.activity_readline_in_pane(
                        "Download folder [blank=retrieved]",
                        hint="enter/paste folder path, or press Enter to use retrieved",
                        mode="IMPORT",
                    ).strip().strip('"') or "retrieved"

                    blob = open(value, "rb").read()
                    airgap_header = self._airgap_parse_header(blob)
                    payload_hash = sha256(blob)
                    local = os.path.join(AIRGAP_PENDING_DIR, f"{payload_hash}.kdk")
                    with open(local, "wb") as f:
                        f.write(blob)
                    self.airgap_blobs_by_hash[payload_hash] = local
                    self.airgap_download_paths_by_hash[payload_hash] = download_path
                    self.airgap_save_state()
                    self.log_event(
                        f"[AIRGAP] imported blob hash={payload_hash[:12]} size={len(blob)} "
                        f"filename={airgap_header.get('filename_hint')} download={download_path} path={local}"
                    )
                    self.activity_system(f"Airgap courier imported ({payload_hash[:12]})")
                    was_unlocked = payload_hash in getattr(self, "airgap_unlocked", set())
                    self.airgap_try_unlock(payload_hash)
                    if was_unlocked:
                        self.activity_airgap_copy_unlocked_to(payload_hash, download_path)
                    return

                # EXPORT
                if not dst:
                    self.activity_system("No recipient selected")
                    return

                value = self.activity_readline_in_pane(
                    "File",
                    hint="enter/paste path to timelock file",
                    mode="EXPORT",
                ).strip().strip('"')
                if not value:
                    self.activity_system("Airgap export cancelled")
                    return
                if not os.path.isfile(value):
                    self.activity_system(f"File not found: {value}")
                    return

                plaintext = open(value, "rb").read()
                filename_hint = os.path.basename(value)

                while True:
                    lock_text = self.activity_readline_in_pane(
                        "Timelock",
                        hint="examples: 20m, 2hr, 2days, 2months, 2years (plain number = blocks)",
                        mode="EXPORT",
                    ).strip()
                    blocks_delay = self.activity_parse_airgap_timelock(lock_text)

                    try:
                        current_height = self.airgap_current_height()
                    except Exception as e:
                        self.activity_system(f"Airgap height unavailable: {e}")
                        return

                    blocks_delay = max(
                        blocks_delay, self.cuckoo_min_delay_blocks(), CUCKOO_MIN_CHUNKS
                    )
                    target_height = current_height + blocks_delay
                    confirm_text = self.activity_timelock_confirmation_text(
                        lock_text, blocks_delay, target_height
                    )
                    confirm = self.activity_readline_in_pane(
                        "Confirm timelock [Y/n]",
                        hint=confirm_text,
                        mode="EXPORT",
                    ).strip().lower()

                    if confirm in ("", "y", "yes"):
                        break
                    if confirm in ("n", "no"):
                        continue
                    self.activity_system("Enter Y to confirm or N to change the timelock")

                cuckoo_chunks = self.cuckoo_chunk_count_for_delay(blocks_delay)
                cuckoo_releases = self.cuckoo_release_schedule(
                    current_height, blocks_delay, cuckoo_chunks
                )

                blob, file_key, airgap_header = self.build_airgap_blob(
                    plaintext, filename_hint=filename_hint
                )
                payload_hash = sha256(blob)
                out = os.path.join(AIRGAP_OUT_DIR, f"airgap_{payload_hash[:12]}.kdk")
                with open(out, "wb") as f:
                    f.write(blob)

                block = self.build_airgap_ticket_block(
                    dst, payload_hash, file_key, target_height, blocks_delay,
                    filename_hint=filename_hint
                )
                payload_id = str((block.get("data", {}) or {}).get(
                    "payload_id", payload_hash[:16]
                ))
                key_blocks = self.cuckoo_build_key_object_blocks(
                    payload_hash, payload_id, file_key, target_height,
                    cuckoo_releases, filename_hint=filename_hint
                )
                k_oid = str((key_blocks[0].get("data", {}) or {}).get("object_id", ""))
                block["data"]["cuckoo_chunks"] = len(key_blocks) - 1
                block["data"]["cuckoo_key_object_id"] = k_oid
                block["data"]["cuckoo_release_heights"] = list(cuckoo_releases)

                ticket_bytes = self.build_airgap_ticket_object_bytes(block)
                ticket_blocks = self.build_kdk_object_blocks(
                    ticket_bytes,
                    filename_hint=f"airgap_ticket_{payload_hash[:12]}.kdkagticket",
                    object_id=sha256(ticket_bytes)[:32],
                )
                self.queue_kdk_object_blocks(dst, ticket_blocks, label="KDK-AIRGAP-TICKET")
                self.queue_cuckoo_key_blocks(
                    dst, key_blocks, cuckoo_releases, payload_hash=payload_hash
                )

                self.airgap_exports_by_hash[payload_hash] = {
                    "filename_hint": filename_hint,
                    "target_height": int(target_height),
                    "blocks": int(blocks_delay),
                    "created_height": int(current_height),
                    "key_object_id": k_oid,
                    "key_chunks": int(len(key_blocks) - 1),
                    "release_heights": [int(x) for x in cuckoo_releases],
                    "dst": str(dst),
                    "courier_path": str(out),
                }
                self.airgap_save_state()

                self.log_event(
                    f"[AIRGAP_TICKET_CHUNKED] dst={short8(dst)} hash={payload_hash[:12]} "
                    f"qlen={len(self.outbound_queue)} cuckoo_chunks={len(key_blocks)-1}"
                )
                self.log_event(
                    f"[AIRGAP] created blob={out} source={filename_hint} "
                    f"plaintext_bytes={len(plaintext)} size={len(blob)} hash={payload_hash[:12]} "
                    f"dst={short8(dst)} target_height={target_height} blocks={blocks_delay} "
                    f"qlen={len(self.outbound_queue)}"
                )
                self.activity_system(
                    f"Timelocked file prepared for {self.activity_peer_name(dst)} "
                    f"({os.path.basename(out)})"
                )
                self.activity_system(f"Unlock height {target_height} ({blocks_delay} blocks)")
                self.activity_system(f"Airgap ticket queued for {self.activity_peer_name(dst)}")

                self.activity_airgap_offer_media_export(out)
            except Exception as e:
                self.activity_system(f"Airgap {mode} failed: {e}")
                self.log_event(f"[AIRGAP] {mode} interactive failed err={e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()


    def airgap_menu(self):
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                qprint("\n[AIRGAP]")
                qprint("  1. Export courier .kdk + queue ticket")
                qprint("  2. Import courier .kdk")
                qprint("  3. Status / pending locks")
                choice = input("[AIRGAP] choice: ").strip()
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    # Re-enter hotkey mode after line-input prompts.
                    # self._raw_term_state is the original terminal state for final shutdown.
                    term_enter_raw_noecho()
        if choice == "1":
            self.airgap_create_interactive()
        elif choice == "2":
            self.airgap_import_interactive()
        elif choice == "3":
            self.airgap_show_pending()
        else:
            qprint("[AIRGAP] cancelled")

    def airgap_handle_ticket(self, src_id: str, data: dict):
        try:
            if data.get("kind") != "AIRGAP_TICKET":
                return
            if data.get("payload_class") != "AIRGAP_1440":
                raise ValueError("bad payload class")
            if int(data.get("declared_size", 0)) != AIRGAP_SIZE:
                raise ValueError("bad declared size")
            ph = str(data.get("payload_hash", ""))
            if len(ph) != 64:
                raise ValueError("bad payload hash")
            if int(data.get("target_height", 0)) < int(data.get("created_height", 0)) + AIRGAP_MIN_BLOCKS:
                raise ValueError("target below minimum")
            fk = data.get("file_key")
            cuckoo = bool(data.get("cuckoo", False))
            if cuckoo:
                if ph in getattr(self, "airgap_pending_keys_by_hash", {}):
                    data["file_key"] = self.airgap_pending_keys_by_hash[ph]
            elif not isinstance(fk, (bytes, bytearray)) or len(fk) != SecretBox.KEY_SIZE:
                raise ValueError("bad file key")
            rec = dict(data)
            rec["_src_id"] = src_id
            rec["_last_remaining"] = None
            self.airgap_tickets_by_hash[ph] = rec
            self.airgap_save_state()
            self.log_event(
                f"[AIRGAP] ticket received from={short8(src_id)} hash={ph[:12]} "
                f"target_height={data.get('target_height')} payload_id={str(data.get('payload_id'))[:8]}"
            )
            self.airgap_try_unlock(ph)
        except Exception as e:
            self.log_event(f"[AIRGAP] ticket rejected from={short8(src_id)} err={e}")

    def airgap_handle_receipt(self, src_id: str, data: dict):
        ph = str(data.get("payload_hash", ""))
        status = str(data.get("status", "?"))
        pid = str(data.get("payload_id", ""))
        self.log_event(f"[AIRGAP] receipt from={short8(src_id)} payload_id={pid[:8]} hash={ph[:12]} status={status}")

    def airgap_find_blob_path(self, payload_hash: str, old_path: str = "") -> str:
        """Return an existing courier blob path for this payload hash if possible."""
        ph = str(payload_hash or "")
        candidates = []
        for pth in [old_path, (getattr(self, "airgap_blobs_by_hash", {}) or {}).get(ph, "")]:
            if isinstance(pth, str) and pth and os.path.exists(pth):
                return pth
        roots = [AIRGAP_PENDING_DIR, AIRGAP_OUT_DIR]
        names = []
        if ph:
            names.extend([f"{ph}.kdk", f"airgap_{ph[:12]}.kdk"])
        for root in roots:
            try:
                for fn in os.listdir(root):
                    if not fn.endswith(".kdk"):
                        continue
                    full = os.path.join(root, fn)
                    if ph and (ph in fn or ph[:12] in fn):
                        candidates.append(full)
            except Exception:
                pass
        for root in roots:
            for name in names:
                full = os.path.join(root, name)
                if os.path.exists(full):
                    candidates.append(full)
        if candidates:
            candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            return candidates[0]
        return ""

    def airgap_try_unlock(self, payload_hash: Optional[str] = None):
        targets = [payload_hash] if payload_hash else list(self.airgap_tickets_by_hash.keys())
        # No pending lock means no height is needed.  In dingo-auto mode,
        # avoiding this lookup also prevents an idle node without a local
        # dingocoind from repeatedly spawning a failing dingocoin-cli process.
        if not targets:
            return
        try:
            current = self.airgap_current_height()
        except Exception as e:
            self._log_event_dedup("airgap-height", f"[AIRGAP] height unavailable; locks remain waiting err={e}")
            return
        changed = False

        for ph in targets:
            if not ph or ph in self.airgap_unlocked:
                continue

            ticket = self.airgap_tickets_by_hash.get(ph)
            path = self.airgap_blobs_by_hash.get(ph)
            if not ticket:
                continue
            path = self.airgap_find_blob_path(ph, path)
            if path:
                self.airgap_blobs_by_hash[ph] = path
            else:
                now_missing = now_ts()
                last_missing = float(ticket.get("_last_missing_blob_log", 0.0) or 0.0)
                if now_missing - last_missing >= 30.0:
                    ticket["_last_missing_blob_log"] = now_missing
                    changed = True
                    self.log_event(f"[AIRGAP] blob missing hash={ph[:12]}; waiting for courier re-import")
                continue
            if bool(ticket.get("cuckoo", False)) and not (isinstance(ticket.get("file_key"), (bytes, bytearray)) and len(ticket.get("file_key")) == SecretBox.KEY_SIZE):
                fk = getattr(self, "airgap_pending_keys_by_hash", {}).get(ph)
                if isinstance(fk, (bytes, bytearray)) and len(fk) == SecretBox.KEY_SIZE:
                    ticket["file_key"] = bytes(fk)
                else:
                    # Avoid log storms: report waiting state only when it changes
                    # or every ~30 seconds.
                    try:
                        now_wait = now_ts()
                        last_wait = float(ticket.get("_last_cuckoo_wait_log", 0.0) or 0.0)
                        if now_wait - last_wait >= 30.0:
                            ticket["_last_cuckoo_wait_log"] = now_wait
                            changed = True
                            exp_chunks = int(ticket.get("cuckoo_chunks", 0) or 0)
                            self.log_event(f"[CUCKOO] waiting for key chunks hash={ph[:12]} have=0/{exp_chunks}")
                    except Exception:
                        self.log_event(f"[CUCKOO] waiting for key chunks hash={ph[:12]}")
                    continue

            target = int(ticket.get("target_height", 0))
            if current < target:
                remaining = target - current
                if ticket.get("_last_remaining") != remaining:
                    ticket["_last_remaining"] = remaining
                    changed = True
                    self.log_event(
                        f"[AIRGAP] matched hash={ph[:12]} waiting target_height={target} remaining={remaining}"
                    )
                    self.activity_airgap_wait_message(ph, target, current, remaining)
                continue

            try:
                self.log_event(f"[AIRGAP] timelock satisfied hash={ph[:12]} height={current} target_height={target}")
                self.activity_system(f"Airgap timelock satisfied ({ph[:12]})")

                blob = open(path, "rb").read()
                airgap_header = self._airgap_parse_header(blob)
                if len(blob) != AIRGAP_SIZE or sha256(blob) != ph:
                    raise ValueError("blob no longer matches ticket commitment")

                enc_len = int(airgap_header["enc_len"])
                enc = blob[AIRGAP_HEADER_SIZE:AIRGAP_HEADER_SIZE + enc_len]
                file_key = bytes(ticket["file_key"])
                plaintext = SecretBox(file_key).decrypt(enc)

                # Use the original filename for the recovered payload. The
                # Airgap ID belongs in logs/state, not in the user's filename.
                filename = str(ticket.get('filename_hint') or airgap_header.get('filename_hint', 'payload.bin') or 'payload.bin')
                internal_out = self.airgap_safe_output_path(AIRGAP_UNLOCKED_DIR, filename)
                with open(internal_out, "wb") as f:
                    f.write(plaintext)

                self.airgap_unlocked.add(ph)
                self.airgap_unlocked_paths_by_hash[ph] = internal_out

                # Also write/copy to the receiver's chosen download folder.
                # Blank imports default to retrieved/.  This is the user-facing
                # location; airgap/unlocked remains the protocol/audit copy.
                download_root = (getattr(self, "airgap_download_paths_by_hash", {}) or {}).get(ph, "retrieved") or "retrieved"
                if os.path.isdir(download_root) or not os.path.splitext(os.path.basename(str(download_root)))[1]:
                    user_out = self.airgap_safe_output_path(download_root, filename)
                else:
                    ensure_dir(os.path.dirname(str(download_root)) or ".")
                    user_out = str(download_root)
                with open(user_out, "wb") as f:
                    f.write(plaintext)

                changed = True
                self.log_event(f"[AIRGAP] decrypted hash={ph[:12]} filename={filename} bytes={len(plaintext)} internal={internal_out} saved={user_out}")
                self.activity_system(f"Airgap saved to {user_out}")

                receipt = self.build_airgap_receipt_block(
                    str(ticket.get("payload_id", ph[:16])), ph, "DECRYPTED", file_key=file_key
                )
                receipt_dst = str(ticket.get("_src_id", ""))
                if receipt_dst:
                    self.outbound_queue.append((receipt_dst, [receipt], "AIRGAP-RECEIPT"))
                    self.log_event(
                        f"[QUEUE] airgap receipt dst={short8(receipt_dst)} hash={ph[:12]} qlen={len(self.outbound_queue)}"
                    )
            except FileNotFoundError as e:
                now_missing = now_ts()
                last_missing = float(ticket.get("_last_missing_blob_log", 0.0) or 0.0)
                if now_missing - last_missing >= 30.0:
                    ticket["_last_missing_blob_log"] = now_missing
                    changed = True
                    self.log_event(f"[AIRGAP] decrypt paused; blob missing hash={ph[:12]} path={path}")
            except Exception as e:
                now_fail = now_ts()
                last_fail = float(ticket.get("_last_decrypt_fail_log", 0.0) or 0.0)
                if now_fail - last_fail >= 30.0:
                    ticket["_last_decrypt_fail_log"] = now_fail
                    changed = True
                    self.log_event(f"[AIRGAP] decrypt failed hash={ph[:12]} err={e}")

        if changed:
            self.airgap_save_state()

    # ------------------------- Chunked object lab layer ------------------------

    def _dynamic_wire_chunk_size(self, dst_id: str, filename_hint: str, total_size: int,
                                 object_id: str, object_hash: str) -> int:
        """Binary-search a frame-safe chunk using the real envelope builder.

        The probe includes optional peer hints when available and a metadata
        safety pad. Actual transmission uses the same builder and automatically
        drops the optional hint if it is the only reason a frame would overflow.
        """
        if not self.peer_keys.get(str(dst_id or "")):
            return min(int(KDK_WIRE_CHUNK_SIZE), 112)
        lo = max(1, int(globals().get("KDK_DYNAMIC_CHUNK_MIN", 48)))
        hi = max(lo, int(KDK_WIRE_CHUNK_SIZE))
        best = 0
        safe_pad = b"X" * max(0, int(globals().get("KDK_DYNAMIC_CHUNK_SAFETY_PAD", 72)))
        while lo <= hi:
            mid = (lo + hi) // 2
            probe = {
                "type": "kdk_chunk_data", "enc": "plain",
                "data": {
                    "kind": "KDK_CHUNK_DATA", "ver": 3,
                    "object_id": str(object_id), "object_hash": str(object_hash),
                    "total_size": int(total_size), "wire_chunk_size": int(mid),
                    "filename_hint": os.path.basename(filename_hint or "message.txt")[:48],
                    "index": 999999, "chunk_count": 999999,
                    "data": b"Z" * mid, "_fit_safety": safe_pad,
                },
            }
            try:
                self._build_encrypted_frame(str(dst_id), [probe], include_peer_hint=True)
                best = mid
                lo = mid + 1
            except Exception:
                hi = mid - 1
        if best <= 0:
            raise ValueError("no frame-safe KDK wire chunk size")
        return max(1, min(int(KDK_WIRE_CHUNK_SIZE), int(best)))

    def build_kdk_object_blocks(self, plaintext: bytes, filename_hint: str = "", object_id: str = "",
                                dst_id: str = "", wire_chunk_size: Optional[int] = None) -> list:
        """Build compact manifest + one block per wire-sized chunk.

        Keep metadata deliberately small so each encrypted envelope remains
        comfortably below MAX_FRAME_SIZE. Integrity is checked at completion
        with the whole-object SHA256, rather than carrying a large per-chunk
        hash table in the manifest.

        object_id may be supplied for deterministic swarm objects such as
        updates. Ordinary user objects keep the old randomized ID behaviour.
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise ValueError("plaintext must be bytes")
        plaintext = bytes(plaintext)
        if len(plaintext) > KDK_OBJECT_MAX_SIZE:
            raise ValueError(f"KDK object too large ({len(plaintext)} > {KDK_OBJECT_MAX_SIZE})")

        object_hash = sha256(plaintext)
        object_id = str(object_id or "").strip()
        if object_id:
            if not re.fullmatch(r"[0-9a-fA-F]{16,64}", object_id):
                raise ValueError("bad deterministic object_id")
            object_id = object_id.lower()[:32]
        else:
            object_nonce = os.urandom(16)
            object_id = sha256(b"KDKOBJ1" + object_nonce + plaintext)[:32]
        if wire_chunk_size is not None:
            wire_chunk_size = max(1, min(int(KDK_WIRE_CHUNK_SIZE), int(wire_chunk_size)))
        else:
            wire_chunk_size = self._dynamic_wire_chunk_size(
                dst_id, filename_hint, len(plaintext), object_id, object_hash
            ) if dst_id else min(int(KDK_WIRE_CHUNK_SIZE), 112)
        chunks = [plaintext[i:i + wire_chunk_size] for i in range(0, len(plaintext), wire_chunk_size)] or [b""]
        chunk_count = len(chunks)

        manifest = {
            "type": "kdk_chunk_manifest",
            "enc": "plain",
            "data": {
                "kind": "KDK_CHUNK_MANIFEST",
                "ver": 3,
                "object_id": object_id,
                "object_hash": object_hash,
                "total_size": len(plaintext),
                "wire_chunk_size": wire_chunk_size,
                "chunk_count": chunk_count,
                "filename_hint": os.path.basename(filename_hint or "message.txt")[:48],
            },
        }

        blocks = [manifest]
        for i, ch in enumerate(chunks):
            blocks.append({
                "type": "kdk_chunk_data",
                "enc": "plain",
                "data": {
                    "kind": "KDK_CHUNK_DATA",
                    "ver": 3,
                    "object_id": object_id,
                    "object_hash": object_hash,
                    "total_size": len(plaintext),
                    "wire_chunk_size": wire_chunk_size,
                    "filename_hint": os.path.basename(filename_hint or "message.txt")[:48],
                    "index": i,
                    "chunk_count": chunk_count,
                    "data": ch,
                },
            })
        return blocks

    def queue_kdk_object_blocks(self, dst_id: str, blocks: list, label: str = "KDK-CHUNK",
                                swarm_slot: Optional[int] = None, swarm_slots: Optional[int] = None,
                                preserve_wire_layout: bool = False):
        """Queue one manifest plus one shuffled initial pass of chunk data.

        The initial pass has no duplicate waves or per-chunk ACK/NACK pattern.
        Chunk order is randomized so a bad burst is less likely to erase one
        contiguous run. Receiver-led PULL and bounded WANT repair operate later
        through their own encrypted control and repair queues.

        For update swarms, swarm_slot/swarm_slots deterministically divide
        chunks between seeders: a node queues only chunks where
        index % swarm_slots == swarm_slot. The manifest is always sent.
        """
        if not blocks:
            return

        # Rebuild ordinary objects from the supplied bytes using the actual
        # destination key. Update swarms deliberately preserve a conservative
        # canonical layout so every seeder uses identical chunk indexes.
        try:
            if preserve_wire_layout:
                raise StopIteration
            old_manifest = blocks[0]
            md = old_manifest.get("data", {}) if isinstance(old_manifest, dict) else {}
            original_chunks = sorted(
                [b for b in blocks[1:] if isinstance(b, dict) and b.get("type") == "kdk_chunk_data"],
                key=lambda b: int((b.get("data", {}) or {}).get("index", -1))
            )
            raw = b"".join(bytes((b.get("data", {}) or {}).get("data", b"")) for b in original_chunks)
            expected_size = int(md.get("total_size", len(raw)) or len(raw))
            if len(raw) == expected_size:
                blocks = self.build_kdk_object_blocks(
                    raw, filename_hint=str(md.get("filename_hint", "message.txt")),
                    object_id=str(md.get("object_id", "")), dst_id=str(dst_id)
                )
                new_size = int((blocks[0].get("data", {}) or {}).get("wire_chunk_size", 0) or 0)
                self.log_event(f"[CHUNK_SIZE] object={str(md.get('object_id',''))[:8]} dynamic={new_size} frame={MAX_FRAME_SIZE}")
        except StopIteration:
            pass
        except Exception as e:
            self.log_event(f"[CHUNK_SIZE] dynamic rebuild failed; retaining supplied blocks err={type(e).__name__}: {e}")

        manifest = blocks[0]
        chunk_blocks = list(blocks[1:])

        # Keep a compact sender-side copy so a bounded WANT repair can requeue
        # only requested chunks. This does not alter wire traffic; it is local state.
        try:
            mdata = manifest.get("data", {}) if isinstance(manifest, dict) else {}
            oid = str(mdata.get("object_id", ""))
            by_idx = {}
            for cb in chunk_blocks:
                cdata = cb.get("data", {}) if isinstance(cb, dict) else {}
                by_idx[int(cdata.get("index", -1))] = cb
            if oid:
                self.chunk_tx_store[oid] = {
                    "dst": dst_id,
                    "manifest": manifest,
                    "chunks": by_idx,
                    "chunk_count": len(by_idx),
                    "created_ts": now_ts(),
                    "filename_hint": str(mdata.get("filename_hint", "")),
                    "is_update": str(mdata.get("filename_hint", "")).lower().startswith("kdk_update_"),
                    "is_user_file": str(label or "").upper() == "KDK-FILE",
                }
        except Exception as e:
            self.log_event(f"[WANT] tx-store failed err={e}")

        # Optional deterministic swarm slice: keep only our assigned chunk
        # indices. Sender-side chunk_tx_store still has the full object so a
        # later WANT repair can be answered by any seeder that has the script.
        selected_count = len(chunk_blocks)
        if swarm_slot is not None and swarm_slots is not None:
            try:
                slots = max(1, int(swarm_slots))
                slot = int(swarm_slot) % slots
                before = len(chunk_blocks)
                chunk_blocks = [
                    cb for cb in chunk_blocks
                    if int((cb.get("data", {}) or {}).get("index", -1)) % slots == slot
                ]
                selected_count = len(chunk_blocks)
                self.log_event(
                    f"[SWARM] slice object={str((manifest.get('data', {}) or {}).get('object_id',''))[:8]} "
                    f"slot={slot}/{slots} selected={selected_count}/{before} dst={short8(dst_id)}"
                )
            except Exception as e:
                self.log_event(f"[SWARM] slice disabled err={type(e).__name__}: {e}")

        random.shuffle(chunk_blocks)

        # Manifests are tiny but essential.  Send several copies, spaced through
        # the data stream, so a large file does not stall as orphan chunks if
        # the first manifest is lost in churn.  Outwardly these are ordinary
        # encrypted payloads, so traffic uniformity is preserved.
        manifest_meta = self._chunk_block_telemetry([manifest])
        manifest_repeats = max(1, int(KDK_MANIFEST_REPEAT_COUNT))

        # Make the first manifest effectively immediate, then keep
        # a few manifest copies spread across the object.  The scheduler also
        # gives MANIFEST-PRIME deterministic priority, so the receiver should
        # learn chunk_count before a long run of anonymous orphan chunks.
        plan = []  # list[(block, label)]
        plan.append((manifest, "KDK-MANIFEST-PRIME"))
        if chunk_blocks:
            span = len(chunk_blocks)
            early = max(1, min(span, int(globals().get("KDK_MANIFEST_EARLY_AT_CHUNKS", 10))))
            insert_after = {early, max(1, span // 2), max(1, span - early)}
            # If a larger repeat count is configured, add evenly spaced fallbacks.
            for r in range(1, max(1, manifest_repeats)):
                insert_after.add(max(1, min(span, int(round((span * r) / max(1, manifest_repeats))))))
            for pos, b in enumerate(chunk_blocks, start=1):
                plan.append((b, label))
                if pos in insert_after:
                    plan.append((manifest, "KDK-MANIFEST"))
        else:
            for _ in range(manifest_repeats - 1):
                plan.append((manifest, "KDK-MANIFEST"))

        if manifest_meta:
            self.log_event(
                f"[CHUNK_Q] {manifest_meta} dst={short8(dst_id)} "
                f"manifest_repeats={manifest_repeats} data_chunks={len(chunk_blocks)} qlen={len(self.outbound_queue)+len(plan)} priority=early"
            )
        for b, blabel in plan:
            self.outbound_queue.append((dst_id, [b], blabel))

    def queue_chunked_object_interactive(self):
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                dst = self.pick_peer_interactive("CHUNK")
                if not dst:
                    return
                mode = input("[CHUNK] input mode: [t]ext or [f]ile? (default=t): ").strip().lower() or "t"
                filename_hint = "message.txt"
                if mode.startswith("f"):
                    path = input(f"[CHUNK] file path <= {KDK_OBJECT_MAX_SIZE} bytes: ").strip().strip('"')
                    if not path or not os.path.exists(path):
                        qprint("[CHUNK] file not found")
                        return
                    plaintext = open(path, "rb").read()
                    filename_hint = os.path.basename(path)
                else:
                    text = input("[CHUNK] text message: ")
                    plaintext = text.encode("utf-8", "ignore")

                blocks = self.build_kdk_object_blocks(plaintext, filename_hint=filename_hint)
                self.queue_kdk_object_blocks(dst, blocks, label="KDK-CHUNK")
                m = blocks[0]["data"]
                self.log_event(
                    f"[QUEUE] chunked object dst={short8(dst)} object={m['object_id'][:8]} "
                    f"bytes={m['total_size']} chunks={m['chunk_count']} qlen={len(self.outbound_queue)}"
                )
            except Exception as e:
                qprint(f"[CHUNK] queue failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def chunk_handle_manifest(self, src_id: str, data: dict):
        try:
            hint0 = str(data.get("filename_hint", "") or "").lower()
            protected_class = hint0.startswith("kdk_update_") or hint0.startswith("airgap_") or hint0.startswith("cuckoo_key_")
            if self.peer_policy_state(src_id) == "muted" and not protected_class:
                self.log_event(f"[PEER_POLICY] muted user-file manifest from={short8(src_id)} hint={hint0[:48]}")
                return
            oid = str(data.get("object_id", ""))
            total_size = int(data.get("total_size", -1))
            chunk_count = int(data.get("chunk_count", 0))
            wire_size = int(data.get("wire_chunk_size", 0))
            oh = str(data.get("object_hash", ""))
            if not oid or len(oh) != 64:
                raise ValueError("bad object id/hash")
            if total_size < 0 or total_size > KDK_OBJECT_MAX_SIZE:
                raise ValueError("bad total size")
            if oid in getattr(self, "chunk_completed", {}):
                self.log_event(f"[CHUNK] ignored completed manifest from={short8(src_id)} object={oid[:8]}")
                return
            if chunk_count <= 0 or chunk_count > 2048:
                raise ValueError("bad chunk count")
            if wire_size <= 0 or wire_size > KDK_WIRE_CHUNK_SIZE:
                raise ValueError("bad wire chunk size")

            rec = self.chunk_rx.get(oid)
            if rec is None:
                _t0 = now_ts()
                rec = {"manifest": None, "chunks": {}, "src": src_id, "sources": {src_id}, "first_ts": _t0, "last_data_ts": _t0, "last_unique_chunk_ts": _t0, "arrival_gaps": [], "want_rounds": 0, "last_want_ts": 0.0, "last_want_have": -1, "bad_dupes": 0, "incoming_notified": False, "last_pull_ts": 0.0}
                self.chunk_rx[oid] = rec
            old_manifest = rec.get("manifest")
            if old_manifest:
                if str(old_manifest.get("object_hash", "")) != oh or int(old_manifest.get("chunk_count", 0)) != chunk_count:
                    raise ValueError("conflicting manifest for object")
            rec["manifest"] = dict(data)
            rec["src"] = src_id
            rec.setdefault("sources", set()).add(src_id)
            if not bool(rec.get("incoming_notified", False)):
                hint = str(data.get("filename_hint") or "object.bin")
                if hint.lower().startswith("kdk_update_"):
                    state = getattr(self, "pull_discovery_state", {}) or {}
                    if bool(state.get("active", False)):
                        state["active"] = False
                        self.pull_discovery_state = state
                        self.log_event(f"[PULL] discovery satisfied object={oid[:8]} attempts={int(state.get('attempts', 0) or 0)}")
                safe_hint = "".join(c for c in os.path.basename(hint) if c.isalnum() or c in ("-", "_", ".")) or "object.bin"
                is_patch = safe_hint.lower().startswith("kdk_update_") or safe_hint.lower().endswith((".kdkpatch", ".json"))
                kind = "Patch" if is_patch else "File"
                self.activity_system(
                    f"Incoming {kind.lower()} from {self.activity_peer_name(src_id)} "
                    f"({safe_hint}, {total_size} bytes)"
                )
                rec["incoming_notified"] = True
            self.log_event(f"[CHUNK] manifest from={short8(src_id)} object={oid[:8]} bytes={total_size} chunks={chunk_count} have={len(rec.get('chunks', {}))}")
            self.chunk_try_complete(oid)
        except Exception as e:
            self.log_event(f"[CHUNK] manifest rejected from={short8(src_id)} err={e}")
            self.activity_system(f"Incoming transfer rejected from {self.activity_peer_name(src_id)}: {e}")

    def chunk_handle_data(self, src_id: str, data: dict):
        try:
            hint0 = str(data.get("filename_hint", "") or "").lower()
            protected_class = hint0.startswith("kdk_update_") or hint0.startswith("airgap_") or hint0.startswith("cuckoo_key_")
            if self.peer_policy_state(src_id) == "muted" and hint0 and not protected_class:
                self.log_event(f"[PEER_POLICY] muted user-file data from={short8(src_id)} hint={hint0[:48]}")
                return
            oid = str(data.get("object_id", ""))
            idx = int(data.get("index", -1))
            chunk_count = int(data.get("chunk_count", 0))
            ch = data.get("data", b"")
            if not oid or idx < 0 or chunk_count <= 0 or idx >= chunk_count:
                raise ValueError("bad chunk index/count")
            if not isinstance(ch, (bytes, bytearray)):
                raise ValueError("chunk data not bytes")
            ch = bytes(ch)
            if len(ch) > KDK_WIRE_CHUNK_SIZE:
                raise ValueError("chunk too large")
            if oid in getattr(self, "chunk_completed", {}):
                # Late repair/relay duplicates after completion are expected; ignore
                # them so they do not recreate a new partial object.
                self.log_event(f"[CHUNK] ignored completed data from={short8(src_id)} object={oid[:8]} idx={idx+1}/{chunk_count}")
                return

            rec = self.chunk_rx.get(oid)
            if rec is None:
                _t0 = now_ts()
                rec = {"manifest": None, "chunks": {}, "src": src_id, "sources": {src_id}, "first_ts": _t0, "last_data_ts": _t0, "last_unique_chunk_ts": _t0, "arrival_gaps": [], "want_rounds": 0, "last_want_ts": 0.0, "last_want_have": -1, "bad_dupes": 0, "incoming_notified": False, "last_pull_ts": 0.0}
                self.chunk_rx[oid] = rec

            manifest = rec.get("manifest")
            if not manifest:
                # Every data chunk carries sufficient bootstrap
                # metadata to recover from total manifest loss and generate WANTs.
                oh = str(data.get("object_hash", ""))
                total_size = int(data.get("total_size", -1))
                wire_size = int(data.get("wire_chunk_size", KDK_WIRE_CHUNK_SIZE) or KDK_WIRE_CHUNK_SIZE)
                hint = str(data.get("filename_hint", "object.bin") or "object.bin")
                if len(oh) == 64 and 0 <= total_size <= KDK_OBJECT_MAX_SIZE and 0 < wire_size <= KDK_WIRE_CHUNK_SIZE:
                    manifest = {
                        "kind": "KDK_CHUNK_MANIFEST", "ver": 4, "provisional": True,
                        "object_id": oid, "object_hash": oh, "total_size": total_size,
                        "wire_chunk_size": wire_size, "chunk_count": chunk_count,
                        "filename_hint": os.path.basename(hint)[:48],
                    }
                    # Preserve Cuckoo timing metadata when recovering from total
                    # manifest loss. Without this, a provisional manifest would
                    # look like an ordinary file and WANT could again request
                    # future-locked key chunks prematurely.
                    if bool(data.get("cuckoo", False)):
                        rels = data.get("release_heights", [])
                        if isinstance(rels, (list, tuple)) and len(rels) >= chunk_count:
                            manifest["cuckoo"] = True
                            manifest["release_heights"] = [int(x) for x in list(rels)[:chunk_count]]
                    rec["manifest"] = manifest
                    self.log_event(f"[CHUNK] provisional manifest object={oid[:8]} chunks={chunk_count} from=data idx={idx+1}")
            if manifest:
                expected_count = int(manifest.get("chunk_count", 0))
                if chunk_count != expected_count or idx >= expected_count:
                    raise ValueError("chunk count conflicts with manifest")

            existing = rec["chunks"].get(idx)
            if existing is not None:
                if existing == ch:
                    # Exact duplicates are expected in a stochastic relay mesh,
                    # but many duplicates with no new progress are a useful
                    # signal that the receiver should ask again for its missing
                    # residue.  Count them without treating them as corruption.
                    rec["dup_hits"] = int(rec.get("dup_hits", 0)) + 1
                    self.log_event(f"[CHUNK] duplicate from={short8(src_id)} object={oid[:8]} idx={idx+1}/{chunk_count} have={len(rec['chunks'])}")
                    return
                rec["bad_dupes"] = int(rec.get("bad_dupes", 0)) + 1
                raise ValueError("conflicting duplicate chunk")

            rec["chunks"][idx] = ch
            rec["src"] = src_id
            rec.setdefault("sources", set()).add(src_id)
            _now_chunk = now_ts()
            try:
                _last_unique = float(rec.get("last_unique_chunk_ts", rec.get("last_data_ts", _now_chunk)) or _now_chunk)
                _gap = _now_chunk - _last_unique
                if 0.05 <= _gap <= 300.0:
                    _gaps = rec.get("arrival_gaps")
                    if not isinstance(_gaps, list):
                        _gaps = []
                    _gaps.append(float(_gap))
                    _win = max(2, int(globals().get("KDK_WANT_CADENCE_WINDOW", 8)))
                    rec["arrival_gaps"] = _gaps[-_win:]
            except Exception:
                pass
            rec["last_unique_chunk_ts"] = _now_chunk
            rec["last_data_ts"] = _now_chunk
            self.log_event(f"[CHUNK] data from={short8(src_id)} object={oid[:8]} idx={idx+1}/{chunk_count} have={len(rec['chunks'])}")
            # Recipient-side progress feedback for Cuckoo Clock.  Announce only
            # the first receipt of a unique key chunk; duplicate stochastic
            # deliveries return above and therefore do not spam the activity pane.
            try:
                _m = rec.get("manifest") or {}
                if bool(_m.get("cuckoo", False)):
                    self.activity_system(f"[CUCKOO] key chunk {idx+1}/{chunk_count} received ({oid[:8]})")
            except Exception:
                pass
            self.chunk_try_complete(oid)
        except Exception as e:
            self.log_event(f"[CHUNK] data rejected from={short8(src_id)} err={e}")

    def chunk_missing_indexes(self, object_id: str) -> list:
        rec = self.chunk_rx.get(object_id)
        if not rec or not rec.get("manifest"):
            return []
        try:
            total = int(rec["manifest"].get("chunk_count", 0))
            chunks = rec.get("chunks", {})
            return [i for i in range(total) if i not in chunks]
        except Exception:
            return []

    def maybe_send_chunk_wants(self, now: Optional[float] = None):
        """Bounded, discreet repair pulse for partial chunk objects.

        This sends at most KDK_WANT_MAX_ROUNDS encrypted WANT envelopes per object.
        It is intentionally not a continuous ACK/NACK loop.
        """
        if not KDK_WANT_ENABLED:
            return
        now = now_ts() if now is None else float(now)
        for oid, rec in list(self.chunk_rx.items()):
            manifest = rec.get("manifest")
            if not manifest:
                continue
            try:
                total = int(manifest.get("chunk_count", 0))
                have = len(rec.get("chunks", {}))
                if have >= total:
                    continue
                # Update pulls deliberately stay coarse/random until the receiver
                # owns most of the object. Only then does WANT zero in on exact
                # missing indexes. Ordinary file transfers retain old behaviour.
                hint = str(manifest.get("filename_hint", "") or "").lower()
                if hint.startswith("kdk_update_") and total > 0:
                    fraction = float(have) / float(total)
                    if fraction < float(KDK_PULL_COARSE_FRACTION):
                        continue

                    # Exact-tail handoff. Once an update reaches the
                    # threshold, cancel only unsent coarse random pull requests for
                    # this object. Replies already in flight may still arrive.
                    # Subsequent repair uses the existing exact 1-based missing-index
                    # WANT path and ordinary earned-turn pacing.
                    if not bool(rec.get("pull_exact_tail", False)):
                        rec["pull_exact_tail"] = True
                        removed = 0
                        kept = []
                        for qitem in list(self.outbound_queue):
                            drop = False
                            try:
                                _qdst, _qblocks, _qlabel = qitem
                                if str(_qlabel) == "KDK-PULL":
                                    for _qb in (_qblocks or []):
                                        _qd = (_qb.get("data", {}) or {}) if isinstance(_qb, dict) else {}
                                        if (str(_qd.get("mode", "")) == "object-random" and
                                                str(_qd.get("object_id", "")) == str(oid)):
                                            drop = True
                                            break
                            except Exception:
                                drop = False
                            if drop:
                                removed += 1
                            else:
                                kept.append(qitem)
                        if removed:
                            self.outbound_queue.clear()
                            self.outbound_queue.extend(kept)
                        self.log_event(
                            f"[PULL] exact-tail object={oid[:8]} have={have}/{total} "
                            f"fraction={fraction:.2f} removed_coarse={removed}"
                        )
                last_data = float(rec.get("last_data_ts", rec.get("first_ts", now)))
                last_want = float(rec.get("last_want_ts", 0.0))
                missing = self.chunk_missing_indexes(oid)
                if not missing:
                    continue

                # Cuckoo chunks are intentionally absent until their
                # release heights.  They are future-locked, not lost.  Exclude
                # unreleased indexes from WANT so they consume zero repair rounds.
                # The manifest already carries one release height per key chunk.
                if bool(manifest.get("cuckoo", False)):
                    release_heights = list(manifest.get("release_heights", []) or [])
                    try:
                        current_h = int(self.cuckoo_consensus_height())
                    except Exception:
                        current_h = 0
                    repairable = []
                    future_locked = []
                    for idx in missing:
                        try:
                            i = int(idx)
                            due = int(release_heights[i]) if 0 <= i < len(release_heights) else 0
                        except Exception:
                            due = 0
                        if due > 0 and (current_h <= 0 or current_h < due):
                            future_locked.append(i)
                        else:
                            repairable.append(i)
                    if future_locked:
                        gate_sig = (current_h, tuple(future_locked), tuple(repairable))
                        if rec.get("cuckoo_want_gate_sig") != gate_sig:
                            rec["cuckoo_want_gate_sig"] = gate_sig
                            next_due = min(
                                [int(release_heights[i]) for i in future_locked if 0 <= i < len(release_heights)],
                                default=0,
                            )
                            self.log_event(
                                f"[WANT] cuckoo-gated object={oid[:8]} height={current_h} "
                                f"future={len(future_locked)} repairable={len(repairable)} next_due={next_due}"
                            )
                    missing = repairable
                    if not missing:
                        continue

                rounds = int(rec.get("want_rounds", 0))
                # once the nominal WANT budget is exhausted, a tiny
                # residue gets the complete bounded convergence budget even when
                # the immediately preceding round made no progress. For Cuckoo
                # objects the residue count below is only the *released* residue.
                if rounds >= KDK_WANT_MAX_ROUNDS:
                    convergence_cap = int(KDK_WANT_MAX_ROUNDS) + int(
                        globals().get("KDK_WANT_CONVERGENCE_ROUNDS", 4)
                    )
                    current_missing_for_cap = len(missing)
                    rescue_limit = int(globals().get(
                        "KDK_WANT_FINAL_RESCUE_MISSING",
                        globals().get("KDK_WANT_FINAL_MISSING", 4),
                    ))
                    small_residue = current_missing_for_cap <= rescue_limit
                    if rounds >= convergence_cap or not small_residue:
                        continue

                # adaptive WANT cadence.  Chunks arrive in stochastic
                # order, so sequence position is meaningless; the receiver estimates
                # the current cadence from recent *unique* chunk arrivals and only
                # sends WANT once that rhythm has gone quiet.
                gaps = rec.get("arrival_gaps", [])
                if not isinstance(gaps, list):
                    gaps = []
                vals = []
                for g in gaps[-max(2, int(globals().get("KDK_WANT_CADENCE_WINDOW", 8))):]:
                    try:
                        gf = float(g)
                        if 0.05 <= gf <= 300.0:
                            vals.append(gf)
                    except Exception:
                        pass
                if vals:
                    sv = sorted(vals)
                    mid = len(sv) // 2
                    cadence = sv[mid] if len(sv) % 2 else (sv[mid - 1] + sv[mid]) / 2.0
                else:
                    cadence = float(globals().get("KDK_WANT_CADENCE_DEFAULT_SECS", 5.0))
                factor = float(globals().get("KDK_WANT_CADENCE_FACTOR", 4.0))
                if len(missing) <= int(KDK_WANT_FINAL_MISSING):
                    factor = float(globals().get("KDK_WANT_CADENCE_FINAL_FACTOR", 2.5))
                quiet_timeout = max(
                    float(globals().get("KDK_WANT_CADENCE_MIN_SECS", 15.0)),
                    min(float(globals().get("KDK_WANT_CADENCE_MAX_SECS", 75.0)), cadence * factor),
                )
                last_unique = float(rec.get("last_unique_chunk_ts", last_data) or last_data)
                idle_for = now - last_unique

                # Still keep a minimum interval after a WANT, especially if
                # the previous request produced no progress.  This prevents
                # repeated WANT waves from overtaking repairs already in flight.
                min_interval = float(KDK_WANT_MIN_INTERVAL_SECS)
                last_want_have = int(rec.get("last_want_have", -1))
                if last_want > 0 and have <= last_want_have:
                    min_interval = max(min_interval, float(KDK_WANT_STALE_RETRY_SECS))
                elif last_want > 0 and have > last_want_have:
                    min_interval = max(6.0, min(min_interval, quiet_timeout * 0.75))
                if len(missing) <= int(KDK_WANT_FINAL_MISSING):
                    min_interval = min(min_interval, max(6.0, quiet_timeout * 0.75))

                if idle_for < quiet_timeout:
                    continue
                if now - last_want < min_interval:
                    continue

                # Dingo-height WANT embargo.  A repair request that
                # would otherwise be eligible must first sit through one or two
                # fresh Dingo block advances.  Dingo height only opens eligibility;
                # it never emits the WANT directly, which remains ordinary queued
                # traffic subject to the normal collision/height cadence.
                h = int(getattr(self, "dingo_scheduler_height", 0) or 0)
                hts = float(getattr(self, "dingo_scheduler_height_ts", 0.0) or 0.0)
                hsrc = str(getattr(self, "dingo_scheduler_source", "") or "")
                hstale = float(globals().get("KDK_HEIGHT_STALE_SECS", 180.0))
                dingo_fresh = bool(h > 0 and hts > 0 and (now - hts) <= hstale and hsrc.startswith("dingo"))
                if not dingo_fresh:
                    last_notice = float(rec.get("want_dingo_wait_notice_ts", 0.0) or 0.0)
                    if now - last_notice >= 60.0:
                        rec["want_dingo_wait_notice_ts"] = now
                        self.log_event(f"[WANT] dingo-wait object={oid[:8]} repair eligible but no fresh Dingo height")
                    continue

                target_h = int(rec.get("want_embargo_target_height", 0) or 0)
                if target_h <= 0:
                    try:
                        lo = max(1, int(globals().get("KDK_WANT_DINGO_DELAY_MIN_BLOCKS", 1)))
                        hi = max(lo, int(globals().get("KDK_WANT_DINGO_DELAY_MAX_BLOCKS", 2)))
                    except Exception:
                        lo, hi = 1, 2
                    delay_blocks = random.randint(lo, hi)
                    target_h = int(h) + int(delay_blocks)
                    rec["want_embargo_base_height"] = int(h)
                    rec["want_embargo_blocks"] = int(delay_blocks)
                    rec["want_embargo_target_height"] = int(target_h)
                    self.log_event(
                        f"[WANT] dingo-embargo object={oid[:8]} height={h} "
                        f"delay={delay_blocks} target={target_h}"
                    )
                    continue
                if h < target_h:
                    continue

                if len(missing) > KDK_WANT_MAX_MISSING:
                    if not rec.get("want_suppressed_logged"):
                        self.log_event(f"[WANT] suppressed object={oid[:8]} missing={len(missing)} max={KDK_WANT_MAX_MISSING}")
                        rec["want_suppressed_logged"] = True
                    continue
                source_ids = [str(x) for x in list(rec.get("sources", set()) or []) if str(x)]
                src_id = str(rec.get("src", ""))
                if src_id and src_id not in source_ids:
                    source_ids.append(src_id)
                # Prefer live direct sources but retain the last source as a
                # fallback: a temporarily quiet seeder may still answer later.
                live_sources = []
                for sid in source_ids:
                    if sid not in getattr(self, "peer_keys", {}):
                        continue
                    try:
                        if now - float(getattr(self, "active_nodes", {}).get(sid, 0.0)) > ACTIVE_TIMEOUT:
                            continue
                    except Exception:
                        pass
                    live_sources.append(sid)
                if live_sources:
                    source_ids = live_sources

                # Seeder-aware update repair. Confirmed contributors remain first
                # choice; if some have gone quiet, supplement only with peers whose
                # advertised build makes them plausible holders of this patch. Never
                # spray WANT at arbitrary active peers.
                want_candidate_reason = "confirmed-sources"
                if hint.startswith("kdk_update_"):
                    likely_ids, want_candidate_reason = self._update_pull_candidate_ids(
                        rec=rec, manifest=manifest, max_peers=int(KDK_PULL_MAX_PEERS)
                    )
                    merged = []
                    for sid in list(source_ids) + list(likely_ids):
                        sid = str(sid or "")
                        if sid and sid not in merged:
                            merged.append(sid)
                    source_ids = merged
                if not source_ids:
                    continue
                random.shuffle(source_ids)
                round_no = rounds + 1

                # WANT messages are control traffic, but they still ride inside
                # the same encrypted fixed-size frame as everything else. Split
                # missing indexes across the seeders that actually contributed
                # this object, so convergence becomes increasingly precise while
                # retaining multi-source behaviour.
                try:
                    want_batch_size = max(1, int(KDK_WANT_BATCH_SIZE))
                except Exception:
                    want_batch_size = 24
                missing_batches = [list(missing[i:i + want_batch_size]) for i in range(0, len(missing), want_batch_size)]
                if not missing_batches:
                    continue

                used_dsts = []
                for part_no, missing_part in enumerate(missing_batches, 1):
                    want_dst = source_ids[(part_no - 1) % len(source_ids)]
                    used_dsts.append(want_dst)
                    block = {
                        "type": "kdk_chunk_want",
                        "enc": "plain",
                        "data": {
                            "kind": "KDK_CHUNK_WANT",
                            "ver": 2,
                            "object_id": oid,
                            "round": round_no,
                            "part": part_no,
                            "parts": len(missing_batches),
                            "missing": list(missing_part),
                            "have": have,
                            "chunk_count": total,
                            "want_manifest": bool(manifest.get("provisional", False)),
                            "ts": int(now),
                        },
                    }
                    self.outbound_queue.append((want_dst, [block], "KDK-WANT"))

                rec["want_rounds"] = round_no
                rec["last_want_ts"] = now
                rec["last_want_have"] = have
                rec.pop("want_embargo_target_height", None)
                rec.pop("want_embargo_base_height", None)
                rec.pop("want_embargo_blocks", None)
                rec.pop("want_dingo_wait_notice_ts", None)
                self.log_event(
                    f"[WANT] queued dsts={','.join(short8(x) for x in sorted(set(used_dsts)))} object={oid[:8]} round={round_no}/" f"{int(KDK_WANT_MAX_ROUNDS) + int(globals().get('KDK_WANT_CONVERGENCE_ROUNDS', 4))} "
                    f"have={have}/{total} missing={len(missing)} batches={len(missing_batches)} "
                    f"batch_size={want_batch_size} cadence={cadence:.1f}s idle={idle_for:.1f}s quiet={quiet_timeout:.1f}s "
                    f"candidates={want_candidate_reason} qlen={len(self.outbound_queue)}"
                )
            except Exception as e:
                self.log_event(f"[WANT] maybe failed object={str(oid)[:8]} err={e}")

    def _update_seed_store_from_memory(self, base_version: str = "", base_hash: str = "") -> Optional[dict]:
        """Newest compatible update already resident in chunk_tx_store."""
        best = None
        best_rev = -1
        for store in list((getattr(self, "chunk_tx_store", {}) or {}).values()):
            if not isinstance(store, dict) or not bool(store.get("is_update", False)):
                continue
            meta = store.get("update_meta", {})
            if not isinstance(meta, dict):
                continue
            if base_hash and str(meta.get("base_hash", "")) != str(base_hash):
                continue
            if base_version and str(meta.get("base_version", "")) != str(base_version):
                continue
            try:
                rev = int(meta.get("target_revision", revision_from_version(str(meta.get("target_version", "")))) or 0)
            except Exception:
                rev = 0
            if rev > best_rev:
                best_rev = rev
                best = store
        return best

    def _update_seed_capsule_from_disk(self, base_version: str = "", base_hash: str = "") -> Optional[bytes]:
        """Return the newest locally retained capsule compatible with requester base."""
        best = None
        best_key = (-1, 0.0)
        roots = (KDK_UPDATE_SEED_DIR, KDK_UPDATE_INCOMING_DIR, KDK_UPDATE_APPLIED_DIR)
        for root in roots:
            try:
                names = os.listdir(root)
            except Exception:
                continue
            for name in names:
                path = os.path.join(root, name)
                if not os.path.isfile(path):
                    continue
                try:
                    raw = open(path, "rb").read()
                    if len(raw) > int(KDK_PATCH_CAPSULE_MAX_SIZE):
                        continue
                    meta = kdk_parse_canonical_capsule(raw)
                    if meta.get("kind") != KDK_UPDATE_KIND:
                        continue
                    if base_hash and str(meta.get("base_hash", "")) != str(base_hash):
                        continue
                    if base_version and version_cmp(str(meta.get("base_version", "")), str(base_version), meta.get("base_revision"), revision_from_version(base_version)) != 0:
                        continue
                    rev = int(meta.get("target_revision", revision_from_version(str(meta.get("target_version", "")))) or 0)
                    key = (rev, float(os.path.getmtime(path)))
                    if key > best_key:
                        best_key = key
                        best = raw
                except Exception:
                    continue
        return best

    def _cache_update_seed_bundle(self, bundle: bytes) -> Tuple[str, dict]:
        """Cache an update capsule under one canonical chunk layout for swarm service."""
        meta = kdk_parse_canonical_capsule(bytes(bundle))
        oid = self.update_object_id(bytes(bundle))
        blocks = self.build_kdk_object_blocks(
            bytes(bundle),
            filename_hint=f"kdk_update_{str(meta.get('target_version', 'patch'))}.json",
            object_id=oid,
            wire_chunk_size=int(KDK_UPDATE_CANONICAL_WIRE_CHUNK_SIZE),
        )
        manifest = blocks[0]
        by_idx = {int((b.get("data", {}) or {}).get("index", -1)): b for b in blocks[1:]}
        self.chunk_tx_store[oid] = {
            "dst": "",
            "manifest": manifest,
            "chunks": by_idx,
            "chunk_count": len(by_idx),
            "created_ts": now_ts(),
            "filename_hint": str((manifest.get("data", {}) or {}).get("filename_hint", "")),
            "is_update": True,
            "update_meta": meta,
        }
        return oid, self.chunk_tx_store[oid]

    def _update_pull_candidate_ids(self, rec: Optional[dict] = None, manifest: Optional[dict] = None,
                                   base_version: str = "", base_revision: int = 0,
                                   max_peers: Optional[int] = None) -> Tuple[list, str]:
        """Return update Pull/WANT targets ranked by evidence that they can seed it.

        Tier 1 is positive object evidence: peers that actually supplied this update
        manifest/data to us. Tier 2 is version evidence: active directable peers that
        advertise a build at least as new as the update target (or, during discovery,
        strictly newer than our current base). Arbitrary active peers are deliberately
        excluded; a Pull should not spray requests at nodes with no reason to possess
        the patch.
        """
        try:
            limit = max(1, int(max_peers if max_peers is not None else KDK_PULL_MAX_PEERS))
        except Exception:
            limit = max(1, int(KDK_PULL_MAX_PEERS))

        available = [str(x) for x in list(self.activity_recipient_ids()) if str(x)]
        if not available:
            return [], "none"
        available_set = set(available)

        confirmed = []
        if isinstance(rec, dict):
            raw_sources = list(rec.get("sources", set()) or [])
            last_src = str(rec.get("src", "") or "")
            if last_src:
                raw_sources.append(last_src)
            for sid in raw_sources:
                sid = str(sid or "")
                if sid and sid in available_set and sid not in confirmed:
                    confirmed.append(sid)

        target_version = ""
        target_revision = 0
        if isinstance(manifest, dict):
            hint = str(manifest.get("filename_hint", "") or "")
            base = os.path.basename(hint)
            low = base.lower()
            if low.startswith("kdk_update_") and low.endswith(".json"):
                target_version = base[len("kdk_update_"):-len(".json")]
                target_revision = revision_from_version(target_version)

        likely = []
        for nid in available:
            if nid in confirmed:
                continue
            caps = getattr(self, "peer_caps", {}).get(nid, {})
            if not isinstance(caps, dict):
                continue
            peer_version = str(caps.get("script_version", "") or "")
            try:
                peer_revision = int(caps.get("script_revision", revision_from_version(peer_version)) or 0)
            except Exception:
                peer_revision = revision_from_version(peer_version)

            is_likely = False
            if target_version:
                # A node already running the target (or a later build) is likely to
                # retain the compatible capsule in seed/incoming/applied storage.
                if target_revision > 0:
                    is_likely = peer_revision >= target_revision
                else:
                    is_likely = version_cmp(peer_version, target_version, peer_revision, target_revision) >= 0
            elif base_version or int(base_revision or 0) > 0:
                # Before a manifest exists, only ask peers demonstrably newer than
                # the receiver. Same/older peers have no positive reason to own the
                # forward patch we are trying to discover.
                try:
                    is_likely = version_cmp(
                        peer_version, str(base_version or "0.0"),
                        peer_revision, int(base_revision or revision_from_version(base_version))
                    ) > 0
                except Exception:
                    is_likely = peer_revision > int(base_revision or 0)
            if is_likely:
                likely.append(nid)

        # Preserve stochasticity within each evidence tier, but never let a merely
        # likely peer displace a confirmed seeder when the cap is reached.
        random.shuffle(confirmed)
        random.shuffle(likely)
        chosen = (confirmed + likely)[:limit]
        if confirmed and likely:
            reason = f"confirmed={len(confirmed)} likely={len(likely)}"
        elif confirmed:
            reason = f"confirmed={len(confirmed)}"
        elif likely:
            reason = f"likely={len(likely)}"
        else:
            reason = "no-seeder-evidence"
        return chosen, reason

    def queue_patch_pull_all(self) -> int:
        """Ask only peers likely to possess a newer compatible patch capsule."""
        if not KDK_PULL_ENABLED:
            self.activity_system("Patch pull is disabled")
            return 0
        try:
            current_raw = open(__file__, "rb").read()
            base_hash = sha256(current_raw)
            base_version = extract_script_version_from_bytes(current_raw)
            base_revision = extract_script_revision_from_bytes(current_raw)
        except Exception as e:
            self.activity_system(f"Patch pull failed: cannot identify local base ({e})")
            return 0

        peers, candidate_reason = self._update_pull_candidate_ids(
            base_version=base_version, base_revision=int(base_revision),
            max_peers=int(KDK_PULL_MAX_PEERS),
        )
        if not peers:
            self.log_event(
                f"[PULL] discovery skipped base={base_version} hash={base_hash[:16]} reason={candidate_reason}"
            )
            self.activity_system("Patch pull: no active peer is advertising a newer build")
            return 0
        rid = gen_rid()
        block = {
            "type": "kdk_chunk_pull", "enc": "plain",
            "data": {
                "kind": "KDK_CHUNK_PULL", "ver": 1, "mode": "latest-update",
                "request_id": rid, "object_id": "", "object_hash": "",
                "base_version": base_version, "base_revision": int(base_revision),
                "base_hash": base_hash, "ts": int(now_ts()),
            },
        }
        for peer_id in peers:
            self.outbound_queue.append((peer_id, [block], "KDK-PULL"))
        now = now_ts()
        self.pull_discovery_state = {
            "active": True, "attempts": 1, "last_ts": now,
            "base_version": base_version, "base_revision": int(base_revision), "base_hash": base_hash,
        }
        self.log_event(
            f"[PULL] discovery queued attempt=1/{int(KDK_PULL_DISCOVERY_MAX_ATTEMPTS)} peers={','.join(short8(x) for x in peers)} "
            f"base={base_version} hash={base_hash[:16]} candidates={candidate_reason} qlen={len(self.outbound_queue)}"
        )
        self.activity_system(f"Patch pull requested from {len(peers)} available peer{'s' if len(peers) != 1 else ''}")
        return len(peers)

    def maybe_retry_patch_discovery(self, now: Optional[float] = None):
        """Retry lossy latest-update discovery until a manifest arrives or the bounded attempt budget is exhausted."""
        if not KDK_PULL_ENABLED:
            return
        state = getattr(self, "pull_discovery_state", {}) or {}
        if not bool(state.get("active", False)):
            return
        now = now_ts() if now is None else float(now)
        if now - float(state.get("last_ts", 0.0) or 0.0) < float(KDK_PULL_DISCOVERY_RETRY_SECS):
            return
        attempts = int(state.get("attempts", 0) or 0)
        if attempts >= int(KDK_PULL_DISCOVERY_MAX_ATTEMPTS):
            state["active"] = False
            self.pull_discovery_state = state
            self.log_event(f"[PULL] discovery exhausted attempts={attempts}")
            self.activity_system("Patch pull discovery timed out; try Pull again")
            return
        peers, candidate_reason = self._update_pull_candidate_ids(
            base_version=str(state.get("base_version", "")),
            base_revision=int(state.get("base_revision", 0) or 0),
            max_peers=int(KDK_PULL_MAX_PEERS),
        )
        if not peers:
            state["last_ts"] = now
            self.pull_discovery_state = state
            self.log_event(f"[PULL] discovery retry skipped reason={candidate_reason}")
            return
        rid = gen_rid()
        block = {
            "type": "kdk_chunk_pull", "enc": "plain",
            "data": {
                "kind": "KDK_CHUNK_PULL", "ver": 1, "mode": "latest-update",
                "request_id": rid, "object_id": "", "object_hash": "",
                "base_version": str(state.get("base_version", "")),
                "base_revision": int(state.get("base_revision", 0) or 0),
                "base_hash": str(state.get("base_hash", "")), "ts": int(now),
            },
        }
        for peer_id in peers:
            self.outbound_queue.append((peer_id, [block], "KDK-PULL"))
        attempts += 1
        state["attempts"] = attempts
        state["last_ts"] = now
        self.pull_discovery_state = state
        self.log_event(
            f"[PULL] discovery retry attempt={attempts}/{int(KDK_PULL_DISCOVERY_MAX_ATTEMPTS)} "
            f"peers={','.join(short8(x) for x in peers)} candidates={candidate_reason} qlen={len(self.outbound_queue)}"
        )

    def maybe_send_chunk_pulls(self, now: Optional[float] = None):
        """Coarse phase: ask multiple peers for random chunks until the object condenses."""
        if not KDK_PULL_ENABLED:
            return
        now = now_ts() if now is None else float(now)
        for oid, rec in list(self.chunk_rx.items()):
            manifest = rec.get("manifest") if isinstance(rec, dict) else None
            if not isinstance(manifest, dict):
                continue
            hint = str(manifest.get("filename_hint", "") or "").lower()
            if not hint.startswith("kdk_update_"):
                continue
            try:
                total = int(manifest.get("chunk_count", 0) or 0)
                have = len(rec.get("chunks", {}) or {})
                if total <= 0 or have >= total:
                    continue
                fraction = float(have) / float(total)
                if fraction >= float(KDK_PULL_COARSE_FRACTION):
                    continue
                last_pull = float(rec.get("last_pull_ts", 0.0) or 0.0)
                if now - last_pull < float(KDK_PULL_INTERVAL_SECS):
                    continue
                # Receiver-aware coarse pulls: do not keep stacking new rounds while
                # older requests for this same object are still waiting to leave.
                # This matters most on slower nodes (for example Android/Termux),
                # where an 18-second timer can otherwise outrun earned-turn emission.
                queued_for_object = 0
                for qitem in list(self.outbound_queue):
                    try:
                        qdst, qblocks, qlabel = qitem
                        if str(qlabel) != "KDK-PULL":
                            continue
                        for qb in (qblocks or []):
                            qd = (qb.get("data", {}) or {}) if isinstance(qb, dict) else {}
                            if str(qd.get("mode", "")) == "object-random" and str(qd.get("object_id", "")) == str(oid):
                                queued_for_object += 1
                                break
                    except Exception:
                        continue
                if queued_for_object >= int(KDK_PULL_COARSE_BACKLOG_MAX):
                    self.log_event(
                        f"[PULL] coarse backpressure object={oid[:8]} have={have}/{total} "
                        f"pending={queued_for_object} limit={int(KDK_PULL_COARSE_BACKLOG_MAX)} qlen={len(self.outbound_queue)}"
                    )
                    rec["last_pull_ts"] = now
                    continue

                peers, candidate_reason = self._update_pull_candidate_ids(
                    rec=rec, manifest=manifest, max_peers=int(KDK_PULL_MAX_PEERS)
                )
                if not peers:
                    rec["last_pull_ts"] = now
                    self.log_event(
                        f"[PULL] coarse skipped object={oid[:8]} have={have}/{total} reason={candidate_reason}"
                    )
                    continue

                # A complete exact bitset is cheap for patch capsules: the capsule
                # ceiling is 50 kB and canonical chunks are 96 bytes, so even the
                # largest update needs only about 66 bytes of have-mask. Bit N-1
                # means chunk index N is already present at the receiver.
                have_mask = bytearray((total + 7) // 8)
                for idx in (rec.get("chunks", {}) or {}).keys():
                    try:
                        n = int(idx)
                        if 1 <= n <= total:
                            bit = n - 1
                            have_mask[bit // 8] |= (1 << (bit % 8))
                    except Exception:
                        continue

                block = {
                    "type": "kdk_chunk_pull", "enc": "plain",
                    "data": {
                        "kind": "KDK_CHUNK_PULL", "ver": 2, "mode": "object-random",
                        "request_id": gen_rid(), "object_id": oid,
                        "object_hash": str(manifest.get("object_hash", "")),
                        "have": have, "have_mask": bytes(have_mask),
                        "chunk_count": total, "ts": int(now),
                    },
                }
                for peer_id in peers:
                    self.outbound_queue.append((peer_id, [block], "KDK-PULL"))
                rec["last_pull_ts"] = now
                self.log_event(
                    f"[PULL] coarse object={oid[:8]} have={have}/{total} fraction={fraction:.2f} "
                    f"peers={','.join(short8(x) for x in peers)} candidates={candidate_reason} qlen={len(self.outbound_queue)}"
                )
            except Exception as e:
                self.log_event(f"[PULL] coarse failed object={str(oid)[:8]} err={type(e).__name__}: {e}")

    def chunk_handle_pull(self, src_id: str, data: dict):
        """Serve a pull opportunistically with a manifest and random chunk sample."""
        try:
            if not KDK_PULL_ENABLED:
                return
            if len(self.outbound_queue) >= int(KDK_PULL_BUSY_QUEUE) or self._repair_pending_count() >= int(KDK_REPAIR_WANT_DEFER_THRESHOLD):
                self.log_event(f"[PULL] busy skip from={short8(src_id)} q={len(self.outbound_queue)} repair={self._repair_pending_count()}")
                return
            mode = str(data.get("mode", "object-random") or "object-random")
            oid = str(data.get("object_id", "") or "")
            store = self.chunk_tx_store.get(oid) if oid else None

            # Restart-durable seeding: if an object-specific pull arrives after this
            # node has restarted, chunk_tx_store may be empty even though the exact
            # update capsule is still retained on disk. Rehydrate that known object
            # by matching its canonical update object id before falling back to the
            # normal latest-update discovery path.
            if not store and oid and mode == "object-random":
                for root in (KDK_UPDATE_SEED_DIR, KDK_UPDATE_INCOMING_DIR, KDK_UPDATE_APPLIED_DIR):
                    try:
                        names = os.listdir(root)
                    except Exception:
                        continue
                    for name in names:
                        path = os.path.join(root, name)
                        if not os.path.isfile(path):
                            continue
                        try:
                            bundle = open(path, "rb").read()
                            if len(bundle) > int(KDK_PATCH_CAPSULE_MAX_SIZE):
                                continue
                            meta = kdk_parse_canonical_capsule(bundle)
                            if meta.get("kind") != KDK_UPDATE_KIND:
                                continue
                            if self.update_object_id(bundle) != oid:
                                continue
                            oid, store = self._cache_update_seed_bundle(bundle)
                            self.log_event(
                                f"[PULL] rehydrated seeder object={oid[:8]} from={path}"
                            )
                            break
                        except Exception:
                            continue
                    if store:
                        break

            if not store and mode == "latest-update":
                req_base_version = str(data.get("base_version", "") or "")
                req_base_hash = str(data.get("base_hash", "") or "")
                store = self._update_seed_store_from_memory(req_base_version, req_base_hash)
                if store:
                    try:
                        oid = str(((store.get("manifest", {}) or {}).get("data", {}) or {}).get("object_id", ""))
                    except Exception:
                        oid = ""
                if not store:
                    bundle = self._update_seed_capsule_from_disk(
                        base_version=req_base_version,
                        base_hash=req_base_hash,
                    )
                    if bundle:
                        oid, store = self._cache_update_seed_bundle(bundle)
            if not store:
                self.log_event(f"[PULL] no-store from={short8(src_id)} object={oid[:8] if oid else 'latest'} mode={mode}")
                return
            manifest = store.get("manifest")
            by_idx = store.get("chunks", {}) or {}
            if not isinstance(manifest, dict) or not by_idx:
                return
            mdata = manifest.get("data", {}) if isinstance(manifest, dict) else {}
            real_oid = str(mdata.get("object_id", oid) or oid)
            requested_hash = str(data.get("object_hash", "") or "")
            if requested_hash and requested_hash != str(mdata.get("object_hash", "")):
                self.log_event(f"[PULL] hash mismatch from={short8(src_id)} object={real_oid[:8]}")
                return
            key = (str(src_id), real_oid)
            last = float(self.pull_last_serve.get(key, 0.0) or 0.0)
            if now_ts() - last < float(KDK_PULL_SERVE_COOLDOWN_SECS):
                return
            self.pull_last_serve[key] = now_ts()

            indexes = list(by_idx.keys())

            # receiver-aware sampling. If the requester supplied the
            # exact have-mask, remove chunks it already owns before randomising.
            # Older peers omit the field and retain the previous behaviour.
            have_mask = data.get("have_mask", b"")
            excluded = 0
            if isinstance(have_mask, (bytes, bytearray)) and have_mask:
                mask = bytes(have_mask)
                filtered = []
                for idx in indexes:
                    try:
                        n = int(idx)
                        bit = n - 1
                        already_have = (
                            bit >= 0 and bit // 8 < len(mask) and
                            bool(mask[bit // 8] & (1 << (bit % 8)))
                        )
                    except Exception:
                        already_have = False
                    if already_have:
                        excluded += 1
                    else:
                        filtered.append(idx)
                indexes = filtered

            random.shuffle(indexes)
            sample_n = min(len(indexes), max(1, int(KDK_PULL_RANDOM_BATCH))) if indexes else 0
            sample = indexes[:sample_n]
            # Manifest first, then a random sample drawn only from chunks the
            # receiver reports missing. Cross-seeder overlap can still occur when
            # replies race, but each later request reflects the receiver's newest
            # holdings and therefore converges quickly.
            self.outbound_queue.append((src_id, [manifest], "KDK-PULL-MANIFEST"))
            for idx in sample:
                self.outbound_queue.append((src_id, [by_idx[idx]], "KDK-PULL-DATA"))
            self.log_event(
                f"[PULL] served dst={short8(src_id)} object={real_oid[:8]} random={len(sample)}/{len(indexes)} "
                f"excluded_have={excluded} mode={mode} qlen={len(self.outbound_queue)}"
            )
        except Exception as e:
            self.log_event(f"[PULL] rejected from={short8(src_id)} err={type(e).__name__}: {e}")

    def chunk_handle_want(self, src_id: str, data: dict):
        """Handle a bounded WANT list by requeueing only requested chunks."""
        try:
            oid = str(data.get("object_id", ""))
            missing = data.get("missing", [])
            round_no = int(data.get("round", 0))
            if not oid or not isinstance(missing, list):
                raise ValueError("bad want")
            if len(missing) > KDK_WANT_MAX_MISSING:
                raise ValueError("too many missing indexes")
            store = self.chunk_tx_store.get(oid)
            if not store:
                self.log_event(f"[WANT] no-store from={short8(src_id)} object={oid[:8]} round={round_no} missing={len(missing)}")
                return
            by_idx = store.get("chunks", {})
            if bool(data.get("want_manifest", False)) and isinstance(store.get("manifest"), dict):
                self.outbound_queue.appendleft((src_id, [store["manifest"]], "KDK-MANIFEST-REPAIR"))
                self.log_event(f"[WANT] manifest repair queued dst={short8(src_id)} object={oid[:8]}")
            try:
                total_chunks_for_gate = int(store.get("chunk_count", 0) or len(by_idx) or int(data.get("chunk_count", 0) or 0))
            except Exception:
                total_chunks_for_gate = len(by_idx) if isinstance(by_idx, dict) else 0

            # first WANT must not immediately turn a fresh transfer
            # into pure repair mode.  If a larger object still has most of its
            # normal data sweep queued, defer this WANT and let the ordinary
            # chunk path continue.  Later WANT rounds will be accepted once the
            # normal queue is down to the tail/residue threshold.
            try:
                normal_remaining = self._normal_chunk_queue_count_for_object(oid, src_id)
                min_chunks = int(globals().get("KDK_REPAIR_EARLY_GATE_MIN_CHUNKS", 8))
                frac = float(globals().get("KDK_REPAIR_ALLOW_WHEN_REMAINING_FRACTION", 0.20))
                abs_tail = int(globals().get("KDK_REPAIR_ALLOW_WHEN_REMAINING_CHUNKS", 8))
                tail_threshold = max(abs_tail, int(math.ceil(max(0, total_chunks_for_gate) * frac)))
                if total_chunks_for_gate >= min_chunks and normal_remaining > tail_threshold:
                    self.log_event(
                        f"[WANT] early-defer from={short8(src_id)} object={oid[:8]} round={round_no} "
                        f"requested={len(missing)} normal_remaining={normal_remaining}/{total_chunks_for_gate} "
                        f"tail_threshold={tail_threshold}"
                    )
                    return
            except Exception as e:
                self.log_event(f"[WANT] early-gate check failed object={oid[:8]} err={type(e).__name__}: {e}")

            is_cuckoo = bool(store.get("cuckoo", False))
            release_heights = store.get("release_heights", {}) if is_cuckoo else {}
            consensus_h = 0
            if release_heights:
                try:
                    consensus_h = int(self.cuckoo_consensus_height())
                except Exception:
                    consensus_h = 0
            req = []
            future_locked = []
            for x in missing:
                try:
                    i = int(x)
                except Exception:
                    continue
                if i in by_idx:
                    if release_heights:
                        due = int(release_heights.get(i, 0) or 0)
                        if due > 0 and (consensus_h <= 0 or consensus_h < due):
                            future_locked.append(i)
                            continue
                    req.append(i)

            # never enter ordinary repair mode merely because the
            # receiver asked for future-locked Cuckoo chunks.  Scheduled Cuckoo
            # release copies must remain untouched in the normal queue/pending clock.
            if is_cuckoo and not req:
                self.log_event(
                    f"[WANT] cuckoo-future from={short8(src_id)} object={oid[:8]} round={round_no} "
                    f"requested={len(missing)} future={len(future_locked)} height={consensus_h}"
                )
                return

            # /dev16.34: a late WANT switches only this receiver/object pair into targeted
            # repair mode. Cuckoo objects deliberately skip this pruning path: their
            # timed release queue is protocol state, not an ordinary transfer tail.
            if not is_cuckoo:
                try:
                    getattr(self, "chunk_repair_mode_objects", set()).add((str(src_id), str(oid)))
                    pruned = self._prune_normal_chunk_queue_for_repair(oid, src_id)
                    if pruned:
                        self.log_event(f"[REPAIR_MODE] dst={short8(src_id)} object={oid[:8]} pruned_normal={pruned} qlen={len(self.outbound_queue)}")
                except Exception as e:
                    self.log_event(f"[REPAIR_MODE] enter failed dst={short8(src_id)} object={oid[:8]} err={type(e).__name__}: {e}")
            # De-duplicate while preserving caller's list, then shuffle to avoid creating
            # a visible sequence in the resend wave.
            req = list(dict.fromkeys(req))
            random.shuffle(req)

            # sender-side repair-wave backoff.  If we already have a
            # sizeable targeted repair set for this receiver/object, do not let
            # every incoming WANT packet refill the side-set immediately.  Let
            # the current wave drain and propagate first.  When the repair set
            # is near empty, accept the next WANT normally.
            try:
                pending_for = self._repair_pending_count_for(src_id, oid)
                inflight_for = self._repair_inflight_count_for(src_id, oid)
                last_accepts = getattr(self, "repair_want_last_accept", None)
                if last_accepts is None:
                    self.repair_want_last_accept = {}
                    last_accepts = self.repair_want_last_accept
                want_key = (str(src_id), oid)
                last_accept = float(last_accepts.get(want_key, 0.0) or 0.0)
                defer_threshold = int(globals().get("KDK_REPAIR_WANT_DEFER_THRESHOLD", 36))
                low_water = int(globals().get("KDK_REPAIR_WANT_DEFER_LOW_WATER", 8))
                defer_secs = float(globals().get("KDK_REPAIR_WANT_DEFER_SECS", 20.0))
                if pending_for > low_water and (pending_for >= defer_threshold or (now_ts() - last_accept) < defer_secs):
                    self.log_event(
                        f"[WANT] deferred from={short8(src_id)} object={oid[:8]} round={round_no} "
                        f"requested={len(missing)} pending={pending_for} inflight={inflight_for} "
                        f"defer={defer_secs:.0f}s"
                    )
                    return
                last_accepts[want_key] = now_ts()
            except Exception as e:
                self.log_event(f"[WANT] defer check failed object={oid[:8]} err={type(e).__name__}: {e}")

            # Final-residue reliability: if the requested set is small, emit the
            # same repair set more than once.  A tiny final residue gets one extra
            # bounded pass. This is sender-side only: no extra WANT chatter and no loop.
            repeats = 1
            try:
                if len(req) <= int(KDK_WANT_FINAL_RESCUE_MISSING):
                    repeats = max(1, int(KDK_WANT_FINAL_RESCUE_REPEATS))
                elif len(req) <= int(KDK_WANT_FINAL_DOUBLE_MISSING):
                    repeats = max(1, int(KDK_WANT_FINAL_REPEATS))
            except Exception:
                repeats = 1

            # repairs are coalesced by (dst, object, index).
            # Repeated WANTs refresh the pending set instead of inflating q.
            already = set()
            try:
                for (r_dst, r_oid, r_idx) in (getattr(self, "repair_pending", {}) or {}).keys():
                    if r_dst == src_id and r_oid == oid:
                        already.add(int(r_idx))
            except Exception:
                already = set()

            requeued = 0
            skipped_pending = 0
            # Repeats no longer create multiple queue entries; the same index
            # simply remains eligible until emitted.  Later WANT rounds refresh
            # the priority/age via _enqueue_repair_chunk.
            wave = list(req)
            random.shuffle(wave)
            skipped_inflight = 0
            for i in wave:
                if i in already:
                    skipped_pending += 1
                added = self._enqueue_repair_chunk(src_id, by_idx[i], round_no=round_no)
                if added:
                    requeued += 1
                else:
                    skipped_inflight += 1

            self.log_event(
                f"[WANT] recv from={short8(src_id)} object={oid[:8]} round={round_no} "
                f"requested={len(missing)} unique={len(req)} repeats={repeats} "
                f"requeued={requeued} skipped_pending={skipped_pending} skipped_inflight={skipped_inflight} "
                f"qlen={len(self.outbound_queue)} repair_pending={self._repair_pending_count()}"
            )
        except Exception as e:
            self.log_event(f"[WANT] rejected from={short8(src_id)} err={e}")

    def chunk_try_complete(self, object_id: str):
        rec = self.chunk_rx.get(object_id)
        if not rec or not rec.get("manifest"):
            return
        try:
            manifest = rec["manifest"]
            chunk_count = int(manifest.get("chunk_count", 0))
            chunks = rec.get("chunks", {})
            if len(chunks) < chunk_count or any(i not in chunks for i in range(chunk_count)):
                return

            blob = b"".join(chunks[i] for i in range(chunk_count))
            if len(blob) != int(manifest.get("total_size", -1)):
                raise ValueError("size mismatch")
            if sha256(blob) != str(manifest.get("object_hash", "")):
                raise ValueError("object hash mismatch")
            hint = str(manifest.get("filename_hint") or "object.bin")
            safe_hint = "".join(c for c in os.path.basename(hint) if c.isalnum() or c in ("-", "_", ".")) or "object.bin"
            out = os.path.join(KDK_CHUNK_COMPLETE_DIR, f"{object_id[:12]}_{safe_hint}")
            with open(out, "wb") as f:
                f.write(blob)
            self.log_event(f"[CHUNK] complete object={object_id[:8]} bytes={len(blob)} -> {out}")
            src_for_object = str(rec.get("src", ""))
            handled_special = False

            # A fully reconstructed patch immediately becomes a seeder source.
            # Preserve the exact canonical manifest/chunk map before chunk_rx is
            # discarded, so later peers can pull from this node without waiting
            # for a fresh push from Bootstrap.
            try:
                if safe_hint.lower().startswith("kdk_update_"):
                    by_idx = {int(i): {
                        "type": "kdk_chunk_data", "enc": "plain",
                        "data": {
                            "kind": "KDK_CHUNK_DATA", "ver": 3,
                            "object_id": object_id,
                            "object_hash": str(manifest.get("object_hash", "")),
                            "total_size": int(manifest.get("total_size", len(blob))),
                            "wire_chunk_size": int(manifest.get("wire_chunk_size", KDK_UPDATE_CANONICAL_WIRE_CHUNK_SIZE)),
                            "filename_hint": safe_hint,
                            "index": int(i), "chunk_count": chunk_count,
                            "data": chunks[int(i)],
                        },
                    } for i in range(chunk_count)}
                    self.chunk_tx_store[object_id] = {
                        "dst": "", "manifest": {"type": "kdk_chunk_manifest", "enc": "plain", "data": dict(manifest)},
                        "chunks": by_idx, "chunk_count": chunk_count, "created_ts": now_ts(),
                        "filename_hint": safe_hint, "is_update": True,
                    }
                    self.log_event(f"[PULL] seeder-ready object={object_id[:8]} chunks={chunk_count}")
            except Exception as e:
                self.log_event(f"[PULL] seeder cache failed object={object_id[:8]} err={type(e).__name__}: {e}")

            try:
                handled_special = bool(self.maybe_handle_update_bundle(blob, object_id, src_for_object))
            except Exception as e:
                self.log_event(f"[CHUNK] update dispatch failed object={object_id[:8]} err={e}")
                handled_special = False

            if not handled_special:
                try:
                    handled_special = bool(self.maybe_handle_airgap_key_object(blob, object_id, src_for_object))
                except Exception as e:
                    self.log_event(f"[CHUNK] cuckoo dispatch failed object={object_id[:8]} err={e}")
                    handled_special = False

            if not handled_special:
                try:
                    handled_special = bool(self.maybe_handle_airgap_ticket_object(blob, object_id, src_for_object))
                except Exception as e:
                    self.log_event(f"[CHUNK] airgap ticket dispatch failed object={object_id[:8]} err={e}")
                    handled_special = False

            if not handled_special:
                final_path = unique_destination("retrieved", safe_hint)
                atomic_write_verified(final_path, blob, str(manifest.get("object_hash", "")))
                try:
                    os.remove(out)
                except Exception:
                    pass
                self.activity_system(f"File received from {self.activity_peer_name(src_for_object)} ({safe_hint}, {len(blob)} bytes)")
                self.activity_system(f"Saved to {final_path}")
                self.log_event(f"[FILE] saved object={object_id[:8]} bytes={len(blob)} -> {final_path}")
            else:
                # Special objects are routed to their own durable location.
                try:
                    os.remove(out)
                except Exception:
                    pass
            self.chunk_completed[object_id] = now_ts()
            src_id = rec.get("src")
            if src_id:
                self.queue_reliable_receipt(
                    str(src_id), "KDK_CHUNK_RECEIPT", object_id,
                    str(manifest.get("object_hash", "")),
                    {"object_id": object_id, "object_hash": manifest.get("object_hash"),
                     "bytes": len(blob), "chunks": chunk_count, "filename_hint": safe_hint},
                )
            self.chunk_rx.pop(object_id, None)
        except Exception as e:
            self.log_event(f"[CHUNK] complete failed object={object_id[:8]} err={e}")
            rec = self.chunk_rx.get(object_id, {})
            src_for_object = str(rec.get("src", ""))
            manifest = rec.get("manifest") if isinstance(rec, dict) else None
            hint = str((manifest or {}).get("filename_hint") or object_id[:8])
            safe_hint = "".join(c for c in os.path.basename(hint) if c.isalnum() or c in ("-", "_", ".")) or object_id[:8]
            self.activity_system(
                f"Transfer failed from {self.activity_peer_name(src_for_object)} "
                f"({safe_hint}): {e}"
            )

    # ------------------------- Update over chunks ------------------------------

    def canonical_update_hash(self, raw: bytes) -> str:
        """Hash script bytes while ignoring per-node development identity fields.

        TEST_MARKER is intentionally local development metadata, so it must not
        make the same version patch validate differently on different nodes.
        """
        text = bytes(raw).decode("utf-8", "strict")
        text = re.sub(
            r'^TEST_MARKER\s*=\s*["\\\'][^"\\\']*["\\\']',
            'TEST_MARKER = "<KDK_NODE_LOCAL>"',
            text,
            count=1,
            flags=re.M,
        )
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def build_update_bundle(self, script_path: str, base_version: str = "", base_hash: str = "", base_path: str = "") -> bytes:
        """Build a deterministic external patch capsule.

        Correct updater rule:
            patch = diff(exact old/base bytes, exact new/target bytes)

        The sender must provide the exact old network file through --update-base-file
        (or an explicit base_path). The receiver accepts only when its current
        script hash equals the capsule's base_hash, and accepts the result only
        when it equals target_hash.
        """
        target_path = os.path.abspath(script_path or __file__)
        if not os.path.exists(target_path):
            raise ValueError(f"target update file not found: {target_path}")
        target_raw = open(target_path, "rb").read()
        if len(target_raw) <= 0 or len(target_raw) > KDK_UPDATE_MAX_SCRIPT_SIZE:
            raise ValueError(f"bad target script size {len(target_raw)}")

        base_path = str(base_path or getattr(self, "update_base_file", "") or "").strip()
        if not base_path:
            raise ValueError("no base file for exact patch capsule; set --update-base-file to the older version")
        base_path = os.path.abspath(base_path)
        if not os.path.exists(base_path):
            raise ValueError(f"base update file not found: {base_path}")
        base_raw = open(base_path, "rb").read()
        if len(base_raw) <= 0 or len(base_raw) > KDK_UPDATE_MAX_SCRIPT_SIZE:
            raise ValueError(f"bad base script size {len(base_raw)}")

        # If the receiver's advertised hash is known, refuse to create a patch
        # from the wrong ancestry.  Prefix matching keeps compatibility with
        # 16-char SCRIPT_HASH advertisements while the capsule itself stores
        # full 64-char hashes.
        if base_hash:
            real_base_hash = sha256(base_raw)
            if not real_base_hash.startswith(str(base_hash)):
                raise ValueError(
                    f"base file hash {real_base_hash[:16]} does not match receiver/base hash {str(base_hash)[:16]}"
                )
        if base_version:
            real_base_version = extract_script_version_from_bytes(base_raw)
            if version_cmp(real_base_version, str(base_version)) != 0:
                raise ValueError(f"base file version {real_base_version} != receiver/base version {base_version}")

        return kdk_make_text_span_capsule(base_raw, target_raw)

    def update_object_id(self, patch_bytes: bytes) -> str:
        """Object identity is the exact canonical patch bytes hash."""
        return sha256(bytes(patch_bytes))[:32]

    def update_seeders_for(self, script_version: str, script_hash: str, dst_id: str = "") -> list:
        """Return deterministic seeder set for a version update.

        Dev swarm rule: use all currently known active peers advertising the
        same script_version as this node, plus self.  We deliberately do not
        require script_hash here, because caps/hash learning can lag at startup
        and test builds may carry harmless local markers.  The receiving node
        still verifies the final bundle hash/version before staging/applying.

        dst_id is excluded so the older receiver never becomes a seeder slot.
        """
        seeders = {self.node_id}
        now = now_ts()
        target = str(dst_id or "")

        for nid, caps in list(getattr(self, "peer_caps", {}).items()):
            nid = str(nid)
            if not nid or nid == target or nid == self.node_id:
                continue
            if not isinstance(caps, dict):
                continue
            if str(caps.get("script_version", "")) != str(script_version):
                continue
            if not kdk_release_identity_matches(caps.get("script_origin", ""), caps.get("script_lineage", "")):
                continue
            try:
                if now - float(getattr(self, "active_nodes", {}).get(nid, 0.0)) > ACTIVE_TIMEOUT:
                    continue
            except Exception:
                pass
            seeders.add(nid)

        # If all same-version caps have not arrived yet, use a conservative
        # dev-mesh fallback: active known peers except the older receiver. This
        # prevents early offers from collapsing to slot 0/1 in local tests.
        if len(seeders) <= 1:
            for nid, ts in list(getattr(self, "active_nodes", {}).items()):
                nid = str(nid)
                if not nid or nid in (target, self.node_id):
                    continue
                try:
                    if now - float(ts) > ACTIVE_TIMEOUT:
                        continue
                except Exception:
                    pass
                seeders.add(nid)

        return sorted(seeders)

    def queue_update_offer_block(self, dst_id: str, bundle: bytes, reason: str = "manual") -> bool:
        """Announce an update using one ordinary KDK chunk manifest only.

        No bulk data is pushed. The capsule is cached/persisted locally as a
        seeder. Receipt of the familiar manifest creates receiver chunk state;
        the existing coarse Pull loop then requests random chunks from the mesh,
        and WANT handles only the final residue.
        """
        try:
            meta = kdk_parse_canonical_capsule(bytes(bundle))
            oid, store = self._cache_update_seed_bundle(bytes(bundle))
            manifest = store.get("manifest") if isinstance(store, dict) else None
            if not isinstance(manifest, dict):
                raise ValueError("cached update has no manifest")
            mdata = manifest.get("data", {}) or {}
            self.outbound_queue.append((dst_id, [manifest], "KDK-UPDATE-MANIFEST-OFFER"))
            self.log_event(
                f"[UPDATE] MANIFEST_OFFER queued dst={short8(dst_id)} object={oid[:8]} "
                f"target={str(meta.get('target_version','?'))} chunks={int(mdata.get('chunk_count',0) or 0)} "
                f"bytes={int(mdata.get('total_size',len(bundle)) or len(bundle))} "
                f"reason={reason} qlen={len(self.outbound_queue)}"
            )
            return True
        except Exception as e:
            self.log_event(
                f"[UPDATE] manifest-offer failed dst={short8(dst_id)} reason={reason} "
                f"err={type(e).__name__}: {e}"
            )
            return False

    def queue_update_to_peer(self, dst_id: str, script_path: str = "", reason: str = "manual", base_version: str = "", base_hash: str = "") -> bool:
        """Prepare/cache an exact capsule and announce it; bulk transfer is Pull-only."""
        try:
            path = str(script_path or getattr(self, "update_offer_file", "") or __file__)
            if not os.path.exists(path):
                self.log_event(f"[UPDATE] offer failed dst={short8(dst_id)} reason={reason} err=file_not_found path={path}")
                return False
            bundle = self.build_update_bundle(
                path,
                base_version=base_version,
                base_hash=base_hash,
                base_path=getattr(self, "update_base_file", ""),
            )
            meta = kdk_parse_canonical_capsule(bundle)
            remote_version = str(meta.get("target_version", "?"))
            if version_cmp(remote_version, SCRIPT_VERSION, meta.get("target_revision"), SCRIPT_REVISION) != 0:
                self.log_event(
                    f"[UPDATE] offer refused dst={short8(dst_id)} reason={reason} "
                    f"bundle_ver={remote_version} local={SCRIPT_VERSION} path={path}"
                )
                return False
            return self.queue_update_offer_block(dst_id, bundle, reason=reason)
        except Exception as e:
            self.log_event(f"[UPDATE] offer failed dst={short8(dst_id)} reason={reason} err={type(e).__name__}: {e}")
            return False

    def maybe_auto_offer_update(self, peer_id: str, peer_ver: str, peer_hash: str, peer_origin: str = "", peer_lineage: str = ""):
        """Offer our current script to an older peer once per peer/local version.

        This is deliberately only for strictly older peer versions. Same-version
        different-hash is a collision and must not trigger update.
        """
        policy = str(getattr(self, "update_policy", "off") or "off")
        if policy not in ("force-latest", "stage"):
            return
        if not kdk_release_identity_matches(peer_origin, peer_lineage):
            return
        if version_cmp(SCRIPT_VERSION, str(peer_ver)) <= 0:
            return
        offer_key = (str(peer_id), str(peer_ver), str(peer_hash), SCRIPT_VERSION, SCRIPT_HASH)
        seen = getattr(self, "update_offer_seen", set())
        if offer_key in seen:
            return
        try:
            seen.add(offer_key)
            self.update_offer_seen = seen
        except Exception:
            pass
        self.queue_update_to_peer(peer_id, script_path=str(getattr(self, "update_offer_file", "") or __file__), reason="auto-older-peer", base_version=str(peer_ver), base_hash=str(peer_hash))

    def _latest_update_file(self, directory: str, suffixes: tuple) -> str:
        """Return the newest regular file in an update directory matching suffixes."""
        try:
            ensure_dir(directory)
            candidates = []
            for fn in os.listdir(directory):
                path = os.path.join(directory, fn)
                if os.path.isfile(path) and fn.lower().endswith(tuple(x.lower() for x in suffixes)):
                    candidates.append(path)
            return max(candidates, key=os.path.getmtime) if candidates else ""
        except Exception:
            return ""

    def _latest_received_patch(self) -> str:
        return self._latest_update_file(KDK_UPDATE_INCOMING_DIR, (".kdkpatch", ".json"))

    def _latest_staged_patch(self) -> str:
        return self._latest_update_file(KDK_UPDATE_STAGED_DIR, (".py",))

    def _patch_file_record(self, path: str, state: str) -> Optional[dict]:
        """Return display metadata for one stored patch artefact."""
        try:
            raw = open(path, "rb").read()
            if path.lower().endswith((".kdkpatch", ".json")):
                meta = kdk_parse_canonical_capsule(raw)
                return {
                    "state": state,
                    "version": str(meta.get("target_version", "?") or "?"),
                    "revision": int(meta.get("target_revision", revision_from_version(str(meta.get("target_version", "")))) or 0),
                    "hash": str(meta.get("target_hash", "") or sha256(raw)),
                    "path": path,
                }
            return {
                "state": state,
                "version": extract_script_version_from_bytes(raw),
                "revision": extract_script_revision_from_bytes(raw),
                "hash": sha256(raw),
                "path": path,
            }
        except Exception:
            return None

    def activity_patch_candidates(self) -> list:
        """Return only currently actionable forward patch candidates.

        A staged build takes precedence over a received capsule for the same
        target hash. Older/current/superseded artefacts are kept out of the
        operational list and remain available through Patch History.
        """
        rows = []
        seen = set()
        current_revision = int(SCRIPT_REVISION)

        staged = self._latest_staged_patch()
        if staged:
            rec = self._patch_file_record(staged, "STAGED")
            if rec and int(rec.get("revision", 0)) > current_revision:
                rows.append(rec)
                seen.add(str(rec.get("hash", "")))

        try:
            ensure_dir(KDK_UPDATE_INCOMING_DIR)
            paths = [os.path.join(KDK_UPDATE_INCOMING_DIR, fn) for fn in os.listdir(KDK_UPDATE_INCOMING_DIR)]
            paths = [p for p in paths if os.path.isfile(p) and p.lower().endswith((".kdkpatch", ".json"))]
            for path in sorted(paths, key=os.path.getmtime, reverse=True):
                rec = self._patch_file_record(path, "RECEIVED")
                if not rec or int(rec.get("revision", 0)) <= current_revision:
                    continue
                th = str(rec.get("hash", ""))
                if th in seen:
                    continue
                seen.add(th)
                rows.append(rec)
        except Exception:
            pass
        return rows

    def activity_patch_history(self) -> list:
        """Return non-actionable patch artefacts for the operator history view."""
        rows = []
        active_paths = {str(c.get("path", "")) for c in self.activity_patch_candidates()}
        roots = (
            (KDK_UPDATE_INCOMING_DIR, "RECEIVED"),
            (KDK_UPDATE_STAGED_DIR, "STAGED"),
            (KDK_UPDATE_APPLIED_DIR, "APPLIED"),
            (KDK_UPDATE_REJECTED_DIR, "REJECTED"),
        )
        for root, state in roots:
            try:
                ensure_dir(root)
                for fn in os.listdir(root):
                    path = os.path.join(root, fn)
                    if not os.path.isfile(path) or path in active_paths:
                        continue
                    if root == KDK_UPDATE_STAGED_DIR and not path.lower().endswith(".py"):
                        continue
                    if root != KDK_UPDATE_STAGED_DIR and not path.lower().endswith((".kdkpatch", ".json")):
                        continue
                    rec = self._patch_file_record(path, state)
                    if rec:
                        rec["mtime"] = os.path.getmtime(path)
                        rows.append(rec)
            except Exception:
                pass
        rows.sort(key=lambda r: float(r.get("mtime", 0)), reverse=True)
        return rows

    def activity_clear_patch_history(self) -> None:
        """Delete history artefacts without touching current received/staged work."""
        history = self.activity_patch_history()
        removed = 0
        errors = 0
        for rec in history:
            try:
                os.remove(str(rec.get("path", "")))
                removed += 1
            except Exception:
                errors += 1
        self.activity_system(f"Patch history cleared: {removed} artefact(s) removed")
        if errors:
            self.activity_system(f"Patch history clear completed with {errors} warning(s)")
        self.log_event(f"[PATCH] HISTORY_CLEAR removed={removed} errors={errors}")

    def activity_patch_menu_entries(self) -> list:
        if bool(getattr(self, "activity_patch_history_open", False)):
            entries = [("history", c) for c in self.activity_patch_history()]
            entries.append(("action", "Clear History"))
            return entries
        entries = [("candidate", c) for c in self.activity_patch_candidates()]
        staged = next((c for c in self.activity_patch_candidates() if c.get("state") == "STAGED"), None)
        apply_label = f"Apply Staged: {staged.get('version')}" if staged else "Apply Staged Patch"
        entries += [("action", x) for x in ("Announce Patch", "Pull Patch", "Details", "Stage Patch", "Delete Patch", apply_label, "History")]
        return entries

    def activity_move_patch_mode(self, delta: int):
        entries = self.activity_patch_menu_entries()
        if entries:
            self.activity_patch_menu_index = (int(getattr(self, "activity_patch_menu_index", 0)) + int(delta)) % len(entries)

    def activity_patch_details(self):
        """Show metadata for the newest received capsule and staged candidate."""
        selected = str(getattr(self, "activity_patch_candidate_path", "") or "")
        incoming = selected if selected and os.path.isfile(selected) and selected.lower().endswith((".kdkpatch", ".json")) else self._latest_received_patch()
        staged = selected if selected and os.path.isfile(selected) and selected.lower().endswith(".py") else self._latest_staged_patch()
        if not incoming and not staged:
            self.activity_system("Patch details: no received or staged patch is available")
            return
        if incoming:
            try:
                raw = open(incoming, "rb").read()
                meta = kdk_parse_canonical_capsule(raw)
                self.activity_system(
                    f"Patch RECEIVED: {meta.get('base_version','?')} -> {meta.get('target_version','?')} "
                    f"({len(raw)} bytes)"
                )
                self.activity_system(f"Base SHA-256: {str(meta.get('base_hash',''))}")
                self.activity_system(f"Target SHA-256: {str(meta.get('target_hash',''))}")
                self.activity_system(f"Capsule SHA-256: {sha256(raw)}")
                note = str(meta.get("note", "") or "").strip()
                if note:
                    self.activity_system(f"Note: {note}")
                current_hash = sha256(open(__file__, "rb").read())
                compatible = (not meta.get("base_hash")) or str(meta.get("base_hash")) == current_hash
                self.activity_system(f"Local base match: {'YES' if compatible else 'NO'}")
            except Exception as e:
                self.activity_system(f"Patch details failed: {e}")
        if staged:
            try:
                raw = open(staged, "rb").read()
                self.activity_system(
                    f"Patch STAGED: {extract_script_version_from_bytes(raw)} "
                    f"SHA-256 {sha256(raw)}"
                )
            except Exception as e:
                self.activity_system(f"Staged patch details failed: {e}")

    def activity_stage_received_patch(self) -> bool:
        """Validate and reconstruct the newest received capsule without applying it."""
        selected = str(getattr(self, "activity_patch_candidate_path", "") or "")
        incoming = selected if selected and os.path.isfile(selected) and selected.lower().endswith((".kdkpatch", ".json")) else self._latest_received_patch()
        if not incoming:
            self.activity_system("No received patch is available to stage")
            return False
        try:
            capsule = open(incoming, "rb").read()
            meta = kdk_parse_canonical_capsule(capsule)
            current_raw = open(__file__, "rb").read()
            patched_raw, meta = kdk_apply_patch_capsule_to_bytes(current_raw, capsule)
            target_version = str(meta.get("target_version", extract_script_version_from_bytes(patched_raw)))
            target_hash = str(meta.get("target_hash", sha256(patched_raw)))
            safe_ver = "".join(c for c in target_version if c.isalnum() or c in ("-", "_", ".")) or "patch"
            staged_name = f"kdk64_patch_{safe_ver}_{target_hash[:12]}.py"
            staged_path = os.path.join(KDK_UPDATE_STAGED_DIR, staged_name)
            atomic_write_verified(staged_path, patched_raw, target_hash)
            self.log_event(f"[PATCH] MANUAL_STAGE target={target_version} hash={target_hash[:16]} -> {staged_path}")
            self.activity_system(f"Patch verified and STAGED: {target_version}")
            self.activity_system("No executable code has been applied")
            return True
        except Exception as e:
            self.activity_system(f"Patch staging failed: {e}")
            return False

    def activity_delete_received_patch(self) -> bool:
        """Delete the newest received candidate and its matching local seed copy."""
        selected = str(getattr(self, "activity_patch_candidate_path", "") or "")
        incoming = selected if selected and os.path.isfile(selected) and selected.lower().endswith((".kdkpatch", ".json")) else self._latest_received_patch()
        if not incoming:
            self.activity_system("No received patch is available to delete")
            return False
        try:
            basename = os.path.basename(incoming)
            raw = open(incoming, "rb").read()
            target_hash = ""
            try:
                target_hash = str(kdk_parse_canonical_capsule(raw).get("target_hash", ""))
            except Exception:
                pass
            os.remove(incoming)
            seed = os.path.join(KDK_UPDATE_SEED_DIR, basename)
            if os.path.isfile(seed):
                os.remove(seed)
            if target_hash:
                try:
                    getattr(self, "update_incoming_by_target_hash", {}).pop(target_hash, None)
                except Exception:
                    pass
            self.log_event(f"[PATCH] DELETED received={basename}")
            self.activity_system(f"Deleted received patch: {basename}")
            return True
        except Exception as e:
            self.activity_system(f"Patch delete failed: {e}")
            return False

    def activity_apply_staged_patch_interactive(self) -> bool:
        """Apply the newest staged candidate only after explicit operator confirmation."""
        staged = self._latest_staged_patch()
        if not staged:
            self.activity_system("No staged patch is available to apply")
            return False
        try:
            raw = open(staged, "rb").read()
            target_version = extract_script_version_from_bytes(raw)
            target_hash = sha256(raw)
            self.activity_system("!!! WARNING — PATCH CAPSULES MAY CONTAIN EXECUTABLE CODE !!!")
            self.activity_system("Integrity validation confirms the bytes, NOT their trustworthiness")
            self.activity_system(f"Applying will replace KryptDisk with {target_version} ({target_hash[:16]})")
            confirm = self.activity_readline_in_pane("Type APPLY to continue").strip()
            if confirm != "APPLY":
                self.activity_system("Patch apply cancelled")
                return False
            self.apply_staged_update(staged, target_version, target_hash)
            return True
        except Exception as e:
            self.activity_system(f"Patch apply failed: {e}")
            return False

    def activity_patch_execute_menu(self):
        """Execute the selected vertical Patch-menu entry."""
        entries = self.activity_patch_menu_entries()
        if not entries:
            self.activity_patch_menu_open = False
            return
        idx = int(getattr(self, "activity_patch_menu_index", 0)) % len(entries)
        kind, value = entries[idx]
        if kind == "candidate":
            self.activity_patch_candidate_path = str(value.get("path", ""))
            self.activity_system(f"Patch selected: {value.get('version','?')} ({value.get('state','?')})")
            return
        if kind == "history":
            self.activity_system(f"Patch history: {value.get('state','?')} {value.get('version','?')} {str(value.get('hash',''))[:12]}")
            return
        action = str(value)
        if action == "History":
            self.activity_patch_history_open = True
            self.activity_patch_menu_index = 0
            return
        if action == "Clear History":
            self.activity_clear_patch_history()
            self.activity_patch_menu_index = 0
            return
        self.activity_patch_menu_open = False
        if action == "Pull Patch":
            self.queue_patch_pull_all(); return
        if action == "Details":
            self.activity_patch_details(); return
        if action == "Stage Patch":
            self.activity_system("!!! WARNING — RECEIVED PATCHES MAY CONTAIN EXECUTABLE CODE !!!")
            self.activity_system("Staging validates/reconstructs the candidate but does NOT establish trust")
            self.activity_stage_received_patch(); return
        if action == "Delete Patch":
            self.activity_delete_received_patch(); return
        if action.startswith("Apply Staged"):
            self.activity_apply_staged_patch_interactive(); return
        if action != "Announce Patch":
            return
        self.activity_announce_patch_interactive()

    def activity_announce_patch_interactive(self):
        """Announce a capsule to the selected peer; only the path is prompted."""
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                dst = self.activity_current_recipient_id()
                if not dst:
                    self.activity_system("No recipient selected")
                    return
                path = self.activity_readline_in_pane("Patch capsule path").strip().strip('"')
                if not path:
                    self.activity_system("Patch announce cancelled")
                    return
                if not os.path.exists(path):
                    self.activity_system(f"Patch file not found: {path}")
                    return
                if path.lower().endswith((".kdkpatch", ".json")):
                    bundle = open(path, "rb").read()
                    meta = kdk_parse_canonical_capsule(bundle)
                else:
                    bundle = self.build_update_bundle(path, base_path=str(getattr(self, "update_base_file", "") or "").strip())
                    meta = kdk_parse_canonical_capsule(bundle)
                if not self.queue_update_offer_block(dst, bundle, reason="manual-manifest-offer"):
                    raise RuntimeError("could not queue update offer")
                remote_version = str(meta.get("target_version", "?") or "?")
                self.activity_system(f"Patch announced to {self.activity_peer_name(dst)}: {remote_version} ({len(bundle)} bytes)")
            except Exception as e:
                self.activity_system(f"Patch failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def maybe_handle_update_bundle(self, blob: bytes, object_id: str, src_id: str) -> bool:
        """Return True if blob was recognised as a KDK patch capsule."""
        try:
            if not isinstance(blob, (bytes, bytearray)):
                return False
            sample = bytes(blob[:64]).lstrip()
            if not sample.startswith(b"{"):
                return False
            bundle_probe = json.loads(bytes(blob).decode("utf-8", "strict"))
            if not isinstance(bundle_probe, dict) or bundle_probe.get("kind") != KDK_UPDATE_KIND:
                return False
            if len(bytes(blob)) > int(KDK_PATCH_CAPSULE_MAX_SIZE):
                raise ValueError(f"patch capsule too large {len(bytes(blob))} > {KDK_PATCH_CAPSULE_MAX_SIZE}; air-gap update required")
        except Exception:
            return False

        try:
            # Capsule bytes must be canonical; object_id must be the patch bytes hash.
            canonical_bundle = kdk_parse_canonical_capsule(bytes(blob))
            expected_object_id = self.update_object_id(bytes(blob))
            if object_id and str(object_id) != expected_object_id:
                self.log_event(
                    f"[PATCH_CAPSULE] object_id mismatch warning object={str(object_id)[:8]} "
                    f"expected={expected_object_id[:8]} from={short8(src_id)}"
                )

            target_version = str(canonical_bundle.get("target_version", "0.0"))
            target_revision = int(canonical_bundle.get("target_revision", revision_from_version(target_version)) or 0)
            target_hash = str(canonical_bundle.get("target_hash", ""))
            base_version = str(canonical_bundle.get("base_version", ""))
            base_revision = int(canonical_bundle.get("base_revision", revision_from_version(base_version)) or 0)
            base_hash = str(canonical_bundle.get("base_hash", ""))
            safe_ver = "".join(c for c in target_version if c.isalnum() or c in ("-", "_", ".")) or "patch"
            incoming_name = f"kdk_update_{safe_ver}_{expected_object_id[:12]}.kdkpatch"
            # Keep one deterministic canonical seed copy independent of staging/applied
            # moves so this node remains a restart-durable seeder after promotion.
            seed_path = os.path.join(KDK_UPDATE_SEED_DIR, incoming_name)
            atomic_write_verified(seed_path, bytes(blob), sha256(bytes(blob)))
            incoming_path = unique_destination(KDK_UPDATE_INCOMING_DIR, incoming_name)
            atomic_write_verified(incoming_path, bytes(blob), sha256(bytes(blob)))
            self.update_incoming_by_target_hash = getattr(self, "update_incoming_by_target_hash", {})
            self.update_incoming_by_target_hash[target_hash] = incoming_path
            self.activity_system(
                f"Patch received from {self.activity_peer_name(src_id)} "
                f"({target_version}, {len(bytes(blob))} bytes)"
            )

            target_origin = str(canonical_bundle.get("target_origin", "") or "")
            target_lineage = str(canonical_bundle.get("target_lineage", "") or "")
            base_origin = str(canonical_bundle.get("base_origin", "") or "")
            base_lineage = str(canonical_bundle.get("base_lineage", "") or "")
            if not kdk_release_identity_matches(target_origin, target_lineage):
                raise ValueError(
                    f"patch target lineage {target_origin or '?'}:{target_lineage or '?'} "
                    f"does not match local {SCRIPT_ORIGIN}:{SCRIPT_LINEAGE}"
                )
            if not kdk_release_identity_matches(base_origin, base_lineage):
                raise ValueError(
                    f"patch base lineage {base_origin or '?'}:{base_lineage or '?'} "
                    f"does not match local {SCRIPT_ORIGIN}:{SCRIPT_LINEAGE}"
                )

            current_raw = open(__file__, "rb").read()
            current_hash = hashlib.sha256(current_raw).hexdigest()
            current_version = extract_script_version_from_bytes(current_raw)

            # Tiny digest ledger: remember accepted target hashes and reject
            # automatic rollback to an older known hash unless explicitly allowed.
            digest_path = KDK_HASH_DIGEST_PATH
            kdk_record_hash_digest(digest_path, current_hash, current_version)

            # classify the capsule by TARGET before checking BASE.
            # After an auto-restart, late chunks from the just-applied old->new
            # capsule may finish reassembling. The new core no longer matches that
            # capsule's base hash, but that is not an update failure: its target is
            # already current. Treat exact-current and older stragglers benignly.
            current_revision = extract_script_revision_from_bytes(current_raw)
            cmpv = version_cmp(target_version, current_version, target_revision, current_revision)
            if cmpv == 0 and target_hash == current_hash:
                self.log_event(
                    f"[PATCH] duplicate already-current target={target_version} "
                    f"object={object_id[:8]} from={short8(src_id)}"
                )
                self.activity_system(f"Patch duplicate ignored: already running {target_version}")
                applied_path = unique_destination(KDK_UPDATE_APPLIED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, applied_path)
                return True
            if cmpv < 0:
                self.log_event(
                    f"[PATCH] stale target ignored target={target_version} local={current_version} "
                    f"object={object_id[:8]} from={short8(src_id)}"
                )
                self.activity_system(f"Patch ignored: {target_version} is older than this node")
                rejected_path = unique_destination(KDK_UPDATE_REJECTED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, rejected_path)
                self.activity_system(f"Moved to {rejected_path}")
                return True

            if (
                target_hash
                and target_hash != current_hash
                and kdk_hash_digest_seen(digest_path, target_hash)
                and not bool(getattr(self, "update_allow_rollback", False))
            ):
                self.log_event(
                    f"[PATCH] rollback rejected object={object_id[:8]} from={short8(src_id)} "
                    f"target={target_version} hash={target_hash[:16]}"
                )
                self.activity_system(f"Patch rejected: rollback to {target_version} is not allowed")
                rejected_path = unique_destination(KDK_UPDATE_REJECTED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, rejected_path)
                self.activity_system(f"Moved to {rejected_path}")
                return True

            # Only genuinely forward candidates reach ancestry validation.
            if base_hash and current_hash != base_hash:
                self.log_event(
                    f"[PATCH] base mismatch object={object_id[:8]} from={short8(src_id)} "
                    f"base={base_hash[:16]} current={current_hash[:16]}"
                )
                self.activity_system(f"Patch failed: base hash mismatch for {target_version}")
                rejected_path = unique_destination(KDK_UPDATE_REJECTED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, rejected_path)
                self.activity_system(f"Moved to {rejected_path}")
                return True
            if base_version and version_cmp(current_version, base_version, current_revision, base_revision) != 0:
                self.log_event(
                    f"[PATCH] base version mismatch object={object_id[:8]} from={short8(src_id)} "
                    f"base={base_version} current={current_version}"
                )
                self.activity_system(f"Patch failed: requires {base_version}, current version is {current_version}")
                rejected_path = unique_destination(KDK_UPDATE_REJECTED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, rejected_path)
                self.activity_system(f"Moved to {rejected_path}")
                return True

            policy = str(getattr(self, "update_policy", "manual") or "manual")
            if policy in ("off", "manual"):
                self.log_event(
                    f"[PATCH] RECEIVED target={target_version} local={SCRIPT_VERSION} "
                    f"policy={policy} staged=no from={short8(src_id)} object={object_id[:8]}"
                )
                self.activity_system("!!! WARNING — PATCH CAPSULES MAY CONTAIN EXECUTABLE CODE !!!")
                self.activity_system("Integrity validation confirms the received bytes, NOT their trustworthiness")
                self.activity_system("Status: RECEIVED — NOT STAGED. Use Patch > Details / Stage / Delete")
                return True

            patched_raw, bundle = kdk_apply_patch_capsule_to_bytes(current_raw, bytes(blob))
            embedded_version = extract_script_version_from_bytes(patched_raw)
            if embedded_version != target_version:
                raise ValueError(f"patched version mismatch {embedded_version!r} != {target_version!r}")

            staged_name = f"kdk64_patch_{safe_ver}_{target_hash[:12]}.py"
            staged_path = os.path.join(KDK_UPDATE_STAGED_DIR, staged_name)
            with open(staged_path, "wb") as f:
                f.write(patched_raw)
            self.log_event(
                f"[PATCH] STAGED target={target_version} local={SCRIPT_VERSION} "
                f"from={short8(src_id)} object={object_id[:8]} ops={len(bundle.get('ops', []))} -> {staged_path}"
            )
            self.activity_system(f"Patch verified and staged successfully ({target_version})")

            if bool(getattr(self, "update_auto_apply", False)) and policy == "force-latest":
                self.log_event(
                    f"[PATCH] AUTO_APPLY target={target_version} object={object_id[:8]} hash={target_hash[:16]}"
                )
                self.apply_staged_update(staged_path, target_version, target_hash)
            return True
        except Exception as e:
            self.log_event(f"[PATCH] rejected object={object_id[:8]} from={short8(src_id)} err={e}")
            try:
                if 'incoming_path' in locals() and os.path.exists(incoming_path):
                    rejected_path = unique_destination(KDK_UPDATE_REJECTED_DIR, os.path.basename(incoming_path))
                    os.replace(incoming_path, rejected_path)
                    self.activity_system(f"Patch rejected; moved to {rejected_path}")
            except Exception:
                pass
            self.activity_system(f"Patch failed from {self.activity_peer_name(src_id)}: {e}")
            return True

    def apply_staged_update(self, staged_path: str, remote_version: str, remote_hash: str):
        """Promote a verified staged build and request one graceful restart path.

        Promotion is atomic, but relaunch is deliberately deferred until run()
        has completed shutdown_cleanup(). This prevents inherited/busy sockets,
        unsaved state and damaged terminal modes on every supported platform.
        """
        target = os.path.abspath(__file__)
        ensure_dir(KDK_UPDATE_BACKUP_DIR)
        with open(target, "rb") as f:
            old = f.read()
        previous_hash = hashlib.sha256(old).hexdigest()
        backup = unique_destination(
            KDK_UPDATE_BACKUP_DIR,
            f"{os.path.basename(target)}.{SCRIPT_VERSION}.{previous_hash[:12]}.bak",
        )
        atomic_write_verified(backup, old, previous_hash)

        with open(staged_path, "rb") as f:
            new = f.read()
        if hashlib.sha256(new).hexdigest() != remote_hash:
            raise ValueError("staged hash changed before apply")

        atomic_write_verified(target, new, remote_hash)
        applied_hash = hashlib.sha256(open(target, "rb").read()).hexdigest()
        if applied_hash != remote_hash:
            atomic_write_verified(target, old, previous_hash)
            raise ValueError("applied hash mismatch after atomic replace; previous build restored")

        kdk_record_hash_digest(KDK_HASH_DIGEST_PATH, previous_hash, extract_script_version_from_bytes(old))
        kdk_record_hash_digest(KDK_HASH_DIGEST_PATH, applied_hash, remote_version)
        try:
            incoming_map = getattr(self, "update_incoming_by_target_hash", {}) or {}
            incoming_path = incoming_map.get(remote_hash)
            if incoming_path and os.path.exists(incoming_path):
                applied_capsule = unique_destination(KDK_UPDATE_APPLIED_DIR, os.path.basename(incoming_path))
                os.replace(incoming_path, applied_capsule)
        except Exception as e:
            self.log_event(f"[UPDATE] applied capsule archive warning err={e}")

        restart_record = {
            "format": 1,
            "created": int(time.time()),
            "target_path": target,
            "backup_path": os.path.abspath(backup),
            "previous_version": SCRIPT_VERSION,
            "previous_hash": previous_hash,
            "target_version": str(remote_version),
            "target_hash": str(applied_hash),
            "launch": kdk_runtime_launch_spec(),
        }
        self._pending_update_restart = restart_record
        self.log_event(
            f"[UPDATE] PROMOTED remote={remote_version} hash={applied_hash[:16]} "
            f"backup={backup}; restart={bool(getattr(self, 'update_auto_restart', True))}"
        )

        if bool(getattr(self, "update_auto_restart", True)):
            self.activity_system(f"Patch promoted ({remote_version}); closing cleanly before restart")
            self.request_shutdown("update-restart", remote_version)
            return

        self.activity_system(f"Patch promoted ({remote_version}); restart required")
        qprint(f"[UPDATE] applied {remote_version} hash={applied_hash[:16]}; restart/relaunch this node")
        self._pending_update_restart = None
        self.request_shutdown("update-manual-restart", remote_version)

    # ------------------------- Reliable delivery state -------------------------

    def reliability_load_state(self):
        try:
            with open(KDK_RELIABILITY_STATE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            self.pending_messages = dict(data.get("pending_messages", {}) or {})
            self.pending_receipts = dict(data.get("pending_receipts", {}) or {})
            self.delivered_message_ids = {str(k): float(v) for k, v in dict(data.get("delivered_message_ids", {}) or {}).items()}
            self.received_receipt_ids = {str(k): float(v) for k, v in dict(data.get("received_receipt_ids", {}) or {}).items()}
        except FileNotFoundError:
            return
        except Exception as e:
            self.log_event(f"[RELIABLE] state load failed err={type(e).__name__}: {e}")

    def reliability_save_state(self):
        try:
            ensure_dir(KDK_RELIABILITY_DIR)
            data = {
                "pending_messages": self.pending_messages,
                "pending_receipts": self.pending_receipts,
                "delivered_message_ids": self.delivered_message_ids,
                "received_receipt_ids": self.received_receipt_ids,
            }
            tmp = KDK_RELIABILITY_STATE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, sort_keys=True, separators=(",", ":"))
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp, KDK_RELIABILITY_STATE_PATH)
        except Exception as e:
            self.log_event(f"[RELIABLE] state save failed err={type(e).__name__}: {e}")

    def _reliable_next_delay(self, attempts: int) -> float:
        delays = tuple(float(x) for x in KDK_RETRY_DELAYS_SECS)
        i = max(0, min(len(delays) - 1, int(attempts) - 1))
        return delays[i] * random.uniform(0.85, 1.20)

    def _queue_reliable_record(self, rec: dict, label: str):
        dst = str(rec.get("dst", ""))
        block = rec.get("block")
        if dst and isinstance(block, dict):
            self.outbound_queue.append((dst, [block], label))
            rec["attempts"] = int(rec.get("attempts", 0)) + 1
            rec["last_attempt_ts"] = now_ts()
            rec["next_attempt_ts"] = now_ts() + self._reliable_next_delay(int(rec["attempts"]))
            return True
        return False

    def maybe_retry_reliable_traffic(self, now: Optional[float] = None):
        now = now_ts() if now is None else float(now)
        changed = False
        for table_name, label in (("pending_messages", "MESSAGE-RETRY"), ("pending_receipts", "RECEIPT-RETRY")):
            table = getattr(self, table_name, {})
            for logical_id, rec in list(table.items()):
                created = float(rec.get("created_ts", now) or now)
                if now - created > float(KDK_RELIABLE_MAX_AGE_SECS):
                    self.log_event(f"[RELIABLE] expired kind={table_name} id={str(logical_id)[:8]} attempts={rec.get('attempts',0)}")
                    table.pop(logical_id, None)
                    changed = True
                    continue
                if now < float(rec.get("next_attempt_ts", 0.0) or 0.0):
                    continue
                if self._queue_reliable_record(rec, label):
                    self.log_event(f"[RELIABLE] retry kind={table_name} id={str(logical_id)[:8]} attempt={rec.get('attempts')} dst={short8(rec.get('dst',''))}")
                    changed = True
        cutoff = now - float(KDK_DELIVERED_CACHE_TTL_SECS)
        for table_name in ("delivered_message_ids", "received_receipt_ids"):
            table = getattr(self, table_name, {})
            for key, ts in list(table.items()):
                if float(ts or 0.0) < cutoff:
                    table.pop(key, None)
                    changed = True
            if len(table) > int(KDK_DELIVERED_CACHE_MAX):
                for key, _ts in sorted(table.items(), key=lambda kv: float(kv[1]))[:-int(KDK_DELIVERED_CACHE_MAX)]:
                    table.pop(key, None)
                    changed = True
        if changed:
            self.reliability_save_state()

    def build_receipt_ack_block(self, receipt_id: str) -> dict:
        return {"type": "receipt_ack", "enc": "plain", "data": {
            "kind": "KDK_RECEIPT_ACK", "receipt_id": str(receipt_id),
            "ts": int(now_ts()), "from": self.name,
        }}

    def queue_reliable_receipt(self, dst_id: str, kind: str, subject_id: str,
                               subject_hash: str = "", extra: Optional[dict] = None):
        if not ENABLE_RECEIPTS or not dst_id or not subject_id:
            return False
        receipt_id = sha256(f"{kind}|{subject_id}|{subject_hash}|{self.node_id}|{dst_id}".encode())[:32]
        data = {
            "kind": str(kind), "receipt_id": receipt_id,
            "subject_id": str(subject_id), "subject_hash": str(subject_hash or ""),
            "status": "DELIVERED", "ts": int(now_ts()), "from": self.name,
        }
        if isinstance(extra, dict):
            data.update(extra)
        block = {"type": "receipt", "enc": "plain", "data": data}
        rec = self.pending_receipts.get(receipt_id)
        if not isinstance(rec, dict):
            rec = {"dst": str(dst_id), "block": block, "created_ts": now_ts(), "attempts": 0, "next_attempt_ts": 0.0}
            self.pending_receipts[receipt_id] = rec
        else:
            rec["block"] = block
            rec["dst"] = str(dst_id)
            rec["next_attempt_ts"] = 0.0
        self._queue_reliable_record(rec, "RECEIPT")
        self.receipt_sent_count += 1
        self.reliability_save_state()
        self.log_event(f"[QUEUE] reliable receipt kind={kind} dst={short8(dst_id)} subject={str(subject_id)[:8]} rid={receipt_id[:8]} qlen={len(self.outbound_queue)}")
        self.trace_payload(
            "RECEIPT_QUEUE", "", kind=str(kind), dst=short8(dst_id),
            subject_id=str(subject_id)[:32], rid=receipt_id[:32]
        )
        return True

    # ------------------------- Message / receipt test layer --------------------

    def random_message_text(self) -> str:
        phrases = [
            "relay stable",
            "mesh alive",
            "collision observed",
            "beacon received",
            "vault reachable",
            "fanout complete",
            "quorum pending",
            "diffusion active",
        ]
        return f"{self.name} says {random.choice(phrases)} at {int(now_ts())}"

    def build_message_block(self, text: str, message_id: str = "") -> dict:
        text = kdk_canonicalize_message_text(text)
        message_id = str(message_id or os.urandom(16).hex())
        return {
            "type": "message",
            "enc": "plain",
            "data": {
                "kind": "KDK_MESSAGE",
                "ver": 2,
                "message_id": message_id,
                "message_hash": sha256(text.encode("utf-8", "ignore")),
                "text": text,
                "ts": int(now_ts()),
                "from": self.name,
            },
        }

    def build_receipt_block(self, sid_hex: str) -> dict:
        # Legacy compatibility for pre-10.20.15 peers.
        return {
            "type": "receipt",
            "enc": "plain",
            "data": {"kind": "MESSAGE_RECEIPT", "sid": sid_hex, "ts": int(now_ts()), "from": self.name},
        }

    def pick_random_directable_peer(self) -> Optional[str]:
        now = now_ts()
        eligible = []

        for nid, ts in self.active_nodes.items():
            if nid == self.node_id:
                continue
            if self.peer_is_suspended(nid):
                continue
            if now - ts > ACTIVE_TIMEOUT:
                continue

            caps = self.peer_caps.get(nid, {})
            if not (isinstance(caps, dict) and caps.get("env")):
                continue

            if nid not in self.peer_keys:
                continue

            eligible.append(nid)

        if not eligible:
            return None

        return random.choice(eligible)

    def queue_message_to_peer(self, dst: str, text: str):
        if not dst:
            qprint("[SEND] no recipient")
            return False
        if self.peer_is_suspended(dst):
            self.activity_system(f"Direct messaging unavailable: {self.activity_peer_name(dst)} is {self.peer_policy_state(dst)}")
            return False
        text = kdk_canonicalize_message_text(text)
        if not text:
            text = self.random_message_text()
        count = len(text)
        if count > KDK_MESSAGE_MAX_CHARS:
            notice = (
                f"Message too long ({count}/{KDK_MESSAGE_MAX_CHARS} characters). "
                "Send as a file or split into shorter messages."
            )
            qprint(f"[SEND] {notice}")
            self.activity_system(notice)
            return False
        block = self.build_message_block(text)
        # build_message_block canonicalises too; use its exact text for logging/UI.
        text = str((block.get("data", {}) or {}).get("text", ""))
        message_id = str((block.get("data", {}) or {}).get("message_id", ""))
        # Character count is the user-facing rule, but UTF-8-heavy text can still
        # exceed the fixed encrypted frame. Probe the exact no-hint envelope now
        # so an impossible message never enters reliability/outbound queues.
        try:
            self._build_encrypted_frame(dst, [block], include_peer_hint=False)
        except ValueError as exc:
            if "Body too large for frame" not in str(exc):
                raise
            notice = (
                "Message is too large for a single KryptDisk frame. "
                "Send as a file or split into shorter messages."
            )
            qprint(f"[SEND] {notice}")
            self.activity_system(notice)
            return False
        rec = {"dst": str(dst), "block": block, "created_ts": now_ts(), "attempts": 0, "next_attempt_ts": 0.0}
        self.pending_messages[message_id] = rec
        self._queue_reliable_record(rec, "MESSAGE")
        self.reliability_save_state()
        self.log_event(
            f"[QUEUE] message src={short8(self.node_id)} dst={short8(dst)} "
            f"mid={message_id[:8]} qlen={len(self.outbound_queue)} text={text!r}"
        )
        recipient_name = self.activity_peer_name(dst)
        self.activity_message(f"{self.name} → {recipient_name}", text)
        return True

    def queue_random_message(self):
        dst = self.pick_random_directable_peer()
        if not dst:
            qprint("[SEND] no eligible peer")
            return
        self.queue_message_to_peer(dst, self.random_message_text())

    def send_menu_interactive(self):
        """Minimal structured-console send prompt.

        This intentionally uses ordinary blocking input rather than curses.
        It gives the user a clear peer choice and text/file option while keeping
        the engine and terminal behaviour simple.
        """
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                qprint("\n+---------------- SEND ----------------+")
                dst = self.pick_peer_interactive("SEND")
                if not dst:
                    qprint("+-------------- CANCELLED -------------+")
                    return
                mode = input("[SEND] [t]ext or [f]ile? (default=t): ").strip().lower() or "t"
                if mode.startswith("f"):
                    path = input(f"[SEND] file path <= {KDK_OBJECT_MAX_SIZE} bytes: ").strip().strip('"')
                    if not path or not os.path.exists(path):
                        qprint("[SEND] file not found")
                        return
                    data = open(path, "rb").read()
                    if len(data) > KDK_OBJECT_MAX_SIZE:
                        qprint(f"[SEND] file too large: {len(data)} > {KDK_OBJECT_MAX_SIZE}")
                        return
                    self._queue_or_defer_user_file(dst, data, path)
                else:
                    text = input("[SEND] text: ")
                    self.queue_message_to_peer(dst, text)
                qprint("+-------------- QUEUED ----------------+")
            except Exception as e:
                qprint(f"[SEND] failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def queue_receipt(self, dst_id: str, sid: Any):
        # Legacy envelope-SID receipt retained for older peers.
        if not ENABLE_RECEIPTS:
            return False
        sid_hex = sid.hex() if isinstance(sid, (bytes, bytearray)) else str(sid)
        block = self.build_receipt_block(sid_hex)
        self.outbound_queue.append((dst_id, [block], "RECEIPT-LEGACY"))
        self.receipt_sent_count += 1
        return True

    def maybe_release_rate_limited_rpcs_on_collision(self):
        any_ready = []
        for rid, meta in list(self.pending_rpcs.items()):
            if meta.get("state") != "RATE_LIMIT":
                continue
            cd = int(meta.get("cooldown_collisions", 1))
            cd = max(0, cd - 1)
            meta["cooldown_collisions"] = cd
            self.pending_rpcs[rid] = meta
            if cd <= 0:
                any_ready.append(rid)

        if not any_ready:
            return

        best_rid = None
        best_ts = None
        for rid in any_ready:
            ts = self.pending_rpcs.get(rid, {}).get("ts", 0.0)
            try:
                ts = float(ts)
            except Exception:
                ts = 0.0
            if best_ts is None or ts < best_ts:
                best_ts = ts
                best_rid = rid

        if not best_rid:
            return

        meta = self.pending_rpcs.get(best_rid)
        if not meta:
            return

        cmd = meta.get("cmd", "?")
        dst = meta.get("dst")
        args = meta.get("args", {}) or {}
        if not isinstance(args, dict):
            args = {}

        if not isinstance(dst, str) or not dst:
            self.pending_rpcs.pop(best_rid, None)
            return

        meta["state"] = "PENDING"
        meta["sent_ts"] = None
        meta.pop("cooldown_collisions", None)
        self.pending_rpcs[best_rid] = meta

        blocks = self._rpc_blocks(cmd, best_rid, args)
        self.outbound_queue.append((dst, blocks, "RPC-RATE-RESEND"))

    def _make_frame(self, body_bytes: bytes) -> bytes:
        blen = len(body_bytes)
        if blen > MAX_FRAME_SIZE - 2:
            raise ValueError("Body too large for frame")
        prefix = blen.to_bytes(2, "big")
        padding = os.urandom(MAX_FRAME_SIZE - 2 - blen)
        return prefix + body_bytes + padding

    def make_dummy_frame(self) -> bytes:
        body_len = random.randint(64, MAX_FRAME_SIZE - 2)
        body = os.urandom(body_len)
        return self._make_frame(body)

    def envelope_v3_sign(self, env: dict) -> bytes:
        tmp = dict(env)
        tmp.pop("sig", None)
        packed = msgpack.packb(tmp, use_bin_type=True)
        return self.signing_key.sign(packed).signature

    def envelope_v3_verify(self, env: dict, sender_vk_bytes: bytes) -> None:
        sig = env.get("sig", b"")
        tmp = dict(env)
        tmp.pop("sig", None)
        packed = msgpack.packb(tmp, use_bin_type=True)
        VerifyKey(sender_vk_bytes).verify(packed, sig)

    # ------------------------- Peer hints v10.19 -------------------------------

    def _peer_hint_addr_for_node(self, node_id: str) -> Optional[Tuple[str, int]]:
        """Return a recently learned address for node_id, if we have one."""
        for addr, nid in list(self.peer_id_by_addr.items()):
            if nid == node_id:
                return addr
        return None

    def _caps_hash(self, caps: Any) -> str:
        try:
            packed = msgpack.packb(caps if isinstance(caps, dict) else {}, use_bin_type=True)
            return sha256(packed)[:12]
        except Exception:
            return ""

    def build_peer_hint_block(self, dst_id: str = "") -> Optional[dict]:
        """Build a small encrypted peer-hint block for every decryptable envelope.

        Important invariants:
          - this block is only ever inside KD-ENVELOPE v3 ciphertext;
          - raw dummy payloads do not carry hints;
          - the hint set is a random slice, never the full peer table;
          - a --advertise-addr self hint may be included so semi-isolated
            nodes can be absorbed into ordinary Brownian fanout.
        """
        if not getattr(self, "peer_hint_enabled", ENABLE_PEER_HINTS):
            return None

        now = now_ts()
        peers = []

        # Optional self-advertisement.  This is not a direct reply route; it is
        # just another encrypted hint that receivers may later probe and add to
        # their ordinary randomized fanout candidates.
        adv = getattr(self, "advertise_addr", None)
        if isinstance(adv, tuple) and len(adv) == 2:
            host, port = adv
            if host and isinstance(port, int):
                peers.append({
                    "id": self.node_id,
                    "a": f"{host}:{int(port)}",
                    "t": int(now),
                    "q": str(getattr(self, "last_quorum_digest", "") or "")[:12],
                    "ch": self._caps_hash(self.caps),
                    "self": True,
                })

        candidates = []
        for nid, ts in list(self.active_nodes.items()):
            if nid == self.node_id or nid == dst_id:
                continue
            try:
                if now - float(ts) > PEER_HINT_TTL_SECS:
                    continue
            except Exception:
                continue
            addr = self._peer_hint_addr_for_node(nid)
            if not addr:
                continue
            host, port = addr
            if not host or not isinstance(port, int):
                continue
            candidates.append((nid, host, port, float(ts)))

        random.shuffle(candidates)
        # Keep the whole hint block small and stochastic.  If a self hint exists,
        # it occupies one slot; the remaining slots are a random peer slice.
        slots_left = max(0, int(PEER_HINT_MAX) - len(peers))
        for nid, host, port, ts in candidates[:slots_left]:
            caps = self.peer_caps.get(nid, {}) or {}
            peers.append({
                "id": nid,
                "a": f"{host}:{int(port)}",
                "t": int(ts),
                "q": str(getattr(self, "last_quorum_digest", "") or "")[:12],
                "ch": self._caps_hash(caps),
            })

        if not peers:
            return None

        return {
            "type": "peer_hint",
            "enc": "plain",
            "data": {
                "kind": "KDK_PEER_HINT",
                "ver": 1,
                "from": self.name,
                "ts": int(now),
                "peers": peers,
            },
        }

    def _parse_hint_addr(self, addr_s: Any) -> Optional[Tuple[str, int]]:
        if not isinstance(addr_s, str) or ":" not in addr_s:
            return None
        host, ps = addr_s.rsplit(":", 1)
        host = host.strip()
        try:
            port = int(ps)
        except Exception:
            return None
        if not host or port <= 0 or port > 65535:
            return None
        return (host, port)

    def handle_peer_hint_block(self, src_id: str, data: dict):
        """Ingest decrypted peer hints.

        Hints remain encrypted/decrypt-gated and stochastic, but once a hint is
        decrypted we make the address eligible for normal Brownian fanout
        immediately.  This is not direct routing: it simply expands the local
        randomized peer set, while HELLO/heartbeat confirms identity over time.
        """
        if not getattr(self, "peer_hint_enabled", ENABLE_PEER_HINTS):
            return
        if data.get("kind") != "KDK_PEER_HINT":
            return
        peers = data.get("peers", [])
        if not isinstance(peers, list):
            return

        learned = 0
        now = now_ts()
        for h in peers[:PEER_HINT_MAX * 2]:
            if not isinstance(h, dict):
                continue
            nid = str(h.get("id", ""))
            if not nid or nid == self.node_id:
                continue
            addr = self._parse_hint_addr(h.get("a"))
            if not addr:
                continue
            # Already known at this exact address: no need to add as candidate.
            if self.peer_id_by_addr.get(addr) == nid or addr in self.peers:
                continue
            key = f"{nid}|{addr[0]}:{addr[1]}"
            self.peer_hint_candidates[key] = {
                "node_id": nid,
                "addr": addr,
                "via": src_id,
                "seen_ts": now,
                "hint_ts": h.get("t", 0),
                "q": str(h.get("q", ""))[:12],
                "failures": 0,
                "self_hint": bool(h.get("self", False)),
            }
            learned += 1
            self.log_event(
                f"[PEER_HINT] fanout-candidate {addr[0]}:{addr[1]} "
                f"via={short8(src_id)} id={short8(nid)} self={bool(h.get('self', False))}"
            )

            # For K▲K, a decrypted peer hint is not a direct reply route;
            # it is an ordinary Brownian fanout candidate.  Add it to the
            # local peer list immediately so status/peers rise and subsequent
            # dummy/message/chunk traffic may randomly include it.  The normal
            # HELLO/heartbeat path still verifies identity over time.
            if addr not in self.peers:
                self.peers.append(addr)
                self.log_event(
                    f"[PEER_HINT] fanout-peer added {addr[0]}:{addr[1]} "
                    f"via={short8(src_id)} id={short8(nid)}"
                )
                try:
                    self.send_hello(addr)
                except Exception:
                    pass

        # Bound the candidate pool; oldest candidates fall out first.
        if len(self.peer_hint_candidates) > PEER_HINT_MAX_CANDIDATES:
            items = sorted(self.peer_hint_candidates.items(), key=lambda kv: float(kv[1].get("seen_ts", 0)))
            for k, _ in items[:len(self.peer_hint_candidates) - PEER_HINT_MAX_CANDIDATES]:
                self.peer_hint_candidates.pop(k, None)

        if learned:
            self.log_event(f"[PEER_HINT] learned={learned} via={short8(src_id)} candidates={len(self.peer_hint_candidates)}")

    def maybe_probe_peer_hints(self, now: float):
        """Slowly probe hinted candidates with HELLO. Hints are never auto-trusted."""
        if not getattr(self, "peer_hint_enabled", ENABLE_PEER_HINTS):
            return
        if now - float(getattr(self, "last_peer_hint_probe_ts", 0.0)) < PEER_HINT_PROBE_INTERVAL:
            return
        self.last_peer_hint_probe_ts = now

        # Expire old pending probes and stale candidates.
        for addr, due in list(self.peer_hint_pending_probes.items()):
            if now - float(due) > PEER_HINT_CONNECT_JITTER_MAX + 60:
                self.peer_hint_pending_probes.pop(addr, None)

        for k, rec in list(self.peer_hint_candidates.items()):
            if now - float(rec.get("seen_ts", now)) > PEER_HINT_TTL_SECS:
                self.peer_hint_candidates.pop(k, None)

        if not self.peer_hint_candidates:
            return
        if random.random() > PEER_HINT_CONNECT_PROB:
            return

        items = list(self.peer_hint_candidates.items())
        random.shuffle(items)
        for key, rec in items:
            addr = rec.get("addr")
            nid = rec.get("node_id", "")
            if not isinstance(addr, tuple) or len(addr) != 2:
                self.peer_hint_candidates.pop(key, None)
                continue
            if addr in self.peer_id_by_addr or nid in self.active_nodes:
                self.peer_hint_candidates.pop(key, None)
                continue
            if addr in self.peer_hint_pending_probes:
                continue
            delay = random.uniform(PEER_HINT_CONNECT_JITTER_MIN, PEER_HINT_CONNECT_JITTER_MAX)
            self.peer_hint_pending_probes[addr] = now + delay
            self.log_event(f"[PEER_HINT] scheduled probe {addr[0]}:{addr[1]} via={short8(str(rec.get('via','')))} in={delay:.1f}s")
            break

        for addr, due in list(self.peer_hint_pending_probes.items()):
            if now < float(due):
                continue
            self.peer_hint_pending_probes.pop(addr, None)
            if addr in self.peer_id_by_addr:
                continue
            self.log_event(f"[PEER_HINT] probing {addr[0]}:{addr[1]}")
            self.send_hello(addr)
            # Add to peer list after first probe so normal heartbeat/discovery can continue.
            if addr not in self.peers:
                self.peers.append(addr)
            break

    def build_envelope_v3(self, dst_id: str, blocks: list) -> dict:
        return {
            "ver": 3,
            "src": self.node_id,
            "dst": dst_id,
            "ts": int(now_ts()),
            "sid": os.urandom(16),
            "nonce": os.urandom(16),
            "blocks": blocks,
        }

    def _build_encrypted_frame(self, dst_id: str, blocks: list,
                               include_peer_hint: bool = True) -> tuple:
        """Build the exact encrypted frame used by injection and size probes."""
        peer_pk = self.peer_keys.get(dst_id)
        if not peer_pk:
            raise KeyError(f"no X25519 key for dst {short8(dst_id)}")

        blocks_to_send = list(blocks) if isinstance(blocks, list) else []
        hint_added = False
        if include_peer_hint:
            hint_block = self.build_peer_hint_block(dst_id=dst_id)
            if hint_block is not None:
                blocks_to_send.append(hint_block)
                hint_added = True
        env = self.build_envelope_v3(dst_id, blocks_to_send)
        env["sig"] = self.envelope_v3_sign(env)
        env_bytes = msgpack.packb(env, use_bin_type=True)
        ciphertext = Box(self.box_sk, peer_pk).encrypt(env_bytes)
        return self._make_frame(ciphertext), hint_added

    def inject_envelope(self, dst_id: str, blocks: list, label: str = "ENVELOPE"):
        if not self.peer_keys.get(dst_id):
            qprint(f"[INJECT] No X25519 key for dst {short8(dst_id)}; cannot encrypt envelope.")
            return

        # Peer hints are optional. Build through the same path used by dynamic
        # chunk sizing; if the hint alone pushes the envelope over the fixed
        # frame limit, rebuild without it rather than requeueing forever.
        try:
            frame, hint_added = self._build_encrypted_frame(dst_id, blocks, include_peer_hint=True)
        except ValueError as e:
            if "Body too large for frame" not in str(e):
                raise
            frame, _ = self._build_encrypted_frame(dst_id, blocks, include_peer_hint=False)
            hint_added = False
            self.log_event(f"[PEER_HINT] omitted frame-overflow label={label} dst={short8(dst_id)}")

        ph = sha256(frame)
        stamp = mine_pow_stamp(
            origin_id=self.node_id,
            ph=ph,
            bits_required=int(self.pow_bits_required),
            epoch_secs=int(self.pow_epoch_secs),
            max_tries=int(self.pow_mine_tries),
        )

        msg = {
            "type": "PAYLOAD",
            "src": self.node_id,
            "origin": self.node_id,
            "data": frame,
            "ph": ph,
            "ttl": PAYLOAD_TTL_DEFAULT,
            "pow": stamp,
            "wave": 0,
            "hops": 0,
            "birth_ts": now_ts(),
            "last_tx_ts": now_ts(),
            "tx_mode": "origin",
            "sender_vk": self.verify_key.encode(),
            "sender_ek": bytes(self.box_pk),
        }

        self.metric_tx_payloads += 1
        self.metric_last_tx_ts = now_ts()
        self.pulse_note_emit(ph, label)
        self.log_event(f"[INJECT] {label} payload {ph[:8]} (env-> {short8(dst_id)})")
        trace_ids = self._trace_block_identity(blocks)
        if self._trace_identity_interesting(trace_ids):
            self._trace_track(ph)
            self.trace_payload(
                "ORIGIN", ph, label=str(label), dst=short8(dst_id),
                ttl=PAYLOAD_TTL_DEFAULT, hops=0, mode="origin", **trace_ids
            )
        self.broadcast(msg)
        return ph

    def inject_dummy(self, label: str = "DUMMY"):
        frame = self.make_dummy_frame()
        ph = sha256(frame)
        stamp = mine_pow_stamp(
            origin_id=self.node_id,
            ph=ph,
            bits_required=int(self.pow_bits_required),
            epoch_secs=int(self.pow_epoch_secs),
            max_tries=int(self.pow_mine_tries),
        )

        msg = {
            "type": "PAYLOAD",
            "src": self.node_id,
            "origin": self.node_id,
            "data": frame,
            "ph": ph,
            "ttl": PAYLOAD_TTL_DEFAULT,
            "pow": stamp,
            "wave": 0,
            "hops": 0,
            "birth_ts": now_ts(),
            "last_tx_ts": now_ts(),
            "tx_mode": "origin",
            # Preserve outward metadata parity with genuine originated payloads.
            # The dummy frame remains undecryptable dummy traffic, but an external
            # observer can no longer classify it merely by missing sender fields.
            "sender_vk": self.verify_key.encode(),
            "sender_ek": bytes(self.box_pk),
        }

        self.metric_tx_payloads += 1
        self.metric_last_tx_ts = now_ts()
        self.pulse_note_emit(ph, label)
        self.log_event(f"[INJECT] {label} payload {ph[:8]} (pow_bits={stamp.get('bits')})")
        self.broadcast(msg)

    # ------------------------- Inbox storage ---------------------------------

    def store_directed_inbox(self, payload_hash: str, plaintext: bytes, src_id: str, dst_id: str):
        self.direct_inbox_count += 1
        ts = now_ts()
        ts_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(ts))
        short = payload_hash[:8]

        self.direct_inbox.append({"hash": payload_hash, "src": src_id, "dst": dst_id, "ts": ts})
        if len(self.direct_inbox) > int(KDK_DIRECT_INBOX_MAX):
            del self.direct_inbox[:-int(KDK_DIRECT_INBOX_MAX)]

        fn = os.path.join("inbox", f"{self.name}_{ts_str}_{short}.msg")
        try:
            with open(fn, "wb") as f:
                header = (
                    f"hash={payload_hash}\n"
                    f"src={src_id}\n"
                    f"dst={dst_id}\n"
                    f"ts={ts_str}\n"
                    f"----plaintext----\n"
                ).encode("utf-8", errors="ignore")
                f.write(header)
                f.write(plaintext)
        except Exception as e:
            qprint(f"[WARN] Failed to write inbox file: {e}")
            return

        qprint(f"[INBOX] Directed payload {short} from {short8(src_id)} saved to {fn}")
        qprint(f"[METRIC] DIRECT_INBOX count={self.direct_inbox_count} last={short}")

    # ------------------------- Vault discovery helper -------------------------

    def choose_vault(self) -> Optional[str]:
        now = now_ts()
        active = [nid for nid, ts in self.active_nodes.items() if now - ts < ACTIVE_TIMEOUT]
        for nid in active:
            if nid == self.node_id:
                continue
            caps = self.peer_caps.get(nid, {})
            if isinstance(caps, dict) and caps.get("vault"):
                return nid
        return None
    
    def _make_retry_schedule(self, base_ts: float) -> list:
        """
        Build a randomized retry schedule for the next RETRY_FURTHER_ATTEMPTS sends.

        Rules:
          - all retries are after RETRY_MIN_DELAY_SECS
          - retries begin within RETRY_WINDOW_SECS from base_ts; enforcing the
            minimum gap may extend a later retry slightly beyond that window
          - retries are sorted
          - retries are separated by at least RETRY_MIN_GAP_SECS
        """
        try:
            n = int(RETRY_FURTHER_ATTEMPTS)
        except Exception:
            n = 0
        if n <= 0:
            return []

        try:
            base = float(base_ts)
        except Exception:
            base = now_ts()

        try:
            min_delay = float(RETRY_MIN_DELAY_SECS)
        except Exception:
            min_delay = 5.0

        try:
            window = float(RETRY_WINDOW_SECS)
        except Exception:
            window = 60.0

        try:
            min_gap = float(RETRY_MIN_GAP_SECS)
        except Exception:
            min_gap = 10.0

        window = max(window, min_delay)
        raw_times = [base + random.uniform(min_delay, window) for _ in range(n)]
        raw_times.sort()

        sched = []
        last = None
        for t in raw_times:
            if last is None:
                t_adj = t
            else:
                t_adj = max(t, last + min_gap)
            sched.append(t_adj)
            last = t_adj

        return sched

    # ------------------------- RPC client (rid + retry) ----------------------

    def _rpc_blocks(self, cmd: str, rid: str, args: dict) -> list:
        return [{
            "type": "rpc",
            "enc": "plain",
            "data": {"cmd": cmd, "rid": rid, "args": args},
        }]

    def rpc_send_new(self, cmd: str, args: dict, label: str):
        dst = self.choose_vault()
        if not dst:
            qprint("[RPC] No vault nodes known.")
            return

        rid = gen_rid()
        if not isinstance(args, dict):
            args = {}

        self.pending_rpcs[rid] = {
            "cmd": cmd,
            "args": dict(args),
            "dst": dst,
            "ts": now_ts(),
            "sent_ts": None,
            "retries": 0,
            "state": "PENDING",
        }

        qprint(f"[RPC] QUEUE {cmd} rid={rid[:8]} dst={short8(dst)}")
        blocks = self._rpc_blocks(cmd, rid, args)

        if getattr(self, "test_fast_rpc", False):
            self.pending_rpcs[rid]["sent_ts"] = now_ts()
            self.inject_envelope(dst, blocks, label=label)
            return

        self.outbound_queue.append((dst, blocks, label))

    def rpc_resend(self, rid: str, count_retry: bool = True):
        meta = self.pending_rpcs.get(rid)
        if not meta:
            return

        cmd = meta.get("cmd", "?")
        dst = meta.get("dst")
        args = meta.get("args", {}) or {}
        if not isinstance(args, dict):
            args = {}
        if not isinstance(dst, str) or not dst:
            return

        meta["ts"] = now_ts()
        meta["sent_ts"] = None
        if count_retry:
            meta["retries"] = int(meta.get("retries", 0)) + 1
        self.pending_rpcs[rid] = meta

        tag = "RPC-RETRY" if count_retry else "RPC-RESEND"
        qprint(f"[RPC] {tag} cmd={cmd} rid={rid[:8]} dst={short8(dst)}")
        blocks = self._rpc_blocks(cmd, rid, args)

        if getattr(self, "test_fast_rpc", False):
            meta["sent_ts"] = now_ts()
            self.pending_rpcs[rid] = meta
            self.inject_envelope(dst, blocks, label=tag)
            return

        self.outbound_queue.append((dst, blocks, tag))

    def send_rpc_ping(self):
        self.rpc_send_new("PING", {}, "RPC-PING")

    def send_rpc_store_test(self):
        self.rpc_send_new("STORE_TEST", {}, "RPC-STORE_TEST")

    def send_rpc_list_test(self):
        self.rpc_send_new("LIST_TEST", {}, "RPC-LIST_TEST")

    def send_rpc_retrieve_test(self):
        dst = self.choose_vault()
        if not dst:
            qprint("[RPC] No vault nodes known.")
            return

        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                qprint("[RPC] Enter item_id to retrieve: ", end="", flush=True)
                item_id = sys.stdin.readline().strip()
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    # Re-enter hotkey mode after line-input prompts.
                    # self._raw_term_state is the original terminal state for final shutdown.
                    term_enter_raw_noecho()

        if not item_id:
            qprint("[RPC] No item_id entered.")
            return

        self.rpc_send_new("RETRIEVE_TEST", {"item_id": item_id}, "RPC-RETRIEVE_TEST")

    # ------------------------- Vault RID log persistence ---------------------

    def vault_rid_log_append(self, src_id: str, rid: str, cmd: str, rep: dict, ts: float):
        try:
            rec = {"src": src_id, "rid": rid, "cmd": cmd, "ts": ts, "reply": rep}
            with open(VAULT_RID_LOG_PATH, "ab") as f:
                f.write(msgpack.packb(rec, use_bin_type=True))
        except Exception as e:
            qprint(f"[WARN] RID log append failed: {e}")

    def vault_rid_log_load(self):
        if not os.path.exists(VAULT_RID_LOG_PATH):
            return
        loaded = 0
        try:
            with open(VAULT_RID_LOG_PATH, "rb") as f:
                unpacker = msgpack.Unpacker(f, raw=False)
                for rec in unpacker:
                    if not isinstance(rec, dict):
                        continue
                    src = rec.get("src")
                    rid = rec.get("rid")
                    cmd = rec.get("cmd")
                    ts = float(rec.get("ts", 0))
                    reply = rec.get("reply")
                    if not (isinstance(src, str) and isinstance(rid, str) and isinstance(cmd, str) and isinstance(reply, dict)):
                        continue
                    if now_ts() - ts <= RPC_DEDUPE_TTL:
                        self.vault_rid_cache[(src, rid, cmd)] = {"ts": ts, "reply": reply}
                        loaded += 1
            if loaded:
                qprint(f"[BOOT] Loaded {loaded} RID cache entries (<= TTL)")
        except Exception as e:
            qprint(f"[WARN] RID log load failed: {e}")

    # ------------------------- Vault rate limiter ----------------------------

    def vault_rate_allow(self, src_id: str) -> Tuple[bool, float]:
        now = now_ts()
        dq = self.vault_rate.get(src_id)
        if dq is None:
            dq = deque()
            self.vault_rate[src_id] = dq

        while dq and (now - dq[0] > VAULT_RATE_WINDOW):
            dq.popleft()

        if len(dq) >= VAULT_RATE_MAX:
            return False, VAULT_RATE_RETRY_AFTER

        dq.append(now)
        return True, 0.0

    # ------------------------- Vault RPC handlers ----------------------------

    def vault_rpc_dispatch(self, src_id: str, cmd: str, args: dict) -> dict:
        if cmd == "PING":
            return {"cmd": "PING", "ok": True, "ts": int(now_ts())}

        if cmd == "STORE_TEST":
            item_id = sha256(os.urandom(16).hex().encode())[:16]
            data = os.urandom(32)
            path = os.path.join("vault_store", f"{item_id}.kdk")
            with open(path, "wb") as f:
                f.write(data)
            qprint(f"[RPC] STORE_TEST wrote 32 bytes to {path}")
            return {"cmd": "STORE_TEST", "ok": True, "item_id": item_id, "size": 32}

        if cmd == "LIST_TEST":
            try:
                items = []
                for fn in os.listdir("vault_store"):
                    if fn.endswith(".kdk"):
                        items.append(fn[:-4])
                items.sort()
            except Exception as e:
                return {"cmd": "LIST_TEST", "ok": False, "code": "LIST_FAILED", "err": str(e)}
            return {"cmd": "LIST_TEST", "ok": True, "items": items}

        if cmd == "RETRIEVE_TEST":
            item_id = str(args.get("item_id", "")).strip()
            if not item_id:
                return {"cmd": "RETRIEVE_TEST", "ok": False, "code": "BAD_ARGS", "item_id": item_id}
            path = os.path.join("vault_store", f"{item_id}.kdk")
            if not os.path.exists(path):
                return {"cmd": "RETRIEVE_TEST", "ok": False, "code": "NOT_FOUND", "item_id": item_id}
            blob = open(path, "rb").read()
            qprint(f"[RPC] RETRIEVE_TEST serving {item_id} ({len(blob)} bytes) to {short8(src_id)}")
            return {"cmd": "RETRIEVE_TEST", "ok": True, "item_id": item_id, "size": len(blob), "blob": blob}

        return {"cmd": cmd, "ok": False, "code": "UNKNOWN_CMD"}

    def vault_handle_rpc(self, src_id: str, rpc: dict) -> Optional[dict]:
        cmd = rpc.get("cmd")
        rid = rpc.get("rid")
        args = rpc.get("args", {}) or {}
        if not isinstance(args, dict):
            args = {}

        if not isinstance(cmd, str) or not isinstance(rid, str) or not rid:
            return {"cmd": str(cmd), "ok": False, "code": "BAD_RPC", "rid": str(rid)}

        cache_key = (src_id, rid, cmd)

        # 1) DEDUPE FIRST (retries must bypass rate limiting)
        cached = self.vault_rid_cache.get(cache_key)
        if cached and (now_ts() - float(cached.get("ts", 0)) < RPC_DEDUPE_TTL):
            rep = dict(cached["reply"])
            rep["rid"] = rid
            rep["deduped"] = True
            qprint(f"[RPC] DEDUPE cmd={cmd} rid={rid[:8]} from {short8(src_id)}")
            return rep

        # 2) RATE LIMIT ONLY NEW (src,rid,cmd)
        allowed, retry_after = self.vault_rate_allow(src_id)
        if not allowed:
            return {"cmd": cmd, "ok": False, "code": "RATE_LIMIT", "retry_after": retry_after, "rid": rid}

        # 3) EXECUTION INVARIANT (must run exactly once)
        self.vault_exec_counts[cache_key] = self.vault_exec_counts.get(cache_key, 0) + 1
        if self.vault_exec_counts[cache_key] > 1:
            qprint(f"[ALERT] RPC EXECUTED >1 cmd={cmd} rid={rid[:8]} from {short8(src_id)} count={self.vault_exec_counts[cache_key]}")

        # 4) EXECUTE
        rep = self.vault_rpc_dispatch(src_id, cmd, args)
        if rep is None:
            return None

        rep["rid"] = rid

        # 5) CACHE + PERSIST BEFORE ANY DROP
        ts = now_ts()
        self.vault_rid_cache[cache_key] = {"ts": ts, "reply": dict(rep)}
        self.vault_rid_log_append(src_id, rid, cmd, dict(rep), ts)
        self.vault_rid_log_count += 1

        # 6) TEST: DROP LIST_TEST REPLY ONCE (true reply loss)
        if self.test_drop_list_once and cmd == "LIST_TEST" and not self._test_drop_once:
            self._test_drop_once = True
            qprint("[TEST] Intentionally dropping LIST_TEST reply once")
            return None

        return rep

    # ------------------------- Client reply handling --------------------------

    def client_handle_rpc_reply(self, src_id: str, rpc_reply: dict):
        cmd = rpc_reply.get("cmd")
        rid = rpc_reply.get("rid")

        if not isinstance(rid, str) or not rid:
            qprint(f"[RPC-REPLY] Missing rid from {short8(src_id)}")
            return

        pending = self.pending_rpcs.get(rid)
        if not pending:
            k = (src_id, rid, cmd)
            last = self.orphan_seen.get(k, 0.0)
            n = now_ts()
            if n - last > ORPHAN_LOG_TTL:
                self.orphan_seen[k] = n
                qprint(f"[RPC-REPLY] Orphan reply rid={rid[:8]} from {short8(src_id)} (cmd={cmd})")
            return

        if rpc_reply.get("code") == "RATE_LIMIT":
            retry_after = float(rpc_reply.get("retry_after", VAULT_RATE_RETRY_AFTER))
            pending["state"] = "RATE_LIMIT"
            pending["sent_ts"] = None
            pending["cooldown_collisions"] = _rate_limit_cooldown_collisions(retry_after)
            self.pending_rpcs[rid] = pending
            qprint(f"[RPC] RATE_LIMIT rid={rid[:8]} cooldown_collisions={pending.get('cooldown_collisions')}")
            return

        prev_state = pending.get("state", "PENDING")
        pending["state"] = "COMPLETED"
        qprint(f"[RPC] STATE {pending.get('cmd','?')} rid={rid[:8]} {prev_state}->COMPLETED")

        del self.pending_rpcs[rid]

        if cmd in ("PING", "STORE_TEST", "LIST_TEST"):
            qprint(f"[RPC-REPLY] {cmd} rid={rid[:8]} from {short8(src_id)}: {rpc_reply}")
            return

        if cmd == "RETRIEVE_TEST":
            if not rpc_reply.get("ok"):
                qprint(f"[RPC-REPLY] RETRIEVE_TEST rid={rid[:8]} failed: {rpc_reply}")
                return
            item_id = rpc_reply.get("item_id")
            blob = rpc_reply.get("blob", b"")
            if not item_id or not isinstance(blob, (bytes, bytearray)):
                qprint(f"[RPC-REPLY] RETRIEVE_TEST rid={rid[:8]} malformed")
                return
            out = os.path.join("retrieved", f"{item_id}.kdk")
            with open(out, "wb") as f:
                f.write(blob)
            qprint(f"[RETRIEVE] rid={rid[:8]} saved {item_id} ({len(blob)} bytes) -> {out}")
            return

        qprint(f"[RPC-REPLY] rid={rid[:8]} from {short8(src_id)}: {rpc_reply}")

    # ------------------------- Block processor --------------------------------

    def process_inbound_blocks(self, budget: int = 8):
        n = 0
        while self.inbound_blocks and n < budget:
            src_id, env_sid, b = self.inbound_blocks.popleft()
            n += 1

            btype = b.get("type")
            data = b.get("data", {})
            if not isinstance(data, dict):
                continue

            if btype == "peer_hint":
                if not self.peer_is_suspended(src_id):
                    self.handle_peer_hint_block(src_id, data)
                continue

            if self.peer_is_suspended(src_id):
                self.log_event(f"[PEER_POLICY] suspended direct block from={short8(src_id)} type={btype}")
                continue

            if btype == "message":
                if self.peer_direct_muted(src_id):
                    self.log_event(f"[PEER_POLICY] muted direct message from={short8(src_id)}")
                    continue
                text = str(data.get("text", ""))
                message_id = str(data.get("message_id", "") or "")
                message_hash = str(data.get("message_hash", "") or sha256(text.encode("utf-8", "ignore")))
                logical_id = message_id or str(env_sid)
                duplicate = bool(logical_id and logical_id in self.delivered_message_ids)
                self.log_event(
                    f"[PLUCK] message from {short8(src_id)} mid={logical_id[:8]} "
                    f"duplicate={duplicate} text={text!r}"
                )
                self.trace_payload(
                    "PLUCK", "", from_node=short8(src_id), mid=logical_id[:32],
                    duplicate=bool(duplicate), message_hash=message_hash[:32]
                )
                if not duplicate:
                    sender_name = str(data.get("from", "") or self.activity_peer_name(src_id))
                    self.activity_message(sender_name, text, typed=True)
                    if logical_id:
                        self.delivered_message_ids[logical_id] = now_ts()
                if ENABLE_RECEIPTS:
                    if message_id:
                        self.queue_reliable_receipt(src_id, "MESSAGE_RECEIPT", message_id, message_hash,
                                                    {"message_id": message_id, "message_hash": message_hash})
                    elif env_sid:
                        self.queue_receipt(src_id, env_sid)
                self.reliability_save_state()
                continue

            elif btype == "receipt":
                sid = data.get("sid")
                kind = str(data.get("kind", "MESSAGE_RECEIPT"))
                receipt_id = str(data.get("receipt_id", "") or "")
                subject_id = str(data.get("subject_id", "") or data.get("message_id", "") or data.get("object_id", ""))
                subject_hash = str(data.get("subject_hash", "") or data.get("message_hash", "") or data.get("object_hash", ""))
                object_id = str(data.get("object_id", "") or (subject_id if kind == "KDK_CHUNK_RECEIPT" else ""))
                self.receipt_recv_count += 1
                if receipt_id:
                    self.received_receipt_ids[receipt_id] = now_ts()
                    self.trace_payload(
                        "RECEIPT_RX", "", from_node=short8(src_id), kind=kind,
                        subject_id=subject_id[:32], rid=receipt_id[:32]
                    )
                    self.outbound_queue.append((src_id, [self.build_receipt_ack_block(receipt_id)], "RECEIPT-ACK"))
                    self.trace_payload("ACK_QUEUE", "", dst=short8(src_id), rid=receipt_id[:32])
                if kind == "MESSAGE_RECEIPT" and subject_id:
                    rec = self.pending_messages.get(subject_id)
                    if isinstance(rec, dict):
                        bdata = ((rec.get("block", {}) or {}).get("data", {}) or {})
                        expected_hash = str(bdata.get("message_hash", ""))
                        if not subject_hash or not expected_hash or subject_hash == expected_hash:
                            self.pending_messages.pop(subject_id, None)
                            self.activity_system(f"Message delivered to {self.activity_peer_name(src_id)} ({subject_id[:8]})")
                    self.log_event(f"[RECEIPT] message from={short8(src_id)} mid={subject_id[:8]} rid={receipt_id[:8]}")
                elif object_id:
                    self.log_event(f"[RECEIPT] received from {short8(src_id)} kind={kind} object={object_id[:8]} rid={receipt_id[:8]}")
                    if kind == "KDK_CHUNK_RECEIPT":
                        txrec = (getattr(self, "chunk_tx_store", {}) or {}).get(object_id, {}) or {}
                        if bool(txrec.get("is_user_file", False)):
                            self._start_file_embargo(object_id)
                        try:
                            cleared = self._clear_repair_state_for_object(object_id, str(src_id))
                            if cleared:
                                self.log_event(f"[REPAIR_MODE] complete object={object_id[:8]} cleared={cleared}")
                        except Exception:
                            pass
                        fname = str(data.get("filename_hint") or "file")
                        nbytes = data.get("bytes", "?")
                        self.activity_system(f"{self.activity_peer_name(src_id)} has received {fname} ({nbytes} bytes)")
                else:
                    self.log_event(f"[RECEIPT] legacy from {short8(src_id)} kind={kind} sid={str(sid)[:8]}")
                    self.activity_system(f"Receipt received from {self.activity_peer_name(src_id)} ({kind})")
                self.reliability_save_state()
                continue

            elif btype == "receipt_ack":
                receipt_id = str(data.get("receipt_id", "") or "")
                self.trace_payload("ACK_RX", "", from_node=short8(src_id), rid=receipt_id[:32])
                if receipt_id and receipt_id in self.pending_receipts:
                    self.pending_receipts.pop(receipt_id, None)
                    self.reliability_save_state()
                    self.log_event(f"[RECEIPT_ACK] from={short8(src_id)} rid={receipt_id[:8]} cleared=1")
                else:
                    self.log_event(f"[RECEIPT_ACK] duplicate/unknown from={short8(src_id)} rid={receipt_id[:8]}")
                continue

            elif btype == "dingo_height_beacon":
                self.dingo_accept_height_beacon(src_id, data)
                continue

            elif btype == "airgap_ticket":
                self.airgap_handle_ticket(src_id, data)
                continue

            elif btype == "airgap_receipt":
                self.airgap_handle_receipt(src_id, data)
                continue

            elif btype == "kdk_chunk_manifest":
                self.chunk_handle_manifest(src_id, data)
                continue

            elif btype == "kdk_chunk_data":
                self.chunk_handle_data(src_id, data)
                continue

            elif btype == "kdk_chunk_want":
                self.chunk_handle_want(src_id, data)
                continue

            elif btype == "kdk_chunk_pull":
                self.chunk_handle_pull(src_id, data)
                continue

            if btype == "rpc" and self.vault_mode:
                rep = self.vault_handle_rpc(src_id, data)
                if rep is None:
                    continue

                rep_blocks = [{"type": "rpc_reply", "enc": "plain", "data": rep}]
                rid8 = str(rep.get("rid", ""))[:8]
                if getattr(self, "test_fast_rpc", False):
                    qprint(f"[RPC] SEND-REPLY cmd={rep.get('cmd')} rid={rid8} dst={short8(src_id)}")
                    self.inject_envelope(src_id, rep_blocks, label="RPC-REPLY")
                else:
                    qprint(f"[RPC] QUEUE-REPLY cmd={rep.get('cmd')} rid={rid8} dst={short8(src_id)}")
                    self.outbound_queue.append((src_id, rep_blocks, "RPC-REPLY"))
                continue

            elif btype == "rpc_reply":
                self.client_handle_rpc_reply(src_id, data)

    # ------------------------- Payload handler --------------------------------

    def handle_payload(self, msg: dict, addr: Tuple[str, int], sender_node_id: str):
        payload = msg.get("data", b"")
        ph = msg.get("ph") or ""
        ttl = int(msg.get("ttl", PAYLOAD_TTL_DEFAULT))
        src_id = msg.get("src", sender_node_id)

        wave = int(msg.get("wave", 0))
        hops = int(msg.get("hops", 0))
        mode = str(msg.get("tx_mode", "unknown"))
        origin = str(msg.get("origin") or msg.get("src") or sender_node_id)
        birth_ts = float(msg.get("birth_ts", now_ts()))
        age = max(0.0, now_ts() - birth_ts)

        if not isinstance(payload, (bytes, bytearray)):
            return
        if not ph:
            ph = sha256(payload)

        trace_rx_fields = {
            "from_node": short8(sender_node_id), "from_addr": f"{addr[0]}:{addr[1]}",
            "origin": short8(origin), "ttl": ttl, "hops": hops, "wave": wave, "mode": mode
        }
        # Relay witness mode: an explicit watch may adopt a transit payload before
        # decryption. Once adopted, the normal selective trace records RX/SEEN and
        # any FORWARD events for this hash. No diagnostic bit is added to the wire.
        if bool(getattr(self, "trace_payloads_enabled", False)) and self._trace_watch_matches(ph, origin):
            self._trace_track(ph)
        if self._trace_is_tracked(ph):
            self.trace_payload("RX", ph, **trace_rx_fields)

        origin = msg.get("origin") or msg.get("src") or sender_node_id
        powd = msg.get("pow") or {}

        # strict PoW stamp parse/validate
        try:
            epoch = int(powd.get("epoch"))
            nonce = powd.get("nonce")
            bits = int(powd.get("bits"))
            if nonce is None:
                raise ValueError("nonce is None")
            nonce = int(nonce)
        except Exception:
            qprint(f"[POW] DROP payload {ph[:8]} missing/invalid stamp")
            self.trace_payload("DROP_POW", ph, reason="invalid_stamp", from_node=short8(sender_node_id)) if self._trace_is_tracked(ph) else None
            return

        req = int(getattr(self, "pow_bits_required", 16))
        if bits < req:
            qprint(f"[POW] DROP payload {ph[:8]} bits too low ({bits} < {req})")
            self.trace_payload("DROP_POW", ph, reason="bits_low", bits=bits, required=req, from_node=short8(sender_node_id)) if self._trace_is_tracked(ph) else None
            return

        if not pow_valid(str(origin), ph, epoch, nonce, bits):
            qprint(f"[POW] DROP payload {ph[:8]} bad stamp origin={short8(str(origin))}")
            self.trace_payload("DROP_POW", ph, reason="bad_stamp", origin=short8(str(origin)), from_node=short8(sender_node_id)) if self._trace_is_tracked(ph) else None
            return

        now = now_ts()
        self.metric_rx_payloads += 1
        self.metric_last_rx_ts = now 
        seen_before = ph in self.seen_payloads
        self.log_event(
            f"[SEEN] ph={ph[:8]} seen_before={seen_before} "
            f"tokens={self.token_count}/{self.token_trigger} from={short8(sender_node_id)}"
        )
        self.seen_payloads[ph] = now
        self.pulse_note_observe(ph, seen_before=seen_before)
        if self._trace_is_tracked(ph):
            self.trace_payload("SEEN", ph, seen_before=bool(seen_before), from_node=short8(sender_node_id))

        qt = self.quorum_tracker.get(ph)
        if qt is None:
            qt = {"seen_by": set(), "quorum_reached": False, "ttl": ttl, "last_ts": now}
            self.quorum_tracker[ph] = qt
        qt["seen_by"].add(self.node_id)
        # A collision copy is signed hop-by-hop by the node that sent this UDP
        # packet.  Seeing it therefore proves that sender has also possessed the
        # payload; count that cryptographic witness toward quorum.
        if isinstance(sender_node_id, str) and sender_node_id and sender_node_id != "unknown":
            qt["seen_by"].add(sender_node_id)
        qt["ttl"] = min(qt["ttl"], ttl)
        qt["last_ts"] = now

        self.check_quorum_for_payload(ph)
        if qt["quorum_reached"]:
            self.pulse_note_quorum(ph)
            # Do not return here. Every received PAYLOAD, including the collision
            # that completes quorum, must still pay its mandatory decrypt attempt.

        origin_id = str(msg.get("origin") or msg.get("src") or sender_node_id)

        sender_vk = msg.get("sender_vk")
        sender_ek = msg.get("sender_ek")

        if isinstance(sender_vk, (bytes, bytearray)):
            self.pubkey_by_node_id[origin_id] = bytes(sender_vk)

        if isinstance(sender_ek, (bytes, bytearray)):
            try:
                self.peer_keys[origin_id] = PublicKey(bytes(sender_ek))
            except Exception:
                pass

        # Opportunistic key-match decrypt.
        # Important: do not permanently suppress future decrypt attempts merely
        # because the first sighting failed. In a live mesh the first copy of a
        # payload can arrive before the relevant peer key/state is available; a
        # later duplicate/relay copy may decrypt cleanly. Mark a payload as
        # terminal only after a successful decrypt, or after decrypting an
        # envelope that is clearly not addressed to this node.
        # Every PAYLOAD sighting performs exactly one local Box decrypt attempt,
        # including first sightings, duplicate/collision copies, and dummy traffic.
        # Relays preserve the originator's sender_ek, so there is no need to scan
        # every known peer key.  decrypt_attempted suppresses duplicate *processing*
        # only; it no longer suppresses the cryptographic attempt itself.
        already_processed = ph in self.decrypt_attempted
        try:
            if len(payload) < 2:
                raise ValueError("frame too short")

            clen = int.from_bytes(payload[:2], "big")
            if clen > len(payload) - 2:
                raise ValueError("bad length prefix")
            ciphertext = payload[2:2 + clen]

            if not isinstance(sender_ek, (bytes, bytearray)):
                raise ValueError("missing sender_ek")

            sender_pk = PublicKey(bytes(sender_ek))
            self.log_event(
                f"[DECRYPT_TRY] ph={ph[:8]} seen_before={seen_before} "
                f"origin={short8(origin_id)} keys=1"
            )
            env_bytes = Box(self.box_sk, sender_pk).decrypt(ciphertext)
            env = msgpack.unpackb(env_bytes, raw=False)
            if not isinstance(env, dict) or env.get("ver") != 3:
                raise ValueError("not envelope v3")

            env_src = env.get("src")
            env_dst = env.get("dst")
            if not isinstance(env_src, str) or not isinstance(env_dst, str):
                raise ValueError("bad env src/dst")

            # A successfully decrypted payload has already paid the required Box
            # cost on this sighting.  If its logical envelope was processed before,
            # do not replay inbox/block side effects; continue to collision handling.
            if already_processed:
                self.log_event(
                    f"[DECRYPT_REPEAT_OK] ph={ph[:8]} seen_before={seen_before} "
                    f"origin={short8(origin_id)}"
                )
            elif env_dst != self.node_id:
                if self._trace_is_tracked(ph):
                    self.trace_payload("DECRYPT_NOT_FOR_ME", ph, env_src=short8(env_src), env_dst=short8(env_dst))
                self.decrypt_attempted[ph] = now_ts()
            else:
                env_ts = float(env.get("ts", 0))
                if abs(now_ts() - env_ts) > ENVELOPE_TS_SKEW:
                    raise ValueError("envelope ts skew too large")

                sid = env.get("sid", b"")
                sid_hex = sid.hex() if isinstance(sid, (bytes, bytearray)) else str(sid)
                replay_key = (env_src, sid_hex)
                if replay_key in self.seen_sids:
                    # Do not return here: duplicate wire sightings still count as
                    # collisions after their one mandatory decrypt attempt.
                    qprint(f"[REPLAY] Ignoring already-processed envelope sid={sid_hex[:8]} from {short8(env_src)}")
                    self.decrypt_attempted[ph] = now_ts()
                else:
                    self.seen_sids[replay_key] = now_ts()

                    sender_vk_bytes = self.pubkey_by_node_id.get(env_src)
                    if not sender_vk_bytes:
                        raise ValueError("missing sender verify key")
                    self.envelope_v3_verify(env, sender_vk_bytes)

                    blocks = env.get("blocks", [])
                    qprint(f"[ENVELOPE] v3 from {short8(env_src)} to {short8(self.node_id)} blocks={len(blocks)}")
                    trace_ids = self._trace_block_identity(blocks)
                    if self._trace_identity_interesting(trace_ids):
                        was_tracked = self._trace_is_tracked(ph)
                        self._trace_track(ph)
                        if not was_tracked:
                            self.trace_payload("RX", ph, **trace_rx_fields)
                            self.trace_payload("SEEN", ph, seen_before=bool(seen_before), from_node=short8(sender_node_id))
                        self.trace_payload(
                            "DECRYPT_OK", ph, env_src=short8(env_src), env_dst=short8(self.node_id),
                            sid=sid_hex[:16], blocks=len(blocks), **trace_ids
                        )
                    self.store_directed_inbox(ph, env_bytes, env_src, self.node_id)

                    if isinstance(blocks, list):
                        for b in blocks:
                            if not isinstance(b, dict):
                                continue
                            if b.get("enc") != "plain":
                                continue
                            meta = self._chunk_block_telemetry([b])
                            if meta:
                                self.log_event(f"[CHUNK_DEC] {meta} from={short8(env_src)} ph={ph[:8]} sid={sid_hex[:8]}")
                            self.inbound_blocks.append((env_src, sid_hex, b))

                    self.decrypt_attempted[ph] = now_ts()

        except Exception as e:
            # Failed decrypts (including dummies and payloads for other nodes) are
            # deliberately not marked terminal, so every later collision copy pays
            # the same single Box-decrypt cost.
            self.log_event(f"[DECRYPT_FAIL] ph={ph[:8]} seen_before={seen_before} origin={short8(origin_id)} err={type(e).__name__}: {e}")
            if self._trace_is_tracked(ph):
                self.trace_payload(
                    "DECRYPT_FAIL", ph, seen_before=bool(seen_before), origin=short8(origin_id),
                    error=type(e).__name__
                )

        # Collision accounting is independent of decrypt success.
        if seen_before:
            self.token_count += 1
            self.timelock_metrics_collisions = int(getattr(self, "timelock_metrics_collisions", 0) or 0) + 1
            try:
                q = getattr(self, "timelock_live_collision_times", None)
                if q is None:
                    self.timelock_live_collision_times = deque()
                    q = self.timelock_live_collision_times
                q.append(float(now_ts()))
            except Exception:
                pass

            self.log_event(
                f"[COLLISION] {ph[:8]} at {self.name} "
                f"tokens={self.token_count}/{self.token_trigger}"
            )

            # Keep RPC cooldown tied to collisions (queue only)
            self.maybe_release_rate_limited_rpcs_on_collision()

            # HARD trigger
            if self.token_count >= self.token_trigger:
                try:
                    self.on_token_trigger()
                except Exception as e:
                    self.log_event(
                        f"[TURN_FAIL] tokens={self.token_count}/{self.token_trigger} "
                        f"err={type(e).__name__}: {e}"
                    )
                finally:
                    self.token_count = 0
        else:
            qprint(
                f"[PAYLOAD] {ph[:8]} ttl={ttl} wave={wave} hops={hops} "
                f"mode={mode} origin={short8(origin)} age={age:.1f}s from={short8(sender_node_id)}"
            )

        # Mandatory Brownian diffusion rule: first sighting and collision copies
        # continue to relay until this node's signed-witness view reaches quorum.
        # Local decrypt success/failure never suppresses this path.
        if self.mesh_should_forward(
            seen_before, src_id, ttl, quorum_reached=bool(qt.get("quorum_reached", False))
        ):
            self.mesh_forward_wave(ph, msg, addr, ttl)

    # ------------------------- Cleanup ----------------------------------------

    def cleanup(self, now: float):
        # Bulk expiry/GC does not need to run on every packet-loop iteration.
        # Keep network receive/retry/scheduler paths responsive, but bound the
        # dictionary sweeps to once per second.
        last_gc = float(getattr(self, "_last_cleanup_gc_ts", 0.0) or 0.0)
        if now - last_gc >= 1.0:
            self._last_cleanup_gc_ts = now

            # Enforce expiry of observer-only telemetry independently of HUD
            # rendering/status calls. These structures must remain ephemeral.
            window = max(
                5.0,
                float(getattr(
                    self,
                    "timelock_live_collision_window_secs",
                    30.0,
                ) or 30.0),
            )
            q = self.timelock_live_collision_times
            cutoff = now - window
            while q and float(q[0]) < cutoff:
                q.popleft()

            self.pulse_prune()
            dead = [nid for nid, ts in self.active_nodes.items()
                    if nid != self.node_id and (now - ts > ACTIVE_TIMEOUT)]
            for nid in dead:
                qprint(f"[CLEAN] Node {short8(nid)} considered inactive")
                self.active_nodes.pop(nid, None)
                self.pubkey_by_node_id.pop(nid, None)
                self.peer_keys.pop(nid, None)
                self.peer_caps.pop(nid, None)

            for ph, ts in list(self.seen_payloads.items()):
                if now - ts > PAYLOAD_DEDUPE_TTL:
                    self.seen_payloads.pop(ph, None)

            # Bound terminal decrypt bookkeeping. Older builds stored True forever;
            # tolerate that legacy shape by expiring non-timestamp values immediately.
            for ph, ts in list(self.decrypt_attempted.items()):
                try:
                    expired = (now - float(ts)) > float(KDK_DECRYPT_ATTEMPTED_TTL)
                except Exception:
                    expired = True
                if expired:
                    self.decrypt_attempted.pop(ph, None)

            # Quorum records contain a set of witnesses and are particularly costly
            # on relay/bootstrap nodes. Keep only recently active payload records.
            for ph, rec in list(self.quorum_tracker.items()):
                try:
                    last_ts = float((rec or {}).get("last_ts", 0.0) or 0.0)
                    expired = (not last_ts) or ((now - last_ts) > float(KDK_QUORUM_TRACKER_TTL))
                except Exception:
                    expired = True
                if expired:
                    self.quorum_tracker.pop(ph, None)

            for k, ts in list(self.seen_sids.items()):
                if now - ts > ENVELOPE_REPLAY_TTL:
                    self.seen_sids.pop(k, None)

            for k, ts in list(self.orphan_seen.items()):
                if now - ts > ORPHAN_LOG_TTL:
                    self.orphan_seen.pop(k, None)

            for oid, rec in list(self.chunk_rx.items()):
                try:
                    if now - float(rec.get("first_ts", now)) > KDK_CHUNK_PARTIAL_TTL:
                        self.log_event(f"[CHUNK] expire partial object={str(oid)[:8]}")
                        self.chunk_rx.pop(oid, None)
                except Exception:
                    self.chunk_rx.pop(oid, None)

            for oid, ts in list(getattr(self, "chunk_completed", {}).items()):
                try:
                    if now - float(ts) > KDK_CHUNK_PARTIAL_TTL:
                        self.chunk_completed.pop(oid, None)
                except Exception:
                    self.chunk_completed.pop(oid, None)

            # Sender/seeder maps deliberately outlive a transfer so Pull/WANT peers
            # can use them, but they must not accumulate for the process lifetime.
            for nid, ts in list(getattr(self, "peer_last_seen", {}).items()):
                if nid == self.node_id:
                    self.peer_last_seen[nid] = now
                    continue
                try:
                    if now - float(ts) > float(KDK_PEER_DIGEST_MAX_AGE):
                        self.peer_last_seen.pop(nid, None)
                except Exception:
                    self.peer_last_seen.pop(nid, None)

            for oid, rec in list(self.chunk_tx_store.items()):
                try:
                    created_ts = float((rec or {}).get("created_ts", now) or now)
                    expired = (now - created_ts) > float(KDK_CHUNK_TX_STORE_TTL)
                except Exception:
                    expired = True
                if expired:
                    self.chunk_tx_store.pop(oid, None)
                    # Remove repair bookkeeping tied to an object we can no longer serve.
                    for key in [k for k in self.repair_pending if len(k) >= 2 and k[1] == oid]:
                        self.repair_pending.pop(key, None)
                    for key in [k for k in self.repair_inflight if len(k) >= 2 and k[1] == oid]:
                        self.repair_inflight.pop(key, None)

        self.maybe_probe_peer_hints(now)

        # Client pending RPCs: Option A retry (+ RATE_LIMIT backoff resend)
        # ------------------------------------------------------------------
        
        # ------------------------------------------------------------------
        # client pending rpcs: Radio-style randomized retry schedule
        # ------------------------------------------------------------------
        due = []
        for rid, meta in list(self.pending_rpcs.items()):
            state = meta.get("state", "PENDING")
            if state == "RATE_LIMIT":
                continue

            sched = meta.get("retry_schedule")
            if not sched:
                base = float(meta.get("ts", now))
                sched = self._make_retry_schedule(base)
                meta["retry_schedule"] = sched
                meta["retry_i"] = 0
                self.pending_rpcs[rid] = meta

            retry_i = int(meta.get("retry_i", 0))

            if retry_i >= len(sched):
                cmd = meta.get("cmd", "?")
                qprint(f"[RPC] GIVE_UP cmd={cmd} rid={rid[:8]} after {RETRY_FURTHER_ATTEMPTS} further attempts")
                self.pending_rpcs.pop(rid, None)
                continue

            sent_ts = meta.get("sent_ts")
            if sent_ts is not None:
                try:
                    if now - float(sent_ts) < RETRY_INFLIGHT_GRACE_SECS:
                        continue
                except Exception:
                    pass

            next_ts = float(sched[retry_i])
            if now >= next_ts:
                due.append((next_ts, rid))

        # Avoid bursts: queue at most ONE due retry per cleanup cycle (oldest first).
        if due:
            due.sort(key=lambda x: x[0])
            _, rid = due[0]
            meta = self.pending_rpcs.get(rid)
            if meta:
                meta["retry_i"] = int(meta.get("retry_i", 0)) + 1
                self.pending_rpcs[rid] = meta
                # Fresh envelope/ciphertext => new ph + new PoW stamp
                self.rpc_resend(rid, count_retry=True)

        # Cuckoo Clock: admit due key chunks into q, then check pending unlocks.
        self.maybe_release_cuckoo_chunks()
        self.airgap_try_unlock()

        for k, v in list(self.vault_rid_cache.items()):
            if now - float(v.get("ts", 0)) > RPC_DEDUPE_TTL:
                self.vault_rid_cache.pop(k, None)

        for src_id, dq in list(self.vault_rate.items()):
            while dq and (now - dq[0] > VAULT_RATE_WINDOW):
                dq.popleft()
            if not dq:
                self.vault_rate.pop(src_id, None)

        if self.vault_mode and self.vault_rid_log_count >= VAULT_RID_LOG_COMPACT_EVERY:
            self.vault_rid_log_count = 0
            try:
                tmp = VAULT_RID_LOG_PATH + ".tmp"
                with open(tmp, "wb") as f:
                    for (src, rid, cmd), v in self.vault_rid_cache.items():
                        rec = {
                            "src": src,
                            "rid": rid,
                            "cmd": cmd,
                            "ts": float(v.get("ts", 0)),
                            "reply": dict(v.get("reply", {})),
                        }
                        f.write(msgpack.packb(rec, use_bin_type=True))
                os.replace(tmp, VAULT_RID_LOG_PATH)
                qprint("[CLEAN] Compacted RID log")
            except Exception as e:
                qprint(f"[WARN] RID log compact failed: {e}")

        for k in list(self.vault_exec_counts.keys()):
            if k not in self.vault_rid_cache:
                self.vault_exec_counts.pop(k, None)
    # ------------------------- Symbolic pulse monitor -------------------------


    def pulse_stream_mark(self, glyph: str):
        """Append a visible event to the moving pulse trace.

        Dummy churn is intentionally thinned so the trace reads as pulses
        rather than a saturated belt. Definitive or meaningful events are
        allowed through immediately.
        """
        try:
            g = str(glyph or "·")[:1]
            if not g:
                g = "·"

            # This is a propagation strip, not a scrolling history trace.
            # It fills from X=0 on the left toward X=Q on the right, then
            # clears and begins again. That avoids the old right-to-left
            # oscilloscope feel once the buffer is full.
            width = max(8, int(getattr(self, "pulse_stream_width", 42)))
            if len(self.pulse_stream) >= width:
                self.pulse_stream.clear()

            # Ambient dummy marks are high-volume. Let most of them become
            # quiet space, with only every Nth dummy/echo becoming visible.
            if g in ("△", "▵"):
                i = int(getattr(self, "pulse_dummy_thin_i", 0)) + 1
                self.pulse_dummy_thin_i = i
                every = max(1, int(getattr(self, "pulse_dummy_thin_every", 5)))
                self.pulse_stream.append(g if (i % every) == 0 else "·")
            else:
                # Meaningful events overwrite a preceding quiet/dummy cell if
                # possible, so ▲/A/receipt symbols read as clean spikes.
                if self.pulse_stream and self.pulse_stream[-1] in ("·", "△", "▵"):
                    self.pulse_stream[-1] = g
                else:
                    self.pulse_stream.append(g)

            self.pulse_stream_last_tick = now_ts()
        except Exception:
            pass

    def pulse_stream_idle_tick(self):
        """Let the trace drift when no local event has appended a glyph."""
        try:
            now = now_ts()
            last = float(getattr(self, "pulse_stream_last_tick", 0.0) or 0.0)
            if now - last >= 0.75:
                width = max(8, int(getattr(self, "pulse_stream_width", 42)))
                if len(self.pulse_stream) >= width:
                    self.pulse_stream.clear()
                self.pulse_stream.append("·")
                self.pulse_stream_last_tick = now
        except Exception:
            pass

    def render_pulse_stream(self, width: int = 42) -> str:
        """Render the local trace left-to-right.

        Older/current sequence begins at the left edge (X=0) and fills toward
        the right edge.  This matches the quorum/progression metaphor rather
        than an oscilloscope memory sweep.
        """
        self.pulse_stream_idle_tick()
        width = max(8, int(width))
        cells = list(getattr(self, "pulse_stream", []))[:width]
        if len(cells) < width:
            cells = cells + (["·"] * (width - len(cells)))
        return "".join(cells)

    def pulse_glyph_for_label(self, label: str) -> str:
        """Return the local display glyph for an emitted payload label.

        The glyph is intentionally not placed on the wire.  It is local UI
        metadata only, so dummy/direct frames remain indistinguishable outside
        this process.
        """
        lab = str(label or "").upper()
        if "AIRGAP" in lab:
            return "A"
        if "RECEIPT" in lab:
            return "▽"
        if lab == "DUMMY":
            return "△"
        return "▲"

    def pulse_note_emit(self, payload_hash: str, label: str = "PAYLOAD"):
        """Start/refresh a local pulse row for a payload emitted by this node."""
        ph = str(payload_hash or "")
        if not ph:
            return
        glyph = self.pulse_glyph_for_label(label)
        now = now_ts()
        if ph not in self.pulse_tracks:
            self.pulse_order.append(ph)
        self.pulse_tracks[ph] = {
            "ph": ph,
            "glyph": glyph,
            "label": str(label or "PAYLOAD"),
            "count": 1,
            "first_ts": now,
            "last_ts": now,
            "quorum_ts": None,
            "velocity": 1,
        }
        self.pulse_stream_mark(glyph)

    def pulse_note_observe(self, payload_hash: str, seen_before: bool = False):
        """Record a local sighting/collision of a tracked payload.

        This is deliberately impressionistic: count means local observations
        toward the selected trigger/quorum N, not proven global delivery.
        """
        ph = str(payload_hash or "")
        tr = self.pulse_tracks.get(ph)
        if not tr:
            return
        now = now_ts()
        n = max(1, int(getattr(self, "token_trigger", COLLISION_TRIGGER_N)))
        prev_last = float(tr.get("last_ts", now))
        tr["last_ts"] = now
        tr["count"] = min(n, int(tr.get("count", 0)) + (1 if seen_before else 0))
        # Repeated local sightings leave a short echo in the moving trace.
        # Seen-before/collision events are shown as decay glyphs rather than
        # fresh emissions, keeping the display interpretive rather than exact.
        base = str(tr.get("glyph", "△"))[:1]
        echo = {"▲": "▴", "△": "▵", "▽": "▾", "▼": "▾", "A": "a"}.get(base, base)
        self.pulse_stream_mark(echo if seen_before else base)
        # Crude liveliness signal: tighter repeated sightings create a denser trace.
        dt = max(0.001, now - prev_last)
        tr["velocity"] = max(1, min(n, int(round(3.0 / dt)) if dt < 3.0 else 1))
        if int(tr.get("count", 0)) >= n and tr.get("quorum_ts") is None:
            tr["quorum_ts"] = now
        self.pulse_tracks[ph] = tr

    def pulse_note_quorum(self, payload_hash: str):
        ph = str(payload_hash or "")
        tr = self.pulse_tracks.get(ph)
        if not tr:
            return
        n = max(1, int(getattr(self, "token_trigger", COLLISION_TRIGGER_N)))
        tr["count"] = n
        tr["quorum_ts"] = tr.get("quorum_ts") or now_ts()
        self.pulse_tracks[ph] = tr
        self.pulse_stream_mark("|")

    def pulse_prune(self):
        now = now_ts()
        max_age = float(getattr(self, "pulse_max_age", 90.0))
        for ph in list(self.pulse_tracks.keys()):
            tr = self.pulse_tracks.get(ph, {})
            age = now - float(tr.get("last_ts", tr.get("first_ts", now)))
            qts = tr.get("quorum_ts")
            if qts is not None:
                age = now - float(qts)
                if age > 12.0:
                    self.pulse_tracks.pop(ph, None)
            elif age > max_age:
                self.pulse_tracks.pop(ph, None)

    def render_turn_ring(self, count: int, n: int) -> str:
        n = max(1, int(n))
        count = max(0, min(int(count), n))
        # Keep large collision thresholds compact in the HUD.  Above 10, each
        # ring position represents ten turns; the exact token/N values remain
        # printed alongside the ring.
        if n > 10:
            slots = max(1, int(math.ceil(n / 10.0)))
            filled = max(0, min(slots, int(count // 10)))
            return "●" * filled + "○" * (slots - filled)
        return "●" * count + "○" * (n - count)

    def render_pulse_trace(self, tr: dict, n: int) -> str:
        n = max(1, int(n))
        glyph = str(tr.get("glyph", "△"))[:1]
        count = max(0, min(int(tr.get("count", 0)), n))
        qts = tr.get("quorum_ts")

        if qts is None:
            return glyph * count + "·" * (n - count)

        age = max(0.0, now_ts() - float(qts))
        if age < 1.5:
            return glyph * n + "|Q"

        decay1 = {"▲": "▴", "△": "▵", "▽": "▾", "▼": "▾", "A": "A"}.get(glyph, glyph)
        decay2 = {"▲": "˄", "△": "˄", "▽": "˅", "▼": "˅", "A": "a"}.get(glyph, "˄")
        if age < 4.0:
            k = max(1, n - 1)
            return " " + (decay1 * k)
        if age < 8.0:
            k = max(1, n - 2)
            return "  " + (decay2 * k)
        return "   ·"

    def render_pulse_rows(self, limit: int = 4) -> List[str]:
        self.pulse_prune()
        n = max(1, int(getattr(self, "token_trigger", COLLISION_TRIGGER_N)))
        rows = []
        for ph in reversed(list(getattr(self, "pulse_order", []))):
            tr = self.pulse_tracks.get(ph)
            if not tr:
                continue
            rows.append(f"{ph[:4]} {self.render_pulse_trace(tr, n)}")
            if len(rows) >= limit:
                break
        if not rows:
            rows.append("---- " + ("·" * n))
        return rows

    # ------------------------- Status line / TUI model ------------------------

    def status_snapshot(self) -> dict:
        """Return compact runtime state for status-line/TUI renderers."""
        now = now_ts()
        active_peers = [nid for nid, ts in self.active_nodes.items() if nid != self.node_id and now - ts < ACTIVE_TIMEOUT]
        airgap_waiting = 0
        try:
            keys = set(self.airgap_tickets_by_hash.keys()) | set(self.airgap_blobs_by_hash.keys())
            airgap_waiting = len([ph for ph in keys if ph not in self.airgap_unlocked])
        except Exception:
            airgap_waiting = 0
        return {
            "name": self.name,
            "peers": len(active_peers),
            "queue": len(self.outbound_queue),
            "repair": self._repair_pending_count(),
            "inflight": self._repair_inflight_count(),
            "qwait": int(getattr(self, "queue_emit_turns_wait", 0)),
            "token": int(getattr(self, "token_count", 0)),
            "n": int(getattr(self, "token_trigger", COLLISION_TRIGGER_N)),
            "turns": int(getattr(self, "metric_turns", 0)),
            "rx": int(getattr(self, "metric_rx_payloads", 0)),
            "tx": int(getattr(self, "metric_tx_payloads", 0)),
            "relay": int(getattr(self, "metric_mesh_forwards", 0)),
            "coll_rate": self.timelock_live_collision_rate(now),
            "airgap": airgap_waiting,
            "receipt_sent": int(getattr(self, "receipt_sent_count", 0)),
            "receipt_recv": int(getattr(self, "receipt_recv_count", 0)),
            "roams": int(getattr(self, "metric_peer_roams", 0)),
        }

    def _ansi(self, colour: str) -> str:
        if not bool(getattr(self, "status_colour_enabled", True)):
            return ""
        return {
            "reset": "\033[0m",
            "red": "\033[31m",
            "green": "\033[32m",
            "yellow": "\033[33m",
            "blue": "\033[34m",
            "magenta": "\033[35m",
            "cyan": "\033[36m",
            "dim": "\033[2m",
        }.get(colour, "")

    def _c(self, text: str, colour: str) -> str:
        if not bool(getattr(self, "status_colour_enabled", True)):
            return str(text)
        return f"{self._ansi(colour)}{text}{self._ansi('reset')}"

    def _inv(self, text: str) -> str:
        """Black-on-white inversion for light panes/logo panels."""
        if not bool(getattr(self, "status_colour_enabled", True)):
            return str(text)
        return f"\033[30;47m{text}\033[0m"

    def panda_logo_lines(self, s: Optional[dict] = None, state: str = "") -> list:
        """Small status logo. Closed eyes when isolated; wide eyes in churn."""
        try:
            peers = int((s or {}).get("peers", 0))
        except Exception:
            peers = 0
        st = str(state or "").upper()
        if peers <= 0 or st == "DEAD":
            eyes = "KꞰ KꞰ"
        elif st == "CHURN":
            eyes = "◉   ◉"
        elif st in ("SIMMER", "SPARSE", "LINK"):
            eyes = "◔   ◔"
        else:
            eyes = "◌   ◌"
        return [
            "┌─────────┐",
            "│ ▼     ▼ │",
            "│         │",
            f"│ {eyes:^7} │",
            "│         │",
            "│    ▼    │",
            "└─────────┘",
        ]

    def _box_line_with_logo(self, text: str, logo_line: str, width: int = 76) -> str:
        """HUD row with a right-aligned inverted panda/logo panel."""
        logo_line = str(logo_line or "")
        logo_w = self._visible_len(logo_line)
        left_w = max(10, int(width) - logo_w - 1)
        raw = self._truncate_visible(str(text), left_w)
        pad = max(0, left_w - self._visible_len(raw))
        logo = self._inv(logo_line) if logo_line else ""
        return "| " + raw + (" " * pad) + " " + logo + " |"

    def _activity_light_line(self, line: str) -> str:
        """Invert a complete activity/transcript-pane line."""
        return self._inv(line) if bool(getattr(self, "activity_light_pane", True)) else str(line)

    def churn_state(self, s: dict) -> tuple:
        """Classify recent activity with small HUD hysteresis.

        This is display-only. It avoids rapid CHURN/SIMMER/IDLE flicker when
        the scheduler is making brief, normal transitions during active relay.
        """
        now = now_ts()
        cur = (int(s.get("rx", 0)), int(s.get("relay", 0)), int(s.get("turns", 0)), int(s.get("tx", 0)))
        prev = getattr(self, "_status_prev_sample", None)
        self._status_prev_sample = (now, cur)
        peers = int(s.get("peers", 0))
        if peers <= 0:
            raw_state, raw_colour = "DEAD", "red"
        elif not prev:
            raw_state, raw_colour = "LINK", "yellow"
        else:
            _t0, old = prev
            drx = max(0, cur[0] - old[0])
            drelay = max(0, cur[1] - old[1])
            dturns = max(0, cur[2] - old[2])
            dtx = max(0, cur[3] - old[3])
            score = drx + dtx + drelay + (2 * dturns)
            if score >= 10:
                raw_state, raw_colour = "CHURN", "green"
            elif score >= 3:
                raw_state, raw_colour = "SIMMER", "green"
            elif score > 0:
                raw_state, raw_colour = "SPARSE", "yellow"
            else:
                raw_state, raw_colour = "IDLE", "dim"

        # Hysteresis is only cosmetic: hold the previous displayed state briefly
        # unless the new state is a significant escalation to CHURN or DEAD.
        prev_state = getattr(self, "_hud_display_state", None)
        prev_colour = getattr(self, "_hud_display_colour", raw_colour)
        prev_ts = float(getattr(self, "_hud_display_state_ts", 0.0) or 0.0)
        hold = float(HUD_STATE_HYSTERESIS_SECS)
        if prev_state and raw_state != prev_state and (now - prev_ts) < hold:
            if raw_state not in ("CHURN", "DEAD"):
                return prev_state, prev_colour

        if raw_state != prev_state:
            self._hud_display_state = raw_state
            self._hud_display_colour = raw_colour
            self._hud_display_state_ts = now
        return raw_state, raw_colour

    def render_status_line(self) -> str:
        spinners = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        ch = spinners[self.status_spinner_i % len(spinners)]
        self.status_spinner_i += 1
        s = self.status_snapshot()
        state, colour = self.churn_state(s)
        ring = self.render_turn_ring(int(s.get("token", 0)), int(s.get("n", 1)))
        pulse = self.render_pulse_stream(width=28)
        rows = " ".join(self.render_pulse_rows(limit=1))
        return (
            f"{ch} KDK mesh | {s['name']} | {self._c(state, colour)} | peers={s['peers']} | "
            f"turn {ring} {s['token']}/{s['n']} | q={s['queue']} qwait={s['qwait']} | "
            f"rx={s['rx']} tx={s['tx']} relay={s['relay']} | "
            f"▽={s['receipt_sent']} ▼={s['receipt_recv']} | {pulse} | {rows}"
        )

    _ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

    def _visible_len(self, text: str) -> int:
        return len(self._ANSI_RE.sub("", str(text)))

    def _truncate_visible(self, text: str, width: int) -> str:
        """Truncate while ignoring ANSI colour escapes for width accounting."""
        s = str(text)
        out = []
        visible = 0
        i = 0
        while i < len(s) and visible < width:
            if s[i] == "\033":
                m = self._ANSI_RE.match(s, i)
                if m:
                    out.append(m.group(0))
                    i = m.end()
                    continue
            out.append(s[i])
            visible += 1
            i += 1
        return "".join(out)

    def _box_line(self, text: str, width: int = 76) -> str:
        raw = self._truncate_visible(str(text), width)
        pad = max(0, width - self._visible_len(raw))
        return "| " + raw + (" " * pad) + " |"


    def identity_colour_rgb(self, node_id: str) -> tuple:
        """Return a stable, readable RGB identity colour derived from node_id.

        Only the hue varies widely. Saturation and lightness are constrained so
        names remain readable in the white transcript pane and do not collide
        with the red/amber/green semantic status palette.
        """
        raw = hashlib.sha256(str(node_id or "unknown").encode("utf-8", "ignore")).digest()
        hue = int.from_bytes(raw[:2], "big") / 65535.0
        sat = 0.62 + (raw[2] / 255.0) * 0.16
        light = 0.34 + (raw[3] / 255.0) * 0.08
        # Small local HSL -> RGB conversion avoids another dependency.
        def hue2rgb(p, q, t):
            if t < 0: t += 1
            if t > 1: t -= 1
            if t < 1/6: return p + (q - p) * 6 * t
            if t < 1/2: return q
            if t < 2/3: return p + (q - p) * (2/3 - t) * 6
            return p
        q = light * (1 + sat) if light < 0.5 else light + sat - light * sat
        pp = 2 * light - q
        r = hue2rgb(pp, q, hue + 1/3)
        g = hue2rgb(pp, q, hue)
        b = hue2rgb(pp, q, hue - 1/3)
        return tuple(max(0, min(255, int(round(v * 255)))) for v in (r, g, b))

    def identity_colour_hex(self, node_id: str) -> str:
        r, g, b = self.identity_colour_rgb(node_id)
        return f"#{r:02X}{g:02X}{b:02X}"

    def identity_colour_name(self, name: str, node_id: str) -> str:
        """Colour only a node name, restoring the surrounding pane foreground."""
        if not self.activity_colour_enabled_now() or not name:
            return str(name)
        r, g, b = self.identity_colour_rgb(node_id)
        restore = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"
        return f"\033[38;2;{r};{g};{b}m{name}{restore}"

    def identity_colour_name_hud(self, name: str, node_id: str) -> str:
        """Colour only the HUD node name, then restore the terminal foreground."""
        if not bool(getattr(self, "status_colour_enabled", True)) or not name:
            return str(name)
        r, g, b = self.identity_colour_rgb(node_id)
        return f"\033[38;2;{r};{g};{b}m{name}\033[39m"

    def activity_identity_name_map(self) -> dict:
        """Known display names mapped to their persistent cryptographic node IDs."""
        out = {str(self.name): str(self.node_id)}
        for nid in set(list(getattr(self, "peer_caps", {}).keys()) + list(getattr(self, "peer_name_by_node_id", {}).keys())):
            name = self.activity_peer_name(nid)
            if name and name not in ("none", short8(nid)):
                out.setdefault(str(name), str(nid))
        return out

    def activity_colour_identity_names(self, text: str, bold: bool = False, restore_dim: bool = False) -> str:
        """Colour exact node-name occurrences while leaving all other text alone.

        System rows may request bold peer references.  In that case the peer
        name temporarily leaves faint mode, keeps its persistent identity colour,
        and then restores the surrounding faint system-message style.
        """
        out = str(text)
        if not self.activity_colour_enabled_now():
            return out
        mapping = self.activity_identity_name_map()
        for name in sorted(mapping, key=len, reverse=True):
            if not name:
                continue
            pat = re.compile(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])")
            if bold:
                r, g, b = self.identity_colour_rgb(mapping[name])
                restore = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"
                tail = "\033[22m\033[2m" if restore_dim else "\033[22m"
                coloured = f"\033[22m\033[1m\033[38;2;{r};{g};{b}m{name}{restore}{tail}"
            else:
                coloured = self.identity_colour_name(name, mapping[name])
            out = pat.sub(lambda _m, c=coloured: c, out)
        return out

    def activity_peer_name(self, node_id: str) -> str:
        """Friendly display name for the activity pane."""
        if not node_id:
            return "none"
        if node_id == self.node_id:
            return self.name
        name = str(getattr(self, "peer_name_by_node_id", {}).get(node_id, "") or "").strip()
        if name:
            return name
        caps = getattr(self, "peer_caps", {}).get(node_id, {})
        if isinstance(caps, dict):
            name = str(caps.get("name", "") or "").strip()
            if name:
                return name
        return short8(node_id)

    def activity_recipient_all_ids(self) -> list:
        """All active, directable peers for the pane header/selector."""
        now = now_ts()
        ids = []
        for nid, ts in list(getattr(self, "active_nodes", {}).items()):
            if nid == self.node_id:
                continue
            if self.peer_is_suspended(nid):
                continue
            try:
                if now - float(ts) > ACTIVE_TIMEOUT:
                    continue
            except Exception:
                continue
            caps = getattr(self, "peer_caps", {}).get(nid, {})
            if isinstance(caps, dict) and caps.get("env") and nid in getattr(self, "peer_keys", {}):
                direct = getattr(self, "peer_addr_by_node_id", {}).get(nid)
                # A missing direct mapping is still usable when the broad candidate
                # pool is populated: broadcast() will enter its cryptographically
                # safe transport fallback instead of silently dropping the PAYLOAD.
                if direct or getattr(self, "peers", None):
                    ids.append(nid)
        ids.sort(key=lambda x: self.activity_peer_name(x).lower())
        return ids

    def activity_recipient_ids(self) -> list:
        """Directable peers filtered by the live type-to-find query."""
        ids = self.activity_recipient_all_ids()
        query = str(getattr(self, "activity_recipient_search", "") or "").strip().casefold()
        if not query:
            return ids
        return [
            nid for nid in ids
            if query in self.activity_peer_name(nid).casefold()
            or query in str(nid).casefold()
            or query in short8(nid).casefold()
        ]

    def activity_current_recipient_id(self) -> str:
        ids = self.activity_recipient_ids()
        if not ids:
            return ""
        selected = str(getattr(self, "activity_recipient_selected_id", "") or "")
        if selected in ids:
            idx = ids.index(selected)
        else:
            idx = min(max(0, int(getattr(self, "activity_recipient_index", 0))), len(ids) - 1)
            selected = ids[idx]
        self.activity_recipient_index = idx
        self.activity_recipient_selected_id = selected
        return selected

    def activity_open_recipient_dropdown(self):
        current = self.activity_current_recipient_id()
        self.activity_recipient_search = ""
        self.activity_recipient_view_start = 0
        self.activity_recipient_selected_id = current
        self.activity_dropdown_open = True
        try:
            self._status_redraw.set()
        except Exception:
            pass

    def activity_close_recipient_dropdown(self):
        self.activity_dropdown_open = False
        self.activity_recipient_search = ""
        self.activity_recipient_view_start = 0
        try:
            self._status_redraw.set()
        except Exception:
            pass

    def activity_recipient_search_key(self, ch: str) -> bool:
        """Consume one printable/backspace key while the To selector is open."""
        if not bool(getattr(self, "activity_dropdown_open", False)):
            return False
        if ch in ("\x08", "\x7f"):
            query = str(getattr(self, "activity_recipient_search", "") or "")
            self.activity_recipient_search = query[:-1]
        elif ch and ch >= " " and not unicodedata.category(ch).startswith("C"):
            query = str(getattr(self, "activity_recipient_search", "") or "")
            if len(query) < 64:
                self.activity_recipient_search = query + ch
        else:
            return False
        ids = self.activity_recipient_ids()
        self.activity_recipient_index = 0
        self.activity_recipient_selected_id = ids[0] if ids else ""
        self.activity_recipient_view_start = 0
        try:
            self._status_redraw.set()
        except Exception:
            pass
        return True

    def activity_recipient_view(self, page_size: int) -> tuple:
        """Return a stable scrolling viewport centred on the selected node ID."""
        ids = self.activity_recipient_ids()
        page_size = max(1, int(page_size))
        self.activity_recipient_page_size = page_size
        if not ids:
            self.activity_recipient_view_start = 0
            return ids, 0, [], 0, 0
        current = self.activity_current_recipient_id()
        idx = ids.index(current) if current in ids else 0
        max_start = max(0, len(ids) - page_size)
        start = max(0, min(int(getattr(self, "activity_recipient_view_start", 0)), max_start))
        if idx < start:
            start = idx
        elif idx >= start + page_size:
            start = idx - page_size + 1
        start = max(0, min(start, max_start))
        self.activity_recipient_view_start = start
        return ids, start, ids[start:start + page_size], start, max(0, len(ids) - (start + page_size))

    def activity_recipient_label(self, node_id: str) -> str:
        """Disambiguate duplicate display names with the short cryptographic ID."""
        name = self.activity_peer_name(node_id)
        folded = name.casefold()
        duplicates = sum(
            1 for nid in self.activity_recipient_all_ids()
            if self.activity_peer_name(nid).casefold() == folded
        )
        return f"{name} · {short8(node_id)}" if duplicates > 1 else name

    def activity_console_mode(self) -> bool:
        return str(getattr(self, "activity_mode", "main") or "main") == "console"

    def activity_actions_list(self) -> list:
        if self.activity_console_mode():
            return list(getattr(self, "console_actions", ["Peers", "Discover", "Nodes", "Queue", "Version", "Name", "Dingo", "RTT Probe", "Trace", "Trace Watch"]) or ["Peers"])
        return list(getattr(self, "activity_actions", ["Text", "File", "Airgap", "Patch", "Console", "Restart", "Exit"]) or ["Text"])

    def activity_current_action(self) -> str:
        actions = self.activity_actions_list()
        if not actions:
            return ""
        if self.activity_console_mode():
            idx = int(getattr(self, "activity_console_action_index", 0)) % len(actions)
            self.activity_console_action_index = idx
            return actions[idx]
        idx = int(getattr(self, "activity_action_index", 0)) % len(actions)
        self.activity_action_index = idx
        return actions[idx]

    def activity_focus_count(self) -> int:
        if self.activity_console_mode():
            return 1
        return 1 + len(self.activity_actions_list())

    def activity_focused_is_to(self) -> bool:
        return (not self.activity_console_mode()) and int(getattr(self, "activity_focus_index", 1)) == 0

    def activity_focused_action_index(self) -> int:
        if self.activity_console_mode():
            return 0
        idx = int(getattr(self, "activity_focus_index", 1)) - 1
        actions = self.activity_actions_list()
        if not actions:
            return 0
        return idx % len(actions)

    def activity_set_focused_action(self):
        if self.activity_console_mode():
            return
        if not self.activity_focused_is_to():
            self.activity_action_index = self.activity_focused_action_index()

    def activity_wrapped_rows(self, inner: int = 78) -> list:
        """Return the currently retained activity history as display rows.

        activity_scroll_offset is measured in *rendered/wrapped rows*, not raw
        messages, so PageUp/PageDown behaves like a terminal history view even
        when long System messages wrap onto multiple pane rows.
        """
        wrapped = []
        try:
            inner = max(20, int(inner))
            for item in list(getattr(self, "activity_lines", []) or []):
                if isinstance(item, dict):
                    who = str(item.get("who", "System") or "System")
                    msg = str(item.get("text", "") or "")
                else:
                    who, msg = item
                prefix = f"{who}: "
                max_msg = max(8, inner - len(prefix) - 2)
                chunks = textwrap.wrap(
                    str(msg),
                    width=max_msg,
                    break_long_words=False,
                    replace_whitespace=False,
                ) or [""]

                # UI-only separation: human sent/received messages get one blank
                # display row on each side, while consecutive System events remain
                # compact. Dedupe adjacent blanks so back-to-back human messages do
                # not grow a double gap. This does not alter transported text.
                human_message = str(who).strip().lower() != "system"
                if human_message and (not wrapped or wrapped[-1][1] != ""):
                    wrapped.append(("", ""))
                wrapped.append((str(who), prefix + chunks[0]))
                for cont in chunks[1:]:
                    wrapped.append((str(who), (" " * len(prefix)) + cont))
                if human_message:
                    wrapped.append(("", ""))
        except Exception:
            return []
        return wrapped

    def activity_max_scroll_offset(self, inner: int = 78) -> int:
        try:
            total = len(self.activity_wrapped_rows(inner))
            page = max(1, int(getattr(self, "activity_history_body_height", 6) or 6))
            return max(0, total - page)
        except Exception:
            return 0

    def activity_scroll(self, delta: int):
        try:
            off = int(getattr(self, "activity_scroll_offset", 0)) + int(delta)
            self.activity_scroll_offset = max(0, min(self.activity_max_scroll_offset(), off))
        except Exception:
            self.activity_scroll_offset = 0

    def activity_page_scroll(self, direction: int):
        """Scroll notification pane by one visible page.

        direction > 0 moves back into history; direction < 0 moves toward the
        live tail. New messages keep appending while the offset remains > 0.
        """
        try:
            page = max(1, int(getattr(self, "activity_history_body_height", 6) or 6) - 1)
            self.activity_scroll(page * (1 if int(direction) > 0 else -1))
        except Exception:
            self.activity_scroll_offset = 0

    def activity_scroll_home(self):
        try:
            self.activity_scroll_offset = self.activity_max_scroll_offset()
        except Exception:
            self.activity_scroll_offset = 0

    def activity_scroll_end(self):
        self.activity_scroll_offset = 0

    def activity_add(self, who: str, text: str):
        """Append a short human-readable line to the activity pane.

        Keep the tuple format used by render_activity_pane, and suppress only
        immediate duplicates so normal repeated messages can still appear later.
        """
        try:
            who = str(who or "System").strip() or "System"
            text = str(text or "").replace("\r", " ").replace("\n", " ").strip()
            if not text:
                return
            try:
                last = self.activity_lines[-1] if self.activity_lines else None
                if isinstance(last, tuple) and len(last) >= 2:
                    if str(last[0]) == who and str(last[1]) == text:
                        return
                elif isinstance(last, dict):
                    if str(last.get("who", "")) == who and str(last.get("text", "")) == text:
                        return
            except Exception:
                pass
            self.activity_lines.append((who, text))
            if int(getattr(self, "activity_scroll_offset", 0) or 0) <= 0:
                self.activity_scroll_offset = 0
        except Exception:
            pass

    def activity_system(self, text: str):
        self.activity_add("System", text)

    def _activity_typewriter_worker(self):
        """Render queued incoming human messages progressively, UI-only."""
        while True:
            with self.activity_typewriter_lock:
                if not self.activity_typewriter_queue:
                    self.activity_typewriter_active = False
                    return
                sender, text = self.activity_typewriter_queue.popleft()

            sender = str(sender or "Peer").strip() or "Peer"
            text = str(text or "").replace("\r", " ").replace("\n", " ").strip()
            if not text:
                continue

            # A mutable activity record lets the HUD redraw the same history row
            # as characters arrive, instead of appending one row per character.
            record = {"who": sender, "text": "", "typing": True}
            try:
                self.activity_lines.append(record)
                if int(getattr(self, "activity_scroll_offset", 0) or 0) <= 0:
                    self.activity_scroll_offset = 0
            except Exception:
                self.activity_add(sender, text)
                continue

            # Aim for a readable terminal feel (~30-45 cps), but cap long-message
            # animation so cosmetic rendering cannot become tedious.
            max_total = 6.0
            nominal = 0.028
            if len(text) * nominal > max_total:
                nominal = max(0.004, max_total / max(1, len(text)))

            shown = []
            for ch in text:
                shown.append(ch)
                record["text"] = "".join(shown)
                # Wake the status renderer for this character. The normal HUD
                # remains on its ordinary interval when no animation is active,
                # but incoming text no longer waits for that coarse refresh and
                # therefore appears as a genuine terminal/teletype stream.
                try:
                    self._status_redraw.set()
                except Exception:
                    pass
                try:
                    if ch in ".!?":
                        delay = min(0.14, nominal * random.uniform(2.8, 4.2))
                    elif ch in ",;:":
                        delay = min(0.08, nominal * random.uniform(1.6, 2.5))
                    elif ch == " ":
                        delay = nominal * random.uniform(0.45, 0.8)
                    else:
                        delay = nominal * random.uniform(0.70, 1.30)
                    time.sleep(max(0.002, delay))
                except Exception:
                    pass
            record["text"] = text
            record["typing"] = False
            try:
                self._status_redraw.set()
            except Exception:
                pass

    def activity_message(self, sender: str, text: str, typed: bool = False):
        if not typed:
            self.activity_add(sender, text)
            return
        try:
            with self.activity_typewriter_lock:
                self.activity_typewriter_queue.append((str(sender), str(text)))
                if self.activity_typewriter_active:
                    return
                self.activity_typewriter_active = True
            threading.Thread(
                target=self._activity_typewriter_worker,
                name=f"kdk-typewriter-{self.port}",
                daemon=True,
            ).start()
        except Exception:
            self.activity_add(sender, text)

    def activity_next_focus(self):
        if bool(getattr(self, "activity_peer_menu_open", False)):
            self.activity_move_peer_menu(1); return
        if bool(getattr(self, "activity_patch_menu_open", False)):
            self.activity_move_patch_mode(1)
            return
        if bool(getattr(self, "activity_airgap_menu_open", False)):
            self.activity_move_airgap_mode(1)
            return
        # If the To list is open, Tab cycles recipients instead of leaving the list.
        if bool(getattr(self, "activity_dropdown_open", False)):
            self.activity_move_recipient(1)
            return
        # Console drop-down should behave like the To/name selector: Tab moves
        # through the visible menu items rather than leaving the menu.
        if self.activity_console_mode() and bool(getattr(self, "activity_console_dropdown_open", False)):
            self.activity_move_console_action(1)
            return
        count = max(1, self.activity_focus_count())
        default_idx = 0 if self.activity_console_mode() else 1
        self.activity_focus_index = (int(getattr(self, "activity_focus_index", default_idx)) + 1) % count
        self.activity_set_focused_action()

    def activity_prev_focus(self):
        if bool(getattr(self, "activity_peer_menu_open", False)):
            self.activity_move_peer_menu(-1); return
        if bool(getattr(self, "activity_patch_menu_open", False)):
            self.activity_move_patch_mode(-1)
            return
        if bool(getattr(self, "activity_airgap_menu_open", False)):
            self.activity_move_airgap_mode(-1)
            return
        if bool(getattr(self, "activity_dropdown_open", False)):
            self.activity_move_recipient(-1)
            return
        if self.activity_console_mode() and bool(getattr(self, "activity_console_dropdown_open", False)):
            self.activity_move_console_action(-1)
            return
        count = max(1, self.activity_focus_count())
        default_idx = 0 if self.activity_console_mode() else 1
        self.activity_focus_index = (int(getattr(self, "activity_focus_index", default_idx)) - 1) % count
        self.activity_set_focused_action()

    def activity_move_recipient(self, delta: int):
        ids = self.activity_recipient_ids()
        if not ids:
            return
        current = self.activity_current_recipient_id()
        idx = ids.index(current) if current in ids else 0
        idx = (idx + int(delta)) % len(ids)
        self.activity_recipient_index = idx
        self.activity_recipient_selected_id = ids[idx]
        try:
            self._status_redraw.set()
        except Exception:
            pass

    def activity_page_recipient(self, direction: int):
        page = max(1, int(getattr(self, "activity_recipient_page_size", 8) or 8))
        self.activity_move_recipient(page * (1 if int(direction) > 0 else -1))

    def activity_recipient_home_end(self, end: bool):
        ids = self.activity_recipient_ids()
        if not ids:
            return
        idx = len(ids) - 1 if end else 0
        self.activity_recipient_index = idx
        self.activity_recipient_selected_id = ids[idx]
        try:
            self._status_redraw.set()
        except Exception:
            pass

    def activity_move_airgap_mode(self, delta: int):
        self.activity_airgap_menu_index = (
            int(getattr(self, "activity_airgap_menu_index", 0)) + int(delta)
        ) % 4

    def activity_move_console_action(self, delta: int):
        actions = self.activity_actions_list()
        if not actions:
            return
        self.activity_console_action_index = (
            int(getattr(self, "activity_console_action_index", 0)) + int(delta)
        ) % len(actions)

    def activity_enter_console(self):
        self.activity_dropdown_open = False
        self.activity_console_dropdown_open = True
        self.activity_mode = "console"
        self.activity_focus_index = 0
        self.activity_console_action_index = 0
        self.activity_system("Console ready")

    def activity_leave_console(self):
        self.activity_dropdown_open = False
        self.activity_console_dropdown_open = False
        self.activity_mode = "main"
        try:
            idx = self.activity_actions_list().index("Console")
        except Exception:
            idx = 0
        self.activity_action_index = idx
        self.activity_focus_index = 1 + idx
        self.activity_system("Console closed")

    def activity_escape_back(self):
        """Esc is local-only: cancel UI state; it never recalls mesh traffic."""
        if bool(getattr(self, "activity_peer_menu_open", False)):
            if str(getattr(self,"activity_peer_menu_level","list"))=="manage":
                nid = str(getattr(self, "activity_peer_menu_node_id", "") or "")
                self.activity_peer_menu_level="list"; self.activity_peer_menu_node_id=""
                self.activity_peer_menu_selected_key = f"peer:{nid}" if nid else ""
                self.activity_peer_menu_current_entry()
            elif str(getattr(self, "activity_peer_menu_search", "") or ""):
                self.activity_peer_menu_search = ""
                self.activity_peer_menu_view_start = 0
                self.activity_peer_menu_current_entry()
            else:
                self.activity_peer_menu_open=False
            return
        if bool(getattr(self, "activity_patch_menu_open", False)):
            if bool(getattr(self, "activity_patch_history_open", False)):
                self.activity_patch_history_open = False
                self.activity_patch_menu_index = 0
                return
            self.activity_patch_menu_open = False
            self.activity_system("Patch menu closed")
            return
        if bool(getattr(self, "activity_airgap_menu_open", False)):
            self.activity_airgap_menu_open = False
            self.activity_system("Airgap cancelled")
            return
        if bool(getattr(self, "activity_timelock_status_open", False)):
            self.activity_timelock_status_open = False
            return
        if bool(getattr(self, "activity_dropdown_open", False)):
            if str(getattr(self, "activity_recipient_search", "") or ""):
                self.activity_recipient_search = ""
                self.activity_recipient_view_start = 0
                ids = self.activity_recipient_ids()
                selected = str(getattr(self, "activity_recipient_selected_id", "") or "")
                if selected in ids:
                    self.activity_recipient_index = ids.index(selected)
                elif ids:
                    self.activity_recipient_index = 0
                    self.activity_recipient_selected_id = ids[0]
                return
            self.activity_close_recipient_dropdown()
            self.activity_system("Back")
            return
        if self.activity_console_mode():
            if bool(getattr(self, "activity_console_dropdown_open", False)):
                self.activity_console_dropdown_open = False
                self.activity_system("Back")
                return
            self.activity_leave_console()
            return
        # Local prompt cancellation is handled inside activity_readline_in_pane.
        self.activity_system("Back")

    def activity_console_show_dingo_height(self):
        self.activity_system("Dingo: checking local client and mesh witness")
        diag = self.dingo_height_diagnostics()

        ch = diag.get("client_height")
        if ch is not None:
            self.activity_system(f"Dingo local height: {ch}")
        else:
            self.activity_system("Dingo local client unavailable")
            err = str(diag.get("client_error", "") or "")
            if err:
                self.activity_system(f"Dingo local error: {err[:120]}")

        nh = diag.get("network_height")
        if nh is not None:
            witness = str(diag.get("network_witness", "") or "")
            wname = self.activity_peer_name(witness) if witness else "unknown"
            age = diag.get("network_age")
            age_text = f" age={int(age)}s" if age is not None else ""
            self.activity_system(f"Dingo mesh height: {nh} via {wname}{age_text}")
        else:
            self.activity_system("Dingo mesh witness unavailable")

        if ch is not None and nh is not None:
            diff = abs(int(ch) - int(nh))
            self.activity_system(f"Dingo local/witness delta: {diff} block{'s' if diff != 1 else ''}")


    def activity_airgap_cleanup(self):
        """Purge local temporary Airgap/Cuckoo artefacts from the Airgap menu.

        This removes scratch/state that can safely be regenerated or re-imported:
        pending courier copies, local outbound courier copies, unlocked scratch
        copies, and Airgap/Cuckoo state files. Patch staging/history, retrieved
        downloads and inbox messages are deliberately untouched.
        """
        roots = [
            AIRGAP_PENDING_DIR,
            AIRGAP_OUT_DIR,
            AIRGAP_UNLOCKED_DIR,
            AIRGAP_STATE_DIR,
        ]
        removed_files = 0
        removed_bytes = 0
        errors = 0
        patterns = (".kdk", ".json", ".tmp", ".msgpack", ".msgpackl")
        for root in roots:
            try:
                if not os.path.isdir(root):
                    continue
                for dirpath, _dirnames, filenames in os.walk(root):
                    for fn in filenames:
                        if not fn.lower().endswith(patterns):
                            continue
                        full = os.path.join(dirpath, fn)
                        try:
                            st = os.stat(full)
                            os.remove(full)
                            removed_files += 1
                            removed_bytes += int(getattr(st, "st_size", 0) or 0)
                        except Exception:
                            errors += 1
            except Exception:
                errors += 1

        # Clear in-memory Airgap/Cuckoo scratch so the running node reflects the purge.
        try:
            self.airgap_tickets_by_hash.clear()
            self.airgap_blobs_by_hash.clear()
            self.airgap_unlocked.clear()
            self.airgap_unlocked_paths_by_hash.clear()
            self.airgap_download_paths_by_hash.clear()
            self.airgap_exports_by_hash.clear()
            self.airgap_pending_keys_by_hash.clear()
            self.cuckoo_pending = []
            self.cuckoo_released.clear()
        except Exception:
            pass

        kb = removed_bytes / 1024.0
        self.activity_system(f"Clean-up removed {removed_files} Airgap artefact(s), {kb:.1f} KiB")
        if errors:
            self.activity_system(f"Clean-up completed with {errors} warning(s)")
        self.log_event(f"[CLEANUP] airgap removed_files={removed_files} removed_bytes={removed_bytes} errors={errors}")

    def activity_add_peer_interactive(self):
        """Prompt for one IP and probe the standard KryptDisk UDP ports."""
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                host = self.activity_readline_in_pane("Peer IP").strip()
                if not host:
                    self.activity_system("Add Peer cancelled")
                    return
                try:
                    ip = str(ipaddress.ip_address(host))
                except ValueError:
                    self.activity_system(f"Invalid IP address: {host}")
                    return
                added = self.add_manual_peer_ip(ip)
                ports = f"{KDK_STANDARD_PEER_PORTS[0]}-{KDK_STANDARD_PEER_PORTS[-1]}"
                if added:
                    self.activity_system(f"Add Peer: probing {ip} on ports {ports}; saved {len(added)} candidate(s)")
                else:
                    self.activity_system(f"Add Peer: {ip} already configured; probes resent on ports {ports}")
            except Exception as e:
                self.activity_system(f"Add Peer failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def activity_console_toggle_trace(self):
        enabled = not bool(getattr(self, "trace_payloads_enabled", False))
        self.trace_payloads_enabled = enabled
        if enabled:
            ensure_dir("logs")
            self.activity_system(
                f"Trace: ON - metadata-only payload tracing to {getattr(self, 'trace_log_path', os.path.join('logs','trace.log'))}"
            )
            self.trace_payload("TRACE_ON", "", events=int(getattr(self, "trace_event_count", 0)))
        else:
            # Record the final event before disabling output.
            self.trace_payload("TRACE_OFF", "", events=int(getattr(self, "trace_event_count", 0)))
            self.trace_payloads_enabled = False
            self.activity_system(
                f"Trace: OFF - {int(getattr(self, 'trace_event_count', 0))} event(s) recorded this run"
            )

    def activity_console_edit_name(self):
        """Edit the mutable display name without moving or replacing identity state."""
        old_name = str(self.name)
        with self.stdin_lock:
            old_term = term_enter_canonical_echo()
            flush_stdin()
            try:
                raw = self.activity_readline_in_pane(
                    "Name",
                    hint=f"current: {old_name}  |  maximum 32 characters",
                )
                if not str(raw).strip():
                    self.activity_system("Display name unchanged")
                    return
                clean = kdk_save_display_name(
                    str(getattr(self, "profile_path", KDK_PROFILE_PATH) or KDK_PROFILE_PATH),
                    raw,
                )
                if clean == old_name:
                    self.activity_system(f"Display name remains {clean}")
                    return
                self.name = clean
                self.log_event(
                    f"[PROFILE] display name changed old={old_name!r} new={clean!r} "
                    f"node_id={short8(self.node_id)}"
                )
                self.activity_system(
                    f"Display name changed: {old_name} -> {clean}; identity remains {short8(self.node_id)}"
                )
                try:
                    self._status_redraw.set()
                except Exception:
                    pass
            except Exception as exc:
                self.activity_system(f"Name change failed: {exc}")
                self.log_event(f"[PROFILE] display name change failed err={type(exc).__name__}: {exc}")
            finally:
                term_restore(old_term)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def activity_console_trace_watch_interactive(self):
        """Add/list/clear runtime relay-witness filters without changing wire state."""
        def show_watches():
            hp = sorted(getattr(self, "trace_watch_hash_prefixes", set()) or ())
            op = sorted(getattr(self, "trace_watch_origin_prefixes", set()) or ())
            self.activity_system(
                "Trace Watch: ph=" + (",".join(hp) if hp else "none") +
                " origin=" + (",".join(op) if op else "none")
            )

        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                show_watches()
                raw = self.activity_readline_in_pane(
                    "Watch ph:<hash-prefix> / origin:<node-id-prefix> / clear / list"
                ).strip()
                if not raw or raw.lower() == "list":
                    show_watches()
                    return
                cmd = raw.lower().strip()
                if cmd == "clear":
                    self.trace_watch_hash_prefixes.clear()
                    self.trace_watch_origin_prefixes.clear()
                    self.activity_system("Trace Watch: cleared")
                    self.trace_payload("WATCH_CLEAR", "")
                    return

                kind = "ph"
                value = cmd
                if ":" in cmd:
                    kind, value = cmd.split(":", 1)
                    kind = kind.strip()
                    value = value.strip()
                value = "".join(ch for ch in value.lower() if ch in "0123456789abcdef")
                if len(value) < 8:
                    self.activity_system("Trace Watch: prefix must contain at least 8 hex characters")
                    return
                if kind in ("ph", "hash", "payload"):
                    self.trace_watch_hash_prefixes.add(value)
                    self.activity_system(f"Trace Watch: payload ph={value} added")
                    self.trace_payload("WATCH_ADD", "", kind="ph", prefix=value)
                elif kind in ("origin", "node", "src"):
                    self.trace_watch_origin_prefixes.add(value)
                    self.activity_system(f"Trace Watch: origin={value} added")
                    self.trace_payload("WATCH_ADD", "", kind="origin", prefix=value)
                else:
                    self.activity_system("Trace Watch: use ph:<prefix>, origin:<prefix>, clear, or list")
            except Exception as e:
                self.activity_system(f"Trace Watch failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def activity_peer_menu_all_ids(self) -> list:
        """Known peers for Console -> Peers, ordered by display name."""
        known=set(); known.update((getattr(self,"peer_addr_by_node_id",{}) or {}).keys()); known.update((getattr(self,"peer_name_by_node_id",{}) or {}).keys()); known.update((getattr(self,"peer_last_seen",{}) or {}).keys()); known.discard(self.node_id)
        return sorted(known,key=lambda nid:(self.activity_peer_name(nid).casefold(), str(nid)))

    def activity_peer_menu_ids(self) -> list:
        """Console peers filtered by name, full/short ID, or known address."""
        rows = self.activity_peer_menu_all_ids()
        query = str(getattr(self, "activity_peer_menu_search", "") or "").strip().casefold()
        if not query:
            return rows
        matched = []
        for nid in rows:
            addr = (getattr(self, "peer_addr_by_node_id", {}) or {}).get(nid)
            atxt = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) and len(addr) == 2 else ""
            if (query in self.activity_peer_name(nid).casefold()
                    or query in str(nid).casefold()
                    or query in short8(nid).casefold()
                    or query in atxt.casefold()):
                matched.append(nid)
        return matched

    @staticmethod
    def activity_peer_menu_entry_key(entry: tuple) -> str:
        return f"{entry[0]}:{entry[1]}"

    def activity_peer_menu_entries(self) -> list:
        if str(getattr(self, "activity_peer_menu_level", "list")) == "manage":
            nid = str(getattr(self, "activity_peer_menu_node_id", "") or "")
            state = self.peer_policy_state(nid)
            return [("action", x) for x in (
                "Details",
                "Unmute Direct" if state == "muted" else "Mute Direct",
                "Resume Peer" if state == "suspended" else "Suspend Peer",
                "Unblock Peer" if state == "blocked" else "Block Peer",
                "Remove Manual Peer", "Back"
            )]
        rows = self.activity_peer_menu_ids()
        return [("peer",nid) for nid in rows] + [("action","Add Peer"),("action","Back")]

    def activity_peer_menu_current_entry(self):
        entries = self.activity_peer_menu_entries()
        if not entries:
            return None
        key = str(getattr(self, "activity_peer_menu_selected_key", "") or "")
        keys = [self.activity_peer_menu_entry_key(entry) for entry in entries]
        if key in keys:
            idx = keys.index(key)
        else:
            idx = min(max(0, int(getattr(self, "activity_peer_menu_index", 0))), len(entries) - 1)
        self.activity_peer_menu_index = idx
        self.activity_peer_menu_selected_key = keys[idx]
        return entries[idx]

    def activity_move_peer_menu(self, delta: int):
        entries=self.activity_peer_menu_entries()
        if entries:
            self.activity_peer_menu_current_entry()
            idx=(int(getattr(self,"activity_peer_menu_index",0))+int(delta))%len(entries)
            self.activity_peer_menu_index=idx
            self.activity_peer_menu_selected_key=self.activity_peer_menu_entry_key(entries[idx])

    def activity_page_peer_menu(self, direction: int):
        page=max(1,int(getattr(self,"activity_peer_menu_page_size",8) or 8))
        self.activity_move_peer_menu(page * (1 if int(direction)>0 else -1))

    def activity_peer_menu_home_end(self, end: bool):
        entries=self.activity_peer_menu_entries()
        if not entries: return
        idx=len(entries)-1 if end else 0
        self.activity_peer_menu_index=idx
        self.activity_peer_menu_selected_key=self.activity_peer_menu_entry_key(entries[idx])

    def activity_peer_menu_search_key(self, ch: str) -> bool:
        if not (bool(getattr(self,"activity_peer_menu_open",False)) and str(getattr(self,"activity_peer_menu_level","list"))=="list"):
            return False
        if ch in ("\x08","\x7f"):
            self.activity_peer_menu_search=str(getattr(self,"activity_peer_menu_search","") or "")[:-1]
        elif ch and ch >= " " and not unicodedata.category(ch).startswith("C"):
            query=str(getattr(self,"activity_peer_menu_search","") or "")
            if len(query)<64: self.activity_peer_menu_search=query+ch
        else:
            return False
        self.activity_peer_menu_index=0; self.activity_peer_menu_view_start=0; self.activity_peer_menu_selected_key=""
        self.activity_peer_menu_current_entry()
        try: self._status_redraw.set()
        except Exception: pass
        return True

    def activity_peer_menu_view(self, page_size: int) -> tuple:
        entries=self.activity_peer_menu_entries(); page_size=max(1,int(page_size)); self.activity_peer_menu_page_size=page_size
        if not entries:
            self.activity_peer_menu_view_start=0
            return entries,0,[],0,0
        self.activity_peer_menu_current_entry(); idx=int(getattr(self,"activity_peer_menu_index",0))
        max_start=max(0,len(entries)-page_size); start=max(0,min(int(getattr(self,"activity_peer_menu_view_start",0)),max_start))
        if idx<start: start=idx
        elif idx>=start+page_size: start=idx-page_size+1
        start=max(0,min(start,max_start)); self.activity_peer_menu_view_start=start
        return entries,start,entries[start:start+page_size],start,max(0,len(entries)-(start+page_size))

    def activity_open_peer_menu(self):
        self.activity_console_dropdown_open=False; self.activity_peer_menu_open=True; self.activity_peer_menu_level="list"; self.activity_peer_menu_index=0; self.activity_peer_menu_node_id=""; self.activity_peer_menu_search=""; self.activity_peer_menu_selected_key=""; self.activity_peer_menu_view_start=0
        self.activity_peer_menu_current_entry()

    def activity_peer_details(self,nid:str):
        addr=(getattr(self,"peer_addr_by_node_id",{}) or {}).get(nid); caps=(getattr(self,"peer_caps",{}) or {}).get(nid,{}) or {}; state=self.peer_policy_state(nid).upper(); name=self.activity_peer_name(nid)
        atxt=f"{addr[0]}:{addr[1]}" if isinstance(addr,tuple) and len(addr)==2 else "unknown"
        self.activity_system(f"Peer {name}: id={nid} address={atxt} policy={state}")
        self.activity_system(f"Peer {name}: relay={'yes' if bool(caps.get('relay')) else 'no'} version={caps.get('script_version','?')}")

    def activity_peer_menu_execute(self):
        entries=self.activity_peer_menu_entries()
        if not entries: self.activity_peer_menu_open=False; return
        current=self.activity_peer_menu_current_entry(); kind,value=current
        if str(getattr(self,"activity_peer_menu_level","list"))=="list":
            if kind=="peer": self.activity_peer_menu_node_id=str(value); self.activity_peer_menu_level="manage"; self.activity_peer_menu_index=0; self.activity_peer_menu_selected_key="action:Details"; return
            if str(value)=="Add Peer":
                self.activity_peer_menu_open=False; self.activity_add_peer_interactive(); self.activity_peer_menu_open=True; self.activity_peer_menu_level="list"; self.activity_peer_menu_index=0; self.activity_peer_menu_search=""; self.activity_peer_menu_selected_key=""; self.activity_peer_menu_view_start=0; self.activity_peer_menu_current_entry(); return
            self.activity_peer_menu_open=False; return
        nid=str(getattr(self,"activity_peer_menu_node_id","") or ""); action=str(value); name=self.activity_peer_name(nid)
        if action=="Back": self.activity_peer_menu_level="list"; self.activity_peer_menu_node_id=""; self.activity_peer_menu_selected_key=f"peer:{nid}"; self.activity_peer_menu_current_entry(); return
        if action=="Details": self.activity_peer_details(nid); return
        if action=="Mute Direct": self.set_peer_policy(nid,"muted"); self.activity_system(f"Peer {name}: direct messages and user files muted")
        elif action=="Unmute Direct": self.set_peer_policy(nid,"allow"); self.activity_system(f"Peer {name}: direct messaging and files allowed")
        elif action=="Suspend Peer": self.set_peer_policy(nid,"suspended"); self.activity_system(f"Peer {name}: suspended locally")
        elif action=="Resume Peer": self.set_peer_policy(nid,"allow"); self.activity_system(f"Peer {name}: resumed")
        elif action=="Block Peer": self.set_peer_policy(nid,"blocked"); self.activity_system(f"Peer {name}: blocked locally")
        elif action=="Unblock Peer": self.set_peer_policy(nid,"allow"); self.activity_system(f"Peer {name}: unblocked")
        elif action=="Remove Manual Peer":
            removed=self.remove_manual_peer_identity(nid); self.activity_system(f"Peer {name}: removed {removed} manual bootstrap endpoint(s)" if removed else f"Peer {name}: no manual bootstrap endpoint to remove")
        self.activity_peer_menu_index=0

    def activity_console_execute(self):
        console_label = self.activity_current_action()
        self.activity_system(f"Console: {console_label}")
        cmd = str(console_label).lower()
        if cmd != "back":
            # After running a console command, keep Console mode active but
            # close the chooser so the command output is visible immediately.
            # Enter opens the chooser again; Esc leaves Console.
            self.activity_console_dropdown_open = False
        if cmd == "back":
            self.activity_leave_console()
        elif cmd == "discover":
            self.last_discover_ts = 0.0
            self.last_discover_height = 0
            self.maybe_discover(now_ts())
            self.activity_system("DISCOVER probe sent")
        elif cmd in ("rtt probe", "rtt", "rtt-probe"):
            try:
                self.manual_rtt_probe()
            except Exception as e:
                self.activity_system(f"RTT Probe failed: {e}")
                self.log_event(f"[HELLO_RTT_PROBE] failed err={type(e).__name__}: {e}")
        elif cmd == "nodes":
            now = now_ts()
            # Passive health view: existing verified traffic supplies the timestamps;
            # this adds no new heartbeat/probe traffic.
            known_ids = {self.node_id}
            known_ids.update(getattr(self, "peer_last_seen", {}).keys())
            known_ids.update(getattr(self, "peer_name_by_node_id", {}).keys())
            known_ids.update(getattr(self, "peer_addr_by_node_id", {}).keys())
            rows = []
            for nid in known_ids:
                name = self.activity_peer_name(nid)
                if nid == self.node_id:
                    age = 0.0
                    state = "Online"
                else:
                    ts = getattr(self, "peer_last_seen", {}).get(nid)
                    if ts is None:
                        age = None
                        state = "Known"
                    else:
                        try:
                            age = max(0.0, now - float(ts))
                        except Exception:
                            age = None
                        if age is None:
                            state = "Known"
                        elif age <= float(ACTIVE_TIMEOUT):
                            state = "Online"
                        elif age <= 5.0 * float(ACTIVE_TIMEOUT):
                            state = "Stale"
                        else:
                            state = "Offline"
                rows.append((name, state, age, nid))
            state_rank = {"Online": 0, "Stale": 1, "Offline": 2, "Known": 3}
            rows.sort(key=lambda x: (state_rank.get(x[1], 9), x[0].lower()))
            if not rows:
                self.activity_system("Nodes: none")
            else:
                self.activity_system("Nodes: mesh health / last heard")
                for name, state, age, nid in rows[:8]:
                    if age is None:
                        heard = "not yet heard directly"
                    elif nid == self.node_id:
                        heard = "local"
                    else:
                        heard = f"{self.activity_human_duration(age)} ago"
                    self.activity_system(
                        f"{name:<12} {state:<7} Last heard {heard} id={short8(nid)}"
                    )
        elif cmd == "queue":
            partial = len(getattr(self, "chunk_rx", {}) or {})
            completed = len(getattr(self, "chunk_completed", {}) or {})
            self.activity_system(
                f"Queue: outbound={len(self.outbound_queue)} qwait={getattr(self, 'queue_emit_turns_wait', 0)} "
                f"partial_chunks={partial} completed_chunks={completed}"
            )
        elif cmd == "peers":
            self.activity_open_peer_menu()
        elif cmd == "version":
            self.activity_system(f"Local: {SCRIPT_VERSION} revision={SCRIPT_REVISION} hash={SCRIPT_HASH}")
            mesh_versions = {}
            local_key = (str(SCRIPT_VERSION), int(SCRIPT_REVISION))
            mesh_versions[local_key] = mesh_versions.get(local_key, 0) + 1
            for nid, caps in list(getattr(self, "peer_caps", {}).items())[:8]:
                if isinstance(caps, dict):
                    peer_version = str(caps.get("script_version", "?"))
                    peer_revision = caps.get("script_revision")
                    try:
                        peer_revision = int(peer_revision)
                    except Exception:
                        peer_revision = revision_from_version(peer_version)
                    mesh_key = (peer_version, peer_revision)
                    mesh_versions[mesh_key] = mesh_versions.get(mesh_key, 0) + 1
                    self.activity_system(
                        f"Peer {self.activity_peer_name(nid)}: {peer_version} revision={peer_revision} "
                        f"hash={caps.get('script_hash','?')}"
                    )
            summary = sorted(mesh_versions.items(), key=lambda item: (-item[0][1], item[0][0]))
            self.activity_system(
                "Mesh summary: " + "; ".join(
                    f"{version} revision={revision} nodes={count}"
                    for (version, revision), count in summary
                )
            )
        elif cmd in ("name", "display name", "display-name"):
            self.activity_console_edit_name()
        elif cmd == "dingo":
            self.activity_console_show_dingo_height()
        elif cmd == "trace":
            self.activity_console_toggle_trace()
        elif cmd in ("trace watch", "trace-watch", "tracewatch"):
            self.activity_console_trace_watch_interactive()
        else:
            self.activity_system(f"Unknown console command: {self.activity_current_action()}")

    def activity_restart_menu(self):
        """Exit cleanly with the dedicated launcher-supervised restart code."""
        self.activity_system("Restart selected - closing cleanly before launcher restart")
        self.request_shutdown("manual-restart", "menu")

    def activity_exit_menu(self):
        """Menu-based graceful exit path for Lite builds."""
        self.activity_system("Exit selected - graceful shutdown requested")
        self.request_shutdown("graceful", "menu")

    def activity_execute_current(self):
        """Enter key behaviour for the beta pane."""
        if bool(getattr(self,"activity_peer_menu_open",False)):
            self.activity_peer_menu_execute(); return
        if bool(getattr(self, "activity_timelock_status_open", False)):
            self.activity_timelock_status_open = False
            return
        if bool(getattr(self, "activity_patch_menu_open", False)):
            self.activity_patch_execute_menu()
            return
        if bool(getattr(self, "activity_airgap_menu_open", False)):
            idx = int(getattr(self, "activity_airgap_menu_index", 0)) % 4
            self.activity_airgap_menu_open = False
            if idx == 2:
                self.activity_timelock_status_open = True
            elif idx == 3:
                self.activity_airgap_cleanup()
            else:
                self.activity_airgap_interactive("export" if idx == 0 else "import")
            return
        if self.activity_console_mode():
            if bool(getattr(self, "activity_console_dropdown_open", False)):
                self.activity_console_execute()
            else:
                self.activity_console_dropdown_open = True
            return
        if self.activity_focused_is_to():
            if bool(getattr(self, "activity_dropdown_open", False)):
                self.activity_close_recipient_dropdown()
            else:
                self.activity_open_recipient_dropdown()
            return

        self.activity_dropdown_open = False
        self.activity_set_focused_action()
        action = self.activity_current_action().lower()
        if action == "text":
            self.activity_send_text_interactive()
        elif action == "file":
            self.activity_send_file_interactive()
        elif action == "airgap":
            self.activity_airgap_menu_index = 0
            self.activity_airgap_menu_open = True
        elif action == "patch":
            self.activity_patch_menu_index = 0
            self.activity_patch_candidate_path = ""
            self.activity_patch_history_open = False
            self.activity_patch_menu_open = True
        elif action == "console":
            self.activity_enter_console()
        elif action == "restart":
            self.activity_restart_menu()
        elif action == "exit":
            self.activity_exit_menu()
        else:
            self.activity_system(f"Unknown action: {self.activity_current_action()}")

    def _activity_wrap_editor_text(self, text: str, width: int) -> list:
        """Wrap editable text while preserving explicit Shift+Enter paragraph breaks."""
        width = max(1, int(width))
        logical = str(text or "").split("\n")
        rows = []
        wrapper = textwrap.TextWrapper(
            width=width,
            expand_tabs=True,
            replace_whitespace=False,
            drop_whitespace=False,
            break_long_words=True,
            break_on_hyphens=False,
        )
        for part in logical:
            if part == "":
                rows.append("")
                continue
            wrapped = wrapper.wrap(part)
            rows.extend(wrapped if wrapped else [""])
        return rows or [""]

    def activity_readline_in_pane(self, label: str, multiline: bool = False, hint: str = "", mode: str = "") -> str:
        """Read editable text inside the activity pane.

        Enter submits. In multiline mode Shift+Enter inserts a newline and the
        editor shows three visible rows, scrolling internally thereafter.
        Esc cancels immediately. Terminals that expose Shift separately are
        supported directly; common xterm/kitty modified-Enter sequences are
        also recognised.
        """
        old_label = getattr(self, "activity_input_label", "")
        old_text = getattr(self, "activity_input_text", "")
        old_multiline = bool(getattr(self, "activity_input_multiline", False))
        old_hint = getattr(self, "activity_input_hint", "")
        old_mode = getattr(self, "activity_input_mode", "")
        self.activity_input_label = str(label or "Input").strip() or "Input"
        self.activity_input_text = ""
        self.activity_input_multiline = bool(multiline)
        self.activity_input_hint = "" if multiline else str(hint or "").strip()
        self.activity_input_mode = "" if multiline else str(mode or "").strip().upper()
        saved = None

        def read_editor_key():
            # Windows console does not encode Shift+Enter in the character
            # returned by msvcrt. Track Shift while waiting for the key as well
            # as immediately before/after reading it; checking only afterwards
            # misses quick key releases on some keyboards/consoles.
            if os.name == "nt" and msvcrt is not None:
                shifted = False
                try:
                    import ctypes
                    user32 = ctypes.windll.user32
                    while not msvcrt.kbhit():
                        if user32.GetAsyncKeyState(0x10) & 0x8000:
                            shifted = True
                        time.sleep(0.004)
                    shifted = shifted or bool(user32.GetAsyncKeyState(0x10) & 0x8000)
                except Exception:
                    pass
                ch = msvcrt.getwch()
                try:
                    shifted = shifted or bool(ctypes.windll.user32.GetAsyncKeyState(0x10) & 0x8000)
                except Exception:
                    pass
                if ch in ("\x00", "\xe0"):
                    try:
                        msvcrt.getwch()
                    except Exception:
                        pass
                    return "", False
                return ch, shifted

            ch = sys.stdin.read(1)
            if ch != "\x1b":
                return ch, False

            # Distinguish a bare Esc from modified-key CSI sequences without
            # waiting noticeably. Typical Shift+Enter encodings include
            # ESC [ 13 ; 2 u and ESC [ 27 ; 2 ; 13 ~.
            seq = ch
            try:
                fd = sys.stdin.fileno()
                deadline = time.time() + 0.035
                while time.time() < deadline and len(seq) < 24:
                    ready, _, _ = select.select([fd], [], [], max(0.0, deadline - time.time()))
                    if not ready:
                        break
                    seq += sys.stdin.read(1)
                    if seq.endswith(("u", "~")):
                        break
            except Exception:
                pass
            if seq in ("\x1b[13;2u", "\x1b[13;2~", "\x1b[27;2;13~"):
                return "\n", True
            return "\x1b", False

        try:
            try:
                saved = term_enter_raw_noecho()
            except Exception:
                saved = None
            # Ask compatible xterm-style terminals to report modified keys.
            # Unsupported terminals harmlessly ignore this sequence.
            if os.name != "nt" and sys.stderr.isatty():
                try:
                    sys.stderr.write("\x1b[>4;2m")
                    sys.stderr.flush()
                except Exception:
                    pass
            while True:
                if bool(getattr(self, "status_box_enabled", False)) and sys.stderr.isatty():
                    try:
                        box = self.render_status_box()
                        lines = box.splitlines()
                        sys.stderr.write("\0337\033[H")
                        for line in lines:
                            sys.stderr.write("\033[2K" + line + "\n")

                        # Place the cursor at the end of the visible editor text.
                        panel_w = self.terminal_panel_width()
                        pane_w = max(50, min(120, int(max(46, panel_w - 4))))
                        inner = pane_w - 2
                        prefix = f" {self.activity_input_label} ▷ "
                        available = max(1, inner - len(prefix))
                        if self.activity_input_multiline:
                            wrapped = self._activity_wrap_editor_text(self.activity_input_text, available)
                            visible = wrapped[-5:]
                            # render_status_box ends with: five editor rows,
                            # separator, two light status rows, bottom border.
                            prompt_row = len(lines) - 9 + len(visible)
                            prompt_col = 2 + len(prefix) + len(visible[-1])
                        else:
                            prompt_row = len(lines) - 1
                            prompt_col = 3 + len(self.activity_input_label) + 3 + len(self.activity_input_text)
                        sys.stderr.write(f"\033[{prompt_row};{prompt_col}H")
                        sys.stderr.flush()
                    except Exception:
                        pass

                ch, shifted = read_editor_key()
                if ch == "\x1b":
                    self.activity_input_text = ""
                    return ""
                if ch in ("\r", "\n"):
                    if self.activity_input_multiline and shifted:
                        self.activity_input_text += "\n"
                        continue
                    return str(self.activity_input_text)
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch in ("\x7f", "\b"):
                    self.activity_input_text = self.activity_input_text[:-1]
                    continue
                if ch and ch >= " ":
                    self.activity_input_text += ch
        finally:
            if os.name != "nt" and sys.stderr.isatty():
                try:
                    sys.stderr.write("\x1b[>4m")
                    sys.stderr.flush()
                except Exception:
                    pass
            term_restore(saved)
            self.activity_input_label = old_label
            self.activity_input_text = old_text
            self.activity_input_multiline = old_multiline
            self.activity_input_hint = old_hint
            self.activity_input_mode = old_mode

    def activity_send_text_interactive(self):
        dst = self.activity_current_recipient_id()
        if not dst:
            self.activity_system("No recipient selected")
            return
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                text = self.activity_readline_in_pane("Text", multiline=True)
                if not text.strip():
                    self.activity_system("Text cancelled")
                    return
                self.queue_message_to_peer(dst, text)
            except Exception as e:
                self.activity_system(f"Text failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def _file_embargo_status(self, now: Optional[float] = None) -> tuple:
        now = now_ts() if now is None else float(now)
        if bool(getattr(self, "file_transfer_inflight", False)):
            return False, "until the current file is delivered"
        start_ts = float(getattr(self, "file_embargo_start_ts", 0.0) or 0.0)
        if start_ts <= 0.0:
            return True, ""
        start_h = int(getattr(self, "file_embargo_start_height", 0) or 0)
        fresh_h = self._fresh_dingo_height_for_control(now)
        if start_h > 0 and fresh_h > 0:
            eligible_h = start_h + int(globals().get("KDK_FILE_EMBARGO_BLOCKS", 2)) + 1
            if fresh_h >= eligible_h:
                return True, ""
            return False, f"until Dingo height {eligible_h}"
        fallback = max(1.0, float(globals().get("KDK_FILE_EMBARGO_FALLBACK_SECS", 120.0)))
        elapsed = max(0.0, now - start_ts)
        if elapsed >= fallback:
            return True, ""
        return False, f"for {int(math.ceil(fallback - elapsed))} more seconds (Dingo fallback)"

    def _start_file_embargo(self, object_id: str = ""):
        now = now_ts()
        h = self._fresh_dingo_height_for_control(now)
        self.file_transfer_inflight = False
        self.file_embargo_start_height = int(h) if h > 0 else 0
        self.file_embargo_start_ts = now
        if h > 0:
            eligible_h = int(h) + int(globals().get("KDK_FILE_EMBARGO_BLOCKS", 2)) + 1
            self.log_event(f"[FILE_EMBARGO] start object={str(object_id)[:8]} height={h} eligible={eligible_h}")
            self.activity_system(f"File transfer cooling period — 2 Dingo heights (until {eligible_h})")
        else:
            secs = int(globals().get("KDK_FILE_EMBARGO_FALLBACK_SECS", 120.0))
            self.log_event(f"[FILE_EMBARGO] start object={str(object_id)[:8]} height=unavailable fallback={secs}s")
            self.activity_system(f"File transfer cooling period — {secs} seconds (Dingo unavailable)")

    def _queue_or_defer_user_file(self, dst: str, data: bytes, path: str):
        if self.peer_is_suspended(dst):
            self.activity_system(f"File transfer unavailable: {self.activity_peer_name(dst)} is {self.peer_policy_state(dst)}")
            return None
        open_now, why = self._file_embargo_status()
        if not open_now:
            self.deferred_file_transfers.append({"dst": str(dst), "data": bytes(data), "path": str(path)})
            self.log_event(f"[FILE_EMBARGO] deferred dst={short8(dst)} file={os.path.basename(path)!r} {why}")
            self.activity_system(f"File queued — transfer embargo {why}")
            return None
        self.file_embargo_start_height = 0
        self.file_embargo_start_ts = 0.0
        blocks = self.build_kdk_object_blocks(data, filename_hint=path)
        self.queue_kdk_object_blocks(dst, blocks, label="KDK-FILE")
        self.file_transfer_inflight = True
        m = blocks[0]["data"]
        self.log_event(f"[QUEUE] file dst={short8(dst)} object={m['object_id'][:8]} bytes={m['total_size']} chunks={m['chunk_count']} qlen={len(self.outbound_queue)}")
        self.activity_system(f"File queued for {self.activity_peer_name(dst)} ({os.path.basename(path)}, {m['total_size']} bytes)")
        return m

    def maybe_release_deferred_files(self, now: Optional[float] = None):
        if not getattr(self, "deferred_file_transfers", None):
            return
        open_now, _why = self._file_embargo_status(now)
        if not open_now:
            return
        rec = self.deferred_file_transfers.popleft()
        try:
            self._queue_or_defer_user_file(str(rec.get("dst", "")), bytes(rec.get("data", b"")), str(rec.get("path", "file.bin")))
            self.log_event(f"[FILE_EMBARGO] released deferred remaining={len(self.deferred_file_transfers)}")
        except Exception as exc:
            self.log_event(f"[FILE_EMBARGO] deferred release failed err={type(exc).__name__}: {exc}")
            self.activity_system(f"Deferred file failed: {exc}")

    def activity_send_file_interactive(self):
        dst = self.activity_current_recipient_id()
        if not dst:
            self.activity_system("No recipient selected")
            return
        with self.stdin_lock:
            old = term_enter_canonical_echo()
            flush_stdin()
            try:
                path = self.activity_readline_in_pane("File", hint="enter/paste file path").strip().strip('"')
                if not path:
                    self.activity_system("File cancelled")
                    return
                if not os.path.exists(path):
                    self.activity_system(f"File not found: {path}")
                    return
                data = open(path, "rb").read()
                if len(data) > KDK_OBJECT_MAX_SIZE:
                    self.activity_system(f"File too large: {len(data)} > {KDK_OBJECT_MAX_SIZE}")
                    return
                self._queue_or_defer_user_file(dst, data, path)
            except Exception as e:
                self.activity_system(f"File failed: {e}")
            finally:
                term_restore(old)
                if self._raw_term_state is not None:
                    term_enter_raw_noecho()

    def activity_handle_arrow(self, direction: str):
        if bool(getattr(self,"activity_peer_menu_open",False)):
            self.activity_move_peer_menu(-1 if direction in ("up","left") else 1); return
        if bool(getattr(self, "activity_patch_menu_open", False)):
            self.activity_move_patch_mode(-1 if direction in ("up", "left") else 1)
            return
        if bool(getattr(self, "activity_airgap_menu_open", False)):
            if direction in ("up", "left"):
                self.activity_move_airgap_mode(-1)
            elif direction in ("down", "right"):
                self.activity_move_airgap_mode(1)
            return
        if bool(getattr(self, "activity_dropdown_open", False)):
            if direction in ("up", "left"):
                self.activity_move_recipient(-1)
            elif direction in ("down", "right"):
                self.activity_move_recipient(1)
            return
        if self.activity_console_mode() and bool(getattr(self, "activity_console_dropdown_open", False)):
            delta = -1 if direction in ("up", "left") else 1
            self.activity_move_console_action(delta)
            return
        # Left/right are bidirectional toolbar navigation. Up/down retain the
        # notification-history behaviour. Both directions wrap naturally.
        if direction == "left":
            self.activity_prev_focus()
        elif direction == "right":
            self.activity_next_focus()
        elif direction == "up":
            self.activity_scroll(1)
        elif direction == "down":
            self.activity_scroll(-1)

    def activity_colour_enabled_now(self) -> bool:
        try:
            return bool(getattr(self, "status_colour_enabled", True)) and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        except Exception:
            return False

    def activity_colour(self, who: str, msg: str = "") -> str:
        """Restrained colour for activity-pane text only."""
        try:
            m = str(msg or "").lower()
            # One deliberately restrained safety accent.  Integrity failures
            # remain red; a valid patch that may contain executable code is a
            # trust decision, so render only that caution in soft amber.
            if "may contain executable code" in m and self.activity_colour_enabled_now():
                return "\033[38;2;190;137;58m"
            # The light transcript pane uses black-on-white; avoid nested colour
            # resets inside rows because they cancel the pane inversion.
            if bool(getattr(self, "activity_light_pane", True)):
                return ""
            if not self.activity_colour_enabled_now():
                return ""
            w = str(who or "")
            if "failed" in m or "error" in m or "rejected" in m:
                return "\033[31m"
            if "waiting" in m or "timelock" in m or "queued" in m:
                return "\033[33m"
            if w == "System":
                return "\033[36m"
            if w == str(getattr(self, "name", "")):
                return "\033[32m"
            return "\033[37m"
        except Exception:
            return ""

    def activity_reset_colour(self) -> str:
        try:
            if not self.activity_colour_enabled_now():
                return ""
            # Inside the light pane, reset only the foreground to black.  A
            # full SGR reset would cancel the white pane background mid-row.
            return "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[0m"
        except Exception:
            return ""

    def activity_human_duration(self, seconds: float) -> str:
        try:
            s = max(0, int(round(float(seconds))))
        except Exception:
            s = 0
        if s < 60:
            return f"{s}s"
        m, sec = divmod(s, 60)
        if m < 60:
            return f"{m}m {sec}s" if sec else f"{m}m"
        h, m = divmod(m, 60)
        if h < 24:
            return f"{h}h {m}m" if m else f"{h}h"
        d, h = divmod(h, 24)
        return f"{d}d {h}h" if h else f"{d}d"

    def activity_airgap_wait_message(self, payload_hash: str, target_height: int, current_height: int, remaining_blocks: int):
        try:
            bs = max(1.0, float(getattr(self, "airgap_block_secs", 60) or 60))
            eta = self.activity_human_duration(max(0, int(remaining_blocks)) * bs)
            self.activity_system(
                f"Airgap waiting {max(0, int(remaining_blocks))} blocks (~{eta}) "
                f"until height {int(target_height)}"
            )
        except Exception:
            self.activity_system(f"Airgap waiting until height {target_height}")


    def terminal_panel_width(self) -> int:
        """Return one shared border-to-border width for the live workspace.

        The UI uses the terminal's current width, leaving a small margin and
        clamping the result so it remains readable on both small SSH windows
        and large desktop terminals.
        """
        try:
            cols = int(shutil.get_terminal_size((100, 24)).columns)
        except Exception:
            cols = 100
        if cols < 82:
            return max(50, cols - 2)
        return max(80, min(120, cols - 2))

    def activity_selected_control(self, text: str, selected: bool) -> str:
        """Render menu focus using the observed light-pane intensity behaviour."""
        text = str(text)
        m = re.match(r"^(\[\s*)(.*?)(\s+[▽▼]\s*\])$", text)

        if bool(getattr(self, "activity_light_pane", True)):
            if not selected:
                return "\033[1m" + text + "\033[22m"
            if m:
                return m.group(1) + "\033[2m" + m.group(2) + m.group(3)[:-1] + "\033[22m" + m.group(3)[-1:]
            return "\033[2m" + text + "\033[22m"

        if not selected:
            return "\033[2m" + text + "\033[22m"
        if m:
            return m.group(1) + "\033[1m" + m.group(2) + m.group(3)[:-1] + "\033[22m" + m.group(3)[-1:]
        return "\033[1m" + text + "\033[22m"

    def activity_peer_control(self, node_id: str, selected: bool, label: str = "") -> str:
        """Render a coloured peer selector independently of menu intensity.

        Peer identities use normal weight while idle and ANSI bold while selected.
        This deliberately leaves the ordinary light-pane menu treatment unchanged.
        """
        node_id = str(node_id or "")
        name = str(label or (self.activity_peer_name(node_id) if node_id else "none"))
        arrow = "▼" if selected else "▽"
        if not node_id or not self.activity_colour_enabled_now():
            if selected:
                foreground = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"
                return f"[ \033[1m{name}\033[22m {foreground}{arrow} ]"
            return f"[ {name} {arrow} ]"

        r, g, b = self.identity_colour_rgb(node_id)
        restore = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"
        colour = f"\033[38;2;{r};{g};{b}m"
        if selected:
            return f"[ {colour}\033[1m{name}\033[22m{restore} {arrow} ]"
        return f"[ {colour}{name}{restore} {arrow} ]"

    def activity_peer_pointer_row(self, text: str, selected: bool) -> str:
        """Render peer-list pointer and peer text as two independent elements.

        The pointer always stays at normal intensity.  Only the selected peer
        text receives bold intensity, so later movement through the list cannot
        accidentally invert/fade the triangle along with the peer label.
        """
        label = str(text)
        if not selected:
            return f"    {label}"
        foreground = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"
        # Reset intensity before the pointer, reset again before the label, then
        # apply bold to the label only.  Reasserting bold after the foreground
        # escape avoids terminals that lose intensity while changing colour.
        return f"  \033[22m{foreground}▶ \033[22m\033[1m{label}\033[22m"

    def render_activity_pane(self, width: int = 78, height: int = 12) -> str:
        """Simple bordered message/system pane below the fixed HUD."""
        width = max(50, min(120, int(width)))
        inner = width - 2
        top = "+" + ("-" * inner) + "+"
        sep = "|" + ("-" * inner) + "|"

        focus = int(getattr(self, "activity_focus_index", 1))
        dropdown = bool(getattr(self, "activity_dropdown_open", False))
        actions = self.activity_actions_list()
        parts = []

        if self.activity_console_mode():
            cur = self.activity_current_action() or "Back"
            mark = "▼" if bool(getattr(self, "activity_console_dropdown_open", False)) else "▽"
            control = self.activity_selected_control(f"[ {cur} {mark} ]", True)
            action_line = f" Console: {control}"
            lines = [top, self._activity_box_line(action_line, inner), sep]
            body_h = max(3, int(height) - 5)
        else:
            rid = self.activity_current_recipient_id()
            to_control = self.activity_peer_control(rid, focus == 0)
            to_line = f" To: {to_control}"
            for i, act in enumerate(actions, start=1):
                mark = "▼" if focus == i else "▽"
                parts.append(self.activity_selected_control(f"[ {act} {mark} ]", focus == i))
            action_line = " " + " ".join(parts)
            lines = [top, self._activity_box_line(to_line, inner), self._activity_box_line(action_line, inner), sep]
            body_h = max(3, int(height) - 6)
        rows = []

        if bool(getattr(self, "activity_timelock_status_open", False)):
            # Focused status mode owns the body completely. Do not fall through
            # to the normal transcript renderer below, otherwise mesh/System
            # history is appended beneath the filtered inventory.
            rows = [("", row) for row in self.activity_airgap_status_rows()]

        elif bool(getattr(self, "activity_peer_menu_open", False)):
            level=str(getattr(self,"activity_peer_menu_level","list"))
            if level=="list":
                query=str(getattr(self,"activity_peer_menu_search","") or "")
                find_text=query if query else "type to filter"
                if query and not self.activity_peer_menu_ids(): find_text += " (no matches)"
                rows.append(("",f" Find peer ▷ {find_text}"))
                entries,start,visible,above,below=self.activity_peer_menu_view(max(1,body_h-3))
                rows.append(("",f" ↑ {above} more item{'s' if above != 1 else ''}" if above else ""))
            else:
                entries=self.activity_peer_menu_entries(); start=0; visible=entries[:max(1,body_h)]; below=0
                self.activity_peer_menu_current_entry()
            cur_i=int(getattr(self,"activity_peer_menu_index",0))%max(1,len(entries))
            for offset,(kind,value) in enumerate(visible):
                i=start+offset; marker="▶" if i==cur_i else " "
                if kind=="peer":
                    nid=str(value); name=self.activity_peer_name(nid); state=self.peer_policy_state(nid); addr=(getattr(self,"peer_addr_by_node_id",{}) or {}).get(nid); atxt=f"{addr[0]}:{addr[1]}" if isinstance(addr,tuple) and len(addr)==2 else "unknown"; suffix="" if state=="allow" else f" [{state.upper()}]"; label=f"{name}: {atxt} id={short8(nid)}{suffix}"
                else: label=str(value)
                rows.append(("",self.activity_peer_pointer_row(label,i==cur_i)))
            if level=="list": rows.append(("",f" ↓ {below} more item{'s' if below != 1 else ''}" if below else ""))
        elif bool(getattr(self, "activity_patch_menu_open", False)):
            entries = self.activity_patch_menu_entries()
            cur_i = int(getattr(self, "activity_patch_menu_index", 0)) % max(1, len(entries))
            for i, (kind, value) in enumerate(entries[:max(1, min(len(entries), body_h))]):
                marker = "▶" if i == cur_i else " "
                if kind in ("candidate", "history"):
                    label = f"{value.get('state','?'):<8} {value.get('version','?')} {str(value.get('hash',''))[:12]}"
                else:
                    label = str(value)
                rows.append(("", self.activity_selected_control(f"  {marker} {label}", i == cur_i)))
        elif bool(getattr(self, "activity_airgap_menu_open", False)):
            cur_i = int(getattr(self, "activity_airgap_menu_index", 0)) % 4
            for i, label in enumerate(("EXPORT", "IMPORT", "TIMELOCK STATUS", "CLEAN-UP")):
                marker = "▶" if i == cur_i else " "
                row = f"  {marker} {label}"
                row = self.activity_selected_control(row, i == cur_i)
                rows.append(("", row))
        elif self.activity_console_mode() and bool(getattr(self, "activity_console_dropdown_open", False)):
            acts = self.activity_actions_list()
            cur_i = int(getattr(self, "activity_console_action_index", 0)) % max(1, len(acts))
            for i, act in enumerate(acts[:max(1, min(len(acts), body_h))]):
                mark = "▼" if i == cur_i else "▽"
                rows.append(("", self.activity_selected_control(f"[ {act} {mark} ]", i == cur_i)))
        elif dropdown:
            query = str(getattr(self, "activity_recipient_search", "") or "")
            find_text = query if query else "type to filter"
            rows.append(("", f" Find peer ▷ {find_text}"))
            page_size = max(1, body_h - 3)
            ids, start, visible_ids, above, below = self.activity_recipient_view(page_size)
            if ids:
                cur = self.activity_current_recipient_id()
                rows.append(("", f" ↑ {above} more peer{'s' if above != 1 else ''}" if above else ""))
                for nid in visible_ids:
                    rows.append(("", self.activity_peer_pointer_row(
                        self.activity_recipient_label(nid), nid == cur
                    )))
                rows.append(("", f" ↓ {below} more peer{'s' if below != 1 else ''}" if below else ""))
            else:
                rows.append(("", ""))
                rows.append(("", "  no matching peers" if query else "  no recipients"))
        else:
            self.activity_history_body_height = body_h
            wrapped = self.activity_wrapped_rows(inner)
            off = max(0, min(int(getattr(self, "activity_scroll_offset", 0) or 0), max(0, len(wrapped) - body_h)))
            self.activity_scroll_offset = off
            # Keep one calm spacer row beneath the menu before transcript
            # content begins. The overall pane remains exactly 22 lines high;
            # only the available transcript body is reduced by one row.
            transcript_h = max(1, body_h - 1)
            end_idx = max(0, len(wrapped) - off)
            start_idx = max(0, end_idx - transcript_h)
            rows = [("", "")] + wrapped[start_idx:end_idx]

        for who, row in rows[:body_h]:
            is_system = str(who) == "System"
            if is_system:
                # On the light pane this terminal renders ANSI bold as paler.
                # Use that deliberately so system chatter recedes while peer
                # references retain their identity colour at normal intensity.
                row = "\033[1m" + str(row)
                row = self.activity_colour_identity_names(row, bold=False)
                row += "\033[22m"
            else:
                # Peer-list selection rows already carry their own pointer/text
                # intensity.  Identity colouring changes foreground only and must
                # not become the final operation that determines selection weight.
                # Selected peer rows need different treatment from ordinary
                # identity-coloured rows.  On several Windows consoles SGR 1
                # changes a true-colour foreground to a brighter/paler colour
                # rather than producing a visibly heavier glyph.  Keep the
                # pointer and label independent: the pointer remains ordinary
                # black, while the selected label uses the pane foreground plus
                # bold.  Unselected peers retain their identity colours.
                if "▶ " in str(row):
                    plain = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", str(row))
                    pointer_pos = plain.find("▶ ")
                    label = plain[pointer_pos + 2:] if pointer_pos >= 0 else plain
                    foreground = "\033[30m" if bool(getattr(self, "activity_light_pane", True)) else "\033[39m"

                    # Match the working To: peer selector exactly: set the
                    # identity foreground first, then enable bold.  On Windows
                    # VT the order matters; setting true-colour *after* SGR 1
                    # can collapse the intended emphasis into bright/grey text.
                    selected_label = label
                    mapping = self.activity_identity_name_map()
                    for peer_name in sorted(mapping, key=len, reverse=True):
                        if not peer_name:
                            continue
                        match = re.search(
                            r"(?<![\w-])" + re.escape(peer_name) + r"(?![\w-])",
                            label,
                        )
                        if match is None:
                            continue
                        start, end = match.span()
                        r, g, b = self.identity_colour_rgb(mapping[peer_name])
                        identity_colour = f"\033[38;2;{r};{g};{b}m"
                        selected_label = (
                            f"{label[:start]}{identity_colour}\033[1m{label[start:end]}"
                            f"\033[22m{foreground}{label[end:]}"
                        )
                        break
                    row = f"  \033[22m{foreground}▶ {selected_label}"
                else:
                    row = self.activity_colour_identity_names(row)
            colour = self.activity_colour(who, row)
            reset = self.activity_reset_colour() if colour else ""
            lines.append(self._activity_box_line(" " + row, inner, prefix_ansi=colour, suffix_ansi=reset))
        header_count = 3 if self.activity_console_mode() else 4
        while len(lines) < header_count + body_h:
            lines.append(self._activity_box_line("", inner))

        lines.append(sep)
        input_label = str(getattr(self, "activity_input_label", "") or "").strip()
        input_line_indices = set()
        if input_label:
            txt = str(getattr(self, "activity_input_text", "") or "")
            prefix = f" {input_label} ▷ "
            if bool(getattr(self, "activity_input_multiline", False)):
                available = max(1, inner - len(prefix))
                wrapped = self._activity_wrap_editor_text(txt, available)
                visible = wrapped[-5:]
                # Reserve five dark compose rows. The editor scrolls only when
                # content exceeds those five rows, leaving comfortable space for
                # normal messages without crowding the transcript above.
                display_rows = visible + ([""] * max(0, 5 - len(visible)))
                for i, row in enumerate(display_rows):
                    input_line_indices.add(len(lines))
                    lead = prefix if i == 0 else (" " * len(prefix))
                    lines.append(self._activity_box_line(lead + row, inner))

                # Keep message limits/hints visually separate from editable text.
                # These rows deliberately stay in the light transcript palette.
                lines.append(sep)
                canonical_count = len(kdk_canonicalize_message_text(txt))
                counter = f" {canonical_count} / {KDK_MESSAGE_MAX_CHARS} chars"
                if canonical_count > KDK_MESSAGE_MAX_CHARS:
                    limit_note = "  OVER LIMIT — split into shorter messages or send as a file."
                elif canonical_count == KDK_MESSAGE_MAX_CHARS:
                    limit_note = "  LIMIT REACHED — split into shorter messages or send as a file."
                else:
                    limit_note = f"  Maximum {KDK_MESSAGE_MAX_CHARS} characters per message."
                lines.append(self._activity_box_line(counter + limit_note, inner))
                lines.append(self._activity_box_line(" Enter Send   Shift+Enter New line", inner))
            else:
                mode = str(getattr(self, "activity_input_mode", "") or "").strip().upper()
                if mode:
                    prefix = f" {mode:<6} | {input_label} ▷ "
                input_line_indices.add(len(lines))
                lines.append(self._activity_box_line(prefix + txt, inner))
                hint = str(getattr(self, "activity_input_hint", "") or "").strip()
                if hint:
                    lines.append(self._activity_box_line(" " + hint, inner))
        else:
            if int(getattr(self, "activity_scroll_offset", 0) or 0) > 0:
                hint = f" History ▲ offset={int(getattr(self, 'activity_scroll_offset', 0) or 0)}  Home start  PgUp/PgDn scroll  End live"
            else:
                hint = " Live ▼   ←/→ or Tab Move   Shift+Tab Reverse   ↑/↓ Menu   Enter Select   Esc Back"
            lines.append(self._activity_box_line(hint, inner))
        lines.append(top)
        if bool(getattr(self, "activity_light_pane", True)):
            lit = []
            for i, line in enumerate(lines):
                # Keep every live editor row dark so the three-line composer is
                # visually distinct from the white transcript/history pane.
                if i in input_line_indices:
                    lit.append(line)
                else:
                    lit.append(self._activity_light_line(line))
            lines = lit
        return "\n".join(lines)

    def _activity_box_line(self, text: str, inner: int, prefix_ansi: str = "", suffix_ansi: str = "") -> str:
        raw = self._truncate_visible(str(text), inner)
        pad = max(0, inner - self._visible_len(raw))
        return "|" + str(prefix_ansi or "") + raw + str(suffix_ansi or "") + (" " * pad) + "|"

    def render_status_box(self) -> str:
        panel_w = self.terminal_panel_width()
        content_w = max(46, panel_w - 4)
        s = self.status_snapshot()
        state, colour = self.churn_state(s)
        # Colour only the local node name in the top-left HUD identity label.
        # The K▲Ʞ mark and all surrounding status text retain their existing colours.
        hud_name = self.identity_colour_name_hud(str(s['name']), str(self.node_id))
        line1 = (
            f"K▲Ʞ {hud_name}  {self._c(state, colour)}  "
            f"peers={s['peers']}  {self._c('coll/s={:.1f}'.format(s['coll_rate']), 'cyan')}  "
            f"rx={s['rx']} tx={s['tx']} relay={s['relay']} turns={s['turns']}"
        )
        emit = "ready" if int(s.get("token", 0)) >= int(s.get("n", 1)) else "locked"
        emit_colour = "green" if emit == "ready" else "yellow"
        turn_n = int(s.get("n", 1))
        ring = self.render_turn_ring(int(s.get("token", 0)), turn_n)
        # Make the scale change explicit: ordinary Turns stays white, while the
        # compact ten-turn scale is highlighted yellow.
        if turn_n > 10:
            turns_label = self._c("Turns x10", "yellow")
        else:
            turns_label = self._c("Turns", "white")
        line2 = (
            f"{turns_label}: {ring} {s['token']}/{s['n']} emit={self._c(emit, emit_colour)}  "
            f"Queues: q={s['queue']} repair={s.get('repair', 0)} qwait={s['qwait']} airgap={s['airgap']}"
        )
        stream_w = max(24, min(64, content_w - 34))
        stream = self.render_pulse_stream(width=stream_w)
        pulse_rows = self.render_pulse_rows(limit=2)
        line3 = "Trace: " + stream
        line4 = "Pulse: " + "   ".join(pulse_rows)
        line5 = f"Receipts: ▽ ack={s['receipt_recv']}  ▼ recv={s['receipt_sent']}"
        hint_count = len(getattr(self, "peer_hint_candidates", {}) or {})
        known_count = len(getattr(self, "peer_addr_by_node_id", {}) or {})
        addr_count = len(getattr(self, "peer_id_by_addr", {}) or {})
        line6 = f"Discovery: known={known_count} addrs={addr_count} hints={hint_count} roams={s.get('roams',0)} self={short8(self.node_id)}"
        last_raw = str(getattr(self, "status_last_event", "idle"))
        last_limit = max(24, content_w - 8)
        last = (last_raw[:max(0, last_limit - 3)] + "...") if len(last_raw) > last_limit else last_raw
        line7 = f"Last: {last}"
        line8 = "Keys: Tab move  Alt+Tab reverse  Up/Down menu  Enter select  Esc back"
        top = "+" + ("-" * max(0, panel_w - 2)) + "+"
        logo = self.panda_logo_lines(s, state)
        hud = "\n".join([
            top,
            self._box_line_with_logo(line1, logo[0], width=content_w),
            self._box_line_with_logo(line2, logo[1], width=content_w),
            self._box_line_with_logo(line3, logo[2], width=content_w),
            self._box_line_with_logo(line4, logo[3], width=content_w),
            self._box_line_with_logo(line5, logo[4], width=content_w),
            self._box_line_with_logo(line6, logo[5], width=content_w),
            self._box_line_with_logo(line7, logo[6], width=content_w),
            self._box_line(line8, width=content_w),
            top,
        ])
        if bool(getattr(self, "activity_pane_enabled", True)):
            try:
                return hud + "\n" + self.render_activity_pane(width=panel_w, height=22)
            except Exception:
                return hud
        return hud

    def prepare_status_screen(self):
        """Prepare a fixed terminal canvas for the live HUD.

        The packaged Windows executable runs in Windows Terminal, where a frame
        taller than the initial viewport can otherwise push every refresh into
        scrollback.  Use the terminal's alternate screen and request enough rows
        for the unchanged 22-line activity pane plus the HUD.
        """
        if not sys.stderr.isatty() or bool(getattr(self, "_status_alt_screen_active", False)):
            return
        try:
            if os.name == "nt":
                # Ensure ANSI cursor/alternate-screen sequences are honoured by
                # the native console host as well as Windows Terminal.
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.GetStdHandle(-12)  # STD_ERROR_HANDLE
                    mode = ctypes.c_uint()
                    if handle not in (0, -1) and kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
                except Exception:
                    pass
                # Preserve today's width while asking for sufficient vertical
                # room. Traditional conhost applies this directly; Windows
                # Terminal safely ignores it when the tab is already larger.
                try:
                    cols = max(90, int(shutil.get_terminal_size((100, 40)).columns))
                    subprocess.run(
                        ["cmd", "/c", f"mode con: cols={cols} lines=40"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        timeout=2, check=False,
                    )
                except Exception:
                    pass
            sys.stderr.write("\033[?1049h\033[2J\033[H\033[?25l")
            sys.stderr.flush()
            self._status_alt_screen_active = True
            self._status_box_lines = 0
        except Exception:
            self._status_alt_screen_active = False

    def restore_status_screen(self):
        """Return from the fixed HUD canvas to the user's normal terminal."""
        try:
            if bool(getattr(self, "_status_alt_screen_active", False)) and sys.stderr.isatty():
                sys.stderr.write("\033[?25h\033[?1049l")
                sys.stderr.flush()
        except Exception:
            pass
        self._status_alt_screen_active = False

    def status_line_loop(self):
        """Small live indicator for quiet mode or structured-console mode.

        This deliberately avoids curses.  It repaints either one line or a small
        ASCII box and leaves the protocol engine untouched.
        """
        while not self._status_stop.is_set():
            try:
                if self.status_line_enabled and sys.stderr.isatty():
                    # Do not draw over interactive AIRGAP/chunk prompts.
                    if not self.stdin_lock.locked():
                        if bool(getattr(self, "status_box_enabled", False)):
                            box = self.render_status_box()
                            lines = box.splitlines()
                            prev_lines = int(getattr(self, "_status_box_lines", 0))
                            height = max(prev_lines, len(lines))
                            # Repaint in place from the terminal origin. Each row
                            # erases its unused remainder, avoiding both stacked HUDs
                            # and the visible flicker caused by a full-screen clear.
                            draw_lines = list(lines)
                            if height > len(draw_lines):
                                draw_lines.extend("" for _ in range(height - len(draw_lines)))
                            frame = "\033[?25l\033[H" + "\n".join(
                                str(line) + "\033[K" for line in draw_lines
                            )
                            frame += "\033[J"
                            sys.stderr.write(frame)
                            self._status_box_lines = len(lines)
                            self._status_last_len = 0
                            sys.stderr.flush()
                        else:
                            line = self.render_status_line()
                            pad = " " * max(0, self._status_last_len - len(line))
                            sys.stderr.write("\r" + line + pad)
                            sys.stderr.flush()
                            self._status_last_len = len(line)
            except Exception:
                pass
            # Sleep at the normal cadence, but permit UI-only producers such as
            # the incoming-message typewriter to wake this renderer immediately.
            # This changes display latency only; protocol/event-loop timing is
            # untouched.
            try:
                self._status_redraw.wait(float(getattr(self, "status_interval", 1.0)))
                self._status_redraw.clear()
            except Exception:
                self._status_stop.wait(float(getattr(self, "status_interval", 1.0)))

    def clear_status_line(self):
        try:
            if self._status_box_lines and sys.stderr.isatty():
                sys.stderr.write("\033[H\033[J\033[?25h")
                self._status_box_lines = 0
                sys.stderr.flush()
            self.restore_status_screen()
            if self._status_last_len and sys.stderr.isatty():
                sys.stderr.write("\r" + (" " * self._status_last_len) + "\r")
                sys.stderr.flush()
                self._status_last_len = 0
        except Exception:
            pass

    # ------------------------- Keyboard watcher -------------------------------

    def keyboard_watcher(self):
        qprint("[INFO] Controls: Tab=move, Alt+Tab=reverse Tab direction, Up/Down=menu, Enter=select, Esc=back")
        self._raw_term_state = term_enter_raw_noecho()

        def handle_ch(ch: str):
            if not ch:
                return False
            raw = ch
            ch = ch.lower()
            if (bool(getattr(self,"activity_peer_menu_open",False))
                    and str(getattr(self,"activity_peer_menu_level","list"))=="list"
                    and raw not in ("\x1b","\t","\r","\n")):
                if self.activity_peer_menu_search_key(raw):
                    return True
            if bool(getattr(self, "activity_dropdown_open", False)) and raw not in ("\x1b", "\t", "\r", "\n"):
                if self.activity_recipient_search_key(raw):
                    return True
            if ch == "\x1b":
                self.activity_escape_back()
            elif ch == "\t":
                if int(getattr(self, "activity_tab_direction", 1)) >= 0:
                    self.activity_next_focus()
                else:
                    self.activity_prev_focus()
            elif ch in ("\r", "\n"):
                self.activity_execute_current()
            elif ch == "i":
                self.inject_dummy("DUMMY")
            elif ch == "e":
                self.log_event("[TURN] manual test emission")
                self.on_token_trigger()
            elif ch == "r":
                self.send_rpc_ping()
            elif ch == "o":
                self.send_rpc_store_test()
            elif ch == "l":
                self.send_rpc_list_test()
            elif ch == "t":
                self.send_rpc_retrieve_test()
            elif ch == "d":
                qprint("[DISCOVER] Manual discover probe")
                self.last_discover_ts = 0.0
                self.last_discover_height = 0
                self.maybe_discover(now_ts())
            elif ch in ("q", "s", "k", "a", "u"):
                # Keep old single-key controls from accidentally doing too much
                # in Lite. Exit is deliberately a visible menu choice.
                self.activity_system("Use Tab/Enter menu controls")
            return True

        def handle_nav(nav: str):
            if nav == "up":
                self.activity_handle_arrow("up")
            elif nav == "down":
                self.activity_handle_arrow("down")
            elif nav == "left":
                self.activity_prev_focus()
            elif nav == "right":
                self.activity_next_focus()
            elif nav == "backtab":
                self.activity_prev_focus()
            elif nav == "pgup":
                if bool(getattr(self,"activity_peer_menu_open",False)) and str(getattr(self,"activity_peer_menu_level","list"))=="list":
                    self.activity_page_peer_menu(-1)
                elif bool(getattr(self, "activity_dropdown_open", False)):
                    self.activity_page_recipient(-1)
                else:
                    self.activity_page_scroll(1)
            elif nav == "pgdn":
                if bool(getattr(self,"activity_peer_menu_open",False)) and str(getattr(self,"activity_peer_menu_level","list"))=="list":
                    self.activity_page_peer_menu(1)
                elif bool(getattr(self, "activity_dropdown_open", False)):
                    self.activity_page_recipient(1)
                else:
                    self.activity_page_scroll(-1)
            elif nav == "home":
                if bool(getattr(self,"activity_peer_menu_open",False)) and str(getattr(self,"activity_peer_menu_level","list"))=="list":
                    self.activity_peer_menu_home_end(False)
                elif bool(getattr(self, "activity_dropdown_open", False)):
                    self.activity_recipient_home_end(False)
                else:
                    self.activity_scroll_home()
            elif nav == "end":
                if bool(getattr(self,"activity_peer_menu_open",False)) and str(getattr(self,"activity_peer_menu_level","list"))=="list":
                    self.activity_peer_menu_home_end(True)
                elif bool(getattr(self, "activity_dropdown_open", False)):
                    self.activity_recipient_home_end(True)
                else:
                    self.activity_scroll_end()

        if os.name == "nt" and msvcrt is not None:
            # Windows console stdin is not select()-able.  Use msvcrt so the
            # Lite menu works in PowerShell, Windows Terminal and the future EXE.
            while not bool(getattr(self, "_shutdown_requested", False)):
                try:
                    if not msvcrt.kbhit():
                        time.sleep(0.05)
                        continue
                    ch = msvcrt.getwch()
                    if ch in ("\x00", "\xe0"):
                        code = msvcrt.getwch()
                        nav_map = {
                            "H": "up", "P": "down", "K": "left", "M": "right",
                            "I": "pgup", "Q": "pgdn", "G": "home", "O": "end",
                        }
                        handle_nav(nav_map.get(code, ""))
                    else:
                        if ch == "\t":
                            shifted = False
                            try:
                                import ctypes
                                shifted = bool(ctypes.windll.user32.GetAsyncKeyState(0x10) & 0x8000)
                            except Exception:
                                shifted = False
                            if shifted:
                                handle_nav("backtab")
                            else:
                                handle_ch(ch)
                        else:
                            handle_ch(ch)
                except KeyboardInterrupt:
                    self.request_shutdown("graceful", "keyboard-interrupt")
                    break
                except Exception:
                    time.sleep(0.1)
            return

        fd = sys.stdin.fileno()

        def read_posix_key_burst() -> bytes:
            """Read one key event without mixing Python buffering and os.read."""
            first = os.read(fd, 1)
            if not first:
                return b""
            data = bytearray(first)
            if first != b"\x1b":
                return bytes(data)

            deadline = time.monotonic() + 0.40
            while time.monotonic() < deadline and len(data) < 32:
                wait = 0.08 if len(data) == 1 else 0.02
                if not select.select([fd], [], [], wait)[0]:
                    break
                chunk = os.read(fd, 32 - len(data))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) >= 3 and (
                    65 <= data[-1] <= 90
                    or 97 <= data[-1] <= 122
                    or data[-1] == 126
                ):
                    break
            return bytes(data)

        while not bool(getattr(self, "_shutdown_requested", False)):
            try:
                if not select.select([fd], [], [], 0.1)[0]:
                    continue

                raw = read_posix_key_burst()
                if not raw:
                    continue

                nav_map = {
                    b"\x1b[A": "up", b"\x1b[B": "down",
                    b"\x1b[C": "right", b"\x1b[D": "left",
                    b"\x1b[Z": "backtab",
                    b"\x1bOA": "up", b"\x1bOB": "down",
                    b"\x1bOC": "right", b"\x1bOD": "left",
                    b"\x1b[5~": "pgup", b"\x1b[6~": "pgdn",
                    b"\x1b[H": "home", b"\x1b[F": "end",
                    b"\x1bOH": "home", b"\x1bOF": "end",
                    b"\x1b[1~": "home", b"\x1b[4~": "end",
                }

                if raw in nav_map:
                    handle_nav(nav_map[raw])
                    continue

                if raw.startswith(b"\x1b[") and raw[-1:] in (b"A", b"B", b"C", b"D", b"Z"):
                    handle_nav({
                        b"A": "up", b"B": "down", b"C": "right",
                        b"D": "left", b"Z": "backtab",
                    }[raw[-1:]])
                    continue

                if raw == b"\x1b":
                    self.activity_escape_back()
                    continue

                try:
                    decoded = raw.decode("utf-8")
                except UnicodeDecodeError:
                    decoded = raw.decode("latin-1", "ignore")
                for ch in decoded:
                    handle_ch(ch)
            except Exception:
                pass

    def maybe_pump_idle_repairs(self, now: float):
        """Emit sparse repair turns when repair_pending is the only work left.

        KryptDisk's normal scheduler is collision-earned. That is fine while
        ordinary file chunks are moving because the mesh keeps creating turns.
        But after repair mode prunes the normal queue, the node can end up with
        q=0 repair=N and no fresh collisions to trigger on_token_trigger().
        This pump only activates in that exact state.
        """
        try:
            if self._repair_pending_count() <= 0:
                return
            if len(getattr(self, "outbound_queue", []) or []) > 0:
                return
            interval = float(globals().get("KDK_REPAIR_IDLE_PUMP_SECS", 1.25))
            last = float(getattr(self, "repair_last_idle_pump_ts", 0.0) or 0.0)
            if now - last < max(0.25, interval):
                return
            self.repair_last_idle_pump_ts = now
            self.log_event(f"[REPAIR_PUMP] idle turn q=0 repair_pending={self._repair_pending_count()}")
            self.on_token_trigger()
        except Exception as e:
            self.log_event(f"[REPAIR_PUMP] failed err={type(e).__name__}: {e}")

    # ------------------------- Shutdown ---------------------------------------

    def request_shutdown(self, mode: str = "graceful", reason: str = ""):
        """Ask the run loop to stop cleanly.

        This is intentionally simple for the first packaged build. It gives the
        launcher and the terminal hotkey a single path into a tidy shutdown
        without changing the mesh protocol.
        """
        try:
            self._shutdown_mode = str(mode or "graceful")
            self._shutdown_reason = str(reason or "")
            self._shutdown_requested = True
            self.activity_system("Exit requested")
            qprint(f"[EXIT] shutdown requested mode={self._shutdown_mode}")
        except Exception:
            self._shutdown_requested = True

    def shutdown_cleanup(self):
        """Best-effort shutdown housekeeping before the socket closes."""
        try:
            self._status_stop.set()
        except Exception:
            pass
        try:
            if bool(getattr(self, "_peer_digest_dirty", False)):
                self.save_peer_digest(force=True)
        except Exception:
            pass
        try:
            self.airgap_save_state()
        except Exception:
            pass
        try:
            self.reliability_save_state()
        except Exception:
            pass
        try:
            self.vault_rid_log_compact()
        except Exception:
            pass
        try:
            self.clear_status_line()
        except Exception:
            pass
        try:
            term_restore(self._raw_term_state)
        except Exception:
            pass
        try:
            self._delayed_send_stop.set()
            with self._delayed_send_cv:
                self._delayed_send_cv.notify_all()
            t = getattr(self, "_delayed_send_thread", None)
            if t is not None and t.is_alive():
                t.join(timeout=0.25)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    # ------------------------- Main loop --------------------------------------

    def run(self):
        if self.vault_mode:
            qprint(f"[RUN] Vault {self.name} running on port {self.port}. Press Ctrl+C or q to stop.")
            qprint(f"[RUN] Node ID: {self.node_id}")
            qprint("[RUN] Vault mode enabled.")
        else:
            qprint(f"[RUN] Node {self.name} running on port {self.port}. Press Ctrl+C or q to stop.")
            qprint(f"[RUN] Node ID: {self.node_id}")
            qprint(f"[RUN] Script version: {SCRIPT_VERSION} revision={SCRIPT_REVISION} hash={SCRIPT_HASH}")

        if bool(getattr(self, "status_line_enabled", False)):
            self.prepare_status_screen()

        self._start_delayed_send_thread()

        if sys.stdin.isatty():
            t = threading.Thread(target=self.keyboard_watcher, daemon=True)
            t.start()

        if bool(getattr(self, "status_line_enabled", False)):
            st = threading.Thread(target=self.status_line_loop, daemon=True)
            st.start()

        self.last_discover_ts = 0.0
        self.last_discover_height = 0
        self._resume_last_mono = time.monotonic()
        self._resume_last_wall = time.time()

        try:
            while not bool(getattr(self, "_shutdown_requested", False)):
                self.maybe_handle_resume_gap()
                now = now_ts()
                self.maybe_send_heartbeats(now)
                self.maybe_discover(now)
                self.process_inbound_blocks(budget=4)
                self.maybe_refresh_dingo_scheduler_height(now)
                self.maybe_release_deferred_files(now)
                self.maybe_retry_reliable_traffic(now)
                self.maybe_retry_patch_discovery(now)
                self.maybe_send_chunk_pulls(now)
                self.maybe_send_chunk_wants(now)
                self.maybe_pump_idle_repairs(now)
                self.maybe_send_dingo_height_beacon(now)
                self.maybe_flush_peer_digest(now)
                self.cleanup(now)

                try:
                    data, addr = self.sock.recvfrom(65535)
                    self.handle_packet(data, addr)
                except socket.timeout:
                    pass
                except Exception as e:
                    qprint(f"[WARN] recv/handle failed: {e}")

        except KeyboardInterrupt:
            self.clear_status_line()
            qprint("\n[RUN] Stopping...")
        finally:
            self.shutdown_cleanup()


# ----------------------------- CLI -------------------------------------------

def parse_peers(peer_args: List[str]) -> List[Tuple[str, int]]:
    peers: List[Tuple[str, int]] = []
    for p in peer_args or []:
        if ":" not in p:
            continue
        host, ps = p.rsplit(":", 1)
        try:
            port = int(ps)
        except Exception:
            continue
        peers.append((host, port))
    return peers

def default_lan_profile_peers(name: str, port: int) -> List[Tuple[str, int]]:
    """Return legacy fallback peers when explicitly configured.

    This is deliberately a fallback. Once the learned peer digest exists, it
    supplies the same candidates without needing launch flags.
    """
    peers: List[Tuple[str, int]] = []
    my_name = str(name or "").strip()
    try:
        my_port = int(port or 0)
    except Exception:
        my_port = 0
    for pname, addr in KDK_DEFAULT_LAN_PROFILE.items():
        host, p = addr
        if (my_name and pname.lower() == my_name.lower()) or (my_port and int(p) == my_port):
            continue
        peers.append((host, int(p)))
    return peers

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--peer", action="append", default=[], help="host:port (repeatable)")
    ap.add_argument("--peer-digest", type=str, default=KDK_PEER_DIGEST_PATH,
                    help="learned peer digest path used for bootstrap candidates")
    ap.add_argument("--no-peer-digest", action="store_true",
                    help="do not load or save the learned peer digest")
    ap.add_argument("--no-default-peers", action="store_true",
                    help="do not use any legacy fallback peers when no peers are supplied")
    ap.add_argument("--relay", action="store_true", help="enable Brownian relay")
    ap.add_argument("--lan-delay-ms", type=float, default=KDK_LAN_DELAY_MS,
                    help="mean one-way delay applied to loopback/private/same-host UDP sends")
    ap.add_argument("--lan-delay-jitter-ms", type=float, default=KDK_LAN_DELAY_JITTER_MS,
                    help="Gaussian jitter sigma for LAN delay")
    ap.add_argument("--no-lan-delay", action="store_true",
                    help="disable LAN/WAN latency normalisation")
    ap.add_argument("--name", type=str, default="")
    ap.add_argument("--profile-path", type=str, default=KDK_PROFILE_PATH,
                    help="persistent profile JSON containing the mutable display name")
    ap.add_argument("--vault", action="store_true", help="enable vault mode")
    ap.add_argument("--verbose", action="store_true", help="enable verbose debug logging")
    ap.add_argument("--debug-wire", action="store_true", help="log noisy wire-level events such as UDP/MESH/DECRYPT_FAIL")
    ap.add_argument("--log-max-mb", type=float, default=5.0, help="rotate each node log after this many MB; default=5")
    ap.add_argument("--log-backups", type=int, default=3, help="number of rotated logs to keep per node; default=3")
    ap.add_argument("--test-drop-list-once", action="store_true",
                    help="TEST: in vault mode, drop the first LIST_TEST reply to validate retry")
    ap.add_argument("--test-fast-rpc", action="store_true",
                    help="TEST: emit RPC envelopes immediately (bypass collision gating)")
    ap.add_argument("--n", "--collision-trigger-n", dest="collision_trigger_n", type=int,
                    default=COLLISION_TRIGGER_N,
                    help="earn one emission turn after N payload collisions; lower=busier churn")
    ap.add_argument("--fan-choices", type=str, default="",
                    help="weighted relay fanout choices, comma-separated; e.g. 1,1,1,1,2 (default: automatic legacy profile)")
    ap.add_argument("--queue-gap-min", type=int, default=QUEUE_EMIT_GAP_MIN_TURNS,
                    help="minimum randomized earned-turn gap between queued real envelopes")
    ap.add_argument("--queue-gap-max", type=int, default=QUEUE_EMIT_GAP_MAX_TURNS,
                    help="maximum randomized earned-turn gap between queued real envelopes")
    ap.add_argument("--pow-bits", type=int, default=16, help="PoW bits required for payload injection/acceptance")
    ap.add_argument("--pow-epoch-secs", type=int, default=60, help="PoW epoch window in seconds")
    ap.add_argument("--pow-mine-tries", type=int, default=2000000, help="Max tries when mining a PoW stamp locally")
    ap.add_argument("--airgap-block-secs", type=int, default=60,
                    help="TEST ONLY: seconds per simulated block for airgap timelock")
    ap.add_argument("--cuckoo-min-delay-secs", type=int, default=CUCKOO_MIN_DELAY_SECS_TEST,
                    help=f"minimum Airgap/Cuckoo delay in seconds; test default={CUCKOO_MIN_DELAY_SECS_TEST}, live target={CUCKOO_MIN_DELAY_SECS_LIVE}")
    ap.add_argument("--cuckoo-min-witnesses", type=int, default=CUCKOO_DEFAULT_MIN_WITNESSES,
                    help="minimum recent Dingo height witnesses needed for Cuckoo release consensus")
    ap.add_argument("--cuckoo-chunks", type=int, default=CUCKOO_DEFAULT_CHUNKS,
                    help="default number of progressive Cuckoo key chunks; clamped 3..12")
    ap.add_argument(
        "--airgap-height-source",
        choices=["test", "dingo-cli", "dingo-auto"],
        default="dingo-auto",
        help="airgap timelock height source"
    )
    ap.add_argument("--dingo-cli", type=str, default="dingocoin-cli",
                    help="path/name of dingocoin-cli for dingo-cli or dingo-auto")
    ap.add_argument("--dingo-cli-arg", action="append", default=[],
                    help="extra argument passed before getblockcount, e.g. -datadir=/path or -rpcwallet=...; repeatable")
    ap.add_argument("--no-dingo-height-beacon", action="store_true",
                    help="disable Dingo block-height witness beacons from this node")
    ap.add_argument("--dingo-beacon-interval", type=float, default=DINGO_HEIGHT_BEACON_INTERVAL_SECS,
                    help="seconds between local Dingo height witness checks")
    ap.add_argument("--dingo-beacon-tolerance", type=int, default=DINGO_HEIGHT_BEACON_TOLERANCE_BLOCKS,
                    help="legacy compatibility setting; local validating nodes now beacon without explorer corroboration")
    ap.add_argument("--quiet-control", action="store_true",
                    help="suppress noisy mesh/churn logs; keep airgap/control logs")
    ap.add_argument("--status-line", action="store_true",
                    help="show a one-line spinner/status bar for quiet mesh activity")
    ap.add_argument("--status-box", "--status-hud", dest="status_box", action="store_true",
                    help="show a small fixed ASCII status box; no curses/TUI dependency")
    ap.add_argument("--no-activity-pane", action="store_true",
                    help="hide the beta message/system activity pane under the status HUD")
    ap.add_argument("--no-colour", "--no-color", dest="no_colour", action="store_true",
                    help="disable ANSI colours in status output")
    ap.add_argument("--advertise-addr", type=str, default="",
                    help="self advertised ip:port for encrypted peer hints, e.g. 192.168.1.50:6009")
    ap.add_argument("--no-peer-hints", action="store_true",
                    help="disable v10.19 encrypted peer-hint discovery blocks")
    ap.add_argument("--directory-public-host", type=str, default="",
                    help="public host/IP to advertise for LAN peers when replying to roaming DISCOVER, e.g. 203.0.113.10")
    ap.add_argument("--directory-map", action="append", default=[], metavar="NODEID=HOST:PORT",
                    help="per-peer public directory advertisement; node ID may be a unique prefix. Repeatable, e.g. 3ce4654c=203.0.113.10:6002")
    ap.add_argument("--no-directory-hints", action="store_true",
                    help="disable signed DISCOVER_REPLY peer-directory/rendezvous hints")
    ap.add_argument("--update-policy", choices=["off", "manual", "stage", "force-latest"], default="manual",
                    help="patch policy: manual receive/inspect (default), stage-only, trusted force-latest, or off")
    ap.add_argument("--auto-apply-update", action="store_true",
                    help="with force-latest, apply a valid strictly-newer staged patch automatically")
    ap.add_argument("--auto-apply-capsules", dest="auto_apply_update", action="store_true",
                    help="alias for --auto-apply-update")
    ap.add_argument("--no-auto-apply-capsules", dest="no_auto_apply_update", action="store_true",
                    help="stage valid capsules only; do not auto-apply/restart")
    ap.add_argument("--no-auto-restart-update", dest="no_auto_restart_update", action="store_true",
                    help="after applying an update, exit with restart code 42 instead of relaunching")
    ap.add_argument("--allow-rollback-capsules", action="store_true",
                    help="allow explicit rollback to an older hash already in the local digest ledger")
    ap.add_argument("--update-offer-file", type=str, default="",
                    help="default script path offered by the 'u' update hotkey")
    ap.add_argument("--update-base-file", type=str, default="",
                    help="base/old script path used to build exact external patch capsules")
    ap.add_argument("--make-patch-capsule", nargs=3, metavar=("BASE", "TARGET", "OUT"),
                    help="utility: build canonical external patch capsule BASE -> TARGET and exit")
    ap.add_argument("--apply-patch-capsule", type=str, default="",
                    help="utility: validate/apply a patch capsule to --patch-script-path and exit")
    ap.add_argument("--patch-script-path", type=str, default="",
                    help="script path for --apply-patch-capsule; defaults to this file")
    ap.add_argument("--patch-commit", action="store_true",
                    help="with --apply-patch-capsule, actually replace script after validation")

    args = ap.parse_args(argv)

    global QUIET_CONTROL
    QUIET_CONTROL = bool(getattr(args, "quiet_control", False))

    if getattr(args, "make_patch_capsule", None):
        base, target, out = args.make_patch_capsule
        capsule = kdk_make_patch_capsule_file(base, target, out)
        meta = json.loads(capsule.decode("utf-8"))
        print(f"[PATCH_CAPSULE] wrote {out}")
        print(f"[PATCH_CAPSULE] bytes={len(capsule)} object_id={sha256(capsule)[:32]}")
        print(f"[PATCH_CAPSULE] base={meta.get('base_version')} {meta.get('base_hash')[:16]}")
        print(f"[PATCH_CAPSULE] target={meta.get('target_version')} {meta.get('target_hash')[:16]}")
        print(f"[PATCH_CAPSULE] ops={len(meta.get('ops', []))}")
        return

    if getattr(args, "apply_patch_capsule", ""):
        script_path = str(getattr(args, "patch_script_path", "") or __file__)
        capsule_path = str(args.apply_patch_capsule)
        patched_raw, meta = kdk_apply_patch_capsule_file(script_path, capsule_path, apply=bool(getattr(args, "patch_commit", False)))
        print(f"[PATCH_CAPSULE] validated {capsule_path}")
        print(f"[PATCH_CAPSULE] script={script_path}")
        print(f"[PATCH_CAPSULE] base={meta.get('base_version')} {meta.get('base_hash')[:16]}")
        print(f"[PATCH_CAPSULE] target={meta.get('target_version')} {meta.get('target_hash')[:16]}")
        print(f"[PATCH_CAPSULE] result={sha256(patched_raw)[:16]}")
        print(f"[PATCH_CAPSULE] committed={bool(getattr(args, 'patch_commit', False))}")
        return

    if not int(getattr(args, "port", 0) or 0):
        ap.error("--port is required unless using --make-patch-capsule or --apply-patch-capsule")

    # Visible, self-contained patch behaviour: centre packaged/native Windows
    # consoles. Other platforms continue unchanged.
    centre_console_window()
    keep_awake_active = bool(getattr(args, "keep_awake", False)) and windows_keep_awake(True)

    peers = parse_peers(args.peer)
    used_default_profile = False
    if not peers and not bool(getattr(args, "no_default_peers", False)):
        peers = default_lan_profile_peers(str(getattr(args, "name", "") or ""), int(getattr(args, "port", 0) or 0))
        used_default_profile = bool(peers)
    profile_path = os.path.abspath(str(getattr(args, "profile_path", KDK_PROFILE_PATH) or KDK_PROFILE_PATH))
    try:
        display_name = kdk_load_display_name(
            profile_path,
            str(getattr(args, "name", "") or "Kryptonaut"),
        )
    except ValueError as exc:
        ap.error(str(exc))

    node = KDNode(
        port=args.port,
        peers=peers,
        relay=bool(args.relay),
        name=display_name,
        vault_mode=bool(args.vault),
        test_drop_list_once=bool(args.test_drop_list_once),
        collision_trigger_n=int(getattr(args, "collision_trigger_n", COLLISION_TRIGGER_N)),
    )

    # Optional weighted fanout profile supplied by the launcher.  Keep the
    # historical automatic profile when omitted.  Values are clamped to positive
    # integers; malformed input is rejected at startup rather than silently changing
    # propagation behaviour.
    fan_raw = str(getattr(args, "fan_choices", "") or "").strip()
    if fan_raw:
        try:
            fan_choices = [int(part.strip()) for part in fan_raw.split(",") if part.strip()]
        except ValueError:
            ap.error("--fan-choices must be comma-separated positive integers, e.g. 1,1,1,1,2")
        if not fan_choices or any(x <= 0 for x in fan_choices):
            ap.error("--fan-choices must contain only positive integers")
        node.fan_choices = tuple(fan_choices)
        node.log_event(f"[FANOUT] runtime choices={','.join(str(x) for x in node.fan_choices)} mean={sum(node.fan_choices)/len(node.fan_choices):.3f}")
    else:
        node.fan_choices = None

    node.verbose = bool(args.verbose or getattr(args, "debug_wire", False))
    node.compact_logs = not bool(getattr(args, "debug_wire", False))
    node.log_max_bytes = max(256 * 1024, int(float(getattr(args, "log_max_mb", 5.0)) * 1024 * 1024))
    node.log_backups = max(0, int(getattr(args, "log_backups", 3)))
    node.peer_digest_path = str(getattr(args, "peer_digest", KDK_PEER_DIGEST_PATH) or KDK_PEER_DIGEST_PATH)
    node.peer_digest_disabled = bool(getattr(args, "no_peer_digest", False))
    node.lan_delay_enabled = not bool(getattr(args, "no_lan_delay", False))
    node.lan_delay_ms = max(0.0, float(getattr(args, "lan_delay_ms", KDK_LAN_DELAY_MS)))
    node.lan_delay_jitter_ms = max(0.0, float(getattr(args, "lan_delay_jitter_ms", KDK_LAN_DELAY_JITTER_MS)))
    if used_default_profile:
        node.log_event(f"[PEER_DIGEST] using default LAN profile candidates={len(peers)}")
    if not node.peer_digest_disabled:
        node.load_peer_digest(node.peer_digest_path)
    node.test_fast_rpc = bool(args.test_fast_rpc)
    node.queue_emit_gap_min_turns = max(1, int(getattr(args, "queue_gap_min", QUEUE_EMIT_GAP_MIN_TURNS)))
    node.queue_emit_gap_max_turns = max(node.queue_emit_gap_min_turns, int(getattr(args, "queue_gap_max", QUEUE_EMIT_GAP_MAX_TURNS)))
    node.pow_bits_required = int(getattr(args, "pow_bits", 16))
    node.pow_epoch_secs = int(getattr(args, "pow_epoch_secs", 60))
    node.pow_mine_tries = int(getattr(args, "pow_mine_tries", 2000000))
    node.airgap_block_secs = int(getattr(args, "airgap_block_secs", 60))
    node.cuckoo_min_delay_secs = max(0, int(getattr(args, "cuckoo_min_delay_secs", CUCKOO_MIN_DELAY_SECS_TEST)))
    node.cuckoo_min_witnesses = max(1, int(getattr(args, "cuckoo_min_witnesses", CUCKOO_DEFAULT_MIN_WITNESSES)))
    node.cuckoo_default_chunks = max(CUCKOO_MIN_CHUNKS, min(CUCKOO_MAX_CHUNKS, int(getattr(args, "cuckoo_chunks", CUCKOO_DEFAULT_CHUNKS))))
    node.airgap_height_source = str(getattr(args, "airgap_height_source", "test") or "test")
    node.airgap_dingo_cli = str(getattr(args, "dingo_cli", "dingocoin-cli") or "dingocoin-cli")
    node.airgap_dingo_cli_args = list(getattr(args, "dingo_cli_arg", []) or [])
    node.airgap_dingo_allow_fallback = bool(getattr(args, "dingo_allow_test_fallback", False))
    node.dingo_height_beacon_enabled = not bool(getattr(args, "no_dingo_height_beacon", False))
    node.dingo_height_beacon_interval_secs = max(0.5, float(getattr(args, "dingo_beacon_interval", DINGO_HEIGHT_BEACON_INTERVAL_SECS)))
    node.dingo_height_beacon_tolerance_blocks = max(0, int(getattr(args, "dingo_beacon_tolerance", DINGO_HEIGHT_BEACON_TOLERANCE_BLOCKS)))
    node.quiet_control = bool(getattr(args, "quiet_control", False))
    node.status_box_enabled = bool(getattr(args, "status_box", False))
    node.activity_pane_enabled = bool(getattr(args, "status_box", False)) and not bool(getattr(args, "no_activity_pane", False))
    node.status_line_enabled = bool(getattr(args, "status_line", False) or getattr(args, "status_box", False))
    node.status_colour_enabled = not bool(getattr(args, "no_colour", False))
    node.peer_hint_enabled = not bool(getattr(args, "no_peer_hints", False))
    node.directory_hint_enabled = not bool(getattr(args, "no_directory_hints", False))
    node.update_policy = str(getattr(args, "update_policy", "manual") or "manual")
    node.update_auto_apply = bool(getattr(args, "auto_apply_update", False)) and not bool(getattr(args, "no_auto_apply_update", False))
    node.update_auto_restart = not bool(getattr(args, "no_auto_restart_update", False))
    node.update_offer_file = str(getattr(args, "update_offer_file", "") or "").strip()
    node.update_base_file = str(getattr(args, "update_base_file", "") or "").strip()
    node.update_allow_rollback = bool(getattr(args, "allow_rollback_capsules", False))
    node.profile_path = profile_path
    node.directory_public_host = str(getattr(args, "directory_public_host", "") or "").strip()
    node.directory_public_map = {}
    for item in list(getattr(args, "directory_map", []) or []):
        try:
            nid, addr_s = str(item).split("=", 1)
            nid = nid.strip()
            addr = node._parse_hint_addr(addr_s.strip())
            if nid and addr:
                node.directory_public_map[nid] = addr
                node.log_event(f"[DIRECTORY] map {nid}->{addr[0]}:{addr[1]}")
            else:
                qprint(f"[DIRECTORY] ignored bad --directory-map {item!r}")
        except Exception:
            qprint(f"[DIRECTORY] ignored bad --directory-map {item!r}")
    if getattr(args, "advertise_addr", ""):
        node.advertise_addr = node._parse_hint_addr(args.advertise_addr)
        if node.advertise_addr:
            node.log_event(f"[PEER_HINT] self advertise {node.advertise_addr[0]}:{node.advertise_addr[1]}")
    qprint(
        f"[RUN] Collision trigger N={node.token_trigger}; "
        f"queued real-envelope gap={node.queue_emit_gap_min_turns}-{node.queue_emit_gap_max_turns} earned turns; "
        f"AIRGAP hotkey={'on' if ENABLE_AIRGAP_HOTKEY else 'off'}; "
        f"height_source={node.airgap_height_source}; "
        f"update_policy={node.update_policy}; auto_apply={node.update_auto_apply}; auto_restart={getattr(node, 'update_auto_restart', True)}; "
        f"release={SCRIPT_ORIGIN}:{SCRIPT_LINEAGE}; keep_awake={keep_awake_active}; "
        f"bootstrap_peers={len(node.peers)}"
    )

    # A supervised child publishes its exact launcher -> child ownership only
    # after keys load, socket bind and all runtime options have been applied.
    if os.environ.get("KDK_LAUNCH_TOKEN") and not kdk_write_supervisor_ready(node):
        raise SystemExit(46)

    # A promoted child clears the marker only after the ready record exists.
    kdk_confirm_promoted_startup()

    try:
        node.run()
    finally:
        if bool(getattr(args, "keep_awake", False)):
            windows_keep_awake(False)
        kdk_clear_supervisor_ready()

    pending_restart = getattr(node, "_pending_update_restart", None)
    if isinstance(pending_restart, dict) and pending_restart:
        if os.environ.get("KDK_SUPERVISED") == "1":
            kdk_write_restart_marker(pending_restart)
            qprint(f"[UPDATE] clean node exit code={KDK_UPDATE_RESTART_EXIT_CODE}; launcher will promote/relaunch")
            raise SystemExit(KDK_UPDATE_RESTART_EXIT_CODE)
        raise SystemExit(kdk_supervise_promoted_restart(pending_restart))

    if str(getattr(node, "_shutdown_mode", "")) == "manual-restart":
        qprint(f"[RESTART] clean node exit code={KDK_MANUAL_RESTART_EXIT_CODE}; launcher will relaunch")
        return KDK_MANUAL_RESTART_EXIT_CODE
    return 0


def build_argv_from_config(config: dict) -> List[str]:
    """Translate launcher config.json into the existing CLI surface.

    Keeping this mapping here means the protocol/node engine still receives
    exactly the same settings it expects, while the packaged app can present a
    much simpler first-run experience.
    """
    cfg = dict(config or {})
    argv: List[str] = []
    port = int(cfg.get("port") or 6001)
    argv += ["--port", str(port)]

    username = str(cfg.get("username") or cfg.get("name") or "Kryptonaut").strip()
    if username:
        argv += ["--name", username]
    profile_path = str(cfg.get("profile_path") or KDK_PROFILE_PATH).strip()
    if profile_path:
        argv += ["--profile-path", profile_path]

    # A packaged first-run app should not silently use the old Pi/VM lab
    # bootstrap profile unless the operator asks for it in config.json.
    if not bool(cfg.get("use_default_lan_profile", False)):
        argv.append("--no-default-peers")

    for peer in list(cfg.get("peers") or []):
        peer = str(peer).strip()
        if peer:
            argv += ["--peer", peer]

    if bool(cfg.get("relay", False)):
        argv.append("--relay")
    if bool(cfg.get("vault", False)):
        argv.append("--vault")
    if bool(cfg.get("verbose", False)):
        argv.append("--verbose")

    mode = str(cfg.get("mode") or "standard").lower()
    if mode in ("standard", "lite"):
        argv += ["--quiet-control", "--status-box"]
    elif bool(cfg.get("status_box", True)):
        argv.append("--status-box")

    if not bool(cfg.get("colour", True)):
        argv.append("--no-colour")
    if bool(cfg.get("keep_awake", False)):
        argv.append("--keep-awake")

    # Public/default update policy is manual consent.  Trusted development
    # deployments may explicitly select stage or force-latest in config.json.
    requested_policy = str(cfg.get("update_policy") or "manual").strip().lower()
    if requested_policy not in ("off", "manual", "stage", "force-latest"):
        requested_policy = "manual"
    argv += ["--update-policy", requested_policy]
    if bool(cfg.get("auto_apply_update", False)):
        argv.append("--auto-apply-capsules")
    if bool(cfg.get("no_auto_apply_update", False)):
        argv.append("--no-auto-apply-capsules")
    if bool(cfg.get("no_auto_restart_update", False)):
        argv.append("--no-auto-restart-update")

    # Optional low-level overrides for developers/operators.
    optional_ints = {
        "pow_bits": "--pow-bits",
        "collision_trigger_n": "--n",
        "queue_gap_min": "--queue-gap-min",
        "queue_gap_max": "--queue-gap-max",
        "cuckoo_min_delay_secs": "--cuckoo-min-delay-secs",
    }
    for key, flag in optional_ints.items():
        if key in cfg and cfg.get(key) not in (None, ""):
            argv += [flag, str(int(cfg.get(key)))]

    if bool(cfg.get("no_peer_digest", False)):
        argv.append("--no-peer-digest")
    return argv


def kdk_launcher_supervise(argv: Optional[List[str]] = None) -> int:
    """Run the node as a child and restart it only after a clean code-43 exit.

    The parent never reads stdin and never owns the UDP socket.  Exactly one
    child node owns the console and network resources at a time.  This avoids
    the overlapping-console/input race caused by a node spawning its own
    replacement before the original process had completely disappeared.
    """
    child_argv = [str(x) for x in list(argv or [])]
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        command = [os.path.abspath(sys.executable), "--kdk-node-child"] + child_argv
    else:
        command = [os.path.abspath(sys.executable), os.path.abspath(__file__), "--kdk-node-child"] + child_argv
    cwd = os.path.abspath(KDK_PROCESS_START_CWD)
    while True:
        qprint(f"[LAUNCHER] starting node command={command!r} cwd={cwd!r}")
        child = subprocess.Popen(command, cwd=cwd, env=os.environ.copy())
        rc = int(child.wait())
        if rc != KDK_MANUAL_RESTART_EXIT_CODE:
            qprint(f"[LAUNCHER] node exited code={rc}")
            return rc
        qprint("[LAUNCHER] restart code received; starting a fresh node")
        time.sleep(0.20)


def launch_from_config(config: dict):
    """Launch and supervise a KDNode using first-run/launcher config."""
    return kdk_launcher_supervise(build_argv_from_config(config))

if __name__ == "__main__":
    raw_argv = list(sys.argv[1:])
    if "--kdk-node-child" in raw_argv:
        raw_argv.remove("--kdk-node-child")
        raise SystemExit(main(raw_argv) or 0)
    raise SystemExit(kdk_launcher_supervise(raw_argv))
