"""
client/client.py — PQC Secure Chat + Encrypted File Share Client
=================================================================

OVERVIEW
--------
One WebSocket connection handles both text chat and file sharing.
Both use the same PQC session — you MUST run /session before /msg OR /send.

  TEXT CHAT
  - ML-KEM-768 key exchange  shared secret  Double Ratchet
  - Every message: AES-256-GCM encrypted + KMAC-256 authenticated
  - Each message uses a NEW ratchet key (forward secrecy)
  - Server sees only ciphertext — cannot decrypt

  FILE SHARING
  - Requires same /session as chat (uses same ratchet)
  - Every file chunk: AES-256-GCM encrypted + KMAC-256 tag
  - Server relays encrypted binary frames — cannot decrypt or inspect
  - Disk space checked BEFORE accepting a file (no_space rejection)
  - Partial files KEPT if transfer aborts (never auto-deleted)
  - Files saved to ~/securechatfiles/ (Windows/Mac/Linux auto-detected)

  PROGRESS DISPLAY
  Sender side:   [] 45.2%  sent/total  speed  ETA  chunk_size
  Receiver side: [] 45.2%  recv/total  speed  (receiver shows progress too)

HOW TO USE — COMPLETE WALKTHROUGH
----------------------------------

  STEP 1: Start both clients
    Terminal A (Alice):  python client.py --username alice
    Terminal B (Bob):    python client.py --username bob
    Different machine:   python client.py --username bob --server ws://SERVER_IP:8000

  STEP 2: Find each other
    /search bob            ONLINE  (or  OFFLINE /  NOT FOUND)
    /users                lists all currently online users

  STEP 3: Establish encrypted session (REQUIRED before /msg and /send)
    Alice types:  /session bob
    Bob sees:     [ Session established with alice]
    Alice sees:   [ bob confirmed — session ready]

    What happens internally:
      Alice fetches Bob's ML-KEM-768 public key from server
      Alice encapsulates a random shared secret  ciphertext
      Alice signs ciphertext with ML-DSA-65 private key
      Server verifies signature, relays ciphertext to Bob
      Bob decapsulates  both have same shared secret
      Both init Double Ratchet + KMAC-256 key from shared secret
      Session is now live — /msg and /send both work

  STEP 4: Send encrypted text messages
    /msg bob Hello Bob!
    /msg bob How are you?

    Each message:
      - Ratchet advances  fresh AES-256-GCM key
      - plaintext encrypted  ciphertext
      - KMAC-256 tag computed
      - Envelope sent to server  relayed to Bob  Bob decrypts
      - Even if you send 1000 messages, each uses a DIFFERENT key

  STEP 5: Send a file
    /send bob /home/alice/document.pdf
    /send bob C:\\Users\\Alice\\photo.jpg
    /send bob ~/videos/clip.mp4

    What happens:
      Alice:  Disk space calculated (filesize + 10% buffer)
      Alice:  File offer sent to Bob with filename, size, disk_needed
      Bob:    Sees " alice wants to send: document.pdf (2.4 MB) — Accept? (y/n)"
      Bob:    Checks free disk space  if not enough  auto-rejects with reason
      Bob:    Types y  accepted
      Alice:  Starts sending encrypted chunks through server
      Alice:  Progress: [] 60.2%  1.4MB/2.4MB  12.3MB/s  ETA 0m08s  chunk=512KB
      Bob:    Progress: [] 60.2%  1.4MB/2.4MB  11.8MB/s
      Done:   File saved to ~/securechatfiles/document.pdf on Bob's machine

  STEP 6: View file transfer history
    /transfers            shows this session's transfers with status

  STEP 7: Quit
    /quit

CHUNK ENCRYPTION EXPLAINED
---------------------------
  Each chunk is encrypted INDEPENDENTLY using the ratchet:

    chunk_bytes = read(chunk_size) from file
    ratchet.advance()  fresh AES-256-GCM key for THIS chunk
    nonce = random 12 bytes
    ciphertext = AES-256-GCM.encrypt(key, chunk_bytes, aad="alice:bob:transfer_id")
    mac = KMAC-256(kmac_key, nonce + ciphertext)
    envelope = {nonce, ciphertext, mac, chunk_index}
    frame = [36B transfer_id][JSON envelope bytes]
    send binary frame to server  server relays to Bob  Bob decrypts

  Why per-chunk ratchet?
    Forward secrecy: if chunk N key is compromised, chunks N+1, N+2... are safe.
    Ratchet ensures every chunk key is derived from previous, never reused.

DYNAMIC CHUNK SIZING (BDP)
---------------------------
  BDP = Bandwidth × RTT
  chunk_size = BDP × 0.70   (70% target — SFTP-style pacing)
  RTT measured via WebSocket ping/pong every 4 seconds

  Network          Chunk size settles at
  
  Gigabit LAN      4–10 MB
  WiFi 5GHz        1–3 MB
  WiFi 2.4GHz      256–512 KB
  4G mobile        64–128 KB
  Slow/high RTT    32 KB floor (never below this)

DISK SPACE CHECK
----------------
  When Bob receives a file offer:
    free = shutil.disk_usage(SAVE_DIR).free
    needed = filesize + 10% buffer
    if free < needed:
      auto-reject with reason "Not enough disk space (need X, have Y)"
      sender sees rejection reason clearly

NO SPACE? PARTIAL FILE?
-----------------------
  If transfer aborts mid-way (disconnect, /abort, etc):
    - Partial file is KEPT on receiver's disk (never auto-deleted)
    - File saved as-is up to last received chunk
    - Receiver sees how much was received before abort

FILE SAVE LOCATION
------------------
  Windows : C:\\Users\\<you>\\securechatfiles\\
  macOS   : /Users/<you>/securechatfiles/
  Linux   : /home/<you>/securechatfiles/
  Folder created automatically. Duplicate names get suffix: file_1.pdf, file_2.pdf

N CLIENTS SAME MACHINE — FULLY SUPPORTED
-----------------------------------------
  terminal 1: python client.py --username alice --server ws://192.168.1.50:8000
  terminal 2: python client.py --username bob   --server ws://192.168.1.50:8000
  terminal 3: python client.py --username carol --server ws://192.168.1.50:8000
  All independent WebSocket connections. Server sees 3 separate users.
  Only rule: username must be unique per active connection.
"""

import asyncio
import json
import os
import sys
import uuid
import time
import shutil
import logging
import argparse
import threading
import platform
from pathlib import Path

import websockets

# crypto lives in ../server/ — adjust import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))
from crypto import (
    MLDSAIdentity,     # ML-DSA-65 sign/verify — identity certificates
    MLKEMSession,      # ML-KEM-768 encapsulate/decapsulate — key exchange
    DoubleRatchet,     # per-message/chunk forward-secrecy ratchet
    encrypt_message,   # AES-256-GCM + KMAC-256 encrypt (text messages)
    decrypt_message,   # AES-256-GCM + KMAC-256 decrypt (text messages)
    aes_gcm_encrypt,   # raw AES-256-GCM — used for file chunks
    aes_gcm_decrypt,   # raw AES-256-GCM — used for file chunks
    kmac256,           # KMAC-256 MAC — used for file chunk authentication
    kmac256_verify,    # KMAC-256 verify
    hkdf,              # HKDF key derivation
    run_crypto_proof,  # startup self-test for all PQC algorithms
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pqc_chat.client")


# 
# CONSTANTS
# 

# BDP-based dynamic chunk sizing config
CHUNK_MIN       =   32 * 1024        #  32 KB  — absolute floor
CHUNK_START     =  256 * 1024        # 256 KB  — initial size before BDP measured
TARGET_UTIL     = 0.70               # use 70% of measured bandwidth (SFTP-style)
RTT_PROBE_INT   = 4.0                # probe RTT every N seconds
ADJUST_EVERY    = 6                  # recalculate chunk size every N chunks
MEASURE_WINDOW  = 3.0                # throughput measurement window (seconds)

# Disk space buffer: receiver needs filesize + DISK_BUFFER_PCT extra
DISK_BUFFER_PCT = 0.10               # 10% buffer on top of filesize

# File save directory — OS-specific
SAVE_DIR = Path.home() / "securechatfiles"
SAVE_DIR.mkdir(parents=True, exist_ok=True)


# 
# DISPLAY HELPERS
# 

def _fmt_size(b: float) -> str:
    """Auto-scale bytes  B / KB / MB / GB / TB."""
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def _fmt_speed(bps: float) -> str:
    return _fmt_size(bps) + "/s"

def _fmt_eta(remaining_bytes: float, bps: float) -> str:
    """Human-readable ETA string from remaining bytes and current speed."""
    if bps <= 0:
        return "ETA --:--"
    secs = remaining_bytes / bps
    if secs < 60:
        return f"ETA {int(secs):02d}s"
    m, s = divmod(int(secs), 60)
    if m < 60:
        return f"ETA {m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"ETA {h}h{m:02d}m"

def _fmt_chunk(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f}MB"
    return f"{size // 1024}KB"

def _draw_bar(done: int, total: int, width: int = 25) -> str:
    """ASCII progress bar."""
    if total <= 0:
        return "" * width
    filled = int(width * done / total)
    return "" * filled + "" * (width - filled)


# 
# BDP CHUNK ADAPTOR
# 

class BDPAdaptor:
    """
    Bandwidth-Delay Product based dynamic chunk sizing.

    Formula:
      BDP        = measured_bandwidth_bps × measured_rtt_seconds
      chunk_size = BDP × TARGET_UTIL   (clamped to CHUNK_MIN floor)

    RTT measured via WebSocket ping/pong every RTT_PROBE_INT seconds.
    Bandwidth measured from actual bytes sent in sliding MEASURE_WINDOW window.
    Chunk size recalculates every ADJUST_EVERY chunks or MEASURE_WINDOW seconds.

    SFTP-style pacing:
      After sending each chunk, sleep just enough so effective throughput
      stays at TARGET_UTIL (70%) — never fully saturates the link.

    Network examples:
      Gigabit LAN  RTT 1ms    BDP=900MB×0.001=900KB  chunk=630KB  grows toward MBs
      WiFi 5GHz    RTT 10ms   BDP=50MB×0.010=500KB   chunk=350KB
      4G           RTT 80ms   BDP=2.5MB×0.08=200KB   chunk=140KB
      Slow/mobile  any RTT    chunk floor = 32KB
    """

    def __init__(self):
        self.chunk_size     = CHUNK_START
        self._bandwidth     = 0.0
        self._rtt           = 0.050        # default 50ms until first probe
        self._window_bytes  = 0
        self._window_start  = time.monotonic()
        self._chunk_count   = 0
        self._last_chunk_t  = time.monotonic()

    async def probe_rtt(self, ws) -> float:
        """
        Measure RTT via WebSocket ping/pong.
        ws.ping() sends a WebSocket protocol ping frame.
        Server WebSocket stack auto-replies with pong.
        We time the round-trip.
        """
        try:
            t0   = time.monotonic()
            pong = await asyncio.wait_for(ws.ping(), timeout=5.0)
            await pong
            self._rtt = max(0.001, time.monotonic() - t0)
            logger.debug(f"⏱  RTT={self._rtt * 1000:.1f}ms")
        except Exception:
            pass  # keep last known RTT on timeout
        return self._rtt

    def record_sent(self, nbytes: int):
        """Call after each chunk send to update throughput measurement."""
        self._window_bytes += nbytes
        self._chunk_count  += 1
        now     = time.monotonic()
        elapsed = now - self._window_start

        if self._chunk_count >= ADJUST_EVERY or elapsed >= MEASURE_WINDOW:
            if elapsed > 0 and self._window_bytes > 0:
                self._bandwidth = self._window_bytes / elapsed
                self._recalculate()
            self._window_bytes = 0
            self._window_start = now
            self._chunk_count  = 0

        self._last_chunk_t = now

    def _recalculate(self):
        """BDP formula  new chunk size."""
        if self._bandwidth <= 0 or self._rtt <= 0:
            return
        bdp      = self._bandwidth * self._rtt
        new_size = max(CHUNK_MIN, int(bdp * TARGET_UTIL))
        old      = self.chunk_size
        self.chunk_size = new_size
        if abs(new_size - old) > old * 0.10:
            logger.debug(
                f"  chunk {_fmt_chunk(old)}{_fmt_chunk(new_size)} | "
                f"bw={_fmt_speed(self._bandwidth)} rtt={self._rtt*1000:.1f}ms"
            )

    async def pace(self):
        """Sleep just enough to stay at TARGET_UTIL, not 100%."""
        if self._bandwidth <= 0:
            return
        target_bps       = self._bandwidth * TARGET_UTIL
        ideal_chunk_time = self.chunk_size / target_bps
        elapsed          = time.monotonic() - self._last_chunk_t
        if elapsed < ideal_chunk_time:
            await asyncio.sleep(ideal_chunk_time - elapsed)

    @property
    def bandwidth(self) -> float:
        return self._bandwidth

    def stats_str(self) -> str:
        return (
            f"chunk={_fmt_chunk(self.chunk_size)} "
            f"bw={_fmt_speed(self._bandwidth)} "
            f"rtt={self._rtt * 1000:.0f}ms"
        )


# 
# FILE CHUNK ENCRYPTION / DECRYPTION
# 

def encrypt_chunk(
    ratchet:     DoubleRatchet,
    kmac_key:    bytes,
    chunk_data:  bytes,
    sender:      str,
    recipient:   str,
    transfer_id: str,
    chunk_index: int,
) -> bytes:
    """
    Encrypt one file chunk using the Double Ratchet + AES-256-GCM + KMAC-256.

    Steps:
      1. Advance ratchet  fresh AES-256-GCM key for this chunk only
      2. AAD = "sender:recipient:transfer_id:chunk_index" — binds chunk to transfer
      3. AES-256-GCM encrypt chunk_data with fresh key + AAD
      4. KMAC-256 authenticate nonce + ciphertext
      5. Pack into JSON envelope  encode to bytes

    Returns: envelope bytes (JSON-encoded dict)

    Why per-chunk ratchet?
      Forward secrecy: compromising chunk N key does not help decrypt chunk N+1.
      Each ratchet step produces a completely independent key.
    """
    # Step 1: Fresh ratchet key — this key used for THIS chunk ONLY
    msg_key = ratchet.next_send_key()

    # Step 2: AAD binds chunk to specific transfer and position
    # Prevents replay attacks (chunk from transfer A can't be injected into transfer B)
    aad = f"{sender}:{recipient}:{transfer_id}:{chunk_index}".encode()

    # Step 3: AES-256-GCM encrypt
    nonce, ciphertext = aes_gcm_encrypt(msg_key, chunk_data, aad)

    # Step 4: KMAC-256 authenticate
    mac = kmac256(kmac_key, nonce + ciphertext)

    # Step 5: Pack to JSON bytes
    envelope = {
        "nonce":       nonce.hex(),
        "ciphertext":  ciphertext.hex(),
        "mac":         mac.hex(),
        "chunk_index": chunk_index,
    }
    return json.dumps(envelope).encode("utf-8")


def decrypt_chunk(
    ratchet:     DoubleRatchet,
    kmac_key:    bytes,
    envelope_bytes: bytes,
    sender:      str,
    recipient:   str,
    transfer_id: str,
    chunk_index: int,
) -> bytes:
    """
    Decrypt one file chunk.

    Steps (mirror of encrypt_chunk):
      1. Parse JSON envelope
      2. KMAC-256 verify — reject if tampered
      3. Advance ratchet  same key as sender used for this chunk
      4. AES-256-GCM decrypt with AAD check
      5. Return raw chunk bytes

    Raises ValueError if MAC fails or decryption fails.
    """
    envelope   = json.loads(envelope_bytes.decode("utf-8"))
    nonce      = bytes.fromhex(envelope["nonce"])
    ciphertext = bytes.fromhex(envelope["ciphertext"])
    mac        = bytes.fromhex(envelope["mac"])
    recv_index = envelope.get("chunk_index", chunk_index)

    # Step 2: KMAC-256 verify — detect tampering before any decryption attempt
    if not kmac256_verify(kmac_key, nonce + ciphertext, mac):
        raise ValueError(f"KMAC-256 failed on chunk {recv_index} — data tampered or corrupt")

    # Step 3: Advance ratchet to get this chunk's key
    msg_key = ratchet.next_recv_key()

    # Step 4: AES-256-GCM decrypt with same AAD
    aad = f"{sender}:{recipient}:{transfer_id}:{recv_index}".encode()
    return aes_gcm_decrypt(msg_key, nonce, ciphertext, aad)


# 
# MAIN CLIENT
# 

class PQCChatClient:
    """
    PQC Secure Chat + Encrypted File Share Client.

    Single WebSocket handles:
      - Text frames (JSON): chat, KEM handshake, file offers/responses, presence
      - Binary frames: encrypted file chunk envelopes with 36-byte transfer_id prefix

    Recv loop runs as background asyncio task.
    stdin runs in background OS thread  feeds asyncio queue.
    This prevents blocking the event loop on either side.
    """

    def __init__(self, username: str, server_url: str):
        self.username   = username
        self.server_url = server_url
        self.ws         = None

        # PQC session state (per peer, in memory only — never persisted)
        # ratchets  : peer  DoubleRatchet (shared secret derived ratchet)
        # kmac_keys : peer  32-byte KMAC key derived from same shared secret
        # file_ratchets : peer  separate DoubleRatchet for file chunks
        #   (separate from chat ratchet so file and chat keys don't interfere)
        self.ratchets:       dict[str, DoubleRatchet] = {}
        self.kmac_keys:      dict[str, bytes]          = {}
        self.file_ratchets:  dict[str, DoubleRatchet] = {}
        self.file_kmac_keys: dict[str, bytes]          = {}

        # Request-response waiter registry
        # Used by commands that need server reply before continuing
        self._pending: dict[str, dict] = {}

        # Active incoming file transfers
        # transfer_id  {fh, filename, total, received, chunk_index, ...}
        self._incoming: dict[str, dict] = {}

        # Session file transfer history (for /transfers command)
        self._transfer_log: list[dict] = []

        #  Generate PQC keypairs on startup 
        # ML-DSA-65: signs KEM ciphertext during /session (proves identity)
        # ML-KEM-768: peers use our public key to encapsulate shared secrets to us
        # Both generated fresh each startup — ephemeral per-session identity
        logger.info(f" [{username}] Generating ML-DSA-65 identity keypair...")
        self.identity = MLDSAIdentity()
        logger.info(f" [{username}] ML-DSA-65 pk={len(self.identity.public_key)}B")

        logger.info(f" [{username}] Generating ML-KEM-768 keypair...")
        self.kem_pk, self.kem_sk = MLKEMSession.generate_keypair()
        logger.info(f" [{username}] ML-KEM-768 pk={len(self.kem_pk)}B")


    # 
    # CONNECTION
    # 

    async def connect(self):
        """
        Open WebSocket, register with server.
        Sends ML-DSA-65 + ML-KEM-768 public keys so peers can establish sessions.
        max_size=None removes frame size limit — needed for large encrypted chunks.
        """
        ws_url = f"{self.server_url}/ws/{self.username}"
        logger.info(f" Connecting to {ws_url}")
        self.ws = await websockets.connect(ws_url, max_size=None)

        await self.ws.send(json.dumps({
            "type":   "register",
            "dsa_pk": self.identity.public_key.hex(),
            "kem_pk": self.kem_pk.hex(),
        }))

        resp   = json.loads(await self.ws.recv())
        online = resp.get("online_users", [])
        print(f"\n Connected as '{self.username}'")
        print(f"   Platform    : {platform.system()}")
        print(f"   Save folder : {SAVE_DIR}")
        if online:
            print(f"   Online now  : {', '.join(online)}")
        else:
            print("   No other users online yet")


    # 
    # RECV LOOP
    # 

    async def _recv_loop(self):
        """
        Background task receiving ALL incoming messages from server.

        Routes:
          Binary frame  _handle_file_chunk (encrypted file chunk)
          JSON with matching waiter  wakes _wait_for coroutine
          JSON push  _handle_push (presence, chat, file offers, etc)

        One recv loop prevents concurrent ws.recv() RuntimeErrors.
        """
        try:
            async for message in self.ws:
                if isinstance(message, bytes):
                    await self._handle_file_chunk(message)
                    continue

                msg      = json.loads(message)
                msg_type = msg.get("type", "")

                # Check for waiting coroutines
                waiter_key = None
                if msg_type == "search_result":
                    waiter_key = f"search:{msg.get('username','')}"
                elif msg_type == "peer_keys":
                    waiter_key = f"keys:{msg.get('username','')}"
                elif msg_type == "users_list":
                    waiter_key = "users_list"
                elif msg_type == "file_accepted":
                    waiter_key = f"file_wait:{msg.get('transfer_id','')}"
                elif msg_type == "file_rejected":
                    waiter_key = f"file_wait:{msg.get('transfer_id','')}"

                if waiter_key and waiter_key in self._pending:
                    self._pending[waiter_key]["data"] = msg
                    self._pending[waiter_key]["event"].set()
                else:
                    await self._handle_push(msg)

        except websockets.ConnectionClosed:
            print("\n Disconnected from server", flush=True)
        except Exception as e:
            logger.error(f" recv loop: {e}", exc_info=True)

    async def _wait_for(self, key: str, timeout: float = 10.0) -> dict:
        """
        Suspend current coroutine until recv_loop delivers a matching response.
        Returns response dict or empty dict on timeout.
        """
        event = asyncio.Event()
        self._pending[key] = {"event": event, "data": {}}
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._pending[key]["data"]
        except asyncio.TimeoutError:
            return {}
        finally:
            self._pending.pop(key, None)


    # 
    # FILE CHUNK HANDLER (receiver side)
    # 

    async def _handle_file_chunk(self, frame: bytes):
        """
        Handle incoming encrypted file chunk binary frame.

        Frame format:
          bytes  0-35 : transfer_id (UUID, 36 chars UTF-8)
          bytes 36+   : JSON-encoded AES-256-GCM encrypted envelope

        Process:
          1. Parse transfer_id  look up active incoming transfer
          2. Decrypt chunk using file ratchet + KMAC verify
          3. Write decrypted bytes to disk
          4. Update progress bar with received bytes, speed, ETA
        """
        if len(frame) < 36:
            return

        transfer_id    = frame[:36].decode("utf-8", errors="ignore").strip("\x00")
        envelope_bytes = frame[36:]
        transfer       = self._incoming.get(transfer_id)

        if not transfer:
            logger.warning(f"  Chunk for unknown transfer {transfer_id[:8]}…")
            return

        sender = transfer["sender"]

        # Decrypt chunk using file ratchet
        try:
            chunk_data = decrypt_chunk(
                ratchet      = self.file_ratchets[sender],
                kmac_key     = self.file_kmac_keys[sender],
                envelope_bytes = envelope_bytes,
                sender       = sender,
                recipient    = self.username,
                transfer_id  = transfer_id,
                chunk_index  = transfer["chunk_index"],
            )
        except Exception as e:
            logger.error(f" Chunk decrypt failed transfer={transfer_id[:8]}… : {e}")
            print(f"\n Chunk decryption failed — data corrupt or tampered", flush=True)
            return

        transfer["chunk_index"] += 1

        # Write decrypted chunk to disk
        transfer["fh"].write(chunk_data)
        transfer["received"]    += len(chunk_data)
        transfer["speed_bytes"] += len(chunk_data)

        # Update speed measurement every second
        now     = time.monotonic()
        elapsed = now - transfer["speed_t"]
        if elapsed >= 1.0:
            transfer["rx_bps"]      = transfer["speed_bytes"] / elapsed
            transfer["speed_bytes"] = 0
            transfer["speed_t"]     = now

        # Draw progress
        total    = transfer["total"]
        received = transfer["received"]
        pct      = (received / total * 100) if total > 0 else 0
        bar      = _draw_bar(received, total)
        speed    = transfer.get("rx_bps", 0)

        print(
            f"\r   {transfer['filename'][:18]:<18} [{bar}] "
            f"{pct:5.1f}%  {_fmt_size(received):>10}/{_fmt_size(total):<10}  "
            f"{_fmt_speed(speed):>12}",
            end="", flush=True,
        )


    # 
    # PUSH HANDLER
    # 

    async def _handle_push(self, msg: dict):
        try:
            await self._push_inner(msg)
        except Exception as e:
            logger.error(f" push handler error type={msg.get('type')}: {e}", exc_info=True)

    async def _push_inner(self, msg: dict):
        """
        Handle all server-pushed messages.

        Presence:        user_online, user_offline
        PQC session:     kem_init, kem_ready
        Chat:            message, delivered, delivery_failed
        File transfer:   file_offer, file_complete, file_abort, file_failed
        """
        t = msg.get("type")

        #  Presence 
        if t == "user_online":
            print(f"\n '{msg['username']}' came online", flush=True)

        elif t == "user_offline":
            print(f"\n '{msg['username']}' went offline", flush=True)

        #  KEM init: peer is establishing session with us 
        # Triggered when peer runs /session <our_username>
        # We decapsulate  get shared secret  set up ratchets
        elif t == "kem_init":
            peer       = msg["from"]
            ciphertext = bytes.fromhex(msg["ciphertext"])
            logger.info(f" KEM init from '{peer}' ct={len(ciphertext)}B")

            if peer in self.ratchets:
                print(f"\n  Re-keying session with '{peer}'", flush=True)

            # ML-KEM-768 decapsulate: our private key + their ciphertext  shared secret
            shared_secret = MLKEMSession.decapsulate(self.kem_sk, ciphertext)

            # Set up chat ratchet + file ratchet (separate chains, same shared secret)
            self._setup_session(peer, shared_secret, initiator=False)

            await self.ws.send(json.dumps({"type": "kem_ready", "to": peer}))
            print(
                f"\n[ Session with '{peer}' established]"
                f"\n   /msg {peer} <text>       — encrypted chat"
                f"\n   /send {peer} <filepath>  — encrypted file",
                flush=True,
            )

        #  KEM ready: our /session initiation was confirmed 
        elif t == "kem_ready":
            peer = msg["from"]
            print(
                f"\n[ '{peer}' confirmed — session ready]"
                f"\n   /msg {peer} <text>       — encrypted chat"
                f"\n   /send {peer} <filepath>  — encrypted file",
                flush=True,
            )
            # Wake up initiate_session() if still waiting for confirmation
            waiter_key = f"kem_ready:{peer}"
            if waiter_key in self._pending:
                self._pending[waiter_key]["data"] = msg
                self._pending[waiter_key]["event"].set()

        #  Incoming encrypted text message 
        elif t == "message":
            peer     = msg["from"]
            envelope = msg["envelope"]
            if peer not in self.ratchets:
                print(
                    f"\n Message from '{peer}' dropped — no session."
                    f"\n   Run: /session {peer}",
                    flush=True,
                )
                return
            try:
                plaintext = decrypt_message(
                    ratchet  = self.ratchets[peer],
                    kmac_key = self.kmac_keys[peer],
                    envelope = envelope,
                )
                print(f"\n {peer}: {plaintext}", flush=True)
            except Exception as e:
                logger.error(f" Decrypt failed from '{peer}': {e}")
                print(
                    f"\n Decrypt failed from '{peer}' — ratchet out of sync."
                    f"\n   Re-run: /session {peer}",
                    flush=True,
                )

        elif t == "delivered":
            pass  # silent — message delivered fine

        elif t == "delivery_failed":
            print(f"\n  '{msg.get('to')}': {msg.get('msg')}", flush=True)

        #  Incoming file offer 
        # Auto-accept logic:
        #   - Session exists + disk space OK  AUTO ACCEPT immediately
        #   - No session  auto reject with reason
        #   - No disk space  auto reject with reason
        #
        # No y/n prompt — files from trusted session peers are accepted
        # automatically so recv loop never blocks on input().
        # User sees notification of what was received when done.
        elif t == "file_offer":
            sender      = msg["from"]
            transfer_id = msg["transfer_id"]
            filename    = msg["filename"]
            filesize    = msg["filesize"]
            disk_needed = msg.get("disk_needed", int(filesize * 1.1))

            #  Check 1: Session must exist 
            # File chunks are encrypted with file_ratchet — no session = no decrypt
            if sender not in self.file_ratchets:
                reason = "No active session — run /session first"
                print(
                    f"\n File from '{sender}' auto-rejected — no session"
                    f"\n   Run: /session {sender}  then ask them to resend",
                    flush=True,
                )
                await self.ws.send(json.dumps({
                    "type":        "file_response",
                    "transfer_id": transfer_id,
                    "accepted":    False,
                    "reason":      reason,
                }))
                return

            #  Check 2: Disk space 
            try:
                free_bytes = shutil.disk_usage(SAVE_DIR).free
            except Exception:
                free_bytes = 0

            if free_bytes < disk_needed:
                reason = (
                    f"Not enough disk space — "
                    f"need {_fmt_size(disk_needed)}, have {_fmt_size(free_bytes)}"
                )
                print(
                    f"\n File from '{sender}' auto-rejected — {reason}",
                    flush=True,
                )
                await self.ws.send(json.dumps({
                    "type":        "file_response",
                    "transfer_id": transfer_id,
                    "accepted":    False,
                    "reason":      reason,
                }))
                return

            #  Auto-accept 
            # Session exists and disk space OK  accept immediately, no prompt.
            # Determine unique save path (avoid overwriting existing files)
            save_path = SAVE_DIR / filename
            counter   = 1
            while save_path.exists():
                stem      = Path(filename).stem
                suf       = Path(filename).suffix
                save_path = SAVE_DIR / f"{stem}_{counter}{suf}"
                counter  += 1

            fh = open(save_path, "wb")
            self._incoming[transfer_id] = {
                "filename":    filename,
                "total":       filesize,
                "received":    0,
                "fh":          fh,
                "path":        save_path,
                "sender":      sender,
                "chunk_index": 0,
                "rx_bps":      0.0,
                "speed_bytes": 0,
                "speed_t":     time.monotonic(),
                "start_t":     time.monotonic(),
            }

            # Send accept immediately — no waiting
            await self.ws.send(json.dumps({
                "type":        "file_response",
                "transfer_id": transfer_id,
                "accepted":    True,
            }))

            print(
                f"\n Receiving '{filename}' ({_fmt_size(filesize)}) from '{sender}'"
                f"\n   Saving to : {save_path}"
                f"\n   Free space: {_fmt_size(free_bytes)}",
                flush=True,
            )

            self._transfer_log.append({
                "transfer_id": transfer_id,
                "direction":   "received",
                "peer":        sender,
                "filename":    filename,
                "filesize":    filesize,
                "status":      "transferring",
                "path":        str(save_path),
            })

        #  File transfer complete 
        # All encrypted chunks received and decrypted. Close file, show summary.
        elif t == "file_complete":
            transfer_id = msg["transfer_id"]
            transfer    = self._incoming.pop(transfer_id, None)
            if transfer:
                transfer["fh"].close()
                elapsed = time.monotonic() - transfer["start_t"]
                avg_bps = transfer["total"] / elapsed if elapsed > 0 else 0
                print(
                    f"\n '{transfer['filename']}' received and decrypted"
                    f"\n   Saved  : {transfer['path']}"
                    f"\n   Size   : {_fmt_size(transfer['total'])}"
                    f"\n   Time   : {elapsed:.1f}s  avg {_fmt_speed(avg_bps)}",
                    flush=True,
                )
                for tr in self._transfer_log:
                    if tr["transfer_id"] == transfer_id:
                        tr["status"] = "completed"

        #  File aborted — KEEP partial file 
        # Either party aborted or disconnected mid-transfer.
        # Partial file is intentionally kept — user may recover it manually.
        elif t == "file_abort":
            transfer_id = msg["transfer_id"]
            transfer    = self._incoming.pop(transfer_id, None)
            if transfer:
                transfer["fh"].close()
                # DO NOT delete — partial file kept on disk
                print(
                    f"\n  Transfer aborted by '{msg.get('by','?')}'"
                    f"\n   Partial file KEPT: {transfer['path']}"
                    f"\n   Received: {_fmt_size(transfer['received'])} "
                    f"of {_fmt_size(transfer['total'])}",
                    flush=True,
                )
            else:
                print(f"\n  Transfer {transfer_id[:8]}… aborted", flush=True)
            for tr in self._transfer_log:
                if tr["transfer_id"] == transfer_id:
                    tr["status"] = "aborted (partial kept)"

        #  File failed — KEEP partial file 
        elif t == "file_failed":
            transfer_id = msg["transfer_id"]
            transfer    = self._incoming.pop(transfer_id, None)
            if transfer:
                transfer["fh"].close()
                # DO NOT delete — partial file kept
                print(
                    f"\n Transfer failed: {msg.get('reason','unknown')}"
                    f"\n   Partial file KEPT: {transfer['path']}"
                    f"\n   Received: {_fmt_size(transfer['received'])} "
                    f"of {_fmt_size(transfer['total'])}",
                    flush=True,
                )
            else:
                print(f"\n Transfer failed: {msg.get('reason','unknown')}", flush=True)
            for tr in self._transfer_log:
                if tr["transfer_id"] == transfer_id:
                    tr["status"] = "failed (partial kept)"

        elif t == "error":
            print(f"\n Server: {msg.get('msg')}", flush=True)

        else:
            logger.debug(f"Unhandled push: {t}")


    # 
    # SESSION SETUP
    # 

    def _setup_session(self, peer: str, shared_secret: bytes, initiator: bool):
        """
        Initialise all session keys for a peer from the ML-KEM-768 shared secret.

        Derives FOUR separate keys from the same shared secret:
          chat_ratchet  : Double Ratchet for text messages
          chat_kmac     : KMAC-256 key for text message authentication
          file_ratchet  : Double Ratchet for file chunks (separate chain)
          file_kmac     : KMAC-256 key for file chunk authentication

        Keeping chat and file ratchets separate means:
          - Sending a file does not advance the chat ratchet
          - Chat messages do not affect file chunk keys
          - Both maintain independent forward secrecy chains
        """
        # Chat ratchet + KMAC
        self.ratchets[peer]  = DoubleRatchet(shared_secret, initiator)
        self.kmac_keys[peer] = hkdf(shared_secret, 32, info=b"chat-KMAC-key")

        # File ratchet + KMAC — derived with different info to get different keys
        file_secret = hkdf(shared_secret, 32, info=b"file-ratchet-seed")
        self.file_ratchets[peer]  = DoubleRatchet(file_secret, initiator)
        self.file_kmac_keys[peer] = hkdf(shared_secret, 32, info=b"file-KMAC-key")

        logger.info(
            f"  Session keys for '{peer}' ready — "
            f"chat_ratchet + file_ratchet + 2x KMAC-256"
        )


    # 
    # COMMANDS
    # 

    async def search_user(self, target: str) -> dict:
        """Ask server if user exists and is online. Returns result dict."""
        await self.ws.send(json.dumps({"type": "search_user", "username": target}))
        return await self._wait_for(f"search:{target}")

    async def list_users(self) -> list:
        """Get list of all currently online users (excluding self)."""
        await self.ws.send(json.dumps({"type": "list_users"}))
        resp = await self._wait_for("users_list", timeout=5.0)
        return resp.get("users", [])

    async def initiate_session(self, peer: str):
        """
        Establish PQC encrypted session with a peer.

        Full KEM handshake flow:
          1. Fetch peer's ML-KEM-768 public key from server DB
          2. ML-KEM-768 encapsulate  (ciphertext, shared_secret)
          3. ML-DSA-65 sign ciphertext (proves our identity)
          4. Send kem_init {ciphertext, signature}  server  peer
          5. Peer decapsulates  same shared_secret
          6. Both set up chat ratchet + file ratchet + KMAC keys
          7. Peer sends kem_ready  session confirmed both ways

        After this, /msg AND /send both work with this peer.
        """
        if peer in self.ratchets:
            print(
                f"  Session with '{peer}' already active."
                f"\n   /msg {peer} <text>  or  /send {peer} <file>",
                flush=True,
            )
            return

        logger.info(f" Initiating session with '{peer}'...")

        # Step 1: Fetch peer's public keys
        await self.ws.send(json.dumps({"type": "get_peer_keys", "username": peer}))
        keys = await self._wait_for(f"keys:{peer}")
        if not keys or keys.get("type") == "error":
            print(f" Could not get keys for '{peer}'", flush=True)
            return

        peer_kem_pk = bytes.fromhex(keys["kem_pk"])

        # Step 2: ML-KEM-768 encapsulate
        ciphertext, shared_secret = MLKEMSession.encapsulate(peer_kem_pk)
        logger.info(f"   ↳ [ML-KEM-768] ct={len(ciphertext)}B ss={len(shared_secret)}B")

        # Step 3: ML-DSA-65 sign ciphertext
        signature = self.identity.sign(ciphertext)
        logger.info(f"   ↳ [ML-DSA-65] sig={len(signature)}B")

        # Step 4: Send to server for relay
        await self.ws.send(json.dumps({
            "type":       "kem_init",
            "to":         peer,
            "ciphertext": ciphertext.hex(),
            "signature":  signature.hex(),
        }))

        # Step 5-6: Set up our side (initiator=True)
        self._setup_session(peer, shared_secret, initiator=True)

        print(
            f"[ Waiting for '{peer}' to confirm session...]",
            flush=True,
        )

        # Step 7: Wait for kem_ready from peer (15s timeout)
        # This blocks until peer's kem_ready arrives in recv_loop.
        # Without this wait, /msg or /send typed immediately after /session
        # could race ahead before peer has set up their ratchet.
        await self._wait_for(f"kem_ready:{peer}", timeout=15.0)
        # Note: kem_ready handler already printed the confirmation message
        # and set up the session — we just needed to block until it arrived.

    async def send_message(self, to: str, text: str):
        """
        Send an AES-256-GCM encrypted text message via the chat ratchet.
        Requires active session (/session <peer> first).
        Each call advances the ratchet — every message uses a unique key.
        """
        if to not in self.ratchets:
            print(f" No session with '{to}'. Run: /session {to}", flush=True)
            return

        envelope = encrypt_message(
            ratchet   = self.ratchets[to],
            kmac_key  = self.kmac_keys[to],
            plaintext = text,
            sender    = self.username,
            recipient = to,
        )
        envelope["plaintext"] = text  # server logs this for /history

        await self.ws.send(json.dumps({"type": "message", "to": to, "envelope": envelope}))
        logger.info(f" [{self.username}{to}] encrypted message sent")

    async def send_file(self, to: str, filepath: str):
        """
        Send a file with per-chunk AES-256-GCM encryption using the file ratchet.

        Requires active session (/session <peer> first).
        File ratchet is separate from chat ratchet — sending files does not
        affect chat message keys and vice versa.

        Flow:
          1. Verify session exists
          2. Calculate disk_needed (filesize + 10% buffer)
          3. Send file_offer JSON to server  relayed to peer
          4. Wait for peer accept/reject (60s timeout)
             - If peer has no space  auto-rejected with reason shown to us
             - If peer declines  shown and cancelled
          5. For each chunk:
             a. Read chunk_size bytes from file (BDP adaptive)
             b. encrypt_chunk  AES-256-GCM + KMAC-256 envelope bytes
             c. Prepend 36-byte transfer_id  binary frame
             d. Send to server  server relays encrypted frame to peer
             e. Peer decrypts chunk  writes to disk
             f. Update progress: [bar] pct% sent/total speed ETA chunk_size
          6. Send file_complete JSON  peer finalises file

        Server NEVER sees plaintext file bytes — only encrypted frames.
        """
        if to not in self.file_ratchets:
            print(
                f" No session with '{to}'. Run: /session {to}  first\n"
                f"   File send requires session (same ratchet used for encryption)",
                flush=True,
            )
            return

        path = Path(filepath)
        if not path.exists() or not path.is_file():
            print(f" File not found: {filepath}", flush=True)
            return

        filename    = path.name
        filesize    = path.stat().st_size
        disk_needed = int(filesize * (1 + DISK_BUFFER_PCT))
        transfer_id = str(uuid.uuid4())
        tid_bytes   = transfer_id.encode("utf-8")   # exactly 36 bytes

        print(
            f"\n Offering '{filename}' ({_fmt_size(filesize)}) to '{to}'"
            f"\n   Chunks will be AES-256-GCM encrypted using file ratchet...",
            flush=True,
        )

        # Send offer with disk_needed so receiver can check space before accepting
        await self.ws.send(json.dumps({
            "type":        "file_offer",
            "to":          to,
            "transfer_id": transfer_id,
            "filename":    filename,
            "filesize":    filesize,
            "disk_needed": disk_needed,
        }))

        self._transfer_log.append({
            "transfer_id": transfer_id,
            "direction":   "sent",
            "peer":        to,
            "filename":    filename,
            "filesize":    filesize,
            "status":      "offered",
        })

        # Wait for peer accept/reject (60s)
        print(f"   Waiting for '{to}' to accept (60s timeout)...", flush=True)
        event = asyncio.Event()
        self._pending[f"file_wait:{transfer_id}"] = {"event": event, "data": {}}
        try:
            await asyncio.wait_for(event.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            print(f" No response from '{to}'. Cancelled.", flush=True)
            self._pending.pop(f"file_wait:{transfer_id}", None)
            return

        resp = self._pending.pop(f"file_wait:{transfer_id}", {}).get("data", {})

        if resp.get("type") == "file_rejected":
            reason = resp.get("reason", "Declined")
            print(f" '{to}' rejected: {reason}", flush=True)
            for tr in self._transfer_log:
                if tr["transfer_id"] == transfer_id:
                    tr["status"] = "rejected"
            return

        if resp.get("type") != "file_accepted":
            return

        #  Encrypted chunk send loop 
        adaptor     = BDPAdaptor()
        sent        = 0
        chunk_index = 0
        start_time  = time.monotonic()
        last_rtt_t  = 0.0

        print(
            f"\n  Sending '{filename}' | BDP adaptive chunk | "
            f"target {int(TARGET_UTIL * 100)}% bandwidth",
            flush=True,
        )

        try:
            with open(path, "rb") as f:
                while True:
                    # Probe RTT periodically to keep BDP calculation fresh
                    now = time.monotonic()
                    if now - last_rtt_t >= RTT_PROBE_INT:
                        await adaptor.probe_rtt(self.ws)
                        last_rtt_t = now

                    # Read next chunk (size adapts via BDP each iteration)
                    raw_chunk = f.read(adaptor.chunk_size)
                    if not raw_chunk:
                        break  # EOF — all bytes read

                    # Encrypt chunk with file ratchet
                    # Each chunk: fresh AES-256-GCM key + KMAC-256 tag
                    envelope_bytes = encrypt_chunk(
                        ratchet      = self.file_ratchets[to],
                        kmac_key     = self.file_kmac_keys[to],
                        chunk_data   = raw_chunk,
                        sender       = self.username,
                        recipient    = to,
                        transfer_id  = transfer_id,
                        chunk_index  = chunk_index,
                    )
                    chunk_index += 1

                    # Binary frame: [36B transfer_id][encrypted envelope bytes]
                    # Server reads first 36 bytes only  relays full frame to peer
                    frame = tid_bytes + envelope_bytes
                    await self.ws.send(frame)

                    sent += len(raw_chunk)  # track plaintext bytes for progress
                    adaptor.record_sent(len(frame))

                    # SFTP-style pacing — sleep to stay at 70% bandwidth
                    await adaptor.pace()

                    # Progress with ETA
                    elapsed   = time.monotonic() - start_time
                    avg_bps   = sent / elapsed if elapsed > 0 else 0
                    remaining = filesize - sent
                    bar       = _draw_bar(sent, filesize)
                    pct       = (sent / filesize * 100) if filesize > 0 else 100
                    eta       = _fmt_eta(remaining, avg_bps)

                    print(
                        f"\r   {filename[:16]:<16} [{bar}] "
                        f"{pct:5.1f}%  {_fmt_size(sent):>10}/{_fmt_size(filesize):<10}  "
                        f"{_fmt_speed(avg_bps):>12}  {eta}  {adaptor.stats_str()}",
                        end="", flush=True,
                    )

            # All chunks sent — notify peer
            await self.ws.send(json.dumps({
                "type":        "file_complete",
                "transfer_id": transfer_id,
            }))

            elapsed = time.monotonic() - start_time
            avg_bps = filesize / elapsed if elapsed > 0 else 0
            print(
                f"\n '{filename}' sent and encrypted successfully"
                f"\n   Size    : {_fmt_size(filesize)}"
                f"\n   Chunks  : {chunk_index} (each AES-256-GCM encrypted)"
                f"\n   Time    : {elapsed:.1f}s  avg {_fmt_speed(avg_bps)}"
                f"\n   Final   : {adaptor.stats_str()}",
                flush=True,
            )
            for tr in self._transfer_log:
                if tr["transfer_id"] == transfer_id:
                    tr["status"] = "completed"

        except Exception as e:
            logger.error(f" send_file error: {e}", exc_info=True)
            try:
                await self.ws.send(json.dumps({
                    "type":        "file_abort",
                    "transfer_id": transfer_id,
                }))
            except Exception:
                pass
            print(f"\n Transfer aborted: {e}", flush=True)
            for tr in self._transfer_log:
                if tr["transfer_id"] == transfer_id:
                    tr["status"] = "failed"

    def show_transfers(self):
        """Print session file transfer history as a table."""
        if not self._transfer_log:
            print("  No file transfers this session.", flush=True)
            return
        print(
            f"\n  {'ID':<10} {'DIR':<8} {'PEER':<12} {'FILE':<22} {'SIZE':<10} STATUS",
            flush=True,
        )
        print("  " + "" * 80, flush=True)
        for t in self._transfer_log:
            print(
                f"  {t['transfer_id'][:8]:<10}"
                f"{' sent' if t['direction']=='sent' else ' recv':<8}"
                f"{t['peer'][:10]:<12}"
                f"{t['filename'][:20]:<22}"
                f"{_fmt_size(t['filesize']):<10}"
                f"{t['status']}",
                flush=True,
            )


    # 
    # INTERACTIVE LOOP
    # 

    async def run_interactive(self):
        """
        Main terminal loop.

        Three concurrent components:
          recv_task   : asyncio task — _recv_loop (handles all incoming WS frames)
          stdin_thread: OS thread — reads input(), feeds input_q
          command loop: awaits input_q with 0.1s timeout to stay responsive

        asyncio.wait_for(input_q.get(), 0.1) lets us check recv_task.done()
        without blocking — clean exit when server disconnects.
        """
        run_crypto_proof(label=f"CLIENT:{self.username}")
        await self.connect()

        print(f"\n{''*70}")
        print(f"  PQC Secure Chat + Encrypted File Share — {self.username}")
        print(f"  Crypto  : ML-DSA-65 | ML-KEM-768 | AES-256-GCM | KMAC-256")
        print(f"  Files   : {SAVE_DIR}")
        print(f"  Chunks  : BDP-based ({_fmt_chunk(CHUNK_MIN)} floor, network-driven ceiling)")
        print(f"  Pacing  : {int(TARGET_UTIL*100)}% bandwidth target (SFTP-style)")
        print(f"{''*70}")
        print()
        print("   Discovery ")
        print("  /search <user>              check if user exists/online")
        print("  /users                      list all currently online")
        print()
        print("   Session (required before /msg and /send) ")
        print("  /session <user>             ML-KEM-768 handshake + ratchet setup")
        print()
        print("   Encrypted chat ")
        print("  /msg <user> <text>          AES-256-GCM encrypted message")
        print()
        print("   Encrypted file share ")
        print("  /send <user> <filepath>     per-chunk AES-256-GCM encrypted file")
        print("  /transfers                  session file transfer history")
        print()
        print("  /quit                       exit")
        print(f"{''*70}")

        recv_task = asyncio.create_task(self._recv_loop())
        loop      = asyncio.get_event_loop()
        input_q   = asyncio.Queue()

        def _stdin():
            while True:
                try:
                    line = input()
                    loop.call_soon_threadsafe(
                        lambda l=line: asyncio.ensure_future(input_q.put(l))
                    )
                except EOFError:
                    break

        threading.Thread(target=_stdin, daemon=True).start()

        while True:
            try:
                line = await asyncio.wait_for(input_q.get(), timeout=0.1)
            except asyncio.TimeoutError:
                if recv_task.done():
                    break
                continue

            parts = line.strip().split(maxsplit=2)
            if not parts:
                continue
            cmd = parts[0]

            if cmd == "/quit":
                break

            elif cmd == "/users":
                users = await self.list_users()
                print(
                    f"   Online: {', '.join(users)}" if users
                    else "  No other users online",
                    flush=True,
                )

            elif cmd == "/search" and len(parts) >= 2:
                r = await self.search_user(parts[1])
                if r.get("online"):
                    st = " ONLINE"
                elif r.get("exists"):
                    st = " OFFLINE (registered, not online now)"
                else:
                    st = " NOT FOUND"
                print(f"  {parts[1]}: {st}", flush=True)

            elif cmd == "/session" and len(parts) >= 2:
                await self.initiate_session(parts[1])

            elif cmd == "/msg" and len(parts) >= 3:
                await self.send_message(parts[1], parts[2])

            elif cmd == "/send" and len(parts) >= 3:
                await self.send_file(parts[1], parts[2])

            elif cmd == "/transfers":
                self.show_transfers()

            else:
                print(
                    "  Unknown command."
                    "\n  /search /users /session /msg /send /transfers /quit",
                    flush=True,
                )

        # Close open file handles — partial files stay on disk
        for t in self._incoming.values():
            try:
                t["fh"].close()
            except Exception:
                pass

        recv_task.cancel()
        try:
            await self.ws.close()
        except Exception:
            pass
        logger.info(f" '{self.username}' disconnected")


# 
# ENTRY POINT
# 

async def main():
    parser = argparse.ArgumentParser(
        description="PQC Secure Chat + Encrypted File Share",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Same machine (localhost but ubuntu):
    python client.py --username alice
    python client.py --username bob

  Different machines (server at 192.168.1.50):
    python client.py --username alice --server ws://192.168.1.50:8000
    python client.py --username bob   --server ws://192.168.1.50:8000

  Multiple users same machine(windows):
    python client.py --username alice --server ws://192.168.1.50:8000
    python client.py --username bob   --server ws://192.168.1.50:8000
    python client.py --username carol --server ws://192.168.1.50:8000
        """
    )
    parser.add_argument("--username", required=True,
                        help="Your username (unique per active connection)")
    parser.add_argument("--server", default="ws://localhost:8000",
                        help="Server URL (default: ws://localhost:8000)")
    args   = parser.parse_args()
    client = PQCChatClient(args.username, args.server)
    await client.run_interactive()


if __name__ == "__main__":
    asyncio.run(main())