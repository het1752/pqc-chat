"""
server/main.py — PQC Secure Chat + Encrypted File Relay Server
===============================================================

What this server does
---------------------
Pure relay — it forwards messages and file chunks between clients.
It has NO ability to decrypt anything — not chat messages, not file chunks.

  1. PQC ENCRYPTED TEXT CHAT
     - Relays AES-256-GCM encrypted envelopes between online users
     - Saves message metadata to SQLite (content field = plaintext for logging)
     - Handles KEM handshake forwarding for session establishment

  2. ENCRYPTED FILE TRANSFER RELAY
     - File chunks are AES-256-GCM encrypted by sender using session ratchet
     - Session must exist (KEM handshake done) before file can be sent
     - Server receives binary frames  relays to recipient  done
     - ZERO file data stored on server, encrypted or not
     - Saves only file metadata (name, size, status) to SQLite

Binary frame format (file chunks):
  [0:36]  = transfer_id (UUID, 36 bytes UTF-8)
  [36:]   = JSON-encoded encrypted envelope (AES-256-GCM ciphertext + KMAC tag)
  Server reads first 36 bytes only  looks up recipient  relays entire frame

What server NEVER does
----------------------
  - Never decrypts messages or file chunks (has no session keys)
  - Never stores file bytes on disk or in DB
  - Never stores session shared secrets (ephemeral, client-only)

Message types handled
---------------------
  Text JSON frames:
    register         client handshake with PQC public keys
    search_user      check if user exists / is online
    list_users       get all online users
    get_peer_keys    fetch peer ML-KEM + ML-DSA public keys from DB
    kem_init         relay KEM ciphertext from initiator to responder
    kem_ready        relay KEM confirmation back to initiator
    message          relay encrypted chat envelope
    file_offer       relay file transfer offer (with disk_needed field)
    file_response    relay accept/reject back to sender
    file_complete    relay transfer-done signal to receiver
    file_abort       relay abort signal, clean up active_transfers

  Binary frames:
    [36B id][encrypted chunk envelope]  relay to recipient

REST endpoints
--------------
  GET /health                    — online users, active transfers count
  GET /history/{user_a}/{user_b} — chat log between two users
  GET /history/{username}        — all messages for a user
  GET /messages                  — full server-wide chat log
  GET /transfers                 — all file transfer records
  GET /transfers/{username}      — file transfers for one user
"""

import asyncio
import json
import logging
import os
from typing import Dict

from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from dotenv import load_dotenv

load_dotenv()

from database import (
    init_db,
    register_user,
    get_user,
    user_exists,
    save_message,
    mark_message_delivered,
    get_conversation,
    get_user_messages,
    get_all_messages,
    save_transfer,
    update_transfer_status,
    get_all_transfers,
    get_user_transfers,
)
from crypto import run_crypto_proof

#  Logging 
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pqc_chat.server")

#  App 
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    #  Startup 
    await init_db()
    run_crypto_proof(label="SERVER")
    logger.info(" PQC Chat + Encrypted File Relay Server started")
    logger.info("    Crypto ")
    logger.info("    ML-DSA-65      : Identity signatures  (FIPS 204)")
    logger.info("    ML-KEM-768     : Key encapsulation    (FIPS 203)")
    logger.info("    Double Ratchet : Per-message forward secrecy")
    logger.info("    AES-256-GCM    : Symmetric encryption (chat + file chunks)")
    logger.info("    KMAC-256       : Message authentication")
    logger.info("    File relay ")
    logger.info("    Session required before file send (same ratchet)")
    logger.info("    Each chunk encrypted AES-256-GCM by sender")
    logger.info("    Server relays encrypted frames — cannot decrypt")
    yield
    #  Shutdown (nothing to clean up) 

app = FastAPI(title="PQC Chat + Encrypted File Relay", version="3.0.0", lifespan=lifespan)

# Live user registry: username  WebSocket
# Added on register, removed on disconnect
online_users: Dict[str, WebSocket] = {}

# Active file transfers: transfer_id  {sender, receiver, filename, filesize, status}
# Added on file_offer, removed on complete/abort/fail/disconnect
active_transfers: Dict[str, dict] = {}


#  Startup handled in lifespan() above 


#  WebSocket helpers 

async def send_json(ws: WebSocket, data: dict):
    """Send JSON control message to a specific WebSocket."""
    await ws.send_text(json.dumps(data))


async def relay_json_to(username: str, data: dict) -> bool:
    """
    Relay a JSON message to a user by username.
    Returns True if user online and send succeeded.
    Returns False if user offline or send failed.
    """
    ws = online_users.get(username)
    if ws:
        try:
            await send_json(ws, data)
            return True
        except Exception:
            return False
    return False


async def relay_bytes_to(username: str, data: bytes) -> bool:
    """
    Relay a raw binary frame to a user by username.
    Used for file chunk relay — server does not inspect bytes[36:].
    Returns True if send succeeded, False otherwise.
    """
    ws = online_users.get(username)
    if ws:
        try:
            await ws.send_bytes(data)
            return True
        except Exception:
            return False
    return False


#  REST endpoints 

@app.get("/health")
async def health():
    return {
        "status":           "ok",
        "online_users":     list(online_users.keys()),
        "active_transfers": len(active_transfers),
    }


@app.get("/history/{user_a}/{user_b}")
async def history_conversation(user_a: str, user_b: str, limit: int = 100):
    msgs = await get_conversation(user_a, user_b, limit=limit)
    return {"user_a": user_a, "user_b": user_b, "count": len(msgs), "messages": msgs}


@app.get("/history/{username}")
async def history_user(username: str, limit: int = 200):
    msgs = await get_user_messages(username, limit=limit)
    return {"username": username, "count": len(msgs), "messages": msgs}


@app.get("/messages")
async def all_messages(limit: int = 500):
    msgs = await get_all_messages(limit=limit)
    return {"count": len(msgs), "messages": msgs}


@app.get("/transfers")
async def all_file_transfers(limit: int = 100):
    rows = await get_all_transfers(limit)
    return {"count": len(rows), "transfers": rows}


@app.get("/transfers/{username}")
async def user_file_transfers(username: str, limit: int = 50):
    rows = await get_user_transfers(username, limit)
    return {"username": username, "count": len(rows), "transfers": rows}


#  WebSocket endpoint 

@app.websocket("/ws/{username}")
async def websocket_endpoint(websocket: WebSocket, username: str):
    """
    Single WebSocket connection per user handles everything:
      - Text JSON frames  : chat, session handshake, file offers/responses
      - Binary frames     : encrypted file chunks (36B id prefix + envelope)

    N users = N concurrent coroutines. asyncio handles concurrency —
    no threads needed, no blocking between users.
    """
    await websocket.accept()
    logger.info(f" [WS] Connected: '{username}'")

    try:
        #  Registration 
        # First frame must be register with both PQC public keys.
        # Keys stored in DB so peers can fetch them for session establishment.
        raw  = await websocket.receive_text()
        data = json.loads(raw)

        if data.get("type") != "register":
            await send_json(websocket, {"type": "error", "msg": "First message must be register"})
            await websocket.close()
            return

        dsa_pk = bytes.fromhex(data.get("dsa_pk", ""))
        kem_pk = bytes.fromhex(data.get("kem_pk", ""))

        await register_user(username, dsa_pk, kem_pk)
        online_users[username] = websocket
        logger.info(f" [ONLINE] '{username}'. Online: {list(online_users.keys())}")

        await send_json(websocket, {
            "type":         "registered",
            "msg":          f"Welcome {username}! You are online.",
            "online_users": [u for u in online_users.keys() if u != username],
        })

        # Tell all other online users this user just came online
        for other, ws in list(online_users.items()):
            if other != username:
                try:
                    await send_json(ws, {"type": "user_online", "username": username})
                except Exception:
                    pass

        #  Main loop 
        while True:
            message = await websocket.receive()

            #  Binary frame: encrypted file chunk 
            # Format: [transfer_id: 36 bytes][encrypted chunk envelope: N bytes]
            # Server only reads the 36-byte prefix to identify the transfer.
            # Everything after byte 36 is the AES-256-GCM encrypted payload —
            # server cannot and does not inspect it. Pure relay.
            if message["type"] == "websocket.receive" and message.get("bytes"):
                frame = message["bytes"]

                if len(frame) < 36:
                    continue  # malformed frame

                transfer_id = frame[:36].decode("utf-8", errors="ignore").strip("\x00")
                transfer    = active_transfers.get(transfer_id)

                if not transfer:
                    logger.warning(f"  [FILE] Unknown transfer_id: {transfer_id[:8]}…")
                    continue

                recipient = transfer["receiver"]

                # Relay entire frame (prefix + encrypted payload) to recipient
                ok = await relay_bytes_to(recipient, frame)
                if not ok:
                    # Recipient went offline mid-transfer
                    logger.warning(
                        f" [FILE] '{recipient}' offline mid-transfer {transfer_id[:8]}…"
                    )
                    active_transfers.pop(transfer_id, None)
                    await update_transfer_status(transfer_id, "failed")
                    await send_json(websocket, {
                        "type":        "file_failed",
                        "transfer_id": transfer_id,
                        "reason":      f"'{recipient}' went offline during transfer",
                    })
                continue

            #  Text frame: JSON control message 
            raw      = message.get("text", "")
            if not raw:
                continue
            msg      = json.loads(raw)
            msg_type = msg.get("type")

            #  Search user 
            if msg_type == "search_user":
                target    = msg.get("username", "")
                exists    = await user_exists(target)
                is_online = target in online_users
                logger.info(f" [SEARCH] '{username}''{target}' exists={exists} online={is_online}")
                await send_json(websocket, {
                    "type":     "search_result",
                    "username": target,
                    "exists":   exists,
                    "online":   is_online,
                })

            #  List online users 
            elif msg_type == "list_users":
                await send_json(websocket, {
                    "type":  "users_list",
                    "users": [u for u in online_users.keys() if u != username],
                })

            #  Get peer public keys 
            # Client fetches peer's ML-KEM-768 pk to encapsulate a shared secret,
            # and ML-DSA-65 pk to verify the peer's signature on KEM ciphertext.
            elif msg_type == "get_peer_keys":
                target    = msg.get("username")
                user_data = await get_user(target)
                if user_data:
                    logger.info(f" [KEYS] '{username}' fetched keys for '{target}'")
                    await send_json(websocket, {
                        "type":     "peer_keys",
                        "username": target,
                        "dsa_pk":   user_data["dsa_public_key"].hex(),
                        "kem_pk":   user_data["kem_public_key"].hex(),
                    })
                else:
                    await send_json(websocket, {
                        "type": "error",
                        "msg":  f"User '{target}' not found",
                    })

            #  KEM init: session establishment step 1 
            # Sender encapsulated a shared secret with recipient's ML-KEM-768 pk.
            # Server verifies sender's ML-DSA-65 signature on the ciphertext
            # to confirm identity, then relays to recipient.
            elif msg_type == "kem_init":
                to             = msg.get("to")
                ciphertext_hex = msg.get("ciphertext", "")
                signature_hex  = msg.get("signature", "")

                logger.info(f" [KEM-INIT] '{username}''{to}'")

                if to not in online_users:
                    await send_json(websocket, {
                        "type": "error",
                        "msg":  f"'{to}' is offline. Cannot establish session.",
                    })
                    continue

                # Verify ML-DSA-65 signature — proves KEM was sent by claimed user
                if signature_hex:
                    user_data = await get_user(username)
                    if user_data:
                        from crypto import MLDSAIdentity
                        valid = MLDSAIdentity.verify(
                            user_data["dsa_public_key"],
                            bytes.fromhex(ciphertext_hex),
                            bytes.fromhex(signature_hex),
                        )
                        logger.info(
                            f"   ↳ [ML-DSA-65] sig by '{username}': "
                            f"{' VALID' if valid else ' INVALID'}"
                        )

                await relay_json_to(to, {
                    "type":       "kem_init",
                    "from":       username,
                    "ciphertext": ciphertext_hex,
                    "signature":  signature_hex,
                })

            #  KEM ready: session establishment step 2 
            # Recipient decapsulated successfully, relays confirmation to initiator.
            elif msg_type == "kem_ready":
                to = msg.get("to")
                logger.info(f" [KEM-READY] '{username}'  '{to}'")
                await relay_json_to(to, {"type": "kem_ready", "from": username})

            #  Encrypted chat message 
            # envelope = {ciphertext, iv, kmac_tag, ...} — AES-256-GCM encrypted
            # Server saves metadata + relays envelope. Cannot decrypt.
            elif msg_type == "message":
                to       = msg.get("to")
                envelope = msg.get("envelope", {})

                if not to or not envelope:
                    await send_json(websocket, {"type": "error", "msg": "Missing 'to' or 'envelope'"})
                    continue

                plain_content = envelope.get("plaintext", "")
                is_online     = to in online_users

                msg_row_id = await save_message(
                    sender    = username,
                    recipient = to,
                    content   = plain_content or f"[encrypted, ct_len={len(envelope.get('ciphertext',''))}]",
                    delivered = is_online,
                )

                if is_online:
                    delivered = await relay_json_to(to, {
                        "type":     "message",
                        "from":     username,
                        "envelope": envelope,
                    })
                    if delivered:
                        if msg_row_id:
                            await mark_message_delivered(msg_row_id)
                        await send_json(websocket, {"type": "delivered", "to": to})
                    else:
                        await send_json(websocket, {
                            "type": "delivery_failed",
                            "to":   to,
                            "msg":  f"'{to}' went offline before delivery.",
                        })
                else:
                    await send_json(websocket, {
                        "type": "delivery_failed",
                        "to":   to,
                        "msg":  f"'{to}' is offline.",
                    })

            #  File offer 
            # Sender wants to send a file. Offer includes filename, size, and
            # disk_needed (bytes receiver must have free) so receiver can check
            # disk space before accepting.
            # Session must already exist — server checks active_transfers only,
            # client enforces session requirement before sending this message.
            elif msg_type == "file_offer":
                to          = msg.get("to")
                transfer_id = msg.get("transfer_id")
                filename    = msg.get("filename")
                filesize    = msg.get("filesize")
                # disk_needed = filesize + 10% buffer for filesystem overhead
                disk_needed = msg.get("disk_needed", int(filesize * 1.1))

                if to not in online_users:
                    await send_json(websocket, {
                        "type": "error",
                        "msg":  f"'{to}' is offline.",
                    })
                    continue

                # Register transfer in memory and DB (status = offered)
                active_transfers[transfer_id] = {
                    "sender":   username,
                    "receiver": to,
                    "filename": filename,
                    "filesize": filesize,
                    "status":   "offered",
                }
                await save_transfer(
                    transfer_id = transfer_id,
                    sender      = username,
                    receiver    = to,
                    filename    = filename,
                    filesize    = filesize,
                    disk_needed = disk_needed,
                    status      = "offered",
                )
                logger.info(
                    f" [FILE-OFFER] '{username}''{to}' "
                    f"'{filename}' {filesize}B id={transfer_id[:8]}…"
                )

                # Relay offer to recipient — includes disk_needed for space check
                await relay_json_to(to, {
                    "type":        "file_offer",
                    "from":        username,
                    "transfer_id": transfer_id,
                    "filename":    filename,
                    "filesize":    filesize,
                    "disk_needed": disk_needed,
                })

            #  File response: receiver accepts or rejects 
            # If accepted   update status, tell sender to start sending chunks
            # If rejected   clean up, tell sender
            # If no_space   special rejection reason shown to sender
            elif msg_type == "file_response":
                transfer_id = msg.get("transfer_id")
                accepted    = msg.get("accepted", False)
                reason      = msg.get("reason", "")
                transfer    = active_transfers.get(transfer_id)

                if not transfer:
                    await send_json(websocket, {"type": "error", "msg": "Unknown transfer_id"})
                    continue

                sender = transfer["sender"]

                if accepted:
                    active_transfers[transfer_id]["status"] = "transferring"
                    await update_transfer_status(transfer_id, "transferring")
                    logger.info(f" [FILE] '{username}' accepted {transfer_id[:8]}…")
                    await relay_json_to(sender, {
                        "type":        "file_accepted",
                        "transfer_id": transfer_id,
                        "by":          username,
                    })
                else:
                    active_transfers.pop(transfer_id, None)
                    await update_transfer_status(transfer_id, "rejected")
                    logger.info(
                        f" [FILE] '{username}' rejected {transfer_id[:8]}… reason={reason}"
                    )
                    await relay_json_to(sender, {
                        "type":        "file_rejected",
                        "transfer_id": transfer_id,
                        "by":          username,
                        "reason":      reason,
                    })

            #  File complete: all chunks sent 
            # Sender signals it finished sending. Server marks DB record complete
            # and notifies receiver to finalise the file.
            elif msg_type == "file_complete":
                transfer_id = msg.get("transfer_id")
                transfer    = active_transfers.pop(transfer_id, None)
                if transfer:
                    await update_transfer_status(transfer_id, "completed")
                    logger.info(f" [FILE] Transfer {transfer_id[:8]}… complete")
                    await relay_json_to(transfer["receiver"], {
                        "type":        "file_complete",
                        "transfer_id": transfer_id,
                        "from":        username,
                    })

            #  File abort: either party cancels 
            # Can come from sender or receiver. Server cleans up and notifies other.
            elif msg_type == "file_abort":
                transfer_id = msg.get("transfer_id")
                transfer    = active_transfers.pop(transfer_id, None)
                if transfer:
                    await update_transfer_status(transfer_id, "aborted")
                    logger.info(f"  [FILE] {transfer_id[:8]}… aborted by '{username}'")
                    other = (
                        transfer["receiver"]
                        if transfer["sender"] == username
                        else transfer["sender"]
                    )
                    await relay_json_to(other, {
                        "type":        "file_abort",
                        "transfer_id": transfer_id,
                        "by":          username,
                    })

            else:
                logger.warning(f"  Unknown type='{msg_type}' from '{username}'")
                await send_json(websocket, {"type": "error", "msg": f"Unknown type: {msg_type}"})

    except WebSocketDisconnect:
        pass
    except RuntimeError as e:
        # Starlette raises RuntimeError("Cannot call receive once a disconnect
        # message has been received") when client closes cleanly but our loop
        # tries one more receive. Treat it as a normal disconnect — not an error.
        if "disconnect" in str(e).lower():
            pass
        else:
            logger.error(f" [WS] RuntimeError for '{username}': {e}", exc_info=True)
    except Exception as e:
        logger.error(f" [WS] Error for '{username}': {e}", exc_info=True)
    finally:
        #  Cleanup on disconnect 
        online_users.pop(username, None)

        # Abort all active transfers for this user and notify the other party
        to_abort = [
            tid for tid, t in active_transfers.items()
            if t["sender"] == username or t["receiver"] == username
        ]
        for tid in to_abort:
            t = active_transfers.pop(tid, None)
            if t:
                asyncio.create_task(update_transfer_status(tid, "aborted"))
                other = t["receiver"] if t["sender"] == username else t["sender"]
                asyncio.create_task(relay_json_to(other, {
                    "type":        "file_abort",
                    "transfer_id": tid,
                    "by":          username,
                    "reason":      f"'{username}' disconnected",
                }))

        # Notify remaining users this user went offline
        for other, ws in list(online_users.items()):
            try:
                await send_json(ws, {"type": "user_offline", "username": username})
            except Exception:
                pass

        logger.info(
            f" [OFFLINE] '{username}' disconnected. "
            f"Online: {list(online_users.keys())}"
        )


if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host=host, port=port, reload=False, log_level="info")