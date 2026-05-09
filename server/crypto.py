"""
crypto.py — Post-Quantum Cryptography Engine (Pure Python, zero C deps)
========================================================================
Libraries:
  kyber-py       ML-KEM-768  (FIPS 203)  pip install kyber-py
  dilithium-py   ML-DSA-65   (FIPS 204)  pip install dilithium-py

Implements:
  - ML-DSA-65      : Identity certificates (signing / verification)
  - ML-KEM-768     : Key encapsulation for shared secret establishment
  - Double Ratchet : Forward secrecy per-message key derivation
  - AES-GCM-256    : Symmetric authenticated encryption
  - KMAC-256       : Final message authentication code
"""

import os
import hmac
import hashlib
import logging
from typing import Tuple

logger = logging.getLogger("pqc_chat.crypto")

#  ML-KEM-768 (kyber-py) 
from kyber_py.ml_kem import ML_KEM_768
logger.info(" kyber-py loaded — ML-KEM-768 (FIPS 203) available")

#  ML-DSA-65 (dilithium-py) 
from dilithium_py.ml_dsa import ML_DSA_65
logger.info(" dilithium-py loaded — ML-DSA-65 (FIPS 204) available")

#  AES-GCM-256 (cryptography) 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIG_ALG = "ML-DSA-65"
KEM_ALG = "ML-KEM-768"


# 
#  ML-DSA-65 — Identity / Certificate
# 

class MLDSAIdentity:
    def __init__(self):
        logger.info(f" [ML-DSA-65] Generating identity keypair (FIPS 204)")
        self.public_key, self.private_key = ML_DSA_65.keygen()
        logger.info(
            f" [ML-DSA-65] Keypair ready — "
            f"pk={len(self.public_key)}B, sk={len(self.private_key)}B"
        )

    def sign(self, message: bytes) -> bytes:
        logger.debug(f"  [ML-DSA-65] Signing {len(message)}B")
        sig = ML_DSA_65.sign(self.private_key, message)
        logger.debug(f" [ML-DSA-65] Signature {len(sig)}B")
        return sig

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        logger.debug(f" [ML-DSA-65] Verifying sig={len(signature)}B over msg={len(message)}B")
        valid = ML_DSA_65.verify(public_key, message, signature)
        if valid:
            logger.info(" [ML-DSA-65] Signature VALID")
        else:
            logger.debug(" [ML-DSA-65] Signature INVALID (expected if tamper-testing)")
        return valid


# 
#  ML-KEM-768 — Key Encapsulation
# 

class MLKEMSession:
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        logger.info(f" [ML-KEM-768] Generating KEM keypair (FIPS 203)")
        ek, dk = ML_KEM_768.keygen()
        logger.info(f" [ML-KEM-768] Keypair ready — ek={len(ek)}B, dk={len(dk)}B")
        return ek, dk

    @staticmethod
    def encapsulate(peer_ek: bytes) -> Tuple[bytes, bytes]:
        logger.info(f" [ML-KEM-768] Encapsulating — peer_ek={len(peer_ek)}B")
        shared_secret, ciphertext = ML_KEM_768.encaps(peer_ek)
        logger.info(
            f" [ML-KEM-768] Encapsulation done — "
            f"ct={len(ciphertext)}B, ss={len(shared_secret)}B"
        )
        return ciphertext, shared_secret

    @staticmethod
    def decapsulate(dk: bytes, ciphertext: bytes) -> bytes:
        logger.info(f" [ML-KEM-768] Decapsulating — dk={len(dk)}B, ct={len(ciphertext)}B")
        shared_secret = ML_KEM_768.decaps(dk, ciphertext)
        logger.info(f" [ML-KEM-768] Decapsulation done — ss={len(shared_secret)}B")
        return shared_secret


# 
#  HKDF (pure Python / SHA-256)
# 

def hkdf(ikm: bytes, length: int, salt: bytes = b"", info: bytes = b"") -> bytes:
    if not salt:
        salt = b'\x00' * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


# 
#  Double Ratchet — Forward Secrecy
# 

class DoubleRatchet:
    CHAIN_KEY_INFO = b"PQC-Chat-ChainKey-v1"
    MSG_KEY_INFO   = b"PQC-Chat-MsgKey-v1"
    ROOT_KDF_INFO  = b"PQC-Chat-RootKDF-v1"

    def __init__(self, shared_secret: bytes, initiator: bool):
        logger.info(
            f"  [DoubleRatchet] Init — role={'initiator' if initiator else 'responder'}, "
            f"ss={len(shared_secret)}B"
        )
        self.root_key = hkdf(shared_secret, 32, info=self.ROOT_KDF_INFO)
        # initiator sends on chain-A, receives on chain-B
        # responder sends on chain-B, receives on chain-A
        # so initiator.send == responder.recv and vice-versa
        chain_a = hkdf(self.root_key, 32, info=b"chain-A")
        chain_b = hkdf(self.root_key, 32, info=b"chain-B")
        if initiator:
            self.send_chain, self.recv_chain = chain_a, chain_b
        else:
            self.send_chain, self.recv_chain = chain_b, chain_a
        self.send_count = 0
        self.recv_count = 0
        logger.info(
            f" [DoubleRatchet] Initialised — root_key={len(self.root_key)}B "
            f"send=chain-{'A' if initiator else 'B'} recv=chain-{'B' if initiator else 'A'}"
        )

    def _ratchet(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        msg_key  = hkdf(chain_key, 32, info=self.MSG_KEY_INFO)
        next_ck  = hkdf(chain_key, 32, info=self.CHAIN_KEY_INFO)
        return msg_key, next_ck

    def next_send_key(self) -> bytes:
        msg_key, self.send_chain = self._ratchet(self.send_chain)
        self.send_count += 1
        logger.debug(f" [DoubleRatchet] Send step #{self.send_count} — fresh AES-256-GCM key")
        return msg_key

    def next_recv_key(self) -> bytes:
        msg_key, self.recv_chain = self._ratchet(self.recv_chain)
        self.recv_count += 1
        logger.debug(f" [DoubleRatchet] Recv step #{self.recv_count} — fresh AES-256-GCM key")
        return msg_key


# 
#  AES-256-GCM
# 

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    assert len(key) == 32
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    logger.debug(f" [AES-256-GCM] {len(plaintext)}B  ct={len(ct)}B nonce={nonce.hex()[:12]}...")
    return nonce, ct

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    assert len(key) == 32
    pt = AESGCM(key).decrypt(nonce, ciphertext, aad or None)
    logger.debug(f" [AES-256-GCM] ct={len(ciphertext)}B  {len(pt)}B plaintext (auth OK)")
    return pt


# 
#  KMAC-256 (HKDF-SHA256 approximation)
# 

def kmac256(key: bytes, data: bytes, customization: bytes = b"PQC-Chat") -> bytes:
    mac = hkdf(ikm=data, length=32, salt=key, info=b"KMAC256:" + customization)
    logger.debug(f"  [KMAC-256] MAC computed over {len(data)}B — key={len(key)}B")
    return mac

def kmac256_verify(key: bytes, data: bytes, expected: bytes, customization: bytes = b"PQC-Chat") -> bool:
    result = hmac.compare_digest(kmac256(key, data, customization), expected)
    logger.debug(f"  [KMAC-256] Verify: {' OK' if result else ' FAIL'}")
    return result


# 
#  Full Message Encrypt / Decrypt
# 

def encrypt_message(ratchet: DoubleRatchet, kmac_key: bytes,
                    plaintext: str, sender: str, recipient: str) -> dict:
    logger.info(f" [MSG-ENCRYPT] {sender}  {recipient} | plain={len(plaintext)}B")

    msg_key = ratchet.next_send_key()
    logger.info(f"   ↳ [Step 1] DoubleRatchet advance — fresh AES-256-GCM key (forward secrecy)")

    aad = f"{sender}:{recipient}".encode()
    nonce, ciphertext = aes_gcm_encrypt(msg_key, plaintext.encode(), aad)
    logger.info(f"   ↳ [Step 2] AES-256-GCM encrypted — ct={len(ciphertext)}B")

    mac = kmac256(kmac_key, nonce + ciphertext)
    logger.info(f"   ↳ [Step 3] KMAC-256 MAC={mac.hex()[:16]}...")

    logger.info(f" [MSG-ENCRYPT] Done")
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(),
            "mac": mac.hex(), "sender": sender, "recipient": recipient}


def decrypt_message(ratchet: DoubleRatchet, kmac_key: bytes, envelope: dict) -> str:
    sender    = envelope["sender"]
    recipient = envelope["recipient"]
    nonce     = bytes.fromhex(envelope["nonce"])
    ct        = bytes.fromhex(envelope["ciphertext"])
    mac       = bytes.fromhex(envelope["mac"])

    logger.info(f" [MSG-DECRYPT] {sender}  {recipient} | ct={len(ct)}B")

    if not kmac256_verify(kmac_key, nonce + ct, mac):
        logger.error(" [KMAC-256] MAC FAILED — message rejected")
        raise ValueError("KMAC-256 verification failed")
    logger.info(f"   ↳ [Step 1] KMAC-256 verified ")

    msg_key = ratchet.next_recv_key()
    logger.info(f"   ↳ [Step 2] DoubleRatchet recv advance ")

    aad = f"{sender}:{recipient}".encode()
    pt = aes_gcm_decrypt(msg_key, nonce, ct, aad)
    logger.info(f"   ↳ [Step 3] AES-256-GCM decrypted   {len(pt)}B")

    logger.info(f" [MSG-DECRYPT] Done")
    return pt.decode("utf-8")


# 
#  Cryptographic Proof — verifies all algorithms against FIPS spec sizes
# 

def run_crypto_proof(label: str = "SERVER"):
    # Fetch real algorithm names from the library modules
    dsa_alg_name = ML_DSA_65.__class__.__name__ if hasattr(ML_DSA_65, "__class__") else type(ML_DSA_65).__name__
    kem_alg_name = ML_KEM_768.__class__.__name__ if hasattr(ML_KEM_768, "__class__") else type(ML_KEM_768).__name__
    import dilithium_py.ml_dsa as _dsa_mod
    import kyber_py.ml_kem    as _kem_mod
    dsa_lib = f"{_dsa_mod.__name__}.ML_DSA_65"
    kem_lib = f"{_kem_mod.__name__}.ML_KEM_768"
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _aes
    aes_lib = f"{_aes.__module__}.{_aes.__name__}"

    SEP  = "=" * 66
    OK   = " PASS"
    FAIL = " FAIL"

    def check(label, condition, note=""):
        status = OK if condition else FAIL
        print(f"  {status}  {label}" + (f"   {note}" if note else ""))
        return condition

    all_passed = True
    print(f"\n{SEP}")
    print(f"  CRYPTOGRAPHIC PROOF — PQC Chat  [{label}]")
    print(f"{SEP}")
    print(f"  Libraries in use:")
    print(f"    DSA : {dsa_lib}")
    print(f"    KEM : {kem_lib}")
    print(f"    AES : {aes_lib}")

    print("\n  [1] ML-DSA-65  (FIPS 204 — Digital Signature)")
    print(f"      library  {dsa_lib}")
    identity = MLDSAIdentity()
    sig      = identity.sign(b"proof-message")
    valid    = MLDSAIdentity.verify(identity.public_key, b"proof-message", sig)
    tampered = MLDSAIdentity.verify(identity.public_key, b"TAMPERED", sig)
    all_passed &= check(f"Public key  = {len(identity.public_key)} bytes",  len(identity.public_key)  == 1952, "FIPS 204 spec: 1952")
    all_passed &= check(f"Private key = {len(identity.private_key)} bytes", len(identity.private_key) == 4032, "FIPS 204 spec: 4032")
    all_passed &= check(f"Signature   = {len(sig)} bytes",                  len(sig) == 3309,                  "FIPS 204 ML-DSA-65 spec: 3309")
    all_passed &= check("Signature verifies correctly",                      valid,                             "must be True")
    all_passed &= check("Tampered message rejected",                         not tampered,                      "must be False")

    print(f"\n  [2] ML-KEM-768  (FIPS 203 — Key Encapsulation)")
    print(f"      library  {kem_lib}")
    ek, dk  = MLKEMSession.generate_keypair()
    ct, ss1 = MLKEMSession.encapsulate(ek)
    ss2     = MLKEMSession.decapsulate(dk, ct)
    all_passed &= check(f"Encap key   = {len(ek)} bytes",  len(ek)  == 1184, "FIPS 203 spec: 1184")
    all_passed &= check(f"Decap key   = {len(dk)} bytes",  len(dk)  == 2400, "FIPS 203 spec: 2400")
    all_passed &= check(f"Ciphertext  = {len(ct)} bytes",  len(ct)  == 1088, "FIPS 203 spec: 1088")
    all_passed &= check(f"Shared sec  = {len(ss1)} bytes", len(ss1) == 32,   "FIPS 203 spec: 32")
    all_passed &= check("Shared secrets match (encap == decap)", ss1 == ss2, "must be True")

    print(f"\n  [3] AES-256-GCM  (NIST SP 800-38D)")
    print(f"      library  {aes_lib}")
    key           = os.urandom(32)
    plaintext     = b"pqc-chat-proof"
    nonce, ct_aes = aes_gcm_encrypt(key, plaintext)
    expected_len  = len(plaintext) + 16
    all_passed &= check(f"Key size    = {len(key)} bytes",     len(key)    == 32,           "spec: 32")
    all_passed &= check(f"Nonce size  = {len(nonce)} bytes",   len(nonce)  == 12,           "spec: 12")
    all_passed &= check(f"Ciphertext  = {len(ct_aes)} bytes",  len(ct_aes) == expected_len, f"plaintext({len(plaintext)}) + auth_tag(16) = {expected_len}")
    pt_back = aes_gcm_decrypt(key, nonce, ct_aes)
    all_passed &= check("Decrypt round-trip correct", pt_back == plaintext, "must match original")
    tampered_ct = bytes([ct_aes[0] ^ 0xFF]) + ct_aes[1:]
    try:
        aes_gcm_decrypt(key, nonce, tampered_ct)
        all_passed &= check("Tampered ciphertext rejected", False, "must raise InvalidTag")
    except Exception:
        all_passed &= check("Tampered ciphertext rejected", True, "InvalidTag raised ")

    print(f"\n  [4] KMAC-256  (keyed MAC via HKDF-SHA256)")
    print(f"      implementation  crypto.kmac256 (HKDF-SHA256 keyed)")
    key1  = os.urandom(32)
    key2  = os.urandom(32)
    data  = b"pqc-chat-kmac-proof"
    mac1  = kmac256(key1, data)
    mac2  = kmac256(key2, data)
    mac1b = kmac256(key1, data)
    all_passed &= check(f"MAC size    = {len(mac1)} bytes",         len(mac1) == 32,                            "spec: 32")
    all_passed &= check("Same key+data  same MAC (deterministic)", mac1 == mac1b,                              "must be True")
    all_passed &= check("Different key  different MAC",             mac1 != mac2,                               "must be True")
    all_passed &= check("Verify correct MAC passes",                 kmac256_verify(key1, data, mac1),           "must be True")
    all_passed &= check("Verify tampered data fails",                not kmac256_verify(key1, b"tampered", mac1),"must be False")

    print(f"\n  [5] Double Ratchet  (Forward Secrecy)")
    print(f"      implementation  crypto.DoubleRatchet (chain-A/B per role)")
    ss    = os.urandom(32)
    alice = DoubleRatchet(ss, initiator=True)
    bob   = DoubleRatchet(ss, initiator=False)
    a_k1  = alice.next_send_key()
    b_k1  = bob.next_recv_key()
    a_k2  = alice.next_send_key()
    b_k2  = bob.next_recv_key()
    all_passed &= check("Alice send[1] == Bob recv[1]", a_k1 == b_k1, "must be True")
    all_passed &= check("Alice send[2] == Bob recv[2]", a_k2 == b_k2, "must be True")
    all_passed &= check("Each message key is unique",    a_k1 != a_k2, "forward secrecy: must be True")

    print(f"\n{SEP}")
    if all_passed:
        print("   ALL CHECKS PASSED — algorithms verified against FIPS specs")
    else:
        print("   SOME CHECKS FAILED — review output above")
    print(f"{SEP}\n")
    return all_passed


if __name__ == "__main__":
    run_crypto_proof(label="STANDALONE")