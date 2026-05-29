#!/usr/bin/env python3
"""
Part 3: Bleichenbacher RSA Signature Forgery (PKCS#1 v1.5, e=3)
Background:
  PKCS#1 v1.5 signed messages look like:
    00 01 FF...FF 00 [ASN.1 algorithm ID] [hash digest]
  A vulnerable verifier strips 00 01, skips FF bytes (without checking the count),
  then locates the 00 separator, parses ASN.1, and checks the hash.
  It does NOT verify that the hash sits at the least-significant (rightmost) bytes.
Attack (Bleichenbacher 2006, e=3):
  Since e=3 is small, we can forge a valid-looking value M by:
    1. Building M = 00 01 FF 00 [ASN.1+hash] 00...00
       (only one FF byte - enough to fool the vulnerable checker)
    2. Computing sig = ceil(M^(1/3)) over the integers
    3. Because M has a leading 00 byte it is smaller than n^(1/3), so sig^3 < n
       and sig^3 mod n == sig^3 (no modular reduction), which preserves our prefix.
    4. sig^3's most-significant bytes match M's prefix exactly.
  The vulnerable verifier then accepts this forged sig as valid.
"""
import sys
import hashlib
import base64
from roots import integer_nthroot
# 2048-bit RSA public key parameters (extracted from the Bank of CSE 467 key)
N = (
    24919640398883222925553383171066647325514229082888406119098919655467304590583977679444115440533220482004105526196100086472932359407779860868734795049192350138322342610380662184696996917181782396348321182939478286904637482877861609595150358453172464732216310338078180377274085554137922331664976494310115425998544579788896789331509511693993062332517564715485689444620831433856100909503677414563846809057164587307619781464919335135289601704053559971755099126871562316313550924016609234178977196414480825102767293422901443940398981001922677050715022771553038056591962048988781124774484687340017740924003380442129607967813
)
E = 3
N_BYTES = (N.bit_length() + 7) // 8  
# DER/ASN.1 prefix identifying SHA-1 in PKCS#1 v1.5
ASN1_SHA1 = bytes.fromhex("3021300906052B0E03021A05000414")
def forge_signature(message: str) -> str:
    """
    Return a base64-encoded forged RSA signature that a vulnerable verifier
    (one that does not check FF count or hash position) will accept.
    """
    digest = hashlib.sha1(message.encode()).digest() 
    hash_block = ASN1_SHA1 + digest  
    prefix = b"\x00\x01\xff\x00"
    padding_zeros = b"\x00" * (N_BYTES - len(prefix) - len(hash_block))
    M_bytes = prefix + hash_block + padding_zeros
    M_int = int.from_bytes(M_bytes, "big")
    sig_int, exact = integer_nthroot(M_int, 3)
    if not exact:
        sig_int += 1  
    sig_bytes = sig_int.to_bytes(N_BYTES, "big")
    return base64.b64encode(sig_bytes).decode()
if __name__ == "__main__":
    message = sys.argv[1]
    print(forge_signature(message))
