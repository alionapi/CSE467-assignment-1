#!/usr/bin/env python3
"""
Part 1: Many-Time Pad Attack
Approach:
  Step 1 – Statistical key recovery.
      XOR every pair of ciphertexts at each position.  When the result is a
      letter (A-Z or a-z), one of the two plaintexts likely has a space at
      that position (space XOR letter = same letter with bit-5 flipped).
      Both XOR-with-space candidates get a vote; the highest-voted byte
      becomes the key guess for that position.

  Step 2 – Known-plaintext refinement.
      The stat pass sometimes picks the wrong byte when votes are tied.
      Applying our recovered/inferred plaintexts fixes those positions exactly.
      Longer/higher-confidence lines are applied last so they override.

  Step 3 – Output.
      Decrypt each ciphertext with the final key and print.  Unrecoverable
      positions (e.g. the tail of line 5, which is the only line that long)
      are shown as '?'.

Note: the assignment states recovering the "entire last line" is the minimum.
The last line decrypts to:
    the answer is: enjoy learning about security in unist cse 467
"""

import sys
VALID = set(b'abcdefghijklmnopqrstuvwxyz :0123456789\n')
def read_ciphertexts(path: str) -> list:
    with open(path) as f:
        return [bytes.fromhex(line.strip()) for line in f if line.strip()]

def statistical_key_guess(cts: list, max_len: int) -> bytearray:
    """Vote-based key recovery exploiting space XOR letter = letter."""
    key = bytearray(max_len)
    for pos in range(max_len):
        votes = {}
        for i in range(len(cts)):
            if pos >= len(cts[i]):
                continue
            for j in range(i + 1, len(cts)):
                if pos >= len(cts[j]):
                    continue
                xored = cts[i][pos] ^ cts[j][pos]
                # XOR is a letter -> one of the two bytes is likely a space
                if chr(xored | 0x20) in 'abcdefghijklmnopqrstuvwxyz':
                    k1 = cts[i][pos] ^ 0x20
                    k2 = cts[j][pos] ^ 0x20
                    votes[k1] = votes.get(k1, 0) + 1
                    votes[k2] = votes.get(k2, 0) + 1
        if votes:
            key[pos] = max(votes, key=lambda k: votes[k])
    return key
def fix_zero_vote_positions(key: bytearray, cts: list) -> None:
    """Brute-force positions with no stat votes if only one valid key exists."""
    for pos in range(len(key)):
        if key[pos] != 0:
            continue
        candidates = [
            k for k in range(256)
            if all(ct[pos] ^ k in VALID for ct in cts if pos < len(ct))
        ]
        if len(candidates) == 1:
            key[pos] = candidates[0]
def apply_known_plaintexts(key: bytearray, cts: list, known: dict) -> None:
    """Fix key bytes using confirmed plaintext; call with lower-priority first."""
    for idx, plain in known.items():
        ct = cts[idx]
        for i in range(min(len(plain), len(ct))):
            if plain[i] in VALID:
                key[i] = ct[i] ^ plain[i]
def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "ctxt.txt"
    cts = read_ciphertexts(path)
    max_len = max(len(c) for c in cts)
    key = statistical_key_guess(cts, max_len)
    fix_zero_vote_positions(key, cts)
    known = {
        10: b"the answer is: enjoy learning about security in unist cse 467",
        9:  (b"patch your systems regularly to reduce vulnerabilities because"
             b" outdated software gives attackers more opportunities to gain"
             b" unauthorized access"),
        8:  (b"the security through obscurity is not a reliable defense because"
             b" hidden designs eventually become known and exposed weaknesses"
             b" can be abused"),
        7:  (b"always validate and sanitize input carefully to prevent injection"
             b" attacks that can corrupt data leak secrets or compromise"
             b" applications"),
        6:  (b" the defense in depth is a fundamental security strategy because"
             b" multiple layers of protection reduce the chance of total system"
             b" compromise"),
        5:  (b"an attacker often exploit incorrect assumptions about security"
             b" weak configurations and implementation flaws rather than"
             b" breaking the underlying mathematics"),
        4:  (b"an encryption protects sensitive data from unauthorized access"
             b" but secure key management is equally critical in every"
             b" practical system"),
        3:  (b"a strong password should be long random and unique so that"
             b" attackers cannot easily guess reuse or crack them with"
             b" automated tools"),
        2:  (b"never reuse a one time pad key in cryptography because key"
             b" reuse immediately destroys the perfect secrecy of the cipher"),
        1:  (b"the security message is often weakened by the human factor"
             b" because even strong systems can fail when users make simple"
             b" mistakes"),
        0:  (b"the security message is not a product but a continuous process"
             b" that requires constant attention careful planning and regular"
             b" improvement"),
    }
    apply_known_plaintexts(key, cts, known)
    for ct in cts:
        decoded = bytes([ct[i] ^ key[i] for i in range(len(ct))])
        line = "".join(chr(b) if b in VALID else "?" for b in decoded)
        print(line.rstrip("\n"))
if __name__ == "__main__":
    main()
