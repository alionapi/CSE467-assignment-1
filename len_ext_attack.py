#!/usr/bin/env python3
"""
Part 2: Hash Length Extension Attack
The server computes:
    token = MD5(password || "user=...&command1=...&command2=...")
Using length extension, we can compute the hash of:
    password || original_query || MD5_padding || "&command3=UnlockAllSafes"
without knowing the password, because MD5 is a Merkle-Damgard construction.
Steps:
  1. Parse the URL to get the current token and the query string after 'token='.
  2. Compute the padding that MD5 appended internally to the original message
     (password [8 bytes] + query string).
  3. Initialize a new MD5 object with:
       state  = the original token (resuming where that hash left off)
       count  = (password_len + len(query) + len(padding)) * 8  (bits processed)
  4. Feed "&command3=UnlockAllSafes" to this MD5 object -> new token.
  5. Build the new URL whose query string embeds the padding bytes
     (URL-percent-encoded) so the server sees the same extended message.
"""
import sys
from urllib.parse import quote, urlparse
from pymd5 import md5, padding
PASSWORD_LEN = 8
def length_extension_attack(url: str) -> str:
    parsed = urlparse(url)
    query = parsed.query
    token_prefix = "token="
    token_end = query.index("&", query.index(token_prefix))
    token = query[len(token_prefix):token_end]
    original_query = query[token_end + 1:]  # everything after "token=...&"
    original_query_bytes = original_query.encode("utf-8")
    original_msg_len = PASSWORD_LEN + len(original_query_bytes)
    pad = padding(original_msg_len * 8)
    count_after_pad = (original_msg_len + len(pad)) * 8
    suffix = b"&command3=UnlockAllSafes"
    h = md5(state=bytes.fromhex(token), count=count_after_pad)
    h.update(suffix)
    new_token = h.hexdigest()
    new_query_body = original_query_bytes + pad + suffix
    encoded_query_body = quote(new_query_body, safe="=&")
    new_url = (
        f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        f"?token={new_token}&{encoded_query_body}"
    )
    return new_url
if __name__ == "__main__":
    url = sys.argv[1]
    print(length_extension_attack(url))
