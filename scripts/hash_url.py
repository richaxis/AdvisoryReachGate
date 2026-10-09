#!/usr/bin/env python3
"""
Print the SHA-256 and size of the FULL response body of a URL.

enqueue_check needs these commitments. The contract hashes the raw response
bytes, so this script hashes raw bytes too (no decoding, no newline changes).

    python scripts/hash_url.py https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q
"""
import hashlib
import sys
import urllib.request


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    url = sys.argv[1]
    req = urllib.request.Request(url, headers={"User-Agent": "advisory-reach-gate-hash"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read()
        print("status :", resp.status)
    print("bytes  :", len(body))
    print("sha256 :", hashlib.sha256(body).hexdigest())
    if len(body) > 96 * 1024:
        print("WARNING: body is over 96 KiB; the contract will BLOCK this input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
