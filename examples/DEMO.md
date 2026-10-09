# Worked example: requests 2.27.0 against GHSA-j8r2-6x86-q33q

The advisory is a real OSV record for the PyPI package `requests` (Proxy-Authorization header leak, fixed in 2.31.0):

```
https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q
```

## 1. Make a manifest you control

Create a tiny public GitHub repo (or a file in an existing one) containing `requirements.txt`:

```
requests==2.27.0
```

Commit it, then copy the **commit-pinned raw URL** (replace the placeholders):

```
https://raw.githubusercontent.com/<user>/<repo>/<40-char-commit>/requirements.txt
```

Always use the commit hash, never `main`, so the bytes cannot change.

## 2. Get the two SHA-256 commitments

```
python scripts/hash_url.py https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q
python scripts/hash_url.py https://raw.githubusercontent.com/<user>/<repo>/<commit>/requirements.txt
```

(No local Python? Run the same two commands in a free Google Colab cell with `!python`, or paste the script into a Colab cell.)

## 3. Call the contract (in this order)

| Step | Method | Arguments |
|---|---|---|
| 1 | `create_pool` | `demo-pypi`, `PyPI`, `api.osv.dev`, `raw.githubusercontent.com` |
| 2 | `enqueue_check` | `demo-pypi`, advisory URL, advisory sha256, manifest URL, manifest sha256, `requests`, a Unix time 2 hours from now |
| 3 | `get_job` | `demo-pypi`, the job id returned |
| 4 | `lease_next` | `demo-pypi`, `300` |
| 5 | `acknowledge` | `demo-pypi`, job id, fence from `get_job` |

Expected: step 3 shows `state: QUEUED`, `verdict: AFFECTED`, `priority` from the advisory's own severity, `report.method: osv`.

## 4. Show both other outcomes (good for LIVE_PROOFS.md)

- Change the manifest to `requests==2.31.0`, commit, hash, enqueue: expect `CLEARED` (NOT_AFFECTED).
- Change it to `requests>=2.0`: expect `BLOCKED` (`package_not_pinned`).
- Submit a wrong advisory hash: expect `BLOCKED` (`advisory_hash_mismatch`).

Each one needs a new commit hash (a new manifest URL) because the same evidence triple cannot be assessed twice in a pool.
