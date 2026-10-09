# AdvisoryReachGate

A reusable GenLayer dispatch queue whose admission and priority come from independently fetched evidence, a security advisory plus a pinned dependency manifest, and never from a caller-assigned severity.

## Problem and why GenLayer

A normal patch queue schedules whatever urgency its submitter types in. "Is this advisory about the version we actually pin?" is usually answered by a person reading prose, or by a script that trusts one source. AdvisoryReachGate makes that question a consensus-controlled admission boundary, then offers ordinary bounded scheduling with robust worker leases.

```
advisory URL + sha256     manifest URL + sha256     package     review_by
          \                       |                    |
           +----- leader and every validator fetch both bodies themselves -----+
                                  |
        status / size / sha256 / UTF-8 checks; exact pinned version read from manifest
                                  |
     structured advisory (OSV JSON)?  --yes-->  plain-code range evaluation
                  |no
                  v
     model extracts ONE range + verbatim quote; contract rejects it unless the quote
     occurs in the advisory and contains every version the model named
                                  |
              verdict computed by code: AFFECTED / NOT_AFFECTED / UNKNOWN
                                  |
                 exact complete-report comparison (strict_eq)
                                  |
       QUEUED (URGENT / NORMAL)  |  CLEARED  |  BLOCKED
                                  |
      priority + FIFO + anti-starvation aging -> authenticated worker
                  -> expiring fenced lease -> ACK
```

## What is different from a thin LLM wrapper

- The model never decides the verdict. Code does. The model can only quote a range the advisory itself states.
- For structured advisories (OSV JSON) the model is not called at all.
- Unsupported version formats (pre-releases, epochs, wildcards) become UNKNOWN. The contract never guesses an ordering, and UNKNOWN is never cleared.
- The whole report must match across validators. There is no confidence tolerance on the admission boundary.

## States

```
Assessment -> BLOCKED (terminal)      evidence failed or verdict UNKNOWN
           -> CLEARED (terminal)      NOT_AFFECTED
           -> QUEUED -> LEASED -> ACKNOWLEDGED (terminal)
                  ^        |
                  |        +-> holder releases
                  |        +-> anyone recovers an expired lease
                  +--------+
QUEUED or LEASED -> review deadline -> EXPIRED (terminal)
```

Priority comes from the advisory's own `database_specific.severity`: CRITICAL or HIGH is URGENT, everything else is NORMAL. A NORMAL job that has waited 600 seconds is treated as urgent. Release and recovery renew the FIFO position. Every new lease increments a fencing token. Acknowledge needs the exact current fence, the authenticated holder and an unexpired lease.

ACK means a worker received the item. It does **not** prove that the dependency was upgraded. No funds, escrow or external calls exist.

## API

| Method | Who | What it does |
|---|---|---|
| `create_pool(pool_id, ecosystem, advisory_host, manifest_host)` | anyone | Fixes ecosystem (`PyPI` or `npm`) and the two allowed hosts. Caller becomes owner and member. |
| `set_worker(pool_id, address, enabled)` | owner | Manages members. Does not revoke live leases. |
| `enqueue_check(pool_id, advisory_url, advisory_sha256, manifest_url, manifest_sha256, package, review_by)` | member | Independently assesses the evidence and records a job. Returns the job id. |
| `lease_next(pool_id, lease_seconds)` | member | Leases the best ready job (2 to 3600 s, capped by the job deadline). Returns `""` if none. |
| `release(pool_id, job_id, fence)` | holder | Returns the job to the queue. |
| `recover(pool_id, job_id)` | anyone | Recovers an expired lease or expires an overdue job. |
| `acknowledge(pool_id, job_id, fence)` | holder | Records receipt. |
| `get_pool`, `get_job`, `event_count`, `get_event` | view | Auditable state. |

Limits: bodies up to 96 KiB, 64 jobs per pool, review deadline 30 seconds to 7 days, https URLs on the pool's exact hosts only (no port, query, fragment or credentials).

Manifests: PyPI reads `name==x.y.z` lines from a `requirements.txt`. npm reads `packages["node_modules/<name>"].version` from a `package-lock.json`. A range such as `>=2.0` is not a pin and gives UNKNOWN.

## Repository layout

```
contracts/AdvisoryReachGate.py   the Intelligent Contract
docs/                            architecture, consensus design, threat model
scripts/hash_url.py              prints the sha256 commitment for a URL body
scripts/check_contract.py        static header / structure checks
tests/unit/                      version, range, manifest and model-grounding logic
tests/direct/                    lifecycle tests against a fake runtime
examples/DEMO.md                 a worked example
LIVE_PROOFS.md                   Studio Next receipts (fill in after real runs)
SUBMISSION.md                    title, short description, evidence links
```

## Validate

```
python -m pip install -r requirements-dev.txt
python scripts/check_contract.py
python -m unittest discover -s tests/unit -v
python -m unittest discover -s tests/direct -v
```

The tests mock web, model and clock calls, and use a small fake GenLayer runtime (`tests/fake_genlayer.py`). They do **not** simulate validator agreement. Real consensus evidence belongs in `LIVE_PROOFS.md`.

## Deploy on Studio Next

- Network: Studio Next, RPC `https://studio-next.genlayer.com/api`, chain ID `61997`
- Explorer: https://explorer-studio-dev.genlayer.com/
- Migration notes: https://docs.genlayer.com/developers/consensus-v06-migration#test-on-studio-dev-first

Deploy `contracts/AdvisoryReachGate.py` with no constructor arguments, then follow `examples/DEMO.md`.

## Known assumptions to confirm on the live network

The contract relies on `gl.nondet.web.get(url)` returning `.status` and raw `.body`, on `gl.message_raw["datetime"]` for the transaction time, and on `hashlib` and `urllib.parse` being available in GenVM. These are the three places to check first if a call fails after deploy. See `LIVE_PROOFS.md`.

This is an experimental test-network release and has not been independently audited.
