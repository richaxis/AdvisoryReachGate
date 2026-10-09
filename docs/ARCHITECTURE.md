# Architecture

## State

| Field | Type | Meaning |
|---|---|---|
| `pools` | `TreeMap[str, str]` | JSON per pool: owner, ecosystem, allowed hosts, members, live leases per worker, job ids, dedupe hashes |
| `jobs` | `TreeMap[str, str]` | JSON per job: evidence URLs, canonical report, verdict, state, priority, times, fence, holder |
| `events` | `TreeMap[str, str]` | Append-only log (`POOL_CREATED`, `ADMITTED_*`, `LEASED`, `RELEASED`, `RECOVERED`, `EXPIRED`, `ACKNOWLEDGED`, `WORKER_SET`) |
| `next_job_id`, `event_total` | `u256` | Counters |

Records are stored as canonical JSON strings (`sort_keys=True`) so every node serializes identically and the state layout stays easy to read.

## Why the pure helpers live in the same file

GenVM loads one contract file. Version parsing, range evaluation, manifest parsing and model-answer validation are plain module-level functions with no `gl` calls, so the tests import them directly and the reviewer can read the whole decision path in one place.

## Job lifecycle

1. `enqueue_check` runs the consensus block and stores the immutable report. It never stores an LLM answer that failed grounding.
2. The verdict maps to a state: AFFECTED to QUEUED, NOT_AFFECTED to CLEARED, UNKNOWN to BLOCKED.
3. Every write method that touches a pool first applies deadlines and lease expiry (`_sweep`), so time-based transitions commit with the next transaction. `lease_next` returns an empty string, instead of raising, when nothing is ready, so those transitions are not rolled back.
4. A lease stores the holder, a fence (incremented on every lease) and an expiry capped by the review deadline.

## Ordering

Effective tier is URGENT if the job priority is URGENT or it has waited at least 600 seconds. Within a tier the order is `queued_at`, then job id. `queued_at` resets on release and recovery.

## What is not here

No funds, no token approvals, no external execution adapters, no proof that a dependency was upgraded.
