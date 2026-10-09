# Threat model

| Threat | Mitigation |
|---|---|
| Caller claims an advisory is critical or that a package is unaffected | No caller-supplied verdict, severity or priority exists. All of it is derived from fetched evidence. |
| Prompt injection inside the advisory text | The model output is never trusted. It must be one small JSON object whose quote occurs verbatim in the advisory and contains the versions. The verdict is computed by code. A model cannot return a verdict field that is used. |
| Fabricated quote or invented fix version | Substring check against the fetched text and version-in-quote check. Failure gives UNKNOWN, which is never cleared. |
| Advisory or manifest changes between submission and validation | SHA-256 commitments over the full body. A mismatch is BLOCKED. |
| Pointing the pool at an attacker's host | Hosts are fixed at pool creation and compared exactly. |
| Oversized or binary evidence | 96 KiB cap, strict UTF-8, JSON or text only. |
| Ambiguous manifests (two different pins) | UNKNOWN. |
| Unsupported version syntax | UNKNOWN. The contract never guesses an ordering. |
| Resampling to get a different answer | Dedupe of the evidence triple per pool. |
| Stale worker closing a newer lease | Monotonic fence token, authenticated holder and unexpired lease are all required. |
| Starvation of low-priority work | NORMAL jobs age into the urgent tier after 600 seconds. |
| Owner revoking someone's live job | `set_worker` never touches live leases. |
| Unbounded scans | 64 jobs per pool. |
| Rolled-back expiry cleanup | `lease_next` returns an empty string when idle so the sweep commits. |

Out of scope: runtime reachability of vulnerable code paths, trust in the advisory publisher, completion of the actual upgrade.
