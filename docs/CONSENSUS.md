# Consensus design

## What every validator re-derives

`enqueue_check` runs one function inside `gl.eq_principle.strict_eq`. That function:

1. fetches the advisory and the manifest (status and raw bytes),
2. checks status 200, size limits, SHA-256 against the caller's commitments and UTF-8,
3. reads the exact pinned version from the manifest,
4. reads affected ranges from the advisory (OSV JSON) or, for prose, asks the model for one range plus a quote,
5. computes the verdict in code,
6. returns the whole report as canonical JSON.

The leader's string must equal every validator's string. The report includes hashes, the pinned version, the intervals used, the method (`osv` or `llm`), the advisory severity, the verdict and a reason code. If validators disagree, the transaction fails. The contract does not store a made-up "conflict" job.

## Why exact match is realistic

- Most of the report is deterministic code over fetched bytes.
- The only model output is one small object (`introduced`, `fixed` or `last_affected`, `quote`).
- That object is checked in code: the quote must be a verbatim substring of the advisory text (whitespace-collapsed), 8 to 300 characters, and must contain every version string the model returned. Only plain dotted numeric versions are accepted and exactly one of `fixed` / `last_affected` must be present.
- A model answer that fails any check yields UNKNOWN with a reason code. Two validators that both fail the same way agree, and the job is BLOCKED.

## Why not `prompt_comparative`

A comparative principle asks a model whether two answers are "close enough". Here the boundary decides whether work is queued, so the contract uses exact comparison of a small, code-validated report instead.

## Evidence rules

- Hosts are fixed per pool and compared exactly. https only, no port, query, fragment or credentials.
- The caller commits to the hash of the full response body. A moved or edited document fails the hash check and becomes BLOCKED, so a later fetch cannot silently change the result.
- The same (advisory hash, manifest hash, package) triple cannot be assessed twice in one pool, so a result cannot be re-sampled.

## Known limits

Shared model mistakes remain possible on the prose path. Advisory sources can themselves be wrong or incomplete. Only simple numeric versions are supported. Static range checking is not runtime reachability analysis.
