# Submission

**Category:** Intelligent Contracts

**Title:** AdvisoryReachGate: evidence-grounded advisory admission and fenced patch queue

**Description:**

AdvisoryReachGate decides whether a security advisory really applies to the exact dependency version you pin, then feeds a patch queue. A caller submits only two URLs with SHA-256 commitments and a package name. The leader and every validator fetch both documents themselves, read the exact pinned version from the manifest, and work out whether it falls inside the advisory's affected range. Structured OSV advisories are evaluated by plain code. For prose advisories the model must return one range plus a verbatim quote, and the contract rejects it unless the quote exists in the advisory and contains every version named. Code, never the model, computes the verdict. The whole report must match exactly across validators. AFFECTED items enter a priority queue (priority comes from the advisory's severity) with FIFO, aging, expiring leases and fencing tokens. Unsupported versions become UNKNOWN, never cleared. Reusable by any team that tracks dependency risk.

**Repository:** _add your GitHub link_

**Deployed on Studio Next:** _add contract address and explorer link_

**Evidence:** `README.md`, `docs/CONSENSUS.md`, `docs/THREAT_MODEL.md`, `tests/`, `LIVE_PROOFS.md`
