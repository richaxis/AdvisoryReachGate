# Live proofs (Studio Next)

Status: **not yet filled in.** Deploy the contract, run the steps in `examples/DEMO.md`, and record the real values below. Do not copy hashes from anywhere else.

- Network: Studio Next, RPC `https://studio-next.genlayer.com/api`, chain ID `61997`
- Explorer: https://explorer-studio-dev.genlayer.com/
- Contract address: _TODO_
- Deployment transaction: _TODO_

| Scenario | Method | Transaction hash | Receipt status (leader / consensus) | Result in `get_job` |
|---|---|---|---|---|
| Affected pin queued | `enqueue_check` | _TODO_ | _TODO_ | QUEUED / AFFECTED |
| Fixed pin cleared | `enqueue_check` | _TODO_ | _TODO_ | CLEARED |
| Unpinned manifest blocked | `enqueue_check` | _TODO_ | _TODO_ | BLOCKED |
| Wrong hash blocked | `enqueue_check` | _TODO_ | _TODO_ | BLOCKED |
| Lease | `lease_next` | _TODO_ | _TODO_ | LEASED, fence 1 |
| Stale ack rejected | `acknowledge` | _TODO_ | expected ERROR | unchanged |
| Acknowledge | `acknowledge` | _TODO_ | _TODO_ | ACKNOWLEDGED |

Label expected rejections as ERROR. They are not successful acknowledgments.
