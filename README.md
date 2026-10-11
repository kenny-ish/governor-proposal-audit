# governor-proposal-audit

`governor-proposal-audit` checks Governor proposal state, snapshot, voting deadline, and remaining blocks through contract calls, with a fallback for Compound Governor Bravo's `proposals(uint256)` record. It uses only the RPC endpoint supplied by the user.

## Example

Against Ethereum mainnet at block 26166114:

```text
Governor 0xc0da02939e1441f497fd74f78ce7decb17b66529 current block 26166114
Chain time: 2026-10-11 02:07:11 UTC
proposal 392: Executed snapshot=21738210 deadline=21757920 (closed, 0 blocks remaining) eta=2025-02-04 09:27:35 UTC
proposal 393: Executed snapshot=21738537 deadline=21758247 (closed, 0 blocks remaining) eta=2025-02-04 10:33:35 UTC
```

## Usage

```text
python governor_proposal_audit.py --rpc RPC_URL --governor ADDRESS --proposal-id ID [--proposal-id ID ...] [--json]
```

Proposal IDs may be repeated to inspect a batch. The tool reads the current block, calls `state(uint256)`, and first tries OpenZeppelin Governor's `proposalSnapshot` and `proposalDeadline`. If those methods are absent, it decodes Compound Governor Bravo's fixed `proposals(uint256)` return value.

## How it works

State code 0 through 7 is rendered as the standard Governor names from Pending to Executed. Deadlines are block numbers, so the reported remaining window is calculated against the current block returned by the same RPC. For Compound Governor Bravo, the queue ETA is also shown when it is nonzero. No transaction is sent.

## Tests

```text
python -m unittest -v
```
