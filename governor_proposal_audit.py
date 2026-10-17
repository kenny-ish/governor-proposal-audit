#!/usr/bin/env python3
"""Inspect Governor proposal state and voting deadlines using JSON-RPC only."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

MASK64 = (1 << 64) - 1


def _rot(value: int, shift: int) -> int:
    value &= MASK64
    if shift == 0:
        return value
    return ((value << shift) | (value >> (64 - shift))) & MASK64


def _lfsr_bit(t: int) -> int:
    value = 0x01
    for _ in range(t % 255):
        high = value & 0x80
        value = ((value << 1) & 0xFF) ^ (0x71 if high else 0)
    return value & 1


def _round_constants() -> List[int]:
    # Keccak's round constants are generated from the specified 8-bit LFSR.
    return [
        sum(_lfsr_bit(j + 7 * round_number) << ((1 << j) - 1) for j in range(7))
        for round_number in range(24)
    ]


def _rotation_offsets() -> List[List[int]]:
    result = [[0 for _ in range(5)] for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        result[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return result


ROUND_CONSTANTS = _round_constants()
ROTATION_OFFSETS = _rotation_offsets()


def _keccak_f(state: List[int]) -> None:
    for constant in ROUND_CONSTANTS:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for y in range(5):
            for x in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rot(state[x + 5 * y], ROTATION_OFFSETS[x][y])
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    """Keccak-256, not NIST SHA3-256."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)
    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8 : i * 8 + 8], "little")
        _keccak_f(state)
    output = bytearray()
    while len(output) < 32:
        for i in range(rate // 8):
            output.extend(state[i].to_bytes(8, "little"))
        if len(output) < 32:
            _keccak_f(state)
    return bytes(output[:32])


def function_selector(signature: str) -> bytes:
    return keccak256(signature.encode("ascii"))[:4]


STATE_SELECTOR = function_selector("state(uint256)")
SNAPSHOT_SELECTOR = function_selector("proposalSnapshot(uint256)")
DEADLINE_SELECTOR = function_selector("proposalDeadline(uint256)")
BRAVO_PROPOSAL_SELECTOR = function_selector("proposals(uint256)")

STATE_NAMES = {
    0: "Pending",
    1: "Active",
    2: "Canceled",
    3: "Defeated",
    4: "Succeeded",
    5: "Queued",
    6: "Expired",
    7: "Executed",
}


def _quantity(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"invalid JSON-RPC quantity: {value!r}")
    return int(value, 16)


def _hex(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError("expected a 0x-prefixed hex value")
    return bytes.fromhex(value[2:])


def _word(data: bytes, index: int) -> int:
    start = index * 32
    if start + 32 > len(data):
        raise ValueError("short ABI return data")
    return int.from_bytes(data[start : start + 32], "big")


def _call_data(selector: bytes, proposal_id: int) -> str:
    return "0x" + (selector + proposal_id.to_bytes(32, "big")).hex()


class JsonRpcError(RuntimeError):
    pass


class JsonRpcClient:
    def __init__(self, url: str, timeout: float = 30.0, opener: Any = urllib.request.urlopen) -> None:
        self.url = url
        self.timeout = timeout
        self.opener = opener
        self._next_id = 1

    def call(self, method: str, params: List[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "governor-proposal-audit/1.0"},
            method="POST",
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise JsonRpcError(f"RPC request failed: {exc}") from exc
        if payload.get("error") is not None:
            raise JsonRpcError(str(payload["error"]))
        return payload.get("result")


def _read_uint(client: JsonRpcClient, address: str, selector: bytes, proposal_id: int) -> int:
    value = client.call("eth_call", [{"to": address, "data": _call_data(selector, proposal_id)}, "latest"])
    return _word(_hex(value), 0)


def _read_bravo_proposal(client: JsonRpcClient, address: str, proposal_id: int) -> Dict[str, int]:
    raw = _hex(client.call("eth_call", [{"to": address, "data": _call_data(BRAVO_PROPOSAL_SELECTOR, proposal_id)}, "latest"]))
    if len(raw) < 10 * 32:
        raise JsonRpcError("proposals(uint256) did not return a Compound Governor Bravo record")
    return {"eta": _word(raw, 2), "snapshot": _word(raw, 3), "deadline": _word(raw, 4)}


def _utc(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def inspect_proposals(client: JsonRpcClient, governor: str, proposal_ids: List[int]) -> Dict[str, Any]:
    latest_block = _quantity(client.call("eth_blockNumber", []))
    block = client.call("eth_getBlockByNumber", [hex(latest_block), False])
    if not block:
        raise JsonRpcError(f"block {latest_block} was not returned")
    block_timestamp = _quantity(block["timestamp"])
    rows: List[Dict[str, Any]] = []
    for proposal_id in proposal_ids:
        if proposal_id < 0 or proposal_id >= 1 << 256:
            raise ValueError("proposal IDs must fit uint256")
        state_code = _read_uint(client, governor, STATE_SELECTOR, proposal_id)
        try:
            snapshot = _read_uint(client, governor, SNAPSHOT_SELECTOR, proposal_id)
            deadline = _read_uint(client, governor, DEADLINE_SELECTOR, proposal_id)
            source = "Governor proposalSnapshot/proposalDeadline"
            eta = None
        except JsonRpcError:
            bravo = _read_bravo_proposal(client, governor, proposal_id)
            snapshot, deadline, eta = bravo["snapshot"], bravo["deadline"], bravo["eta"]
            source = "Compound Governor Bravo proposals"
        row: Dict[str, Any] = {
            "proposal_id": str(proposal_id),
            "state_code": state_code,
            "state": STATE_NAMES.get(state_code, f"Unknown({state_code})"),
            "snapshot_block": snapshot,
            "deadline_block": deadline,
            "current_block": latest_block,
            "blocks_until_deadline": max(0, deadline - latest_block),
            "voting_window": "not started" if latest_block <= snapshot else ("open" if latest_block <= deadline else "closed"),
            "source": source,
        }
        if eta is not None:
            row["eta_seconds"] = eta
            row["eta_utc"] = _utc(eta) if eta else None
        rows.append(row)
    return {"governor": governor, "current_block": latest_block, "chain_time": _utc(block_timestamp), "proposals": rows}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Governor proposal states and voting deadlines from JSON-RPC.")
    parser.add_argument("--rpc", required=True, help="JSON-RPC URL")
    parser.add_argument("--governor", required=True, help="Governor contract address")
    parser.add_argument("--proposal-id", required=True, action="append", type=int, help="proposal ID, repeat for a batch")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit JSON")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    governor = args.governor.lower()
    if len(governor) != 42 or not governor.startswith("0x"):
        raise SystemExit("--governor must be a 20-byte 0x address")
    client = JsonRpcClient(args.rpc)
    try:
        result = inspect_proposals(client, governor, args.proposal_id)
    except (ValueError, JsonRpcError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    print(f"Governor {result['governor']} current block {result['current_block']}")
    print(f"Chain time: {result['chain_time']}")
    for row in result["proposals"]:
        eta = f" eta={row['eta_utc']}" if "eta_utc" in row else ""
        print(f"proposal {row['proposal_id']}: {row['state']} snapshot={row['snapshot_block']} deadline={row['deadline_block']} ({row['voting_window']}, {row['blocks_until_deadline']} blocks remaining){eta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
