import unittest

import governor_proposal_audit as tool


CURRENT_BLOCK = 26166114
CURRENT_TIMESTAMP = 1791684431
REAL_PROPOSALS = {
    392: {"eta": 1738661255, "snapshot": 21738210, "deadline": 21757920},
    393: {"eta": 1738665215, "snapshot": 21738537, "deadline": 21758247},
}


def bravo_return(proposal_id, eta, snapshot, deadline):
    words = [
        proposal_id,
        int("0x" + "11" * 20, 16),
        eta,
        snapshot,
        deadline,
        0,
        0,
        0,
        0,
        1,
    ]
    return "0x" + b"".join(value.to_bytes(32, "big") for value in words).hex()


class FakeRpc:
    def __init__(self):
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_blockNumber":
            return hex(CURRENT_BLOCK)
        if method == "eth_getBlockByNumber":
            return {"timestamp": hex(CURRENT_TIMESTAMP)}
        if method == "eth_call":
            data = params[0]["data"]
            selector = data[2:10]
            proposal_id = int(data[10:], 16) if len(data) > 10 else None
            if selector == tool.STATE_SELECTOR.hex():
                return "0x" + (7).to_bytes(32, "big").hex()
            if selector in {tool.SNAPSHOT_SELECTOR.hex(), tool.DEADLINE_SELECTOR.hex()}:
                raise tool.JsonRpcError("execution reverted: method is absent")
            if selector == tool.BRAVO_PROPOSAL_SELECTOR.hex():
                row = REAL_PROPOSALS[proposal_id]
                return bravo_return(proposal_id, row["eta"], row["snapshot"], row["deadline"])
        raise AssertionError((method, params))


class GovernorProposalAuditTests(unittest.TestCase):
    def test_keccak_empty_is_ethereum_keccak(self):
        self.assertEqual(
            tool.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_inspects_real_compound_governor_values_without_network(self):
        rpc = FakeRpc()
        result = tool.inspect_proposals(
            rpc,
            "0xc0da02939e1441f497fd74f78ce7decb17b66529",
            [392, 393],
        )
        first, second = result["proposals"]
        self.assertEqual(result["current_block"], CURRENT_BLOCK)
        self.assertEqual(first["state"], "Executed")
        self.assertEqual(first["snapshot_block"], 21738210)
        self.assertEqual(first["deadline_block"], 21757920)
        self.assertEqual(first["eta_utc"], "2025-02-04 09:27:35 UTC")
        self.assertEqual(second["deadline_block"], 21758247)
        self.assertEqual(second["eta_utc"], "2025-02-04 10:33:35 UTC")
        self.assertEqual(first["source"], "Compound Governor Bravo proposals")
        self.assertTrue(any(call[0] == "eth_call" for call in rpc.calls))

    def test_oz_snapshot_block_is_not_started(self):
        class StandardBoundaryRpc(FakeRpc):
            def call(self, method, params):
                if method == "eth_blockNumber":
                    return hex(100)
                if method == "eth_call":
                    selector = params[0]["data"][2:10]
                    if selector == tool.STATE_SELECTOR.hex():
                        return "0x" + (0).to_bytes(32, "big").hex()
                    if selector == tool.SNAPSHOT_SELECTOR.hex():
                        return "0x" + (100).to_bytes(32, "big").hex()
                    if selector == tool.DEADLINE_SELECTOR.hex():
                        return "0x" + (200).to_bytes(32, "big").hex()
                return super().call(method, params)

        row = tool.inspect_proposals(StandardBoundaryRpc(), "0x" + "22" * 20, [1])["proposals"][0]
        self.assertEqual(row["voting_window"], "not started")

    def test_bravo_start_block_is_not_started(self):
        class BravoBoundaryRpc(FakeRpc):
            def call(self, method, params):
                if method == "eth_blockNumber":
                    return hex(REAL_PROPOSALS[392]["snapshot"])
                return super().call(method, params)

        row = tool.inspect_proposals(
            BravoBoundaryRpc(),
            "0xc0da02939e1441f497fd74f78ce7decb17b66529",
            [392],
        )["proposals"][0]
        self.assertEqual(row["voting_window"], "not started")

    def test_standard_governor_methods_are_preferred(self):
        class StandardRpc(FakeRpc):
            def call(self, method, params):
                if method == "eth_call":
                    selector = params[0]["data"][2:10]
                    if selector == tool.STATE_SELECTOR.hex():
                        return "0x" + (1).to_bytes(32, "big").hex()
                    if selector == tool.SNAPSHOT_SELECTOR.hex():
                        return "0x" + (100).to_bytes(32, "big").hex()
                    if selector == tool.DEADLINE_SELECTOR.hex():
                        return "0x" + (200).to_bytes(32, "big").hex()
                return super().call(method, params)

        row = tool.inspect_proposals(StandardRpc(), "0x" + "22" * 20, [1])["proposals"][0]
        self.assertEqual(row["state"], "Active")
        self.assertEqual(row["snapshot_block"], 100)
        self.assertEqual(row["deadline_block"], 200)
        self.assertEqual(row["source"], "Governor proposalSnapshot/proposalDeadline")


if __name__ == "__main__":
    unittest.main()
