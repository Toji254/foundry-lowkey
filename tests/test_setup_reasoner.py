import unittest
from unittest.mock import Mock

from lowkey.setup_reasoner import rank_setup_candidates


class SetupReasonerTests(unittest.TestCase):
    def setUp(self):
        self.candidates = [
            {
                "signature": "deposit(uint256)",
                "name": "deposit",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "assets", "type": "uint256"}],
            },
            {
                "signature": "stake(address,uint256)",
                "name": "stake",
                "stateMutability": "nonpayable",
                "inputs": [
                    {"name": "token", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                ],
            },
        ]

    def test_disabled_automatic_assist_does_not_call_provider(self):
        provider = Mock()
        provider.status.return_value = {
            "enabled": True,
            "usable": True,
            "auto_assist": False,
            "jev_autonomous": False,
        }
        result = rank_setup_candidates(self.candidates, ai_module=provider)
        self.assertEqual(result["mode"], "deterministic")
        self.assertEqual(result["reason"], "automatic_assist_disabled")
        provider.request_structured.assert_not_called()

    def test_ai_can_only_rank_an_exact_abi_candidate(self):
        provider = Mock()
        provider.status.return_value = {
            "enabled": True,
            "usable": True,
            "auto_assist": True,
            "provider": "ollama",
            "model": "local-test",
        }
        provider.request_structured.return_value = {
            "selected_signature": "stake(address,uint256)",
            "rationale": "The candidate appears to establish a token-backed position.",
        }
        result = rank_setup_candidates(self.candidates, ai_module=provider)
        self.assertEqual(result["mode"], "ai_ranked_candidate")
        self.assertEqual(result["selected_signature"], "stake(address,uint256)")
        call = provider.request_structured.call_args.kwargs
        self.assertEqual(call["purpose"], "setup_reasoning")
        self.assertEqual(call["required_fields"], ("selected_signature", "rationale"))
        constraints = call["context"]["selection_constraints"]
        self.assertFalse(constraints["target_address_included"])
        self.assertFalse(constraints["rpc_url_included"])
        self.assertFalse(constraints["credentials_included"])
        self.assertNotIn("http://", repr(call["context"]).lower())
        self.assertNotIn("https://", repr(call["context"]).lower())

    def test_model_cannot_invent_a_function(self):
        provider = Mock()
        provider.status.return_value = {
            "enabled": True,
            "usable": True,
            "auto_assist": True,
        }
        provider.request_structured.return_value = {
            "selected_signature": "drainAll(address)",
            "rationale": "Invented function.",
        }
        result = rank_setup_candidates(self.candidates, ai_module=provider)
        self.assertEqual(result["mode"], "deterministic")
        self.assertIsNone(result["selected_signature"])
        self.assertEqual(result["reason"], "model_selection_not_in_candidate_set")

    def test_provider_failure_falls_back_without_blocking_native_setup(self):
        provider = Mock()
        provider.status.return_value = {
            "enabled": True,
            "usable": True,
            "auto_assist": True,
        }
        provider.request_structured.side_effect = TimeoutError("provider unavailable")
        result = rank_setup_candidates(self.candidates, ai_module=provider)
        self.assertEqual(result["mode"], "deterministic")
        self.assertEqual(result["reason"], "ai_assist_unavailable:TimeoutError")

    def test_single_candidate_never_spends_an_ai_request(self):
        provider = Mock()
        result = rank_setup_candidates(self.candidates[:1], ai_module=provider)
        self.assertEqual(result["reason"], "not_ambiguous")
        provider.status.assert_not_called()
        provider.request_structured.assert_not_called()


if __name__ == "__main__":
    unittest.main()
