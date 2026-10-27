import unittest

from lowkey import provider_adapters as adapters


class ProviderAdapterRegistryTests(unittest.TestCase):
    def test_builtin_providers_are_replaceable_transport_slots(self):
        for name in ("deepseek", "gemini", "ollama", "openai", "openai-compatible"):
            self.assertIsNotNone(adapters.get_provider_adapter(name))
        self.assertEqual(adapters.provider_adapter_status()["registered_providers"], [
            "deepseek", "gemini", "ollama", "openai", "openai-compatible"
        ])

    def test_custom_adapter_can_be_registered_without_changing_review_agent(self):
        class FixtureAdapter:
            name = "fixture"

            def send(self, **kwargs):
                return b"fixture"

        adapters.register_provider_adapter("unit-fixture", FixtureAdapter())
        self.assertEqual(adapters.get_provider_adapter("unit-fixture").send(), b"fixture")
        adapters._ADAPTERS.pop("unit-fixture", None)

    def test_duplicate_registration_requires_explicit_replace(self):
        class FixtureAdapter:
            def send(self, **kwargs):
                return b"fixture"

        adapters.register_provider_adapter("unit-duplicate", FixtureAdapter())
        self.addCleanup(adapters._ADAPTERS.pop, "unit-duplicate", None)
        with self.assertRaisesRegex(ValueError, "already registered"):
            adapters.register_provider_adapter("unit-duplicate", FixtureAdapter())
        adapters.register_provider_adapter("unit-duplicate", FixtureAdapter(), replace=True)

    def test_http_429_and_quota_payloads_are_safe_failover_categories(self):
        import io
        from urllib.error import HTTPError

        adapter = adapters.OpenAICompatibleAdapter()
        request = object()

        def quota_urlopen(*args, **kwargs):
            raise HTTPError(
                "https://provider.example/v1/chat/completions", 403, "forbidden", {},
                io.BytesIO(b'{"error":{"code":"RESOURCE_EXHAUSTED","message":"quota exceeded SECRET_MARKER"}}'),
            )

        with self.assertRaises(adapters.ProviderAdapterError) as caught:
            adapter.send(
                config={"base_url": "https://provider.example/v1", "timeout_seconds": 5},
                api_key="must-not-be-logged", payload={}, request_type=lambda *a, **k: request,
                urlopen_fn=quota_urlopen, http_error_type=HTTPError,
            )
        self.assertEqual(caught.exception.category, "quota")
        self.assertNotIn("SECRET_MARKER", str(caught.exception))
        self.assertNotIn("must-not-be-logged", str(caught.exception))

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaises(adapters.ProviderAdapterError):
            adapters.get_provider_adapter("unknown-provider")


if __name__ == "__main__":
    unittest.main()
