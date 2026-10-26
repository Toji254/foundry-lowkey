import unittest

from lowkey import provider_adapters as adapters


class ProviderAdapterRegistryTests(unittest.TestCase):
    def test_builtin_providers_are_replaceable_transport_slots(self):
        for name in ("deepseek", "openai", "openai-compatible", "ollama"):
            self.assertIsNotNone(adapters.get_provider_adapter(name))
        self.assertEqual(adapters.provider_adapter_status()["registered_providers"], [
            "deepseek", "ollama", "openai", "openai-compatible"
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

    def test_unknown_adapter_is_rejected(self):
        with self.assertRaises(adapters.ProviderAdapterError):
            adapters.get_provider_adapter("unknown-provider")


if __name__ == "__main__":
    unittest.main()
