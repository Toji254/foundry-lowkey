import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import break_engine


class EthereumKeccakFallbackTests(unittest.TestCase):
    def test_empty_input_matches_ethereum_keccak256_vector(self):
        self.assertEqual(
            break_engine._keccak256_fallback(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )

    def test_abc_matches_ethereum_keccak256_vector(self):
        self.assertEqual(
            break_engine._keccak256_fallback(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_multiblock_input_matches_keccak256_vector(self):
        # The input crosses the 136-byte Keccak-256 rate boundary.
        self.assertEqual(
            break_engine._keccak256_fallback(b"a" * 200).hex(),
            "96ea54061def936c4be90b518992fdc6f12f535068a256229aca54267b4d084d",
        )

    def test_public_provider_returns_exactly_32_bytes(self):
        digest = break_engine._keccak256(b"lowkey")
        self.assertIsInstance(digest, bytes)
        self.assertEqual(len(digest), 32)

    def test_rejects_non_bytes_input(self):
        for value in ("abc", bytearray(b"abc"), None):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(TypeError):
                    break_engine._keccak256_fallback(value)


if __name__ == "__main__":
    unittest.main()
