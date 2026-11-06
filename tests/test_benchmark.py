import contextlib
import io
import unittest

from lowkey import benchmark


class BenchmarkTests(unittest.TestCase):
    def test_regression_benchmark_passes(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = benchmark.run([])
        self.assertEqual(code, 0)
        output = stream.getvalue()
        self.assertIn("LOWKEY SECURITY REGRESSION BENCHMARK", output)
        self.assertIn("Failed: 0", output)

    def test_json_output_is_machine_readable(self):
        import json

        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = benchmark.run(["--json"])
        payload = json.loads(stream.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["failed"], 0)
        self.assertTrue(payload["not_a_security_accuracy_claim"])


if __name__ == "__main__":
    unittest.main()
