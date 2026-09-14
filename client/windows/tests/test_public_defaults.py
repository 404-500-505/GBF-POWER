import importlib.util
import json
from pathlib import Path
import unittest


WINDOWS = Path(__file__).resolve().parents[1]
APP = WINDOWS / "app"


class PublicDefaultsTests(unittest.TestCase):
    def test_fresh_checkout_has_no_live_activation_endpoint(self):
        path = APP / "assets" / "activation.example.json"
        self.assertTrue(path.is_file(), "activation example is missing")
        config = json.loads(path.read_text(encoding="utf-8"))
        self.assertTrue(config["host"].endswith(".example.com"))
        self.assertEqual(config["certificate_sha256"], "0" * 64)

    def test_default_config_has_no_legacy_shared_ssh_key(self):
        path = APP / "client_runtime.py"
        self.assertTrue(path.is_file(), "client runtime is missing")
        spec = importlib.util.spec_from_file_location("public_client_runtime", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIsNone(module.default_config().get("ssh"))


if __name__ == "__main__":
    unittest.main()
