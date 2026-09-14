import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/check_links.py'


def load_checker():
    spec = importlib.util.spec_from_file_location('check_links', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MarkdownLinkCheckerTests(unittest.TestCase):
    def test_missing_relative_target_fails(self):
        checker = load_checker()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'README.md').write_text('[missing](docs/nope.md)\n', encoding='utf-8')
            self.assertNotEqual(checker.check(root), [])

    def test_existing_target_and_external_links_pass(self):
        checker = load_checker()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'docs').mkdir()
            (root/'docs/guide.md').write_text('# Guide\n', encoding='utf-8')
            (root/'README.md').write_text('[guide](docs/guide.md) [site](https://example.com) [heading](#x)\n', encoding='utf-8')
            self.assertEqual(checker.check(root), [])

    def test_repository_escape_fails(self):
        checker = load_checker()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'README.md').write_text('[escape](../outside.md)\n', encoding='utf-8')
            self.assertNotEqual(checker.check(root), [])


if __name__ == '__main__':
    unittest.main()
