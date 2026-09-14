from pathlib import Path
import unittest


REPOSITORY = Path(__file__).resolve().parents[3]


class BrandingTests(unittest.TestCase):
    def test_public_icon_is_original_vector_without_embedded_image(self):
        source = (REPOSITORY / "assets" / "icon.svg").read_text(encoding="utf-8")
        self.assertIn("<svg", source)
        self.assertNotIn("<image", source.lower())
        self.assertNotIn("data:", source.lower())


if __name__ == "__main__":
    unittest.main()
