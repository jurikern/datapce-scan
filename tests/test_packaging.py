import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PackagingTests(unittest.TestCase):
    def test_licence_file_and_metadata(self):
        with open(os.path.join(ROOT, "LICENSE")) as f:
            text = f.read()
        self.assertIn("MIT License", text)
        self.assertIn("2026 jkn", text)
        with open(os.path.join(ROOT, "pyproject.toml")) as f:
            pp = f.read()
        self.assertIn('license = "MIT"', pp)
        self.assertIn("jkn@datapce.com", pp)
        self.assertIn("LICENSE", pp)
        self.assertIn("NOTICE", pp)
