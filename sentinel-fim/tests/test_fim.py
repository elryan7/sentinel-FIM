import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import fim  # noqa: E402


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = fim.main(list(args))
    return code, out.getvalue(), err.getvalue()


class FimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "site"
        self.root.mkdir()
        (self.root / "a.txt").write_text("alpha")
        (self.root / "sub").mkdir()
        (self.root / "sub" / "b.txt").write_text("beta")
        self.base = str(Path(self._tmp.name) / "base.json")
        os.environ.pop("FIM_KEY", None)

    def tearDown(self):
        os.environ.pop("FIM_KEY", None)
        self._tmp.cleanup()

    def init(self, *extra):
        return run("init", str(self.root), "-b", self.base, *extra)

    def check(self, *extra):
        return run("check", str(self.root), "-b", self.base, "--json", *extra)

    def test_no_change(self):
        self.assertEqual(self.init()[0], 0)
        code, out, _ = self.check()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["added"], [])

    def test_detects_add_modify_remove(self):
        self.init()
        (self.root / "a.txt").write_text("ALTERED")
        (self.root / "new.txt").write_text("x")
        (self.root / "sub" / "b.txt").unlink()
        code, out, _ = self.check()
        res = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(res["added"], ["new.txt"])
        self.assertEqual(res["removed"], ["sub/b.txt"])
        self.assertEqual(res["modified"], [{"path": "a.txt", "changes": ["sha256"]}])

    @unittest.skipIf(os.name == "nt", "permissions POSIX")
    def test_detects_permission_change(self):
        self.init()
        os.chmod(self.root / "a.txt", 0o777)
        res = json.loads(self.check()[1])
        self.assertEqual(res["modified"], [{"path": "a.txt", "changes": ["mode"]}])

    def test_exclude(self):
        (self.root / "x.log").write_text("1")
        self.init("-e", "*.log")
        (self.root / "x.log").write_text("2")
        self.assertEqual(self.check()[0], 0)

    def test_baseline_inside_root_is_ignored(self):
        self.base = str(self.root / "base.json")
        self.init()
        self.assertEqual(self.check()[0], 0)

    def test_hmac_detects_tampered_baseline(self):
        os.environ["FIM_KEY"] = "secret"
        self.init()
        doc = json.loads(Path(self.base).read_text())
        doc["data"]["files"].pop("a.txt")
        Path(self.base).write_text(json.dumps(doc))
        code, _, err = self.check()
        self.assertEqual(code, 2)
        self.assertIn("signature invalide", err)

    def test_unsigned_baseline_rejected_when_key_set(self):
        self.init()
        os.environ["FIM_KEY"] = "secret"
        self.assertEqual(self.check()[0], 2)

    def test_missing_baseline(self):
        self.assertEqual(self.check()[0], 2)

    def test_update_refreshes_baseline(self):
        self.init()
        (self.root / "a.txt").write_text("v2")
        self.assertEqual(self.check("--update")[0], 1)
        self.assertEqual(self.check()[0], 0)


if __name__ == "__main__":
    unittest.main()
