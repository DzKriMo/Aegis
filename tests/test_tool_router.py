import shutil
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.runtime.tool_router import execute_tool  # noqa: E402


class ToolRouterTests(unittest.TestCase):
    def _make_workspace(self) -> Path:
        base = ROOT / ".tmp" / "tool_router_tests" / uuid.uuid4().hex
        base.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(base, ignore_errors=True))
        return base

    def test_directory_list_returns_entries(self):
        tmp = self._make_workspace()
        Path(tmp, "a.txt").write_text("hello", encoding="utf-8")
        result = execute_tool(
            tool_name="directory_list",
            payload={"path": str(tmp)},
            environment="dev",
            allowlist=[],
            denylist=[],
            filesystem_root=str(tmp),
        )
        self.assertTrue(result.allowed)
        names = [entry["name"] for entry in result.result["entries"]]
        self.assertIn("a.txt", names)

    def test_filesystem_write_respects_root(self):
        tmp = self._make_workspace()
        target = str(Path(tmp) / "note.txt")
        result = execute_tool(
            tool_name="filesystem_write",
            payload={"path": target, "content": "abc"},
            environment="dev",
            allowlist=[],
            denylist=[],
            filesystem_root=str(tmp),
        )
        self.assertTrue(result.allowed)
        self.assertEqual(Path(target).read_text(encoding="utf-8"), "abc")

    def test_json_transform_keys(self):
        result = execute_tool(
            tool_name="json_transform",
            payload={"data": {"a": 1, "b": 2}, "operation": "keys"},
            environment="dev",
            allowlist=[],
            denylist=[],
            filesystem_root=None,
        )
        self.assertTrue(result.allowed)
        self.assertEqual(result.result["keys"], ["a", "b"])


if __name__ == "__main__":
    unittest.main()
