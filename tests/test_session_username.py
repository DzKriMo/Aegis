import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aegis.storage.store import InMemoryStore  # noqa: E402


class SessionUsernameTests(unittest.TestCase):
    def test_create_session_persists_username(self):
        store = InMemoryStore()
        store.create_session("s1", username="alice")

        session = store.get_session("s1")
        self.assertEqual("alice", session.get("username"))

    def test_create_session_without_username_keeps_none(self):
        store = InMemoryStore()
        store.create_session("s2")

        listed = store.list_sessions()
        self.assertIn("s2", listed)
        self.assertIsNone(listed["s2"].get("username"))


if __name__ == "__main__":
    unittest.main()
