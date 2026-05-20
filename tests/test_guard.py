import json
import tempfile
import unittest
from pathlib import Path

from agent_safety_hooks.guard import find_command, match_rules, run_hook


class GuardTest(unittest.TestCase):
    def test_blocks_dangerous_commands(self):
        commands = [
            "rm -rf build",
            "git push --force origin main",
            "git push -f origin main",
            "git push --force-with-lease origin main",
            "psql -c 'DROP TABLE users'",
            "TRUNCATE events",
            "DELETE FROM users",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(match_rules(command))

    def test_allows_normal_commands(self):
        commands = [
            "git status",
            "git push origin main",
            "rm -r build",
            "DELETE FROM users WHERE id = 1",
            "python3 -m unittest",
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertFalse(match_rules(command))

    def test_finds_command_from_nested_payload(self):
        payload = {"toolUse": {"input": {"command": "rm -rf build"}}}
        self.assertEqual(find_command(payload), "rm -rf build")

    def test_run_hook_logs_blocked_command(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "blocked.jsonl"
            code, message = run_hook(
                {"tool_input": {"command": "rm -rf build"}, "cwd": "/repo"},
                log_path=log_path,
            )
            self.assertEqual(code, 2)
            self.assertIn("Blocked by agent-safety-hooks", message)
            entry = json.loads(log_path.read_text().strip())
            self.assertEqual(entry["attempted_command"], "rm -rf build")
            self.assertEqual(entry["project_path"], "/repo")
            self.assertIn("recursive-force-delete", entry["rules"])


if __name__ == "__main__":
    unittest.main()
