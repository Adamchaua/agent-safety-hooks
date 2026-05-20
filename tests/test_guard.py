import json
import os
import tempfile
import unittest
from importlib import reload
from pathlib import Path
from unittest.mock import patch

import agent_safety_hooks.guard as guard
from agent_safety_hooks.guard import find_command, load_custom_rules, match_rules, run_hook


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

    def test_loads_custom_deny_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "rules.json"
            config_path.write_text(
                json.dumps(
                    {
                        "deny": [
                            {
                                "name": "prod-kubectl-delete",
                                "pattern": r"\bkubectl\s+delete\b.*\bprod\b",
                                "message": "Production deletes need approval.",
                            }
                        ]
                    }
                )
            )
            rules = load_custom_rules(config_path)
            matches = match_rules("kubectl delete pod api -n prod", rules)
            self.assertEqual([rule.name for rule in matches], ["prod-kubectl-delete"])
            self.assertEqual(matches[0].message, "Production deletes need approval.")

    def test_invalid_custom_regex_falls_back_to_literal_match(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "rules.json"
            config_path.write_text(json.dumps({"deny": ["docker compose down [prod"]}))
            rules = load_custom_rules(config_path)
            self.assertTrue(match_rules("docker compose down [prod", rules))

    def test_deny_file_env_var_sets_default_config_path(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "project-rules.json"
            config_path.write_text(json.dumps({"deny": ["terraform destroy"]}))
            with patch.dict(os.environ, {"AGENT_SAFETY_HOOKS_DENY_FILE": str(config_path)}):
                reloaded_guard = reload(guard)
                try:
                    self.assertTrue(reloaded_guard.match_rules("terraform destroy"))
                finally:
                    reload(guard)


if __name__ == "__main__":
    unittest.main()
