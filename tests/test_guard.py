import json
import os
import tempfile
import unittest
from importlib import reload
from pathlib import Path
from unittest.mock import patch

import agent_safety_hooks.guard as guard
from agent_safety_hooks.guard import (
    find_command,
    is_dry_run,
    load_custom_allow_rules,
    load_custom_rules,
    main,
    match_allow_rules,
    match_rules,
    redact_secrets,
    run_hook,
)


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

    def test_loads_custom_allow_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "rules.json"
            config_path.write_text(
                json.dumps(
                    {
                        "deny": ["rm -rf"],
                        "allow": [
                            {
                                "name": "local-build-cleanup",
                                "pattern": r"^rm\s+-rf\s+build$",
                                "message": "Local build cleanup is allowed.",
                            }
                        ],
                    }
                )
            )
            rules = load_custom_allow_rules(config_path)
            matches = match_allow_rules("rm -rf build", rules)
            self.assertEqual([rule.name for rule in matches], ["local-build-cleanup"])

    def test_custom_allow_rules_override_deny_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "rules.json"
            config_path.write_text(json.dumps({"allow": [r"^rm\s+-rf\s+build$"]}))
            with patch.dict(os.environ, {"AGENT_SAFETY_HOOKS_DENY_FILE": str(config_path)}):
                reloaded_guard = reload(guard)
                try:
                    code, message = reloaded_guard.run_hook({"command": "rm -rf build", "cwd": "/repo"})
                finally:
                    reload(guard)
            self.assertEqual(code, 0)
            self.assertEqual(message, "")

    def test_dry_run_reports_but_allows_command(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "blocked.jsonl"
            code, message = run_hook(
                {"tool_input": {"command": "rm -rf build"}, "cwd": "/repo", "dry_run": True},
                log_path=log_path,
            )
            self.assertEqual(code, 0)
            self.assertIn("Would block by agent-safety-hooks", message)
            self.assertTrue(log_path.exists())

    def test_dry_run_env_var_enables_audit_mode(self):
        with patch.dict(os.environ, {"AGENT_SAFETY_HOOKS_DRY_RUN": "true"}):
            self.assertTrue(is_dry_run({}))

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

    def test_redacts_secrets_before_logging(self):
        command = "OPENAI_API_KEY=sk-testSecretValue1234567890; rm -rf build"
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "blocked.jsonl"
            _, message = run_hook({"tool_input": {"command": command}, "cwd": "/repo"}, log_path=log_path)
            entry = json.loads(log_path.read_text().strip())
            self.assertEqual(entry["attempted_command"], "OPENAI_API_KEY=[REDACTED]; rm -rf build")
            self.assertIn("OPENAI_API_KEY=[REDACTED]; rm -rf build", message)
            self.assertNotIn("sk-testSecretValue", entry["attempted_command"])
            self.assertNotIn("sk-testSecretValue", message)

    def test_redacts_common_token_shapes(self):
        self.assertEqual(
            redact_secrets("curl -H 'Authorization: Bearer tok_12345678901234567890' rm -rf build"),
            "curl -H 'Authorization: Bearer [REDACTED]' rm -rf build",
        )
        self.assertEqual(redact_secrets("X-API-Key: abc123 rm -rf build"), "X-API-Key: [REDACTED] rm -rf build")

    def test_main_accepts_direct_command_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"AGENT_SAFETY_HOME": directory}):
                code = main(["--command", "rm -rf build", "--cwd", "/repo", "--dry-run"])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
