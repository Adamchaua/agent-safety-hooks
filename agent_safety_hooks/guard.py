from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_LOG_PATH = Path.home() / ".agent-safety-hooks" / "blocked.jsonl"


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    message: str


RULES: tuple[Rule, ...] = (
    Rule(
        "recursive-force-delete",
        re.compile(r"(^|[;&|`$()\n])\s*rm\s+[^\n;&|]*-[^\n;&|]*r[^\n;&|]*f|(^|[;&|`$()\n])\s*rm\s+[^\n;&|]*-[^\n;&|]*f[^\n;&|]*r", re.I),
        "`rm -rf` can irreversibly delete files. Ask for explicit approval first.",
    ),
    Rule(
        "force-push",
        re.compile(r"\bgit\s+push\b[^\n;&|]*(--force|-f|--force-with-lease)\b", re.I),
        "Force-pushing can rewrite shared history. Ask for explicit approval first.",
    ),
    Rule(
        "drop-table",
        re.compile(r"\bDROP\s+TABLE\b", re.I),
        "`DROP TABLE` can destroy schema and data. Ask for explicit approval first.",
    ),
    Rule(
        "truncate",
        re.compile(r"\bTRUNCATE\b", re.I),
        "`TRUNCATE` can delete all rows from a table. Ask for explicit approval first.",
    ),
    Rule(
        "delete-without-where",
        re.compile(r"\bDELETE\s+FROM\s+[\w.\"`]+(?![^;\n]*\bWHERE\b)", re.I),
        "`DELETE FROM` without `WHERE` can remove every row. Add a WHERE clause or ask first.",
    ),
)


def load_payload(stdin: str | None = None) -> dict[str, Any]:
    raw = sys.stdin.read() if stdin is None else stdin
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {"command": raw}
    return payload if isinstance(payload, dict) else {}


def find_command(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("command", "cmd", "bash_command", "input"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item
        for key in ("tool_input", "toolUse", "tool_use", "parameters", "args"):
            command = find_command(value.get(key))
            if command:
                return command
        for item in value.values():
            command = find_command(item)
            if command:
                return command
    elif isinstance(value, list):
        for item in value:
            command = find_command(item)
            if command:
                return command
    elif isinstance(value, str):
        return value
    return ""


def project_path(payload: dict[str, Any]) -> str:
    for key in ("cwd", "project_path", "workspace", "root", "repo_path"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return os.getcwd()


def match_rules(command: str, rules: Iterable[Rule] = RULES) -> list[Rule]:
    return [rule for rule in rules if rule.pattern.search(command)]


def write_block_log(command: str, path: str, rules: list[Rule], log_path: Path = DEFAULT_LOG_PATH) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "project_path": path,
        "attempted_command": command,
        "rules": [rule.name for rule in rules],
        "messages": [rule.message for rule in rules],
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_hook(payload: dict[str, Any], log_path: Path = DEFAULT_LOG_PATH) -> tuple[int, str]:
    command = find_command(payload)
    rules = match_rules(command)
    if not rules:
        return 0, ""
    path = project_path(payload)
    write_block_log(command, path, rules, log_path)
    reasons = "\n".join(f"- {rule.message}" for rule in rules)
    message = f"Blocked by agent-safety-hooks.\n{reasons}\nCommand: {command}\nProject: {path}"
    return 2, message


def main() -> int:
    payload = load_payload()
    code, message = run_hook(payload)
    if message:
        print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
