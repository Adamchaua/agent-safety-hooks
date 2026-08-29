# Agent Safety Hooks

Tiny safety hooks for AI coding agents. The first hook stops destructive shell commands before they run, so an agent cannot accidentally wipe files, rewrite Git history, or delete database rows without a human decision.

## 🔍 Why This Exists

AI coding agents are getting useful enough to run real terminal commands. That creates a simple new pain point for developers:

> How do I let the agent work fast without letting it run the one command that ruins my day?

This repo starts with a small, auditable guard for that problem.

## 🛑 What It Blocks

- `rm -rf`
- `git push --force`, `git push -f`, `git push --force-with-lease`
- `DROP TABLE`
- `TRUNCATE`
- `DELETE FROM ...` without a `WHERE` clause
- Optional custom deny rules from `~/.agent-safety-hooks/rules.json`

Blocked attempts are logged to:

```text
~/.agent-safety-hooks/blocked.jsonl
```

The log redacts common token and key shapes before writing command text, including `*_TOKEN=...`, `*_API_KEY=...`, bearer tokens, GitHub personal access tokens, and provider API keys.

## 🚀 Quick Start

```bash
python3 -m pip install -e .
printf '%s\n' '{"tool_input":{"command":"rm -rf build"},"cwd":"/repo"}' | agent-safety-guard
```

Expected result: the command is blocked with exit code `2` and a clear reason.

You can also check one command directly, which is useful for CI scripts or quick local smoke tests:

```bash
agent-safety-guard --command "git push --force origin main" --cwd /repo
```

## 🧩 Claude Code Hook Usage

Install locally:

```bash
python3 -m pip install -e .
```

Then register this command as a Claude Code `pre-tool-use` hook:

```bash
agent-safety-guard
```

The hook accepts JSON on stdin and tries common payload shapes such as:

```json
{"tool_input":{"command":"git status"},"cwd":"/repo"}
```

Normal commands exit `0`. Blocked commands exit `2`.

## ⚙️ Custom Deny Rules

Create a starter config:

```bash
printf '%s\n' '{"command":"init-config"}' | agent-safety-guard
```

Then edit `~/.agent-safety-hooks/rules.json`, or set `AGENT_SAFETY_HOOKS_DENY_FILE` to load rules from a project-specific file:

```json
{
  "deny": [
    {
      "name": "production-kubectl-delete",
      "pattern": "\\bkubectl\\s+delete\\b.*\\b(prod|production)\\b",
      "message": "Deleting production Kubernetes resources needs human approval."
    }
  ]
}
```

Rules are regular expressions matched case-insensitively against the shell command. Invalid regex patterns are treated as literal text so a typo does not crash the hook.

## ✅ Custom Allow Rules

Some teams have safe cleanup commands they run constantly, such as removing local build output. Add an `allow` list to the same config file to bypass deny rules for exact, trusted patterns:

```json
{
  "allow": [
    {
      "name": "local-build-cleanup",
      "pattern": "^rm\\s+-rf\\s+(build|dist|\\.pytest_cache)$",
      "message": "Allow deleting local generated build artifacts."
    }
  ]
}
```

Keep allow rules narrow. A broad pattern can weaken the guard.

## 🟡 Dry-Run Mode

Teams can audit what would be blocked before enforcing the guard:

```bash
AGENT_SAFETY_HOOKS_DRY_RUN=true agent-safety-guard
```

Dry-run mode still logs matching commands, but exits `0` and prints `Would block by agent-safety-hooks (dry run).` instead of blocking the command. Hook payloads can also set `"dry_run": true` for per-call auditing.

Direct command checks can use the same mode:

```bash
agent-safety-guard --dry-run --command "rm -rf build"
```

## 🧪 Verification

```bash
python3 -m unittest discover -s tests -v
```

## 🗺️ Roadmap

- Adapters/examples for more coding-agent CLIs
- Preset rule packs for Git, database, cloud, and Kubernetes workflows
- CI reporter that summarizes blocked command patterns without secrets
- GitHub Action that checks agent-generated scripts for dangerous commands

## 💛 Support

If this saves you time or prevents an expensive mistake, you can support future development:

- EVM: `0x1ecab01075f3bdf1b56b7d849c8e28ef88943624`
- PayPal: `ckelvinkhanh32@gmail.com`

No pressure. The tool is useful first; support is optional.

## 📄 License

MIT
