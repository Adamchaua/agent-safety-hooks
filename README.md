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

Blocked attempts are logged to:

```text
~/.agent-safety-hooks/blocked.jsonl
```

## 🚀 Quick Start

```bash
python3 -m pip install -e .
printf '%s\n' '{"tool_input":{"command":"rm -rf build"},"cwd":"/repo"}' | agent-safety-guard
```

Expected result: the command is blocked with exit code `2` and a clear reason.

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

## 🧪 Verification

```bash
python3 -m unittest discover -s tests -v
```

## 🗺️ Roadmap

- Config file for custom allow/deny rules
- Dry-run mode for teams adopting hooks gradually
- Adapters/examples for more coding-agent CLIs
- GitHub Action that checks agent-generated scripts for dangerous commands

## 💛 Support

If this saves you time or prevents an expensive mistake, you can support future development:

- EVM: `0x1ecab01075f3bdf1b56b7d849c8e28ef88943624`
- PayPal: `ckelvinkhanh32@gmail.com`

No pressure. The tool is useful first; support is optional.

## 📄 License

MIT
