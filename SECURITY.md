# Security Policy

## Supported Use

Agent Safety Hooks is intended for authorized, local, and maintainer-friendly use. Please use it only on systems, repositories, and workflows you are allowed to inspect or automate.

## Reporting Security Issues

If you find a vulnerability, unsafe default, secret-handling issue, or behavior that could put users at risk, please report it with a minimal reproduction and the affected version or commit.

Do not post real tokens, API keys, private repository data, wallet keys, OAuth credentials, customer data, or exploit details in a public issue. Redact sensitive values from logs, screenshots, and reproduction steps.

## Scope

Security-relevant areas include:

- command matching and bypass behavior
- hook installation examples
- destructive command detection
- shell quoting and argument parsing

## Maintainer Notes

Security-sensitive fixes should keep diffs narrow, include a clear verification path, and avoid unrelated formatting, dependency, or generated-file churn.
