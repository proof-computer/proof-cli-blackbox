# Agent Instructions

This public package owns the Blackbox plugin for the root `proof` CLI.

- Keep this package public-safe. Do not add private Blackbox workspace package
  dependencies.
- Preserve behavior with the standalone `blackbox` compatibility bin. Command
  logic should live behind exported command-specific runners; `runBlackboxCli`
  is the standalone-bin compatibility adapter over those same functions.
- Keep package verification focused on the npm tarball surface: `dist`,
  `oclif.manifest.json`, and `README.md`.

## CLI Development Guidance

When changing CLI behavior, review Liran Tal's Node.js CLI Apps Best
Practices and its agent-oriented skill:

- https://github.com/lirantal/nodejs-cli-apps-best-practices
- https://github.com/lirantal/nodejs-cli-apps-best-practices/tree/main/skills/nodejs-cli-best-practices

Use it as a checklist for POSIX-style flags, structured output,
configuration precedence, actionable errors, debug output, exit codes, version
output, package `files`, strict opt-in analytics, and argument-injection
safety. Blackbox's local DEK/read-token state and secret-handling rules remain
stricter where they apply.
