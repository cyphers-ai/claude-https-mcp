# Secure HTTPS Skill

An agent skill for [claude-https-mcp](https://github.com/cyphers-ai/claude-https-mcp) that teaches AI coding agents when and how to use the `SecureWebFetch` tool for enterprise-grade HTTPS requests.

## What This Skill Does

This skill provides **procedural knowledge** to Claude Code so it knows:
- When to use `SecureWebFetch` vs. built-in fetch
- How to interpret TLS error codes and suggest fixes
- How to guide users through common configuration scenarios (mTLS, pinning, proxies, FIPS)

The skill complements the MCP server — the MCP provides the runtime tool, the skill provides the agent intelligence.

## Installation

### One-Command Setup

```bash
npx skills add cyphers-ai/claude-https-mcp
```

This installs the skill files to `~/.claude/skills/`. If the MCP server is not yet installed, run the included setup script:

```bash
bash ~/.claude/skills/secure-https/scripts/setup.sh
```

### Manual Installation

```bash
cp -r skills/secure-https ~/.claude/skills/
```

## What Gets Installed

```
~/.claude/skills/secure-https/
  SKILL.md          # Agent instructions (loaded on-demand)
  metadata.json     # Skill metadata
  scripts/
    setup.sh        # Automates MCP server installation
  README.md         # This file
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- [claude-https-mcp](https://github.com/cyphers-ai/claude-https-mcp) MCP server (the setup script handles this)
- Node.js 18+

## License

MIT
