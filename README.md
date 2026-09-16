# rote plays

These are small, read-only diagnostic tools for a developer's own machine, published as [rote](https://play.modiqo.ai) Plays. All 18 were built during the Rote Playoffs (Sep 1-6 2026), where they placed 1st. Run any of them with one command:

```
rote play run https://play.modiqo.ai/dotisacat/<name> --yes [param=value]
```

`rote` itself installs from https://play.modiqo.ai/install.

| Play | Version | What it answers | Run |
| --- | --- | --- | --- |
| [agent-resource-audit](https://play.modiqo.ai/dotisacat/agent-resource-audit) | 0.2.10 | What agent processes are running right now, how much memory they hold, and what on-disk sessions match them. | `rote play run https://play.modiqo.ai/dotisacat/agent-resource-audit --yes` |
| [mcp-doctor](https://play.modiqo.ai/dotisacat/mcp-doctor) | 0.1.6 | Whether each configured MCP server is healthy, and what to do about the ones that are not. | `rote play run https://play.modiqo.ai/dotisacat/mcp-doctor --yes` |
| [mcp-context-tax](https://play.modiqo.ai/dotisacat/mcp-context-tax) | 0.1.8 | How many context-window tokens your configured MCP servers consume before you type a word. | `rote play run https://play.modiqo.ai/dotisacat/mcp-context-tax --yes` |
| [mcp-config-secrets-audit](https://play.modiqo.ai/dotisacat/mcp-config-secrets-audit) | 0.1.4 | Whether any configured MCP server carries an inline secret-shaped value, especially in a world- or group-readable config file. | `rote play run https://play.modiqo.ai/dotisacat/mcp-config-secrets-audit --yes` |
| [mcp-package-health](https://play.modiqo.ai/dotisacat/mcp-package-health) | 0.1.2 | Whether the npm and PyPI packages behind your MCP servers are still maintained. | `rote play run https://play.modiqo.ai/dotisacat/mcp-package-health --yes` |
| [session-digest](https://play.modiqo.ai/dotisacat/session-digest) | 0.1.5 | What your agents actually did while you were away, digested from local session transcripts. | `rote play run https://play.modiqo.ai/dotisacat/session-digest --yes` |
| [agent-disk-tax](https://play.modiqo.ai/dotisacat/agent-disk-tax) | 0.1.3 | What your agent tooling costs you in disk space right now, by category, with the largest offenders named. | `rote play run https://play.modiqo.ai/dotisacat/agent-disk-tax --yes` |
| [agent-plugin-inventory](https://play.modiqo.ai/dotisacat/agent-plugin-inventory) | 0.1.4 | What Claude Code plugins, skills, marketplaces, and Codex plugin-equivalents are installed, and which look stale or broken. | `rote play run https://play.modiqo.ai/dotisacat/agent-plugin-inventory --yes` |
| [commit-attribution-guard](https://play.modiqo.ai/dotisacat/commit-attribution-guard) | 0.1.5 | Whether your recent commit messages carry AI-attribution marks you may not have meant to publish. | `rote play run https://play.modiqo.ai/dotisacat/commit-attribution-guard --yes repo=/abs/path` |
| [commit-identity-check](https://play.modiqo.ai/dotisacat/commit-identity-check) | 0.1.1 | What git identity (name and email) your next commit in each repo would actually use, before you commit it. | `rote play run https://play.modiqo.ai/dotisacat/commit-identity-check --yes` |
| [git-credential-exposure](https://play.modiqo.ai/dotisacat/git-credential-exposure) | 0.1.4 | Where git credentials are exposed in cleartext, across `~/.git-credentials`, `credential.helper` config, and repo remote URLs. | `rote play run https://play.modiqo.ai/dotisacat/git-credential-exposure --yes` |
| [laptop-loss-drill](https://play.modiqo.ai/dotisacat/laptop-loss-drill) | 0.1.4 | What you would lose if this laptop died right now, backed by evidence. | `rote play run https://play.modiqo.ai/dotisacat/laptop-loss-drill --yes` |
| [timemachine-exclusions-audit](https://play.modiqo.ai/dotisacat/timemachine-exclusions-audit) | 0.1.2 | Whether Time Machine actually backs up the paths you think it does. | `rote play run https://play.modiqo.ai/dotisacat/timemachine-exclusions-audit --yes` |
| [shell-history-leak-scan](https://play.modiqo.ai/dotisacat/shell-history-leak-scan) | 0.1.3 | Whether secret-shaped values were typed into a shell prompt and landed in shell history files. | `rote play run https://play.modiqo.ai/dotisacat/shell-history-leak-scan --yes` |
| [scheduled-job-graveyard](https://play.modiqo.ai/dotisacat/scheduled-job-graveyard) | 0.1.4 | Which scheduled jobs (crontab, LaunchAgents, LaunchDaemons) exist on this machine and whether they still work. | `rote play run https://play.modiqo.ai/dotisacat/scheduled-job-graveyard --yes` |
| [command-shadow-audit](https://play.modiqo.ai/dotisacat/command-shadow-audit) | 0.1.4 | What actually runs when you type a given command, and what it silently shadows. | `rote play run https://play.modiqo.ai/dotisacat/command-shadow-audit --yes` |
| [python-ssl-doctor](https://play.modiqo.ai/dotisacat/python-ssl-doctor) | 0.1.4 | Which python installs on PATH have a working TLS trust chain, and how to fix the ones that don't. | `rote play run https://play.modiqo.ai/dotisacat/python-ssl-doctor --yes` |
| [playoffs-standings](https://play.modiqo.ai/dotisacat/playoffs-standings) | 0.2.8 | Where your Play stands in the public registry, and what shipped since your last run. | `rote play run https://play.modiqo.ai/dotisacat/playoffs-standings --yes` |

## Layout

`plays/<name>/` holds each Play's `main.ts`, `deps.toml`, and `resources/`, mirrored byte-for-byte from the local rote install. `scripts/sync.sh` regenerates `plays/` from `~/.rote/flows/<name>/`.

## Trust

Every play here is read-only against the machine it runs on: none of them write, delete, or execute anything on your behalf. None reads or transmits credentials. Each needs only `python3` plus whatever its own `deps.toml` declares. Three plays make network calls of their own: `playoffs-standings` calls the public registry API, `mcp-package-health` calls `registry.npmjs.org` and `pypi.org`, and `python-ssl-doctor` opens one bounded TLS handshake per python install against `pypi.org:443` to test its trust chain. None of the other 15 plays make a network call of their own.

## License

MIT, see [LICENSE](LICENSE).
