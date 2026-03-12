# Kenoma

> **"Negative day" vulnerability detection** — find security patches in open-source repositories before CVEs are published.

Kenoma is a GitHub Action that uses AI to analyze git commits and identify when developers are quietly patching exploitable security vulnerabilities — giving you time to act before public disclosure.

Based on [vulnerability-spoiler-alert-action](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action) by [@spaceraccoon](https://github.com/spaceraccoon), with significant improvements.

---

## How it works

1. Monitors a list of public repositories you define
2. On every run, fetches new commits since the last check
3. Sends each commit diff to an AI model for analysis
4. The model only flags commits where it can produce a **concrete, exploitable proof-of-concept**
5. Optionally runs a second judge model to confirm detections
6. Creates a GitHub Issue with full vulnerability details when confirmed

---

## Improvements over the original

| Feature | Original | Kenoma |
|---|---|---|
| Parallel commit analysis | Sequential | Parallel with configurable concurrency limit |
| API retry logic | None | Exponential backoff on transient errors (429, 5xx, timeouts) |
| LLM timeout | None | Configurable per-call timeout with automatic retry |
| Issue deduplication | None | Checks for existing issues before creating duplicates |
| State versioning | Flat JSON | Versioned with `_version` and `_updatedAt` metadata |
| Structured logging | Generic | Timestamped logs with per-repository context |
| Token usage logging | None | Logs input/output tokens per LLM call |
| Path filter | None | Only analyze commits touching specified file paths |
| Author skip list | None | Skip commits from bots, dependabot, etc. |
| Web API compatibility | `Buffer` (Node-only) | `TextDecoder` + `atob` (standard Web API) |

---

## Quick start

```yaml
name: Kenoma — Vulnerability Monitor

on:
  schedule:
    - cron: '0 */6 * * *'
  workflow_dispatch:

permissions:
  contents: write
  issues: write

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Kenoma
        uses: icarosama/kenoma@main
        with:
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
          repositories: '[
            {"owner":"spring-projects","repo":"spring-framework"},
            {"owner":"apache","repo":"logging-log4j2"},
            {"owner":"FasterXML","repo":"jackson-databind"}
          ]'

      - name: Save state
        run: |
          git config user.name "github-actions"
          git config user.email "github-actions@github.com"
          git add .vulnerability-spoiler-state.json
          git diff --cached --quiet || git commit -m "chore: update kenoma state"
          git push
```

---

## All inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `api-key` | Yes | — | API key for the model provider |
| `github-token` | Yes | `${{ github.token }}` | GitHub token for API access |
| `repositories` | Yes | — | JSON array of `{"owner","repo"}` objects to monitor |
| `provider` | No | `anthropic` | `anthropic`, `openai`, `deepseek`, or `openai-compatible` |
| `model` | No | `claude-sonnet-4-6` | Model to use for analysis |
| `base-url` | No | — | Custom base URL for `openai-compatible` providers |
| `max-commits` | No | `50` | Max commits to analyze per repo per run |
| `max-concurrency` | No | `3` | Commits analyzed in parallel per repo |
| `llm-timeout-seconds` | No | `60` | Seconds before an LLM call is aborted and retried |
| `path-filter` | No | — | Comma-separated path prefixes — only analyze commits touching these paths |
| `skip-authors` | No | — | Comma-separated author substrings to skip (e.g. `[bot],dependabot`) |
| `enable-repo-context` | No | `false` | Fetch modified file contents for extra context (max 3 files) |
| `enable-judge` | No | `false` | Run a second model to confirm positive detections |
| `judge-model` | No | same as `model` | Model to use for the judge pass |
| `create-issues` | No | `true` | Whether to create GitHub issues for detections |
| `issue-repo` | No | current repo | Repository to create issues in (`owner/repo`) |
| `state-file` | No | `.vulnerability-spoiler-state.json` | Path to state tracking file |

---

## Outputs

| Output | Description |
|---|---|
| `vulnerabilities-found` | Number of vulnerabilities detected |
| `issues-created` | Number of issues created |
| `analyzed-commits` | Total commits analyzed in this run |
| `results` | JSON array of all detected vulnerabilities |

---

## Issue format

When a vulnerability is detected, Kenoma opens an issue like this:

```
[Vulnerability] expressjs/express: Path Traversal — High
```

Containing:
- Repository and commit link
- Vulnerability type and severity
- Description of the flaw and how the patch fixes it
- Vulnerable code snippet (before the patch)
- Concrete proof-of-concept exploit

---

## Security considerations

Commit messages, PR descriptions, and diffs from monitored repositories are attacker-controlled inputs. A malicious actor could craft commits to manipulate model behavior (prompt injection). Treat all detections as advisory and review before acting. Use a private repository for issue creation to avoid exposing findings publicly.

---

## License

MIT — see [LICENSE](LICENSE)

Original work by [Eugene Lim (@spaceraccoon)](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action).
