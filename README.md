# Kenoma

GitHub Action for monitoring open-source repositories for security vulnerability patches — before CVEs are published.

Fork of [vulnerability-spoiler-alert-action](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action) by [@spaceraccoon](https://github.com/spaceraccoon).

---

## Changes from the original

- Parallel commit analysis with configurable concurrency
- Retry with exponential backoff on transient API errors
- Timeout per LLM call
- Deduplication check before opening issues
- Versioned state file with timestamps
- Structured logs with per-repo context and token usage
- `path-filter` input — only analyze commits touching specific paths
- `skip-authors` input — skip commits from bots or specific authors
- Replaced Node.js `Buffer` with standard Web API (`TextDecoder` / `atob`)

---

## Usage

```yaml
- uses: icarosama/kenoma@main
  with:
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    github-token: ${{ secrets.GITHUB_TOKEN }}
    repositories: '[{"owner":"expressjs","repo":"express"}]'
```

**New inputs:**

| Input | Default | Description |
|---|---|---|
| `max-concurrency` | `3` | Parallel commits per repo |
| `llm-timeout-seconds` | `60` | Timeout per LLM call |
| `path-filter` | — | Only analyze commits touching these paths (comma-separated) |
| `skip-authors` | — | Skip commits from these authors (comma-separated) |

All original inputs from the upstream action remain supported unchanged.

---

## License

MIT. Original work by [Eugene Lim (@spaceraccoon)](https://github.com/spaceraccoon/vulnerability-spoiler-alert-action).
