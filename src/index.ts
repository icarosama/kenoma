import * as core from "@actions/core";
import * as github from "@actions/github";
import { readFileSync, writeFileSync, existsSync, realpathSync } from "fs";
import { resolve, normalize, sep, basename } from "path";
import type {
  ActionInputs,
  RepoConfig,
  State,
  DetectedVulnerability,
  ActionOutputs,
} from "./types.js";
import {
  initOctokit,
  getCommitsSince,
  getLatestCommitSha,
  createVulnerabilityIssue,
  getModifiedFilesContent,
  checkExistingIssue,
  extractModifiedPaths,
  getVersionInfo,
} from "./github.js";
import { initAnalyzer, analyzeCommit, judgeAnalysis } from "./analyzer.js";
import type { ProviderType } from "./providers.js";
import { createConcurrencyLimiter, makeLogger } from "./utils.js";

const STATE_VERSION = 2;

function sanitizeStatePath(input: string): string {
  if (!input || input.includes("\0")) {
    throw new Error("Invalid state-file path");
  }

  const cwd = realpathSync(process.cwd());
  const resolved = resolve(cwd, input);
  const normalized = normalize(resolved);

  if (!normalized.startsWith(cwd + sep)) {
    throw new Error(
      `state-file path must be within the working directory. Got: ${input}`
    );
  }

  if (!basename(normalized)) {
    throw new Error(
      `state-file path must point to a file, not a directory. Got: ${input}`
    );
  }

  return normalized;
}

function getInputs(): ActionInputs {
  const reposInput = core.getInput("repositories", { required: true });
  let repositories: RepoConfig[];

  try {
    const parsed = JSON.parse(reposInput);

    if (!Array.isArray(parsed)) {
      throw new Error("Expected a JSON array");
    }

    for (const item of parsed) {
      if (
        typeof item !== "object" ||
        item === null ||
        typeof item.owner !== "string" ||
        typeof item.repo !== "string" ||
        !item.owner ||
        !item.repo
      ) {
        throw new Error(
          `Each entry must be an object with non-empty "owner" and "repo" string fields`
        );
      }
    }

    repositories = parsed as RepoConfig[];
  } catch (e) {
    throw new Error(
      `Invalid repositories input: ${e instanceof Error ? e.message : e}`
    );
  }

  const issueRepoInput = core.getInput("issue-repo");
  let issueRepo: { owner: string; repo: string };

  if (issueRepoInput) {
    const [owner, repo] = issueRepoInput.split("/");
    if (!owner || !repo) {
      throw new Error(
        `Invalid issue-repo format. Expected "owner/repo", got: ${issueRepoInput}`
      );
    }
    issueRepo = { owner, repo };
  } else {
    issueRepo = {
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
    };
  }

  const apiKey = core.getInput("api-key") || core.getInput("anthropic-api-key");
  if (!apiKey) {
    throw new Error("Either 'api-key' or 'anthropic-api-key' input is required");
  }

  const modelInput = core.getInput("model") || "claude-sonnet-4-6";
  const validProviders = ["anthropic", "openai", "deepseek", "openai-compatible"] as const satisfies readonly ProviderType[];
  const providerInput = core.getInput("provider").trim();
  if (!validProviders.some((p) => p === providerInput)) {
    throw new Error(`Invalid provider "${providerInput}". Expected one of: ${validProviders.join(", ")}`);
  }
  const provider = providerInput as ProviderType;
  const baseUrl = core.getInput("base-url") || undefined;

  const llmTimeoutSeconds = Math.max(10, parseInt(core.getInput("llm-timeout-seconds") || "60", 10));
  const maxConcurrency = Math.max(1, parseInt(core.getInput("max-concurrency") || "3", 10));

  const pathFilter = core
    .getInput("path-filter")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  const skipAuthors = core
    .getInput("skip-authors")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    apiKey,
    provider,
    baseUrl,
    githubToken: core.getInput("github-token", { required: true }),
    repositories,
    stateFile: sanitizeStatePath(core.getInput("state-file") || ".vulnerability-spoiler-state.json"),
    createIssues: core.getInput("create-issues") !== "false",
    issueRepo,
    model: modelInput,
    maxCommits: parseInt(core.getInput("max-commits") || "50", 10),
    enableRepoContext: core.getBooleanInput("enable-repo-context"),
    enableJudge: core.getBooleanInput("enable-judge"),
    judgeModel: core.getInput("judge-model") || "",
    maxConcurrency,
    pathFilter,
    skipAuthors,
    llmTimeoutMs: llmTimeoutSeconds * 1000,
  };
}

function loadState(stateFilePath: string): State {
  if (!existsSync(stateFilePath)) {
    return {};
  }
  try {
    const raw = JSON.parse(readFileSync(stateFilePath, "utf-8")) as Record<string, unknown>;
    // Strip internal metadata keys (_version, _updatedAt) — only keep repo entries
    const repos: State = {};
    for (const [key, val] of Object.entries(raw)) {
      if (!key.startsWith("_") && typeof val === "string") {
        repos[key] = val;
      }
    }
    return repos;
  } catch {
    core.warning(`Failed to parse state file, starting fresh`);
    return {};
  }
}

function saveState(stateFilePath: string, state: State): void {
  const data = {
    _version: STATE_VERSION,
    _updatedAt: new Date().toISOString(),
    ...state,
  };
  writeFileSync(stateFilePath, JSON.stringify(data, null, 2) + "\n");
}

function getRepoKey(repo: RepoConfig): string {
  return `${repo.owner}/${repo.repo}`;
}

/**
 * Applies path and author filters to a list of commits.
 * Returns only commits that should be analyzed.
 */
function filterCommits(
  commits: Awaited<ReturnType<typeof getCommitsSince>>,
  pathFilter: string[],
  skipAuthors: string[],
  log: ReturnType<typeof makeLogger>
) {
  return commits.filter((commit) => {
    // Author exclusion filter
    if (skipAuthors.length > 0) {
      const authorLower = commit.author.toLowerCase();
      if (skipAuthors.some((a) => authorLower.includes(a.toLowerCase()))) {
        log.info(`Skipping commit ${commit.sha.substring(0, 7)}: author "${commit.author}" is in skip-authors list`);
        return false;
      }
    }

    // Path inclusion filter — at least one modified file must match
    if (pathFilter.length > 0) {
      const modifiedPaths = extractModifiedPaths(commit.diff);
      const matches = modifiedPaths.some((p) =>
        pathFilter.some((f) => p.includes(f) || p.startsWith(f))
      );
      if (!matches) {
        log.info(
          `Skipping commit ${commit.sha.substring(0, 7)}: no modified paths match path-filter`
        );
        return false;
      }
    }

    return true;
  });
}

async function run(): Promise<void> {
  try {
    const inputs = getInputs();

    // Initialize clients
    initOctokit(inputs.githubToken);
    initAnalyzer({
      provider: inputs.provider,
      apiKey: inputs.apiKey,
      model: inputs.model,
      baseUrl: inputs.baseUrl,
      timeoutMs: inputs.llmTimeoutMs,
    });

    // Load state
    const state = loadState(inputs.stateFile);
    const limit = createConcurrencyLimiter(inputs.maxConcurrency);

    const log = makeLogger("main");
    log.info(`Monitoring ${inputs.repositories.length} repositories (concurrency: ${inputs.maxConcurrency})`);

    const outputs: ActionOutputs = {
      vulnerabilitiesFound: 0,
      issuesCreated: 0,
      analyzedCommits: 0,
      results: [],
    };

    // Process each repository sequentially (state is per-repo)
    for (const repo of inputs.repositories) {
      const repoKey = getRepoKey(repo);
      const repoLog = makeLogger(repoKey);
      const lastSha = state[repoKey] || null;

      repoLog.info(`Processing...`);

      try {
        // First run for this repo — just record HEAD and move on
        if (lastSha === null) {
          repoLog.info(`First run, recording current HEAD`);
          state[repoKey] = await getLatestCommitSha(repo);
          continue;
        }

        // Fetch commits since last check
        const allCommits = await getCommitsSince(repo, lastSha, inputs.maxCommits);
        repoLog.info(`Found ${allCommits.length} new commit(s) since ${lastSha.substring(0, 7)}`);

        if (allCommits.length === 0) continue;

        // Apply path/author filters before analysis to save API costs
        const commits = filterCommits(allCommits, inputs.pathFilter, inputs.skipAuthors, repoLog);
        repoLog.info(`${commits.length}/${allCommits.length} commits pass filters`);

        outputs.analyzedCommits += commits.length;

        // Parallel: fetch repo context + run LLM analysis
        type AnalysisResult = {
          commit: (typeof commits)[number];
          analysis: import("./types.js").VulnerabilityAnalysis;
          repoContext: string;
        };

        const analysisResults = await Promise.all(
          commits.map((commit) =>
            limit(async (): Promise<AnalysisResult> => {
              repoLog.info(`Analyzing commit ${commit.sha.substring(0, 7)}...`);

              let repoContext = "";
              if (inputs.enableRepoContext) {
                try {
                  repoContext = await getModifiedFilesContent(repo, commit.diff, commit.sha);
                  if (repoContext) repoLog.info(`  Fetched context for ${commit.sha.substring(0, 7)}`);
                } catch (error) {
                  repoLog.warning(`  Failed to fetch repo context for ${commit.sha.substring(0, 7)}: ${error}`);
                }
              }

              const analysis = await analyzeCommit(commit, repoContext);
              return { commit, analysis, repoContext };
            })
          )
        );

        // Sequential: judge + issue creation (avoids duplicate-issue race conditions)
        for (const { commit, analysis, repoContext } of analysisResults) {
          if (!analysis.isVulnerabilityPatch) {
            repoLog.info(`No vulnerability in ${commit.sha.substring(0, 7)}`);
            continue;
          }

          repoLog.warning(
            `VULNERABILITY DETECTED in ${commit.sha.substring(0, 7)}: ${analysis.vulnerabilityType} (${analysis.severity})`
          );

          // Optional judge pass
          if (inputs.enableJudge) {
            const judgeModelToUse = inputs.judgeModel || inputs.model;
            try {
              const judge = await judgeAnalysis(commit, analysis, judgeModelToUse, repoContext);
              if (!judge.agrees) {
                repoLog.info(`  Judge DISAGREED: ${judge.reasoning} — skipping`);
                continue;
              }
              repoLog.info(`  Judge CONFIRMED: ${judge.reasoning}`);
            } catch (error) {
              repoLog.warning(`  Judge failed: ${error}, proceeding anyway`);
            }
          }

          const vulnerability: DetectedVulnerability = { repo, commit, analysis };

          if (inputs.createIssues) {
            try {
              const isDuplicate = await checkExistingIssue(inputs.issueRepo, commit.sha);
              if (isDuplicate) {
                repoLog.info(`  Skipping duplicate issue for ${commit.sha.substring(0, 7)}`);
              } else {
                let versionInfo: import("./types.js").VersionInfo | undefined;
                try {
                  versionInfo = await getVersionInfo(repo, commit.date);
                } catch (error) {
                  repoLog.warning(`  Failed to fetch version info: ${error}`);
                }

                const issueUrl = await createVulnerabilityIssue(
                  inputs.issueRepo,
                  repo,
                  commit,
                  analysis,
                  versionInfo
                );
                vulnerability.issueUrl = issueUrl;
                outputs.issuesCreated++;
                repoLog.info(`  Created issue: ${issueUrl}`);
              }
            } catch (error) {
              repoLog.warning(`  Failed to create issue: ${error}`);
            }
          }

          outputs.vulnerabilitiesFound++;
          outputs.results.push(vulnerability);
        }

        // Update state with the newest commit SHA
        state[repoKey] = allCommits[0].sha;
      } catch (error) {
        repoLog.error(`Error processing repository: ${error}`);
      }
    }

    // Persist state with version metadata
    saveState(inputs.stateFile, state);
    log.info(`State saved to ${inputs.stateFile}`);

    // Set outputs
    core.setOutput("vulnerabilities-found", outputs.vulnerabilitiesFound);
    core.setOutput("issues-created", outputs.issuesCreated);
    core.setOutput("analyzed-commits", outputs.analyzedCommits);
    core.setOutput("results", JSON.stringify(outputs.results));

    // Summary
    log.info(`=== Summary ===`);
    log.info(`Commits analyzed: ${outputs.analyzedCommits}`);
    log.info(`Vulnerabilities found: ${outputs.vulnerabilitiesFound}`);
    log.info(`Issues created: ${outputs.issuesCreated}`);

    if (outputs.vulnerabilitiesFound > 0) {
      core.warning(`Detected ${outputs.vulnerabilitiesFound} potential vulnerabilities!`);
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed("An unexpected error occurred");
    }
  }
}

run();
