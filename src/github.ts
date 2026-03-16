import { Octokit } from "@octokit/rest";
import * as core from "@actions/core";
import type {
  RepoConfig,
  CommitInfo,
  VulnerabilityAnalysis,
  PullRequestInfo,
  VersionInfo,
} from "./types.js";
import { withRetry } from "./utils.js";

let octokit: Octokit;

export function initOctokit(token: string): void {
  octokit = new Octokit({ auth: token });
}

export async function getCommitsSince(
  repo: RepoConfig,
  sinceSha: string | null,
  maxCommits: number
): Promise<CommitInfo[]> {
  const commits: CommitInfo[] = [];

  const { data: commitList } = await withRetry(() =>
    octokit.repos.listCommits({
      owner: repo.owner,
      repo: repo.repo,
      per_page: Math.min(maxCommits, 100),
    })
  );

  let foundSinceSha = sinceSha === null;
  let count = 0;

  for (const commit of commitList) {
    if (commit.sha === sinceSha) {
      foundSinceSha = true;
      break;
    }

    if (!foundSinceSha && count < maxCommits) {
      const { data: fullCommit } = await withRetry(() =>
        octokit.repos.getCommit({
          owner: repo.owner,
          repo: repo.repo,
          ref: commit.sha,
          mediaType: { format: "diff" },
        })
      );

      const diff =
        typeof fullCommit === "string"
          ? fullCommit
          : (fullCommit as unknown as { data: string }).data || "";

      const pullRequest = await getAssociatedPullRequest(repo, commit.sha);

      commits.push({
        sha: commit.sha,
        message: commit.commit.message,
        author: commit.commit.author?.name || "Unknown",
        date: commit.commit.author?.date || new Date().toISOString(),
        url: commit.html_url,
        diff: truncateDiff(diff, 15000),
        pullRequest,
      });

      count++;
    }
  }

  return commits;
}

async function getAssociatedPullRequest(
  repo: RepoConfig,
  commitSha: string
): Promise<PullRequestInfo | null> {
  try {
    const { data: prs } = await withRetry(() =>
      octokit.repos.listPullRequestsAssociatedWithCommit({
        owner: repo.owner,
        repo: repo.repo,
        commit_sha: commitSha,
      })
    );

    if (prs.length === 0) return null;

    const pr = prs[0];
    return {
      number: pr.number,
      title: pr.title,
      body: pr.body,
      url: pr.html_url,
      labels: pr.labels.map((label) =>
        typeof label === "string" ? label : label.name || ""
      ),
      mergedAt: pr.merged_at,
    };
  } catch {
    return null;
  }
}

export async function getLatestCommitSha(repo: RepoConfig): Promise<string> {
  const { data: commits } = await withRetry(() =>
    octokit.repos.listCommits({
      owner: repo.owner,
      repo: repo.repo,
      per_page: 1,
    })
  );

  if (commits.length === 0) {
    throw new Error(`No commits found for ${repo.owner}/${repo.repo}`);
  }

  return commits[0].sha;
}

/**
 * Checks whether an issue already exists for the given commit SHA to prevent duplicates.
 */
export async function checkExistingIssue(
  issueRepo: { owner: string; repo: string },
  commitSha: string
): Promise<boolean> {
  try {
    const shortSha = commitSha.substring(0, 7);
    const { data } = await withRetry(() =>
      octokit.search.issuesAndPullRequests({
        q: `repo:${issueRepo.owner}/${issueRepo.repo} is:issue ${shortSha} in:body`,
        per_page: 1,
      })
    );
    return data.total_count > 0;
  } catch {
    // If search fails, allow creation to proceed rather than silently dropping detections
    return false;
  }
}

const SHODAN_PRODUCT_MAP: Record<string, string> = {
  "nginx/nginx": "nginx",
  "redis/redis": "Redis",
  "haproxy/haproxy": "HAProxy",
  "apache/tomcat": "Apache Tomcat",
  "elastic/elasticsearch": "Elasticsearch",
  "nodejs/node": "Node.js",
  "hashicorp/vault": "Vault",
  "keycloak/keycloak": "Keycloak",
  "openssl/openssl": "OpenSSL",
  "curl/curl": "curl",
  "rabbitmq/rabbitmq-server": "RabbitMQ",
  "istio/istio": "Istio",
  "grpc/grpc-java": "gRPC",
};

function buildShodanQuery(repo: RepoConfig, version: string | null): string | null {
  const product = SHODAN_PRODUCT_MAP[`${repo.owner}/${repo.repo}`];
  if (!product) return null;
  return version ? `product:"${product}" version:"${version}"` : `product:"${product}"`;
}

function buildCensysQuery(repo: RepoConfig, version: string | null): string | null {
  const product = SHODAN_PRODUCT_MAP[`${repo.owner}/${repo.repo}`];
  if (!product) return null;
  return version
    ? `services.software.product="${product}" AND services.software.version="${version}"`
    : `services.software.product="${product}"`;
}

export async function getVersionInfo(
  repo: RepoConfig,
  fixCommitDate: string
): Promise<VersionInfo> {
  const fixDate = new Date(fixCommitDate);

  let latestVulnerableVersion: string | null = null;
  let fixedVersion: string | null = null;
  let riskWindowDays: number | null = null;
  let riskWindowStatus: "open" | "closed" = "open";

  try {
    const { data: releases } = await withRetry(() =>
      octokit.repos.listReleases({
        owner: repo.owner,
        repo: repo.repo,
        per_page: 30,
      })
    );

    const sorted = releases
      .filter((r) => r.published_at)
      .sort((a, b) => new Date(a.published_at!).getTime() - new Date(b.published_at!).getTime());

    for (const release of sorted) {
      const releaseDate = new Date(release.published_at!);
      if (releaseDate < fixDate) {
        latestVulnerableVersion = release.tag_name;
      } else if (fixedVersion === null) {
        fixedVersion = release.tag_name;
        riskWindowDays = Math.ceil(
          (releaseDate.getTime() - fixDate.getTime()) / (1000 * 60 * 60 * 24)
        );
        riskWindowStatus = "closed";
      }
    }
  } catch {
    // Non-fatal — version enrichment is best-effort
  }

  return {
    latestVulnerableVersion,
    fixedVersion,
    riskWindowDays,
    riskWindowStatus,
    shodanQuery: buildShodanQuery(repo, latestVulnerableVersion),
    censysQuery: buildCensysQuery(repo, latestVulnerableVersion),
  };
}

export async function createVulnerabilityIssue(
  issueRepo: { owner: string; repo: string },
  repo: RepoConfig,
  commit: CommitInfo,
  analysis: VulnerabilityAnalysis,
  versionInfo?: VersionInfo
): Promise<string> {
  const allowedSeverities = ["critical", "high", "medium", "low"];
  const rawSeverity = analysis.severity?.toLowerCase() || "unknown";
  const severityLabel = allowedSeverities.includes(rawSeverity) ? rawSeverity : "unknown";
  const repoFullName = `${repo.owner}/${repo.repo}`;

  const safeAuthor = escapeMarkdown(commit.author);
  const safeMessage = escapeCodeFence(commit.message);
  const safeVulnType = escapeMarkdown(analysis.vulnerabilityType || "Unknown");
  const safeSeverity = escapeMarkdown(analysis.severity || "Unknown");
  const safeDescription = escapeMarkdown(analysis.description || "No description available.");
  const safeAffectedCode = analysis.affectedCode ? escapeCodeFence(analysis.affectedCode) : null;
  const safePoC = analysis.proofOfConcept ? escapeCodeFence(analysis.proofOfConcept) : null;

  const prSection = commit.pullRequest
    ? `
### Pull Request
**PR:** [#${commit.pullRequest.number} - ${escapeMarkdown(commit.pullRequest.title)}](${commit.pullRequest.url})
**Labels:** ${commit.pullRequest.labels.length > 0 ? commit.pullRequest.labels.map(l => escapeMarkdown(l)).join(", ") : "None"}
${commit.pullRequest.body ? `\n**Description:**\n${escapeMarkdown(commit.pullRequest.body.substring(0, 500))}${commit.pullRequest.body.length > 500 ? "..." : ""}` : ""}
`
    : "";

  let versionSection = "";
  if (versionInfo) {
    const vulnVersion = versionInfo.latestVulnerableVersion
      ? `\`${versionInfo.latestVulnerableVersion}\``
      : "Unknown (no releases found)";
    const fixVersion = versionInfo.fixedVersion
      ? `\`${versionInfo.fixedVersion}\``
      : "⚠️ Not yet released — patch is public but no official release available";
    const riskWindow =
      versionInfo.riskWindowStatus === "closed" && versionInfo.riskWindowDays !== null
        ? `${versionInfo.riskWindowDays} day(s) between fix commit and official release`
        : "⚠️ Open — fix committed but no release published yet";

    const searchSection =
      versionInfo.shodanQuery || versionInfo.censysQuery
        ? `
### Exposure Search

> Use these queries to find assets potentially running the vulnerable version.
${versionInfo.shodanQuery ? `\n**Shodan:** \`${versionInfo.shodanQuery}\`` : ""}
${versionInfo.censysQuery ? `\n**Censys:** \`${versionInfo.censysQuery}\`` : ""}
`
        : "";

    versionSection = `
### Version Information

| Field | Value |
|-------|-------|
| **Last Vulnerable Version** | ${vulnVersion} |
| **Fixed Version** | ${fixVersion} |
| **Risk Window** | ${riskWindow} |
${searchSection}`;
  }

  const body = `## Potential Security Vulnerability Detected

**Repository:** [${repoFullName}](https://github.com/${repoFullName})
**Commit:** [${commit.sha.substring(0, 7)}](${commit.url})
**Author:** ${safeAuthor}
**Date:** ${commit.date}

### Commit Message
\`\`\`
${safeMessage}
\`\`\`
${prSection}
### Analysis

**Vulnerability Type:** ${safeVulnType}
**Severity:** ${safeSeverity}

### Description
${safeDescription}

### Affected Code
${safeAffectedCode ? `\`\`\`\n${safeAffectedCode}\n\`\`\`` : "Not specified"}

### Proof of Concept
${safePoC ? `\`\`\`\n${safePoC}\n\`\`\`` : "Not specified"}
${versionSection}
---
*This issue was automatically created by [Kenoma](https://github.com/icarosama/kenoma).*
*Detected at: ${new Date().toISOString()}*
`;

  const { data: issue } = await withRetry(() =>
    octokit.issues.create({
      owner: issueRepo.owner,
      repo: issueRepo.repo,
      title: `[Vulnerability] ${repoFullName}: ${safeVulnType}`,
      body,
      labels: ["vulnerability", `severity:${severityLabel}`],
    })
  );

  return issue.html_url;
}

export function truncateDiff(diff: string, maxLength: number): string {
  if (diff.length <= maxLength) return diff;
  return diff.substring(0, maxLength) + "\n\n... [diff truncated]";
}

/**
 * Extracts modified file paths from a git diff, skipping newly added files.
 * Exported for use in commit path filtering.
 */
export function extractModifiedPaths(diff: string): string[] {
  // Split diff into per-file sections and skip newly added files.
  // New files don't exist in the parent commit, so fetching them at parent SHA
  // would produce a 404. They are identified by "new file mode" or "--- /dev/null".
  const paths: string[] = [];
  const sections = diff.split(/^(?=diff --git )/m);

  for (const section of sections) {
    if (/^new file mode/m.test(section) || /^--- \/dev\/null/m.test(section)) {
      continue;
    }
    // Handle both quoted paths (spaces/special chars) and unquoted paths
    // Quoted:   diff --git "a/path with spaces" "b/path with spaces"
    // Unquoted: diff --git a/path b/path
    const match = section.match(/^diff --git "?a\/(.+?)"? "?b\//m);
    if (match) {
      paths.push(match[1]);
    }
  }

  return paths;
}

function escapeCodeFence(text: string): string {
  return text.replace(/`{3,}/g, (match) => "`\u200B".repeat(match.length));
}

export async function getModifiedFilesContent(
  repo: RepoConfig,
  diff: string,
  commitSha: string
): Promise<string> {
  // Extract file paths from diff
  const paths = extractModifiedPaths(diff);

  // Fetch parent commit SHA (GitHub API doesn't support ~1 syntax)
  let parentSha: string;
  try {
    const { data: commit } = await withRetry(() =>
      octokit.repos.getCommit({
        owner: repo.owner,
        repo: repo.repo,
        ref: commitSha,
      })
    );
    if (!commit.parents || commit.parents.length === 0) {
      return ""; // Initial commit, no parent
    }
    parentSha = commit.parents[0].sha;
  } catch {
    return ""; // Failed to get parent
  }

  // Fetch each file at parent commit, max 3 files
  const fileContents: string[] = [];

  for (const path of paths.slice(0, 3)) {
    try {
      const { data } = await withRetry(() =>
        octokit.repos.getContent({
          owner: repo.owner,
          repo: repo.repo,
          path,
          ref: parentSha,
        })
      );

      if (
        !Array.isArray(data) &&
        data.type === "file" &&
        data.encoding === "base64"
      ) {
        const bytes = Uint8Array.from(atob(data.content), (c: string) => c.charCodeAt(0));
        const content = new TextDecoder("utf-8").decode(bytes);
        // Truncate at 3000 chars
        const truncated =
          content.length > 3000
            ? content.substring(0, 3000) + "\n... [truncated]"
            : content;
        const safeContent = escapeCodeFence(truncated);
        fileContents.push(
          `**${path}** (before patch):\n\`\`\`\n${safeContent}\n\`\`\``
        );
      }
    } catch {
      // Skip files that don't exist or fail to fetch
      continue;
    }
  }

  return fileContents.length > 0
    ? `## Modified Files Context\n\n${fileContents.join("\n\n")}\n\n`
    : "";
}

function escapeMarkdown(text: string): string {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
