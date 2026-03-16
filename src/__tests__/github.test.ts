import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CommitInfo, VulnerabilityAnalysis, VersionInfo, RepoConfig } from "../types.js";

const mockListCommits = vi.fn();
const mockGetCommit = vi.fn();
const mockListPRs = vi.fn();
const mockCreateIssue = vi.fn();
const mockGetContent = vi.fn();
const mockListReleases = vi.fn();

vi.mock("@octokit/rest", () => ({
  Octokit: class {
    repos = {
      listCommits: mockListCommits,
      getCommit: mockGetCommit,
      listPullRequestsAssociatedWithCommit: mockListPRs,
      getContent: mockGetContent,
      listReleases: mockListReleases,
    };
    issues = {
      create: mockCreateIssue,
    };
  },
}));

vi.mock("@actions/core", () => ({
  warning: vi.fn(),
  info: vi.fn(),
}));

import {
  initOctokit,
  getLatestCommitSha,
  getCommitsSince,
  createVulnerabilityIssue,
  getVersionInfo,
  truncateDiff,
  getModifiedFilesContent,
} from "../github.js";

const repo: RepoConfig = { owner: "testorg", repo: "testrepo" };

describe("truncateDiff", () => {
  it("returns the diff unchanged when under maxLength", () => {
    const diff = "short diff content";
    expect(truncateDiff(diff, 100)).toBe(diff);
  });

  it("returns the diff unchanged when exactly at maxLength", () => {
    const diff = "x".repeat(100);
    expect(truncateDiff(diff, 100)).toBe(diff);
  });

  it("truncates and appends marker when over maxLength", () => {
    const diff = "x".repeat(200);
    const result = truncateDiff(diff, 100);
    expect(result).toHaveLength(100 + "\n\n... [diff truncated]".length);
    expect(result).toContain("... [diff truncated]");
    expect(result.startsWith("x".repeat(100))).toBe(true);
  });
});

describe("getLatestCommitSha", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("returns the SHA of the most recent commit", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [{ sha: "abc123" }],
    });

    const sha = await getLatestCommitSha(repo);
    expect(sha).toBe("abc123");
    expect(mockListCommits).toHaveBeenCalledWith({
      owner: "testorg",
      repo: "testrepo",
      per_page: 1,
    });
  });

  it("throws when the repository has no commits", async () => {
    mockListCommits.mockResolvedValueOnce({ data: [] });

    await expect(getLatestCommitSha(repo)).rejects.toThrow(
      "No commits found for testorg/testrepo"
    );
  });
});

describe("getCommitsSince", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("returns commits up to the sinceSha", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "new1", commit: { message: "fix A", author: { name: "Alice", date: "2025-01-02" } }, html_url: "https://github.com/testorg/testrepo/commit/new1" },
        { sha: "new2", commit: { message: "fix B", author: { name: "Bob", date: "2025-01-01" } }, html_url: "https://github.com/testorg/testrepo/commit/new2" },
        { sha: "old_sha", commit: { message: "old", author: { name: "Carol", date: "2024-12-31" } }, html_url: "https://github.com/testorg/testrepo/commit/old_sha" },
      ],
    });

    mockGetCommit
      .mockResolvedValueOnce({ data: "diff for new1" })
      .mockResolvedValueOnce({ data: "diff for new2" });

    mockListPRs
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({ data: [] });

    const commits = await getCommitsSince(repo, "old_sha", 50);

    expect(commits).toHaveLength(2);
    expect(commits[0].sha).toBe("new1");
    expect(commits[1].sha).toBe("new2");
  });

  it("returns empty array when no new commits exist", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "old_sha", commit: { message: "old", author: { name: "Carol", date: "2024-12-31" } }, html_url: "url" },
      ],
    });

    const commits = await getCommitsSince(repo, "old_sha", 50);
    expect(commits).toHaveLength(0);
  });

  it("respects maxCommits limit", async () => {
    mockListCommits.mockResolvedValueOnce({
      data: [
        { sha: "c1", commit: { message: "m1", author: { name: "A", date: "d1" } }, html_url: "u1" },
        { sha: "c2", commit: { message: "m2", author: { name: "B", date: "d2" } }, html_url: "u2" },
        { sha: "c3", commit: { message: "m3", author: { name: "C", date: "d3" } }, html_url: "u3" },
        { sha: "old_sha", commit: { message: "old", author: { name: "D", date: "d4" } }, html_url: "u4" },
      ],
    });

    mockGetCommit.mockResolvedValue({ data: "diff" });
    mockListPRs.mockResolvedValue({ data: [] });

    const commits = await getCommitsSince(repo, "old_sha", 2);

    expect(commits).toHaveLength(2);
    expect(mockGetCommit).toHaveBeenCalledTimes(2);
  });
});

describe("createVulnerabilityIssue", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  const commit: CommitInfo = {
    sha: "abc123def456",
    message: "Fix XSS in template renderer",
    author: "Jane Doe",
    date: "2025-01-15T10:30:00Z",
    url: "https://github.com/testorg/testrepo/commit/abc123def456",
    diff: "some diff",
    pullRequest: null,
  };

  const analysis: VulnerabilityAnalysis = {
    isVulnerabilityPatch: true,
    vulnerabilityType: "XSS",
    severity: "High",
    description: "Template renderer did not escape user input.",
    affectedCode: "render(userInput)",
    proofOfConcept: "<script>alert(1)</script>",
  };

  it("creates an issue with correct title, labels, and body", async () => {
    mockCreateIssue.mockResolvedValueOnce({
      data: { html_url: "https://github.com/testorg/testrepo/issues/1" },
    });

    const issueRepo = { owner: "testorg", repo: "testrepo" };
    const url = await createVulnerabilityIssue(issueRepo, repo, commit, analysis);

    expect(url).toBe("https://github.com/testorg/testrepo/issues/1");

    const call = mockCreateIssue.mock.calls[0][0];
    expect(call.title).toContain("XSS");
    expect(call.title).toContain("testorg/testrepo");
    expect(call.labels).toContain("vulnerability");
    expect(call.labels).toContain("severity:high");
    expect(call.body).toContain("XSS");
    expect(call.body).toContain("abc123d");
    expect(call.body).toContain("<script>alert(1)</script>");
  });

  it("includes version enrichment section when versionInfo is provided", async () => {
    mockCreateIssue.mockResolvedValueOnce({
      data: { html_url: "https://github.com/testorg/testrepo/issues/2" },
    });

    const versionInfo: VersionInfo = {
      latestVulnerableVersion: "v1.1.0",
      fixedVersion: "v1.2.0",
      riskWindowDays: 5,
      riskWindowStatus: "closed",
      shodanQuery: 'product:"nginx" version:"1.1.0"',
      censysQuery: 'services.software.product="nginx" AND services.software.version="1.1.0"',
    };

    const issueRepo = { owner: "testorg", repo: "testrepo" };
    await createVulnerabilityIssue(issueRepo, repo, commit, analysis, versionInfo);

    const body = mockCreateIssue.mock.calls[0][0].body as string;
    expect(body).toContain("Version Information");
    expect(body).toContain("v1.1.0");
    expect(body).toContain("v1.2.0");
    expect(body).toContain("5 day(s)");
    expect(body).toContain("Exposure Search");
    expect(body).toContain('product:"nginx"');
    expect(body).toContain('services.software.product="nginx"');
  });

  it("shows open risk window warning when fix is not yet released", async () => {
    mockCreateIssue.mockResolvedValueOnce({
      data: { html_url: "https://github.com/testorg/testrepo/issues/3" },
    });

    const versionInfo: VersionInfo = {
      latestVulnerableVersion: "v1.1.0",
      fixedVersion: null,
      riskWindowDays: null,
      riskWindowStatus: "open",
      shodanQuery: null,
      censysQuery: null,
    };

    const issueRepo = { owner: "testorg", repo: "testrepo" };
    await createVulnerabilityIssue(issueRepo, repo, commit, analysis, versionInfo);

    const body = mockCreateIssue.mock.calls[0][0].body as string;
    expect(body).toContain("Not yet released");
    expect(body).toContain("Open —");
  });
});

describe("getVersionInfo", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("identifies last vulnerable version and fixed version", async () => {
    mockListReleases.mockResolvedValueOnce({
      data: [
        { tag_name: "v1.0.0", published_at: "2025-01-01T00:00:00Z" },
        { tag_name: "v1.1.0", published_at: "2025-01-10T00:00:00Z" },
        { tag_name: "v1.2.0", published_at: "2025-01-20T00:00:00Z" },
      ],
    });

    // Fix committed on Jan 15 — v1.1.0 is last vulnerable, v1.2.0 is fixed
    const info = await getVersionInfo(repo, "2025-01-15T12:00:00Z");

    expect(info.latestVulnerableVersion).toBe("v1.1.0");
    expect(info.fixedVersion).toBe("v1.2.0");
    expect(info.riskWindowStatus).toBe("closed");
    expect(info.riskWindowDays).toBe(5);
  });

  it("returns open risk window when no release exists after fix", async () => {
    mockListReleases.mockResolvedValueOnce({
      data: [
        { tag_name: "v1.0.0", published_at: "2025-01-01T00:00:00Z" },
        { tag_name: "v1.1.0", published_at: "2025-01-10T00:00:00Z" },
      ],
    });

    const info = await getVersionInfo(repo, "2025-01-15T12:00:00Z");

    expect(info.latestVulnerableVersion).toBe("v1.1.0");
    expect(info.fixedVersion).toBeNull();
    expect(info.riskWindowStatus).toBe("open");
    expect(info.riskWindowDays).toBeNull();
  });

  it("builds Shodan and Censys queries for known repos", async () => {
    mockListReleases.mockResolvedValueOnce({
      data: [{ tag_name: "1.26.3", published_at: "2025-01-01T00:00:00Z" }],
    });

    const nginxRepo: RepoConfig = { owner: "nginx", repo: "nginx" };
    const info = await getVersionInfo(nginxRepo, "2025-01-15T12:00:00Z");

    expect(info.shodanQuery).toBe('product:"nginx" version:"1.26.3"');
    expect(info.censysQuery).toBe('services.software.product="nginx" AND services.software.version="1.26.3"');
  });

  it("returns null queries for repos not in the product map", async () => {
    mockListReleases.mockResolvedValueOnce({ data: [] });

    const info = await getVersionInfo(repo, "2025-01-15T12:00:00Z");

    expect(info.shodanQuery).toBeNull();
    expect(info.censysQuery).toBeNull();
  });

  it("returns empty version info gracefully when releases API fails", async () => {
    mockListReleases.mockRejectedValueOnce(new Error("API error"));

    const info = await getVersionInfo(repo, "2025-01-15T12:00:00Z");

    expect(info.latestVulnerableVersion).toBeNull();
    expect(info.fixedVersion).toBeNull();
    expect(info.riskWindowStatus).toBe("open");
  });
});

describe("getModifiedFilesContent", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initOctokit("test-token");
  });

  it("fetches and formats file content from parent commit", async () => {
    const diff = `diff --git a/src/foo.ts b/src/foo.ts
index 1234567..abcdefg 100644
--- a/src/foo.ts
+++ b/src/foo.ts
@@ -1,3 +1,4 @@`;

    const fileContent = "const x = 1;\nconst y = 2;\n";

    // Mock parent commit fetch
    mockGetCommit.mockResolvedValueOnce({
      data: {
        parents: [{ sha: "parent123" }],
      },
    });

    mockGetContent.mockResolvedValueOnce({
      data: {
        type: "file",
        encoding: "base64",
        content: Buffer.from(fileContent).toString("base64"),
      },
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toContain("Modified Files Context");
    expect(result).toContain("**src/foo.ts** (before patch):");
    expect(result).toContain(fileContent);
    expect(mockGetContent).toHaveBeenCalledWith({
      owner: "testorg",
      repo: "testrepo",
      path: "src/foo.ts",
      ref: "parent123",
    });
  });

  it("truncates files over 3000 characters", async () => {
    const diff = `diff --git a/src/long.ts b/src/long.ts`;
    const longContent = "x".repeat(4000);

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [{ sha: "parent123" }] },
    });

    mockGetContent.mockResolvedValueOnce({
      data: {
        type: "file",
        encoding: "base64",
        content: Buffer.from(longContent).toString("base64"),
      },
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toContain("x".repeat(3000));
    expect(result).toContain("... [truncated]");
    expect(result.length).toBeLessThan(longContent.length + 200);
  });

  it("returns empty string when no files are found", async () => {
    const diff = `diff --git a/src/missing.ts b/src/missing.ts`;

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [{ sha: "parent123" }] },
    });
    mockGetContent.mockRejectedValueOnce(new Error("Not found"));

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toBe("");
  });

  it("limits to 3 files maximum", async () => {
    const diff = `diff --git a/src/a.ts b/src/a.ts
diff --git a/src/b.ts b/src/b.ts
diff --git a/src/c.ts b/src/c.ts
diff --git a/src/d.ts b/src/d.ts`;

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [{ sha: "parent123" }] },
    });

    mockGetContent.mockResolvedValue({
      data: {
        type: "file",
        encoding: "base64",
        content: Buffer.from("content").toString("base64"),
      },
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(mockGetContent).toHaveBeenCalledTimes(3);
    expect(result).toContain("**src/a.ts**");
    expect(result).toContain("**src/b.ts**");
    expect(result).toContain("**src/c.ts**");
    expect(result).not.toContain("**src/d.ts**");
  });

  it("skips directories and non-base64 content", async () => {
    const diff = `diff --git a/src/dir b/src/dir`;

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [{ sha: "parent123" }] },
    });
    mockGetContent.mockResolvedValueOnce({
      data: { type: "dir" },
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toBe("");
  });

  it("handles quoted file paths with spaces", async () => {
    const diff = `diff --git "a/src/my file.ts" "b/src/my file.ts"
index 1234567..abcdefg 100644
--- "a/src/my file.ts"
+++ "b/src/my file.ts"
@@ -1,3 +1,4 @@`;

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [{ sha: "parent123" }] },
    });

    mockGetContent.mockResolvedValueOnce({
      data: {
        type: "file",
        encoding: "base64",
        content: Buffer.from("const x = 1;").toString("base64"),
      },
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toContain("**src/my file.ts** (before patch):");
    expect(mockGetContent).toHaveBeenCalledWith({
      owner: "testorg",
      repo: "testrepo",
      path: "src/my file.ts",
      ref: "parent123",
    });
  });

  it("returns empty string when commit has no parent", async () => {
    const diff = `diff --git a/src/foo.ts b/src/foo.ts`;

    mockGetCommit.mockResolvedValueOnce({
      data: { parents: [] }, // Initial commit
    });

    const result = await getModifiedFilesContent(repo, diff, "abc123");

    expect(result).toBe("");
    expect(mockGetContent).not.toHaveBeenCalled();
  });
});
