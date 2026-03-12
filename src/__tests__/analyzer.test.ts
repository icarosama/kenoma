import { describe, it, expect, vi, beforeEach } from "vitest";
import type { CommitInfo, JudgeAnalysis, VulnerabilityAnalysis } from "../types.js";

const mockComplete = vi.fn();

vi.mock("../providers.js", () => ({
  createProvider: vi.fn(() => ({ complete: mockComplete })),
}));

import { initAnalyzer, analyzeCommit, judgeAnalysis } from "../analyzer.js";

const baseCommit: CommitInfo = {
  sha: "abc123def456",
  message: "Fix input validation in query parser",
  author: "Jane Doe",
  date: "2025-01-15T10:30:00Z",
  url: "https://github.com/example/repo/commit/abc123def456",
  diff: `--- a/src/query.ts\n+++ b/src/query.ts\n@@ -10,6 +10,7 @@\n function parseQuery(input: string) {\n+  input = sanitize(input);\n   return db.query(input);\n }`,
  pullRequest: null,
};

describe("analyzeCommit", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initAnalyzer({ provider: "anthropic", apiKey: "test-api-key", model: "claude-sonnet-4-6" });
  });

  it("returns vulnerability analysis when model detects a vuln", async () => {
    const vulnResponse: VulnerabilityAnalysis = {
      isVulnerabilityPatch: true,
      vulnerabilityType: "SQL Injection",
      severity: "High",
      description: "The query parser passed unsanitized input directly to db.query().",
      affectedCode: "return db.query(input);",
      proofOfConcept: "parseQuery(\"'; DROP TABLE users; --\")",
    };

    mockComplete.mockResolvedValueOnce(vulnResponse);

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(true);
    expect(result.vulnerabilityType).toBe("SQL Injection");
    expect(result.severity).toBe("High");
    expect(result.proofOfConcept).toBeTruthy();
  });

  it("returns non-vulnerability when model says no vuln", async () => {
    const safeResponse: VulnerabilityAnalysis = {
      isVulnerabilityPatch: false,
      vulnerabilityType: null,
      severity: null,
      description: null,
      affectedCode: null,
      proofOfConcept: null,
    };

    mockComplete.mockResolvedValueOnce(safeResponse);

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(false);
    expect(result.vulnerabilityType).toBeNull();
  });

  it("returns safe default when complete() throws", async () => {
    mockComplete.mockRejectedValueOnce(new Error("API or parse error"));

    const result = await analyzeCommit(baseCommit);

    expect(result.isVulnerabilityPatch).toBe(false);
    expect(result.vulnerabilityType).toBeNull();
    expect(result.severity).toBeNull();
  });

  it("includes PR context in the prompt when commit has a PR", async () => {
    const commitWithPR: CommitInfo = {
      ...baseCommit,
      pullRequest: {
        number: 42,
        title: "Fix SQL injection in query parser",
        body: "This PR fixes a critical SQL injection vulnerability.",
        url: "https://github.com/example/repo/pull/42",
        labels: ["security", "bug"],
        mergedAt: "2025-01-15T12:00:00Z",
      },
    };

    mockComplete.mockResolvedValueOnce({
      isVulnerabilityPatch: false, vulnerabilityType: null, severity: null,
      description: null, affectedCode: null, proofOfConcept: null,
    });

    await analyzeCommit(commitWithPR);

    const prompt = mockComplete.mock.calls[0][0] as string;
    expect(prompt).toContain("PR #42");
    expect(prompt).toContain("Fix SQL injection in query parser");
    expect(prompt).toContain("security, bug");
  });

  it("includes repo context in prompt when provided", async () => {
    mockComplete.mockResolvedValueOnce({
      isVulnerabilityPatch: false, vulnerabilityType: null, severity: null,
      description: null, affectedCode: null, proofOfConcept: null,
    });

    const repoContext = "## Modified Files Context\n\n**src/foo.ts** (before patch):\n```\nconst x = 1;\n```\n\n";
    await analyzeCommit(baseCommit, repoContext);

    const prompt = mockComplete.mock.calls[0][0] as string;
    expect(prompt).toContain("Modified Files Context");
    expect(prompt).toContain("src/foo.ts");
  });

  it("omits PR section when commit has no pull request", async () => {
    mockComplete.mockResolvedValueOnce({
      isVulnerabilityPatch: false, vulnerabilityType: null, severity: null,
      description: null, affectedCode: null, proofOfConcept: null,
    });

    await analyzeCommit(baseCommit);

    const prompt = mockComplete.mock.calls[0][0] as string;
    expect(prompt).not.toContain("Associated Pull Request");
  });
});

describe("judgeAnalysis", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    initAnalyzer({ provider: "anthropic", apiKey: "test-api-key", model: "claude-sonnet-4-6" });
  });

  const primaryAnalysis: VulnerabilityAnalysis = {
    isVulnerabilityPatch: true,
    vulnerabilityType: "SQL Injection",
    severity: "High",
    description: "Unsanitized input passed to database query",
    affectedCode: "db.query(userInput)",
    proofOfConcept: "'; DROP TABLE users; --",
  };

  const testCommit: CommitInfo = {
    sha: "test-sha-123",
    message: "Fix SQL injection",
    author: "Test Author",
    date: "2025-01-01T00:00:00Z",
    url: "https://github.com/test/repo/commit/test-sha-123",
    diff: "- db.query(userInput)\n+ db.query(sanitize(userInput))",
    pullRequest: null,
  };

  it("returns agreement when judge confirms vulnerability", async () => {
    mockComplete.mockResolvedValueOnce({ agrees: true, reasoning: "The vulnerability is valid and exploitable" });

    const result = await judgeAnalysis(testCommit, primaryAnalysis, "claude-sonnet-4-6");

    expect(result.agrees).toBe(true);
    expect(result.reasoning).toContain("valid and exploitable");
  });

  it("returns disagreement when judge rejects vulnerability", async () => {
    mockComplete.mockResolvedValueOnce({ agrees: false, reasoning: "This is a false positive, no actual vulnerability" });

    const result = await judgeAnalysis(testCommit, primaryAnalysis, "claude-sonnet-4-6");

    expect(result.agrees).toBe(false);
    expect(result.reasoning).toContain("false positive");
  });

  it("returns typed JudgeAnalysis result", async () => {
    mockComplete.mockResolvedValueOnce({ agrees: true, reasoning: "Valid vulnerability" });

    const result: JudgeAnalysis = await judgeAnalysis(testCommit, primaryAnalysis, "claude-sonnet-4-6");

    expect(result.agrees).toBe(true);
    expect(result.reasoning).toContain("Valid vulnerability");
  });

  it("defaults to agreement when complete() throws", async () => {
    mockComplete.mockRejectedValueOnce(new Error("API or parse error"));

    const result = await judgeAnalysis(testCommit, primaryAnalysis, "claude-sonnet-4-6");

    expect(result.agrees).toBe(true);
    expect(result.reasoning).toBe("Judge failed to respond");
  });

  it("includes commit diff and analysis details in prompt", async () => {
    mockComplete.mockResolvedValueOnce({ agrees: true, reasoning: "Confirmed" });

    await judgeAnalysis(testCommit, primaryAnalysis, "claude-sonnet-4-6");

    const prompt = mockComplete.mock.calls[0][0] as string;
    expect(prompt).toContain("test-sha-123");
    expect(prompt).toContain("SQL Injection");
    expect(prompt).toContain("High");
    expect(prompt).toContain("'; DROP TABLE users; --");
    expect(prompt).toContain("db.query(sanitize(userInput))");
  });
});
