import type { RepoConfig, CommitInfo, VulnerabilityAnalysis, VersionInfo } from "./types.js";
export declare function initOctokit(token: string): void;
export declare function getCommitsSince(repo: RepoConfig, sinceSha: string | null, maxCommits: number): Promise<CommitInfo[]>;
export declare function getLatestCommitSha(repo: RepoConfig): Promise<string>;
/**
 * Checks whether an issue already exists for the given commit SHA to prevent duplicates.
 */
export declare function checkExistingIssue(issueRepo: {
    owner: string;
    repo: string;
}, commitSha: string): Promise<boolean>;
export declare function getVersionInfo(repo: RepoConfig, fixCommitDate: string): Promise<VersionInfo>;
export declare function createVulnerabilityIssue(issueRepo: {
    owner: string;
    repo: string;
}, repo: RepoConfig, commit: CommitInfo, analysis: VulnerabilityAnalysis, versionInfo?: VersionInfo): Promise<string>;
export declare function truncateDiff(diff: string, maxLength: number): string;
/**
 * Extracts modified file paths from a git diff, skipping newly added files.
 * Exported for use in commit path filtering.
 */
export declare function extractModifiedPaths(diff: string): string[];
export declare function getModifiedFilesContent(repo: RepoConfig, diff: string, commitSha: string): Promise<string>;
