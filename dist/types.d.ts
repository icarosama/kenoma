export interface RepoConfig {
    owner: string;
    repo: string;
}
export interface ActionInputs {
    apiKey: string;
    provider: import("./providers.js").ProviderType;
    baseUrl?: string;
    githubToken: string;
    repositories: RepoConfig[];
    stateFile: string;
    createIssues: boolean;
    issueRepo: {
        owner: string;
        repo: string;
    };
    model: string;
    maxCommits: number;
    enableRepoContext: boolean;
    enableJudge: boolean;
    judgeModel: string;
    maxConcurrency: number;
    pathFilter: string[];
    skipAuthors: string[];
    llmTimeoutMs: number;
}
/**
 * Repo key -> last analyzed commit SHA.
 * Serialized with _version and _updatedAt metadata (stripped on load).
 */
export type State = Record<string, string>;
export interface PullRequestInfo {
    number: number;
    title: string;
    body: string | null;
    url: string;
    labels: string[];
    mergedAt: string | null;
}
export interface CommitInfo {
    sha: string;
    message: string;
    author: string;
    date: string;
    url: string;
    diff: string;
    pullRequest: PullRequestInfo | null;
}
import { z } from "zod";
export declare const VulnerabilityAnalysisSchema: z.ZodObject<{
    isVulnerabilityPatch: z.ZodBoolean;
    vulnerabilityType: z.ZodNullable<z.ZodString>;
    severity: z.ZodNullable<z.ZodEnum<{
        Critical: "Critical";
        High: "High";
        Medium: "Medium";
        Low: "Low";
    }>>;
    description: z.ZodNullable<z.ZodString>;
    affectedCode: z.ZodNullable<z.ZodString>;
    proofOfConcept: z.ZodNullable<z.ZodString>;
}, z.core.$strip>;
export type VulnerabilityAnalysis = z.infer<typeof VulnerabilityAnalysisSchema>;
export declare const JudgeAnalysisSchema: z.ZodObject<{
    agrees: z.ZodBoolean;
    reasoning: z.ZodString;
}, z.core.$strip>;
export type JudgeAnalysis = z.infer<typeof JudgeAnalysisSchema>;
export interface VersionInfo {
    latestVulnerableVersion: string | null;
    fixedVersion: string | null;
    riskWindowDays: number | null;
    riskWindowStatus: "open" | "closed";
    shodanQuery: string | null;
    censysQuery: string | null;
}
export interface DetectedVulnerability {
    repo: RepoConfig;
    commit: CommitInfo;
    analysis: VulnerabilityAnalysis;
    issueUrl?: string;
}
export interface ActionOutputs {
    vulnerabilitiesFound: number;
    issuesCreated: number;
    analyzedCommits: number;
    results: DetectedVulnerability[];
}
