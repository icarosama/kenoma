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
  issueRepo: { owner: string; repo: string };
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

export const VulnerabilityAnalysisSchema = z.object({
  isVulnerabilityPatch: z.boolean(),
  vulnerabilityType: z.string().nullable(),
  severity: z.enum(["Critical", "High", "Medium", "Low"]).nullable(),
  description: z.string().nullable(),
  affectedCode: z.string().nullable(),
  proofOfConcept: z.string().nullable(),
});
export type VulnerabilityAnalysis = z.infer<typeof VulnerabilityAnalysisSchema>;

export const JudgeAnalysisSchema = z.object({
  agrees: z.boolean(),
  reasoning: z.string(),
});
export type JudgeAnalysis = z.infer<typeof JudgeAnalysisSchema>;

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
