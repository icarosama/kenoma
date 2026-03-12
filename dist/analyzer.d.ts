import { type CommitInfo, type VulnerabilityAnalysis, type JudgeAnalysis } from "./types.js";
import type { ProviderConfig } from "./providers.js";
export declare function initAnalyzer(config: ProviderConfig): void;
export declare function analyzeCommit(commit: CommitInfo, repoContext?: string): Promise<VulnerabilityAnalysis>;
export declare function judgeAnalysis(commit: CommitInfo, primaryAnalysis: VulnerabilityAnalysis, judgeModel: string, repoContext?: string): Promise<JudgeAnalysis>;
