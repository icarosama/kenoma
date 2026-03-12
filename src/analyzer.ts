import * as core from "@actions/core";
import {
  VulnerabilityAnalysisSchema,
  JudgeAnalysisSchema,
  type CommitInfo,
  type VulnerabilityAnalysis,
  type JudgeAnalysis,
} from "./types.js";
import { createProvider } from "./providers.js";
import type { LLMProvider, ProviderConfig } from "./providers.js";
import { withRetry } from "./utils.js";

let provider: LLMProvider;
let providerConfig: ProviderConfig;

export function initAnalyzer(config: ProviderConfig): void {
  providerConfig = config;
  provider = createProvider(config);
}

const ANALYSIS_PROMPT = `You are a security researcher analyzing git commits to identify security vulnerability patches.

Analyze the following commit and determine if it is patching an EXPLOITABLE security vulnerability.

## Commit Information
**SHA:** {sha}
**Author:** {author}
**Date:** {date}
**Message:**
{message}
{prSection}
{repoContext}

## Diff
{diff}

## Instructions
Your task is to identify commits that patch REAL, EXPLOITABLE security vulnerabilities. You must be able to demonstrate the vulnerability with a concrete proof of concept.

Only flag a commit as a vulnerability patch if ALL of the following are true:
1. The code BEFORE the patch had a clear security flaw
2. You can write a specific proof of concept showing how to exploit it
3. The vulnerability has real security impact (not just theoretical)

DO NOT flag:
- General code quality improvements or defensive coding practices
- Adding validation that prevents edge cases but has no security impact
- Performance fixes or refactoring
- Error handling improvements without security implications
- Changes that only affect internal/trusted code paths
- Commits where you cannot write a concrete exploit PoC

Respond with a JSON object (and nothing else) in the following format:
{
  "isVulnerabilityPatch": boolean,
  "vulnerabilityType": string | null,
  "severity": "Critical" | "High" | "Medium" | "Low" | null,
  "description": string | null,
  "affectedCode": string | null,
  "proofOfConcept": string | null
}

If this is NOT an exploitable security vulnerability patch, set isVulnerabilityPatch to false and all other fields to null.

If this IS patching an exploitable vulnerability:
- vulnerabilityType: The vulnerability class (e.g., "SQL Injection", "XSS", "Path Traversal", "Prototype Pollution", "Command Injection")
- severity: Based on exploitability and impact (Critical = RCE/auth bypass, High = data leak/privilege escalation, Medium = limited impact, Low = edge case)
- description: 2-3 sentences explaining the vulnerability and how the patch fixes it
- affectedCode: The vulnerable code snippet BEFORE the patch (max 5 lines)
- proofOfConcept: A CONCRETE exploit example showing malicious input and expected behavior. This must be specific code or commands that would trigger the vulnerability, not a general description.

Example proofOfConcept formats:
- For XSS: \`<script>alert(document.cookie)</script>\` in the username field
- For SQL Injection: \`' OR 1=1 --\` as the password parameter
- For Path Traversal: \`GET /api/files?path=../../../etc/passwd\`
- For Command Injection: \`; rm -rf /\` appended to the filename

If you cannot write a specific, concrete proof of concept, set isVulnerabilityPatch to false.`;

export async function analyzeCommit(
  commit: CommitInfo,
  repoContext: string = ""
): Promise<VulnerabilityAnalysis> {
  let prSection = "";
  if (commit.pullRequest) {
    const pr = commit.pullRequest;
    prSection = `
## Associated Pull Request
**PR #${pr.number}:** ${pr.title}
**URL:** ${pr.url}
**Labels:** ${pr.labels.length > 0 ? pr.labels.join(", ") : "None"}
${pr.body ? `**Description:**\n${pr.body.substring(0, 1000)}${pr.body.length > 1000 ? "..." : ""}` : ""}
`;
  }

  const replacements: Record<string, string> = {
    "{sha}": commit.sha,
    "{author}": commit.author,
    "{date}": commit.date,
    "{message}": commit.message,
    "{prSection}": prSection,
    "{repoContext}": repoContext,
    "{diff}": commit.diff,
  };

  const prompt = ANALYSIS_PROMPT.replace(
    /\{sha\}|\{author\}|\{date\}|\{message\}|\{prSection\}|\{repoContext\}|\{diff\}/g,
    (match) => replacements[match] ?? match
  );

  try {
    return await withRetry(() => provider.complete(prompt, VulnerabilityAnalysisSchema));
  } catch (error) {
    core.warning(`Analysis failed for commit ${commit.sha.substring(0, 7)}: ${error}`);
    return {
      isVulnerabilityPatch: false,
      vulnerabilityType: null,
      severity: null,
      description: null,
      affectedCode: null,
      proofOfConcept: null,
    };
  }
}

export async function judgeAnalysis(
  commit: CommitInfo,
  primaryAnalysis: VulnerabilityAnalysis,
  judgeModel: string,
  repoContext: string = ""
): Promise<JudgeAnalysis> {
  const judgeProvider = createProvider({ ...providerConfig, model: judgeModel });

  const prompt = `You are reviewing a security vulnerability assessment. The primary analyzer detected a potential vulnerability.

## Commit Being Reviewed
**SHA:** ${commit.sha}
**Message:** ${commit.message}

## Primary Analysis Conclusion
- **Vulnerability Type:** ${primaryAnalysis.vulnerabilityType}
- **Severity:** ${primaryAnalysis.severity}
- **Description:** ${primaryAnalysis.description}
- **Proof of Concept:** ${primaryAnalysis.proofOfConcept}

${repoContext}## Code Changes (Diff)
${commit.diff}

## Your Task
Review the commit diff above and the primary analysis conclusion. Do you AGREE or DISAGREE that this commit patches a real, exploitable vulnerability?

Consider:
1. Does the diff show an actual security fix?
2. Is the proof of concept realistic and specific?
3. Could the vulnerability actually be exploited?

Respond with JSON only:
{
  "agrees": boolean,
  "reasoning": string (2-3 sentences explaining your decision)
}`;

  try {
    return await withRetry(() => judgeProvider.complete(prompt, JudgeAnalysisSchema));
  } catch (error) {
    core.warning(`Judge failed for commit ${commit.sha.substring(0, 7)}: ${error}`);
    return { agrees: true, reasoning: "Judge failed to respond" };
  }
}
