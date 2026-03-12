import type { ZodType } from "zod";
export type ProviderType = "anthropic" | "openai" | "deepseek" | "openai-compatible";
export interface ProviderConfig {
    provider: ProviderType;
    apiKey: string;
    model: string;
    baseUrl?: string;
    timeoutMs?: number;
}
export interface LLMProvider {
    complete<T>(prompt: string, schema: ZodType<T>): Promise<T>;
}
export declare function createProvider(config: ProviderConfig): LLMProvider;
