import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import OpenAI from "openai";
import { zodResponseFormat } from "openai/helpers/zod";
import * as core from "@actions/core";
import type { ZodType } from "zod";
import { withTimeout } from "./utils.js";

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

class AnthropicProvider implements LLMProvider {
  private client: Anthropic;
  private model: string;
  private timeoutMs: number;

  constructor(apiKey: string, model: string, timeoutMs: number) {
    this.client = new Anthropic({ apiKey });
    this.model = model;
    this.timeoutMs = timeoutMs;
  }

  async complete<T>(prompt: string, schema: ZodType<T>): Promise<T> {
    const request = this.client.messages.parse({
      model: this.model,
      max_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
      output_config: { format: zodOutputFormat(schema) },
    });

    const response = await withTimeout(request, this.timeoutMs, "Anthropic API");

    const usage = (response as { usage?: { input_tokens: number; output_tokens: number } }).usage;
    if (usage) {
      core.info(`    Tokens: ${usage.input_tokens} in / ${usage.output_tokens} out`);
    }

    return response.parsed_output as T;
  }
}

// Covers OpenAI, DeepSeek, and any OpenAI-compatible endpoint.
// DeepSeek and many other providers implement the same /chat/completions API.
class OpenAICompatibleProvider implements LLMProvider {
  private client: OpenAI;
  private model: string;
  private timeoutMs: number;

  constructor(apiKey: string, model: string, timeoutMs: number, baseUrl?: string) {
    this.client = new OpenAI({
      apiKey,
      ...(baseUrl ? { baseURL: baseUrl } : {}),
    });
    this.model = model;
    this.timeoutMs = timeoutMs;
  }

  async complete<T>(prompt: string, schema: ZodType<T>): Promise<T> {
    const request = this.client.chat.completions.parse({
      model: this.model,
      max_completion_tokens: 1024,
      messages: [{ role: "user", content: prompt }],
      response_format: zodResponseFormat(schema, "response"),
    });

    const response = await withTimeout(request, this.timeoutMs, "OpenAI API");

    const usage = response.usage;
    if (usage) {
      core.info(
        `    Tokens: ${usage.prompt_tokens} in / ${usage.completion_tokens} out (${usage.total_tokens} total)`
      );
    }

    const parsed = response.choices[0]?.message?.parsed;
    if (parsed === null || parsed === undefined) {
      throw new Error("Empty response from API");
    }
    return parsed;
  }
}

const DEEPSEEK_BASE_URL = "https://api.deepseek.com";

export function createProvider(config: ProviderConfig): LLMProvider {
  const timeoutMs = config.timeoutMs ?? 60_000;
  switch (config.provider) {
    case "anthropic":
      return new AnthropicProvider(config.apiKey, config.model, timeoutMs);
    case "openai":
      return new OpenAICompatibleProvider(config.apiKey, config.model, timeoutMs, config.baseUrl);
    case "deepseek":
      return new OpenAICompatibleProvider(
        config.apiKey,
        config.model,
        timeoutMs,
        config.baseUrl ?? DEEPSEEK_BASE_URL
      );
    case "openai-compatible":
      if (!config.baseUrl) {
        throw new Error("base-url is required when provider is 'openai-compatible'");
      }
      return new OpenAICompatibleProvider(config.apiKey, config.model, timeoutMs, config.baseUrl);
    default: {
      const _exhaustive: never = config.provider;
      throw new Error(`Unknown provider: ${_exhaustive}`);
    }
  }
}
