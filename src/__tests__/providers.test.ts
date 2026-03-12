import { describe, it, expect, vi, beforeEach } from "vitest";
import { z } from "zod";

const { mockMessagesParse, mockCompletionsParse, mockZodOutputFormat, mockZodResponseFormat } = vi.hoisted(() => ({
  mockMessagesParse: vi.fn(),
  mockCompletionsParse: vi.fn(),
  mockZodOutputFormat: vi.fn((schema: unknown) => ({ type: "json_schema", schema })),
  mockZodResponseFormat: vi.fn((schema: unknown, name: string) => ({ type: "json_schema", name, schema })),
}));

let capturedAnthropicOptions: Record<string, unknown>;
let capturedOpenAIOptions: Record<string, unknown>;

vi.mock("@anthropic-ai/sdk", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      capturedAnthropicOptions = options;
    }
    messages = { parse: mockMessagesParse };
  },
}));

vi.mock("@anthropic-ai/sdk/helpers/zod", () => ({
  zodOutputFormat: mockZodOutputFormat,
}));

vi.mock("openai", () => ({
  default: class {
    constructor(options: Record<string, unknown>) {
      capturedOpenAIOptions = options;
    }
    chat = { completions: { parse: mockCompletionsParse } };
  },
}));

vi.mock("openai/helpers/zod", () => ({
  zodResponseFormat: mockZodResponseFormat,
}));

import { createProvider } from "../providers.js";

const testSchema = z.object({ key: z.string() });

beforeEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// createProvider — factory routing
// ---------------------------------------------------------------------------

describe("createProvider", () => {
  describe("anthropic", () => {
    it("passes the api key to the Anthropic client", () => {
      createProvider({ provider: "anthropic", apiKey: "sk-ant-key", model: "claude-opus-4" });
      expect(capturedAnthropicOptions.apiKey).toBe("sk-ant-key");
    });
  });

  describe("openai", () => {
    it("passes the api key to the OpenAI client", () => {
      createProvider({ provider: "openai", apiKey: "sk-openai-key", model: "gpt-4o" });
      expect(capturedOpenAIOptions.apiKey).toBe("sk-openai-key");
    });

    it("uses no base URL by default", () => {
      createProvider({ provider: "openai", apiKey: "sk-test", model: "gpt-4o" });
      expect(capturedOpenAIOptions.baseURL).toBeUndefined();
    });

    it("forwards a custom base URL", () => {
      createProvider({ provider: "openai", apiKey: "sk-test", model: "gpt-4o", baseUrl: "https://custom.example.com/v1" });
      expect(capturedOpenAIOptions.baseURL).toBe("https://custom.example.com/v1");
    });
  });

  describe("deepseek", () => {
    it("defaults to the DeepSeek base URL", () => {
      createProvider({ provider: "deepseek", apiKey: "sk-ds-key", model: "deepseek-chat" });
      expect(capturedOpenAIOptions.baseURL).toBe("https://api.deepseek.com");
    });

    it("allows overriding the base URL", () => {
      createProvider({ provider: "deepseek", apiKey: "sk-ds-key", model: "deepseek-chat", baseUrl: "https://my-proxy.com" });
      expect(capturedOpenAIOptions.baseURL).toBe("https://my-proxy.com");
    });
  });

  describe("openai-compatible", () => {
    it("uses the provided base URL", () => {
      createProvider({ provider: "openai-compatible", apiKey: "sk-test", model: "llama3", baseUrl: "http://localhost:11434/v1" });
      expect(capturedOpenAIOptions.baseURL).toBe("http://localhost:11434/v1");
    });

    it("throws when base-url is omitted", () => {
      expect(() =>
        createProvider({ provider: "openai-compatible", apiKey: "sk-test", model: "llama3" })
      ).toThrow("base-url is required when provider is 'openai-compatible'");
    });
  });
});

// ---------------------------------------------------------------------------
// AnthropicProvider — complete()
// ---------------------------------------------------------------------------

describe("AnthropicProvider.complete()", () => {
  it("returns the parsed_output from messages.parse", async () => {
    const provider = createProvider({ provider: "anthropic", apiKey: "sk-ant-key", model: "claude-opus-4" });
    mockMessagesParse.mockResolvedValueOnce({ parsed_output: { key: "value" } });

    const result = await provider.complete("prompt", testSchema);

    expect(result).toEqual({ key: "value" });
  });

  it("calls messages.parse with zodOutputFormat in output_config", async () => {
    const provider = createProvider({ provider: "anthropic", apiKey: "sk-ant-key", model: "claude-opus-4" });
    mockMessagesParse.mockResolvedValueOnce({ parsed_output: { key: "value" } });

    await provider.complete("my prompt", testSchema);

    const call = mockMessagesParse.mock.calls[0][0];
    expect(call.model).toBe("claude-opus-4");
    expect(call.messages).toEqual([{ role: "user", content: "my prompt" }]);
    expect(mockZodOutputFormat).toHaveBeenCalledWith(testSchema);
    expect(call.output_config.format).toEqual(mockZodOutputFormat.mock.results[0].value);
  });


});

// ---------------------------------------------------------------------------
// OpenAICompatibleProvider — complete()
// ---------------------------------------------------------------------------

describe("OpenAICompatibleProvider.complete()", () => {
  it("returns the parsed response object", async () => {
    const provider = createProvider({ provider: "openai", apiKey: "sk-test", model: "gpt-4o" });
    mockCompletionsParse.mockResolvedValueOnce({
      choices: [{ message: { parsed: { key: "value" } } }],
    });

    const result = await provider.complete("prompt", testSchema);

    expect(result).toEqual({ key: "value" });
  });

  it("calls completions.parse with zodResponseFormat in response_format", async () => {
    const provider = createProvider({ provider: "openai", apiKey: "sk-test", model: "gpt-4o" });
    mockCompletionsParse.mockResolvedValueOnce({
      choices: [{ message: { parsed: { key: "ok" } } }],
    });

    await provider.complete("my prompt", testSchema);

    const call = mockCompletionsParse.mock.calls[0][0];
    expect(call.model).toBe("gpt-4o");
    expect(call.messages).toEqual([{ role: "user", content: "my prompt" }]);
    expect(mockZodResponseFormat).toHaveBeenCalledWith(testSchema, "response");
    expect(call.response_format).toEqual(mockZodResponseFormat.mock.results[0].value);
  });

  it("throws when parsed is null", async () => {
    const provider = createProvider({ provider: "openai", apiKey: "sk-test", model: "gpt-4o" });
    mockCompletionsParse.mockResolvedValueOnce({
      choices: [{ message: { parsed: null } }],
    });

    await expect(provider.complete("prompt", testSchema)).rejects.toThrow("Empty response from API");
  });

  it("works the same for deepseek", async () => {
    const provider = createProvider({ provider: "deepseek", apiKey: "sk-ds-key", model: "deepseek-chat" });
    mockCompletionsParse.mockResolvedValueOnce({
      choices: [{ message: { parsed: { key: "vuln" } } }],
    });

    const result = await provider.complete("prompt", testSchema);

    expect(result).toEqual({ key: "vuln" });
    expect(mockZodResponseFormat).toHaveBeenCalledWith(testSchema, "response");
  });
});
