import { checkKeywordFilter } from "./keyword-filter";
import { App } from "../../mocks/obsidian";
import type { FilterRule } from "./types";

function makeRule(
  overrides: Partial<FilterRule> & { pattern: string },
): FilterRule {
  return {
    id: "test-rule",
    mode: "deny",
    isRegex: false,
    enabled: true,
    description: "test",
    ...overrides,
  };
}

describe("checkKeywordFilter", () => {
  describe("literal matching", () => {
    it("matches a keyword in file content", async () => {
      const app = new App();
      app.vault._cachedRead = "This file contains password data";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password" })],
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("does not match when keyword absent", async () => {
      const app = new App();
      app.vault._cachedRead = "This file is clean";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password" })],
        app.vault,
      );

      expect(result).toBeNull();
    });

    it("literal match is case-sensitive", async () => {
      const app = new App();
      app.vault._cachedRead = "This has Password uppercase";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password" })],
        app.vault,
      );

      expect(result).toBeNull();
    });
  });

  describe("regex with /i flag", () => {
    it("matches case-insensitively with regexFlags=i", async () => {
      const app = new App();
      app.vault._cachedRead = "This has Password uppercase";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password", isRegex: true, regexFlags: "i" })],
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("matches all-caps with regexFlags=i", async () => {
      const app = new App();
      app.vault._cachedRead = "SECRET PASSWORD HERE";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password", isRegex: true, regexFlags: "i" })],
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("regex without /i stays case-sensitive", async () => {
      const app = new App();
      app.vault._cachedRead = "This has Password uppercase";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "password", isRegex: true })],
        app.vault,
      );

      expect(result).toBeNull();
    });
  });

  describe("multi-word quoted keyword", () => {
    it("matches a literal multi-word string", async () => {
      const app = new App();
      app.vault._cachedRead = "when you see this line anywhere in the text, deny it";

      const result = await checkKeywordFilter(
        "some/file.md",
        [makeRule({ pattern: "when you see this line anywhere in the text" })],
        app.vault,
      );

      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });
  });
});
