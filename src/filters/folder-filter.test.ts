import { checkFolderFilter } from "./folder-filter";
import type { FilterRule } from "./types";

function makeRule(
  overrides: Partial<FilterRule> & { pattern: string },
): FilterRule {
  return {
    id: "test-rule",
    mode: "allow",
    isRegex: false,
    enabled: true,
    description: "test",
    ...overrides,
  };
}

describe("checkFolderFilter", () => {
  describe("glob matching", () => {
    const rules = [makeRule({ pattern: "PAI/**", mode: "allow" })];

    it("matches files directly in folder", () => {
      const result = checkFolderFilter("PAI/file.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });

    it("matches files in nested subfolders", () => {
      const result = checkFolderFilter("PAI/sub/deep/file.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });

    it("does not match files outside the folder", () => {
      const result = checkFolderFilter("Other/file.md", rules);
      expect(result).toBeNull();
    });

    it("does not match files with similar prefix", () => {
      const result = checkFolderFilter("PAINFUL/file.md", rules);
      expect(result).toBeNull();
    });

    it("matches directory entries (trailing slash)", () => {
      const result = checkFolderFilter("PAI/subfolder/", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });
  });

  describe("multiple rules — first match wins", () => {
    const rules = [
      makeRule({ id: "r1", pattern: "Private/**", mode: "deny" }),
      makeRule({ id: "r2", pattern: "**", mode: "allow" }),
    ];

    it("denies files matching first rule", () => {
      const result = checkFolderFilter("Private/secret.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("allows files matching second rule", () => {
      const result = checkFolderFilter("Public/readme.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });
  });

  describe("regex patterns", () => {
    const rules = [
      makeRule({ pattern: "^(PAI|Projects)/", isRegex: true, mode: "allow" }),
    ];

    it("matches PAI folder via regex", () => {
      const result = checkFolderFilter("PAI/file.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });

    it("matches Projects folder via regex", () => {
      const result = checkFolderFilter("Projects/app.ts", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });

    it("does not match other folders", () => {
      const result = checkFolderFilter("Archive/old.md", rules);
      expect(result).toBeNull();
    });
  });

  describe("disabled rules", () => {
    const rules = [
      makeRule({ pattern: "PAI/**", mode: "allow", enabled: false }),
      makeRule({ pattern: "**", mode: "deny" }),
    ];

    it("skips disabled rules", () => {
      const result = checkFolderFilter("PAI/file.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false); // Hits the catch-all deny
    });
  });

  describe("deny mode", () => {
    const rules = [makeRule({ pattern: "Secret/**", mode: "deny" })];

    it("returns allowed=false for deny rules", () => {
      const result = checkFolderFilter("Secret/notes.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
      expect(result!.filterType).toBe("folder");
    });
  });

  describe("empty rules", () => {
    it("returns null when no rules defined", () => {
      const result = checkFolderFilter("any/file.md", []);
      expect(result).toBeNull();
    });
  });

  describe("regex with /i flag (case-insensitive)", () => {
    const rules = [
      makeRule({ pattern: "^private/", isRegex: true, mode: "deny", regexFlags: "i" }),
    ];

    it("matches case-insensitively with /i flag", () => {
      const result = checkFolderFilter("Private/secret.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("matches lowercase with /i flag", () => {
      const result = checkFolderFilter("private/secret.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("matches uppercase with /i flag", () => {
      const result = checkFolderFilter("PRIVATE/secret.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });
  });

  describe("regex without /i flag stays case-sensitive", () => {
    const rules = [
      makeRule({ pattern: "^private/", isRegex: true, mode: "deny" }),
    ];

    it("matches exact case", () => {
      const result = checkFolderFilter("private/secret.md", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(false);
    });

    it("does not match different case without /i", () => {
      const result = checkFolderFilter("Private/secret.md", rules);
      expect(result).toBeNull();
    });
  });

  describe("dot files", () => {
    const rules = [makeRule({ pattern: "**", mode: "allow" })];

    it("matches dot files with dot: true", () => {
      const result = checkFolderFilter(".obsidian/config.json", rules);
      expect(result).not.toBeNull();
      expect(result!.allowed).toBe(true);
    });
  });
});
