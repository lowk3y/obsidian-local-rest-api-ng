import { checkDocumentNameFilter } from "./document-name-filter";
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

describe("checkDocumentNameFilter", () => {
  it("matches basename against glob pattern", () => {
    const rules = [makeRule({ pattern: "*.md", mode: "allow" })];
    const result = checkDocumentNameFilter("folder/note.md", rules);
    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(true);
  });

  it("does not match different extension", () => {
    const rules = [makeRule({ pattern: "*.md", mode: "allow" })];
    const result = checkDocumentNameFilter("folder/image.png", rules);
    expect(result).toBeNull();
  });

  it("extracts basename from nested path", () => {
    const rules = [makeRule({ pattern: "README*", mode: "deny" })];
    const result = checkDocumentNameFilter(
      "deep/nested/path/README.md",
      rules,
    );
    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
  });

  it("handles file at root (no folder)", () => {
    const rules = [makeRule({ pattern: "*.md", mode: "allow" })];
    const result = checkDocumentNameFilter("note.md", rules);
    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(true);
  });

  it("matches regex patterns against basename", () => {
    const rules = [
      makeRule({ pattern: "^draft-", isRegex: true, mode: "deny" }),
    ];
    const result = checkDocumentNameFilter(
      "notes/draft-ideas.md",
      rules,
    );
    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
  });

  it("skips disabled rules", () => {
    const rules = [
      makeRule({ pattern: "*.md", mode: "deny", enabled: false }),
    ];
    const result = checkDocumentNameFilter("note.md", rules);
    expect(result).toBeNull();
  });

  it("returns correct filterType", () => {
    const rules = [makeRule({ pattern: "*.md", mode: "allow" })];
    const result = checkDocumentNameFilter("note.md", rules);
    expect(result!.filterType).toBe("document-name");
  });
});
